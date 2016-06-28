"""Serve nix store objects over HTTP."""
import argparse
import logging
import os
from os.path import exists, isdir, join, basename, dirname
import re
from subprocess import check_output, Popen, PIPE
import sqlite3

from flask import Flask, make_response, send_file, request, jsonify
import six

from servenix.utils import decode_str, strip_output
from servenix.exceptions import (NoSuchObject, NoNarGenerated,
                                 BaseHTTPError, NixImportFailed,
                                 CouldNotUpdateHash, ClientError)

_HASH_REGEX=re.compile(r"[a-z0-9]{32}")
_PATH_REGEX=re.compile(r"([a-z0-9]{32})-[^' \n/]*$")

class NixServer(Flask):
    """Serves nix packages."""
    def __init__(self, nix_store_path, nix_bin_path, nix_state_path,
                 compression_type, debug, logger):
        # Path to the local nix store.
        self._nix_store_path = nix_store_path
        # Path to the local nix state directory.
        self._nix_state_path = nix_state_path
        # Path to the folder containing nix binaries.
        self._nix_bin_path = nix_bin_path
        # Connection to the local nix SQLite database.
        self._db = sqlite3.connect(
            join(self._nix_state_path, "nix", "db", "db.sqlite"))
        # Matches valid nix store paths (local to this store)
        self._full_store_path_regex = re.compile(
            join(self._nix_store_path, _PATH_REGEX.pattern))
        self._compression_type = compression_type
        # Cache mapping object hashes to store paths.
        self._hashes_to_paths = {}
        # Cache mapping store paths to object info.
        self._paths_to_info = {}
        # Set of known store paths.
        self._known_store_paths = set()
        # A static string telling a nix client what this store serves.
        self._cache_info = "\n".join([
            "StoreDir: {}".format(self._nix_store_path),
            "WantMassQuery: 1",
            "Priority: 30"
        ]) + "\n"
        if self._compression_type == "bzip2":
            self._content_type = "application/x-bzip2"
            self._nar_extension = ".nar.bz2"
        else:
            self._content_type = "application/x-xz"
            self._nar_extension = ".nar.xz"
        # Enable interactive debugging on unknown errors.
        self._debug = debug
        # Logger for messaging.
        self._logger = logger

    def store_path_from_hash(self, store_object_hash):
        """Look up a store path using its hash.

        The name of every object in the nix store starts with a
        32-character hash. We can find the full path by finding an
        object that starts with this hash.

        :param store_object_hash: The 32-character hash prefix of the object.
        :type store_object_hash: ``str``

        :return: The full store path to the object.
        :rtype: ``str``

        :raises: :py:class:`NoSuchObject` if the object isn't in the store.
        """
        if store_object_hash in self._hashes_to_paths:
            return self._hashes_to_paths[store_object_hash]
        with self._db:
            query = ("SELECT path FROM ValidPaths WHERE path LIKE '{}%'"
                     .format(join(self._nix_store_path, store_object_hash)))
            full_path = self._db.execute(query).fetchone()
            if full_path is None:
                raise NoSuchObject("No object with hash {} was found."
                                   .format(store_object_hash))
            # fetchone returns a tuple, so grab its first element.
            full_path = full_path[0]
            self._hashes_to_paths[store_object_hash] = full_path
            return full_path

    def check_in_store(self, store_path):
        """Check that a store path exists in the nix store.

        :param store_path: Path to an object in the nix store. Is assumed
            to match the full path regex.
        :type store_path: ``str``

        :raises: :py:class:`NoSuchObject` if the object isn't in the store.
        """
        if store_path in self._known_store_paths:
            return
        with self._db:
            query = ("SELECT path FROM ValidPaths WHERE path = '{}'"
                     .format(store_path))
            if self._db.execute(query).fetchone() is None:
                raise NoSuchObject("No object with path {} was found."
                                   .format(store_path))
            self._known_store_paths.add(store_path)

    def get_object_info(self, store_path):
        """Given a store path, get some information about the path.

        :param store_path: Path to the object in the store. The path is assumed
            to exist in the store and in the SQLite database. The path must
            conform to the path regex.
        :type store_path: ``str``

        :return: A dictionary of store object information.
        :rtype: ``dict``
        """
        if store_path in self._paths_to_info:
            return self._paths_to_info[store_path]
        # Build the compressed version. Compute its hash and size.
        nar_path = self.build_nar(store_path)
        du = strip_output("du -sb {}".format(nar_path))
        file_size = int(du.split()[0])
        file_hash = strip_output("nix-hash --type sha256 --base32 --flat {}"
                                 .format(nar_path))
        with self._db:
            basic_query = ("SELECT id, hash, deriver, narSize FROM ValidPaths "
                           "WHERE path = '{}'".format(store_path))
            _id, _hash, deriver, nar_size = \
                self._db.execute(basic_query).fetchone()
            # Some paths have corrupt hashes stored in the sqlite
            # database. I'm not sure why this happens, but we check the
            # actual hash using nix-hash and if it doesn't match what
            # is stored in the database, we update the database.
            correct_hash = "sha256:{}".format(
                strip_output("nix-hash --type sha256 {}".format(store_path)))
            if correct_hash != _hash:
                self._logger.warn("Incorrect hash {} stored for path {}. Updating."
                             .format(registered_store_obj_hash, store_path))
                self._db.execute("UPDATE ValidPaths SET hash = '{}' "
                                 "WHERE path = '{}'"
                                 .format(correct_hash, store_path))
            references_query = ("SELECT path FROM Refs JOIN ValidPaths "
                                "ON reference = id WHERE referrer = {}"
                                .format(_id))
            references = self._db.execute(references_query).fetchall()
        info = {
            "StorePath": store_path,
            "NarHash": correct_hash,
            "NarSize": nar_size,
            "FileSize": str(file_size),
            "FileHash": "sha256:{}".format(file_hash)
        }
        if references != []:
            info["References"] = " ".join(basename(ref[0])
                                          for ref in references)
        if deriver is not None and deriver != "":
            info["Deriver"] = basename(deriver)
        self._paths_to_info[store_path] = info
        return info

    def build_nar(self, store_path):
        """Build a nix archive (nar) and return the resulting path."""
        # Construct a nix expression which will produce a nar.
        if isinstance(store_path, tuple):
            store_path = store_path[0]

        nar_expr = "".join([
            "(import <nix/nar.nix> {",
            'storePath = "{}";'.format(store_path),
            'hashAlgo = "sha256";',
            'compressionType = "{}";'.format(self._compression_type),
            "})"])

        # Nix-build this expression, resulting in a store object.
        compressed_path = strip_output([
            join(self._nix_bin_path, "nix-build"),
            "--expr", nar_expr, "--no-out-link"
        ], shell=False)

        # This path will contain a compressed file; return its path.
        contents = map(decode_str, os.listdir(compressed_path))
        for filename in contents:
            if filename.endswith(self._nar_extension):
                return join(compressed_path, filename)
        raise NoNarGenerated(compressed_path, self._nar_extension)

    def make_app(self):
        """Create a flask app and set up routes on it.

        :return: A flask app.
        :rtype: :py:class:`Flask`
        """
        app = Flask(__name__)

        @app.route("/nix-cache-info")
        def nix_cache_info():
            """Return information about the binary cache."""
            return self._cache_info

        @app.route("/<obj_hash>.narinfo")
        def get_narinfo(obj_hash):
            """Given an object's 32-character hash, return information on it.

            The information includes the object's size (uncompressed), sha256
            hash, store path, and reference graph.

            If the object isn't found, return a 404.

            :param obj_hash: First 32 characters of the object's store path.
            :type obj_hash: ``str``
            """
            if _HASH_REGEX.match(obj_hash) is None:
                raise ClientError("Hash {} must match {}"
                                  .format(obj_hash, _HASH_REGEX.pattern), 400)
            store_path = self.store_path_from_hash(obj_hash)
            store_info = self.get_object_info(store_path)
            # Add a few more keys to the store object, specific to the
            # compression type we're serving.
            store_info["URL"] = "nar/{}{}".format(obj_hash,
                                                  self._nar_extension)
            store_info["Compression"] = self._compression_type
            info_string = "\n".join("{}: {}".format(k, v)
                             for k, v in store_info.items()) + "\n"
            return make_response((info_string, 200,
                                 {"Content-Type": "text/x-nix-narinfo"}))

        @app.route("/nar/<obj_hash>{}".format(self._nar_extension))
        def serve_nar(obj_hash):
            """Return the compressed binary from the nix store.

            If the object isn't found, return a 404.

            :param obj_hash: First 32 characters of the object's store path.
            :type obj_hash: ``str``
            """
            store_path = self.store_path_from_hash(obj_hash)
            nar_path = self.build_nar(store_path)
            return send_file(nar_path, mimetype=self._content_type)

        @app.route("/query-paths")
        def query_paths():
            """Given a list of store paths, find which are/not in the store.

            The request must contain JSON containing a single array
            with a list of store path strings. The response will be a
            JSON dictionary mapping store paths to True if they exist
            on the server, and False otherwise.
            """
            paths = request.get_json()
            if not isinstance(paths, list):
                raise ClientError("Expected a list, but got a {}"
                                  .format(type(paths).__name__))
            else:
                for p in paths:
                    if not isinstance(p, six.string_types):
                        raise ClientError("List element {} is not a string."
                                          .format(p))

            # Dictionary where we'll store the path results. Keys are
            # paths; values are True if the path is in the store and
            # False otherwise.
            path_results = {}
            # Validate that all paths match the path regex; this will make
            # the SQL query we build correct and safe.
            for path in paths:
                match = self._full_store_path_regex.match(path)
                if match is None:
                    raise ClientError(
                        "Encountered invalid store path '{}': does not match "
                        "pattern '{}'"
                        .format(path, self._full_store_path_regex.pattern))
                try:
                    self.check_in_store(path)
                    path_results[path] = True
                except NoSuchObject:
                    path_results[path] = False
            return jsonify(path_results)

        @app.route("/import-path", methods=["POST"])
        def import_path():
            """Receives a new store object.

            Request should contain binary data which can be fed into
            the 'nix-store --import' command (which is to say, the
            request should be the result of a call to `nix-store
            --export`, or an equivalent). Note that the import will
            fail if the all of the path's references do not already
            exist on the server. It is up to the client to ensure
            that paths are sent in the correct order.

            After the object is successfully imported, a compressed
            NAR will be created automatically.
            """
            # TODO: compressed exports?
            proc = Popen([join(self._nix_bin_path, "nix-store"), "--import"],
                         stdin=PIPE, stderr=PIPE, stdout=PIPE)
            # Stream the request data into the subprocess.
            out, err = proc.communicate(input=request.stream)
            if proc.wait() != 0:
                raise NixImportFailed(err)
            # The resulting path is printed to stdout. Grab it here.
            result_path = decode_str(out).strip()
            # Spin off a thread to build a NAR of the path.
            Thread(target=self.build_nar, args=(result_path,)).start()
            # Return the path as an indicator of success.
            return (result_path, 200)

        @app.errorhandler(BaseHTTPError)
        def handle_http_error(error):
            if error.status_code >= 500:
                self._logger.exception(error)
            self._logger.error(error.message)
            response = jsonify(error.to_dict())
            response.status_code = error.status_code
            return response

        if self._debug is True:
            @app.errorhandler(Exception)
            def handle_unknown(error):
                """If we encounter an unknown error, this will be triggered."""
                self._logger.exception(error)
                if sys.stdin.isatty():
                    import ipdb
                    ipdb.set_trace()
                return ("An unknown error occurred", 500)

        return app


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="servenix")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port to listen on.")
    parser.add_argument("--host", default="localhost",
                        help="Host to listen on.")
    parser.add_argument("--compression-type", default="xz",
                        choices=("xz", "bzip2"),
                        help="How served objects should be compressed.")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Enable interactive debugging on unknown errors.")
    parser.add_argument("--log-level", help="Log messages level.",
                        default="INFO", choices=("CRITICAL", "ERROR", "INFO",
                                                 "WARNING", "DEBUG"))
    return parser.parse_args()


def main():
    """Main entry point."""
    try:
        nix_bin_path = os.environ["NIX_BIN_PATH"]
        assert exists(join(nix_bin_path, "nix-build"))
        # The store path can be given explicitly, or else it will be
        # inferred to be 2 levels up from the bin path. E.g., if the
        # bin path is /foo/bar/123-nix/bin, the store directory will
        # be /foo/bar.
        nix_store_path = os.environ.get("NIX_STORE_PATH",
                                        dirname(dirname(nix_bin_path)))
        assert isdir(nix_store_path), \
            "Nix store directory {} doesn't exist".format(nix_store_path)
        # The state path can be given explicitly, or else it will be
        # inferred to be sibling to the store directory.
        nix_state_path = os.environ.get("NIX_STATE_PATH",
                                        join(dirname(nix_store_path), "var"))
        assert isdir(nix_state_path), \
            "Nix state directory {} doesn't exist".format(nix_state_path)
    except KeyError as err:
        exit("Invalid environment: variable {} must be set.".format(err))
    args = _get_args()
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, args.log_level))
    nixserver = NixServer(nix_store_path=nix_store_path,
                          nix_state_path=nix_state_path,
                          nix_bin_path=nix_bin_path,
                          compression_type=args.compression_type,
                          debug=args.debug,
                          logger=logger)
    app = nixserver.make_app()
    app.run(port=args.port, host=args.host)

if __name__ == "__main__":
    main()
