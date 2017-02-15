"""Serve nix store objects over HTTP."""
import argparse
import logging
import os
from os.path import exists, isdir, join, basename, dirname
import re
from subprocess import check_output, Popen, PIPE, CalledProcessError
from threading import Thread
# Special-case here to address a runtime bug I've encountered.
# Essentially having python libraries other than those
# specifically built for this library in a PYTHONPATH can cause a
# sqlite3 import to fail when it tries to load them (esp. if they are
# python2 and this is python3, or vice-versa). This seems to be due to
# the compiled C extensions that the sqlite3 library uses.
try:
    import sqlite3
except ImportError as err:
    if "does not define init" in str(err):
        exit("Could not import sqlite3. This is probably due to PYTHONPATH "
             "corruption: make sure your PYTHONPATH is empty prior to "
             "running this command.")
    else:
        raise

from flask import Flask, make_response, send_file, request, jsonify
import six

from servenix import __version__
from servenix.common.utils import decode_str, strip_output, find_nix_paths
from servenix.common.exceptions import (NoSuchObject, NoNarGenerated,
                                        BaseHTTPError, NixImportFailed,
                                        CouldNotUpdateHash, ClientError)

_HASH_REGEX=re.compile(r"[a-z0-9]{32}")
_PATH_REGEX=re.compile(r"([a-z0-9]{32})-[^' \n/]*$")

# The types of NAR compression supported by the server.
COMPRESSION_TYPES = ("xz", "bzip2")

class NixServer(Flask):
    """Serves nix packages."""
    def __init__(self, nix_store_path, nix_bin_path, nix_state_path,
                 compression_type, debug):
        # Path to the local nix store.
        self._nix_store_path = nix_store_path
        # Path to the local nix state directory.
        self._nix_state_path = nix_state_path
        # Path to the folder containing nix binaries.
        self._nix_bin_path = nix_bin_path
        # Matches valid nix store paths (local to this store)
        self._full_store_path_regex = re.compile(
            join(self._nix_store_path, _PATH_REGEX.pattern))
        if compression_type not in COMPRESSION_TYPES:
            raise ValueError("Invalid compression type: {}. Valid types are "
                             + ", ".join(COMPRESSION_TYPES))
        self._compression_type = compression_type
        # Cache mapping object hashes to store paths.
        self._hashes_to_paths = {}
        # Cache mapping object hashes to store paths which have been validated.
        self._hashes_to_valid_paths = {}
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
            self._nar_extension = ".nar.bz2"
        else:
            self._nar_extension = ".nar.xz"
        # Enable interactive debugging on unknown errors.
        self._debug = debug
        # Test connect to the nix database; if successful, then we
        # will use a direct connection to the database rather than
        # using nix-store. This is much faster, but is unavailable on
        # some systems.
        try:
            db_path = join(nix_state_path, "nix", "db", "db.sqlite")
            query = "select * from ValidPaths limit 1"
            db_con = sqlite3.connect(db_path)
            db_con.execute(query).fetchall()
            # If this succeeds, assign the db_con attribute.
            self._db_con = db_con
        except Exception as err:
            logging.warn("Couldn't connect to the database ({}). Can't "
                         "operate in direct-database mode :(".format(err))
            self._db_con = None

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
        if store_object_hash in self._hashes_to_valid_paths:
            # Case: the hash maps to a path which has been validated
            # to exist in the nix store and in the database.
            return self._hashes_to_valid_paths[store_object_hash]
        elif store_object_hash in self._hashes_to_paths:
            # Case: the hash maps to a path which is known to exist in
            # the nix-store, but hasn't been checked for existence in
            # the database. Check that it's in the DB before returning.
            path = self._hashes_to_paths[store_object_hash]
            if self.check_in_store(path):
                self._hashes_to_valid_paths[store_object_hash] = path
                return path
            # Otherwise, remove it from the known hashes and raise an error.
            self._hashes_to_paths.pop(store_object_hash, None)
            raise NoSuchObject("No object with hash {} was found!"
                               .format(store_object_hash))
        if self._db_con is not None:
            # If we have a direct database connection, use this to check
            # path existence.
            query = "select path from ValidPaths where path like ?"
            path_prefix = join(self._nix_store_path, store_object_hash) + "%"
            with self._db_con:
                paths = self._db_con.execute(query, (path_prefix,)).fetchall()
            if len(paths) > 0:
                path = paths[0][0]
                self._hashes_to_valid_paths[store_object_hash] = path
                return path
        else:
            # Get the list of store objects by listing the directory.
            # Iterate through them until a matching hash is found, or
            # we've exhausted all paths, in which case we error.
            for path in map(decode_str, os.listdir(self._nix_store_path)):
                match = _PATH_REGEX.match(path)
                if match is None:
                    continue
                path = join(self._nix_store_path, path)
                prefix = match.group(1)
                # Add every path seen to the _hashes_to_paths cache.
                self._hashes_to_paths[prefix] = path
                if prefix == store_object_hash:
                    # The path exists in the store. Ensure it's also a
                    # valid path according to nix-store.
                    if not self.check_in_store(path):
                        break
                    self._hashes_to_valid_paths[store_object_hash] = path
                    return path
        # If we've gotten here, then the hash doesn't match any path.
        raise NoSuchObject("No object with hash {} was found."
                           .format(store_object_hash))

    def check_in_store(self, store_path):
        """Check that a store path exists in the nix store.

        :param store_path: Path to an object in the nix store. Is assumed
            to match the full path regex.
        :type store_path: ``str``

        :return: True if it's in the store, and False otherwise.
        :rtype: ``bool``
        """
        if store_path in self._known_store_paths:
            return True
        elif not exists(store_path):
            # If the path isn't in the filesystem, it definitely is
            # not a valid path.
            return False
        # If it is on the filesystem, it doesn't necessarily mean
        # that it's a registered path in the store. Check that
        # here.
        # If we have a connection to the database, all we have to
        # do is look in the database.
        if self._db_con is not None:
            query = "select path from ValidPaths where path = ?"
            with self._db_con:
                results = self._db_con.execute(query, (store_path,)).fetchall()
            if len(results) > 0:
                self._known_store_paths.add(store_path)
                return True
            else:
                return False
        else:
            # Otherwise we have to use the slower method :(
            try:
                self.query_store(store_path, "--hash", hide_stderr=True)
                self._known_store_paths.add(store_path)
                return True
            except CalledProcessError:
                return False

    def query_store(self, store_path, query, hide_stderr=False):
        """Given a query (e.g. --hash or --size), perform the query.

        :param store_path: The store path to query.
        :type store_path: ``str``
        :param query: The query to perform. Must be a valid nix-store query.
        :type query: ``str``
        :param hide_stderr: If true, stderr will be hidden.
        :type hide_stderr: ``bool``

        :return: The result of the query.
        :rtype: ``str``
        """
        nix_store = join(self._nix_bin_path, "nix-store")
        command = [nix_store, "-q", query, store_path]
        result = strip_output(command, shell=False, hide_stderr=hide_stderr)
        return result

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
        nar_size = self.query_store(store_path, "--size")
        nar_hash = self.query_store(store_path, "--hash")
        references = self.query_store(store_path, "--references").split()
        deriver = self.query_store(store_path, "--deriver")
        info = {
            "StorePath": store_path,
            "NarHash": nar_hash,
            "NarSize": nar_size,
            "FileSize": str(file_size),
            "FileHash": "sha256:{}".format(file_hash)
        }
        if references != []:
            info["References"] = " ".join(basename(ref) for ref in references)
        if deriver != "unknown-deriver":
            info["Deriver"] = basename(deriver)
        self._paths_to_info[store_path] = info
        return info

    def build_nar(self, store_path, compression_type=None, 
                  nar_extension=None):
        """Build a nix archive (nar) and return the resulting path."""
        if isinstance(store_path, tuple):
            store_path = store_path[0]

        if compression_type is None:
            compression_type = self._compression_type
            nar_extension = self._nar_extension

        # Construct a nix expression which will produce a nar.
        nar_expr = "".join([
            "(import <nix/nar.nix> {",
            'storePath = "{}";'.format(store_path),
            'hashAlgo = "sha256";',
            'compressionType = "{}";'.format(compression_type),
            "})"])

        # Nix-build this expression, resulting in a store object.
        compressed_path = strip_output([
            join(self._nix_bin_path, "nix-build"),
            "--expr", nar_expr, "--no-out-link"
        ], shell=False)

        # This path will contain a compressed file; return its path.
        contents = map(decode_str, os.listdir(compressed_path))
        for filename in contents:
            if filename.endswith(nar_extension):
                return join(compressed_path, filename)
        # This might happen if we run out of disk space or something
        # else terrible.
        raise NoNarGenerated(compressed_path, nar_extension)

    def make_app(self):
        """Create a flask app and set up routes on it.

        :return: A flask app.
        :rtype: :py:class:`Flask`
        """
        app = Flask(__name__)

        @app.route("/nix-cache-info")
        def nix_cache_info():
            """Return information about the binary cache."""
            info_string = self._cache_info
            return make_response((info_string, 200,
                                 {"Content-Type": "application/octet-stream"}))

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
                                 {"Content-Type": "application/octet-stream"}))

        @app.route("/nar/<obj_hash>.nar.xz")
        def serve_nar_xz(obj_hash):
            """Return the compressed binary from the nix store, in xz format.

            If the object isn't found, return a 404.

            :param obj_hash: First 32 characters of the object's store path.
            :type obj_hash: ``str``
            """
            store_path = self.store_path_from_hash(obj_hash)
            nar_path = self.build_nar(store_path, "xz", ".nar.xz")
            return send_file(nar_path, mimetype="application/octet-stream")

        @app.route("/nar/<obj_hash>.nar.bz2")
        def serve_nar_bz2(obj_hash):
            """Return the compressed binary from the nix store, in bz2 format.

            If the object isn't found, return a 404.

            :param obj_hash: First 32 characters of the object's store path.
            :type obj_hash: ``str``
            """
            store_path = self.store_path_from_hash(obj_hash)
            nar_path = self.build_nar(store_path, "bzip2", ".nar.bz2")
            return send_file(nar_path, mimetype="application/octet-stream")

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
            logging.debug("Request asked about {} paths".format(len(paths)))

            # Dictionary where we'll store the path results. Keys are
            # paths; values are True if the path is in the store and
            # False otherwise.
            path_results = {}
            found = 0
            not_found = 0
            # Validate that all paths match the path regex; this will make
            # the SQL query we build correct and safe.
            for path in paths:
                match = self._full_store_path_regex.match(path)
                if match is None:
                    raise ClientError(
                        "Encountered invalid store path '{}': does not match "
                        "pattern '{}'"
                        .format(path, self._full_store_path_regex.pattern))
                if self.check_in_store(path):
                    path_results[path] = True
                    found += 1
                else:
                    path_results[path] = False
                    not_found += 1
            logging.debug("{} of these paths were found, and {} were not."
                          .format(found, not_found))
            return jsonify(path_results)

        @app.route("/import-path", methods=["POST"])
        def import_path():
            """Receives a new store object.

            The request should contain binary data which can be fed
            into the 'nix-store --import' command (which is to say,
            the request should be the result of a call to `nix-store
            --export`, or an equivalent). The binary data can
            optionally be compressed with gzip, in which case the
            "Content-Type" header should be set appropriately.

            Note that the import will fail if the all of the path's
            references do not already exist on the server. It is up to
            the client to ensure that paths are sent in the correct
            order.

            After the object is successfully imported, a compressed
            NAR will be created automatically.
            """
            content_type = request.headers.get("content-type")
            def decompress(program):
                """Decompresses the request data by via the given program."""
                proc = Popen(program, stdin=PIPE, stdout=PIPE, shell=True)
                out = proc.communicate(input=request.data)[0]
                if proc.wait() != 0:
                    raise ServerError("Decompression with '{}' failed"
                                      .format(program))
                return out
            if content_type is None or content_type == "":
                data = request.data
            elif content_type == "application/x-gzip":
                data = decompress("gzip -d")
            else:
                msg = "Unsupported content type '{}'".format(content_type)
                raise ClientError(msg)
            proc = Popen([join(self._nix_bin_path, "nix-store"), "--import"],
                         stdin=PIPE, stderr=PIPE, stdout=PIPE)
            # Get the request data and send it to the subprocess.
            out, err = proc.communicate(input=data)
            if proc.wait() != 0:
                raise NixImportFailed(err)
            # The resulting path is printed to stdout. Grab it here.
            result_path = decode_str(out).strip()
            # Spin off a thread to build a NAR of the path, to speed
            # up future fetches.
            Thread(target=self.build_nar, args=(result_path,)).start()
            # Return the path as an indicator of success.
            return (result_path, 200)

        @app.errorhandler(BaseHTTPError)
        def handle_http_error(error):
            if error.status_code >= 500:
                logging.exception(error)
            logging.error(error.message)
            response = jsonify(error.to_dict())
            response.status_code = error.status_code
            return response

        if self._debug is True:
            @app.errorhandler(Exception)
            def handle_unknown(error):
                """If we encounter an unknown error, this will be triggered."""
                logging.exception(error)
                if sys.stdin.isatty():
                    import ipdb
                    ipdb.set_trace()
                return ("An unknown error occurred", 500)

        return app


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="servenix")
    parser.add_argument("--version", action="version", version=__version__)
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
    nix_paths = find_nix_paths()
    args = _get_args()
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(message)s")
    nixserver = NixServer(nix_store_path=nix_paths["nix_store_path"],
                          nix_state_path=nix_paths["nix_state_path"],
                          nix_bin_path=nix_paths["nix_bin_path"],
                          compression_type=args.compression_type,
                          debug=args.debug)
    app = nixserver.make_app()
    app.run(port=args.port, host=args.host)

if __name__ == "__main__":
    main()
