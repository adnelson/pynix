"""Serve nix store objects over HTTP."""
import argparse
import functools
import json
import logging
import os
from os.path import exists, isdir, isabs, join, basename, dirname
import re
import gzip
from subprocess import Popen, PIPE, CalledProcessError
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

from pynix import __version__
from pynix.binary_cache.nix_info_caches import PathReferenceCache
from pynix.utils import (decode_str, strip_output, query_store, tell_size,
                         NIX_STORE_PATH, NIX_STATE_PATH, NIX_BIN_PATH,
                         NIX_DB_PATH, is_path_in_store)
from pynix.narinfo import NarInfo
from pynix.exceptions import (NoSuchObject, NoNarGenerated,
                              BaseHTTPError, NixImportFailed,
                              CouldNotUpdateHash, ClientError)

_HASH_REGEX=re.compile(r"[a-z0-9]{32}")
_PATH_REGEX=re.compile(r"([a-z0-9]{32})-[^' \n/]*$")
# Matches valid nix store paths.
_STORE_PATH_REGEX = re.compile(
    join(NIX_STORE_PATH, _PATH_REGEX.pattern))

_NAR_CACHE_SIZE = int(os.getenv("NAR_CACHE_SIZE", 2048))

class NixServer(object):
    """Serves nix packages."""
    def __init__(self, compression_type="xz", direct_db=True):
        """Initializer.

        :param compression_type: How to compress NARs. Either 'xz' or 'bzip2'.
        :type compression_type: ``str``
        """
        self._compression_type = compression_type
        # Cache mapping object hashes to store paths.
        self._hashes_to_paths = {}
        # Cache mapping object hashes to store paths which have been validated.
        self._hashes_to_valid_paths = {}
        # Set of known store paths.
        self._known_store_paths = set()
        # A static string telling a nix client what this store serves.
        self._cache_info = "\n".join([
            "StoreDir: {}".format(NIX_STORE_PATH),
            "WantMassQuery: 1",
            "Priority: 30"
        ]) + "\n"
        if self._compression_type == "bzip2":
            self._nar_extension = ".nar.bz2"
        else:
            self._nar_extension = ".nar.xz"

        logging.info("Nix store path: {}".format(NIX_STORE_PATH))
        logging.info("Nix state path: {}".format(NIX_STATE_PATH))
        logging.info("Nix bin path: {}".format(NIX_BIN_PATH))


        # Try to connect to the database, and use this information to
        # also initialze the path reference cache.
        if direct_db is False:
            self._db_con = None
            self._reference_cache = PathReferenceCache(direct_db=False)
        else:
            # Test connect to the nix database; if successful, then we
            # will use a direct connection to the database rather than
            # using nix-store. This is much faster, but is unavailable on
            # some systems.
            try:
                query = "select * from ValidPaths limit 1"
                db_con = sqlite3.connect(NIX_DB_PATH)
                db_con.execute(query).fetchall()
                # If this succeeds, assign the db_con attribute.
                self._db_con = db_con
                self._reference_cache = PathReferenceCache(db_con=db_con,
                                                           location=None)
            except Exception as err:
                logging.warn("Couldn't connect to the database ({}). Can't "
                             "operate in direct-database mode :(".format(err))
                self._db_con = None
                self._reference_cache = PathReferenceCache(direct_db=False)

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
            path_prefix = join(NIX_STORE_PATH, store_object_hash) + "%"
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
            for path in map(decode_str, os.listdir(NIX_STORE_PATH)):
                match = _PATH_REGEX.match(path)
                if match is None:
                    continue
                path = join(NIX_STORE_PATH, path)
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

    def _compute_fetch_order(self, paths):
        """Given a list of paths, compute an order to fetch them in.

        The returned order will respect the dependency tree; no child
        will appear before its parent in the list. In addition, the
        returned list may be larger as some dependencies of input
        paths might not be in the original list.

        :param paths: A list of store paths.
        :type paths: ``list`` of ``str``

        :return: A list of tuples of (paths, refs) in dependency-first order.
        :rtype: ``list`` of (``str``, ``list`` of ``str``)
        """
        order = []
        order_set = set()
        def _order(path):
            if path not in order_set:
                refs = self._reference_cache.get_references(path)
                for ref in refs:
                    _order(ref)
                order.append((path, refs))
                order_set.add(path)
        logging.debug("Computing a fetch order for {}"
                      .format(tell_size(paths, "path")))
        for path in paths:
            if not isabs(path):
                path = os.path.join(NIX_STORE_PATH, path)
            _order(path)
        logging.debug("Finished computing fetch order.")
        return order

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
        in_store = is_path_in_store(store_path, db_con=self._db_con)
        if in_store is True:
            self._known_store_paths.add(store_path)
        return in_store

    @functools.lru_cache(maxsize=_NAR_CACHE_SIZE)
    def build_nar(self, store_path, compression_type):
        """Start a build of a NAR (nix archive). The result is a
        future which will result in a NAR path."""
        return self._pool.submit(NarInfo.build_nar, store_path,
                                 compression_type)

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
            narinfo = NarInfo.from_store_path(
                store_path,
                compression_type=self._compression_type)
            return make_response((narinfo.to_string(), 200,
                                 {"Content-Type": "application/octet-stream"}))

        @app.route("/nar/<obj_hash>{}".format(self._nar_extension))
        def serve_nar(obj_hash):
            """Return the compressed binary from the nix store.

            If the object isn't found, return a 404.

            :param obj_hash: First 32 characters of the object's store path.
            :type obj_hash: ``str``
            """
            store_path = self.store_path_from_hash(obj_hash)
            nar_path = self.build_nar(store_path, self._compression_type).result()
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
                match = _STORE_PATH_REGEX.match(path)
                if match is None:
                    raise ClientError(
                        "Encountered invalid store path '{}': does not match "
                        "pattern '{}'"
                        .format(path, _STORE_PATH_REGEX.pattern))
                if self.check_in_store(path):
                    path_results[path] = True
                    found += 1
                else:
                    path_results[path] = False
                    not_found += 1
            logging.debug("{} of these paths were found, and {} were not."
                          .format(found, not_found))
            return jsonify(path_results)

        @app.route("/compute-fetch-order")
        def compute_fetch_order():
            """Compute a fetch order for a client.

            Input data should be a list of store paths separated by
            newlines. Every store path in the list must exist on the
            server or a 404 will be returned.

            Returns a list in gzipped JSON. Each element of the list
            is a length 2 list where the first element is a store path
            and the second element is a list of references of that path.
            """
            paths = [p.decode("utf-8") for p in request.get_data().split()]
            paths_j = json.dumps(self._compute_fetch_order(paths))
            return make_response(gzip.compress(paths_j.encode("utf-8")), 200,
                                 {"Content-Type": "application/octet-stream"})


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
            if content_type in (None, "", "application/octet-stream"):
                data = request.data
            elif content_type == "application/x-gzip":
                data = gzip.decompress(request.data)
            else:
                msg = "Unsupported content type '{}'".format(content_type)
                raise ClientError(msg)
            proc = Popen([join(NIX_BIN_PATH, "nix-store"), "--import"],
                         stdin=PIPE, stderr=PIPE, stdout=PIPE)
            # Get the request data and send it to the subprocess.
            out, err = proc.communicate(input=data)
            if proc.wait() != 0:
                raise NixImportFailed(err)
            # The resulting path is printed to stdout. Grab it here.
            result_path = decode_str(out).strip()
            # Spin off a thread to build a NAR of the path, to speed
            # up future fetches.
            self.build_nar(result_path, self._compression_type)
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
        return app


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="nix-server")
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
                        default=os.environ.get("LOG_LEVEL", "INFO"),
                        choices=("CRITICAL", "ERROR", "INFO",
                                 "WARNING", "DEBUG"))
    parser.add_argument("--no-db", action="store_false", dest="direct_db",
                        help="Disable direct-database mode.")
    parser.set_defaults(direct_db=os.getenv("NO_DIRECT_DB", "") == "")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = _get_args()
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(message)s")
    nixserver = NixServer(compression_type=args.compression_type,
                          direct_db=args.direct_db)
    app = nixserver.make_app()
    app.run(port=args.port, host=args.host)

if __name__ == "__main__":
    main()
