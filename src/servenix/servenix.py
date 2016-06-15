"""Serve nix store objects over HTTP."""
import os
from os.path import exists, isdir, join
import argparse
from flask import Flask, make_response, send_file
from subprocess import check_output
import re

_HASH_REGEX=re.compile(r"[a-z0-9]{32}")
_PATH_REGEX=re.compile(r"([a-z0-9]{32})-.*")

class NoSuchObject(IOError):
    """Raises when a store object can't be found."""
    def __init__(self, message):
        self.message = message

def check_output_str(command):
    """Call check_output and convert into a string."""
    result = check_output(command)
    if hasattr(result, "decode"):
        return result.decode("utf-8")
    else:
        return result

class NixServer(Flask):
    """Serves nix packages."""
    def __init__(self, nix_store_path, nix_bin_path, compression_type):
        self._nix_store_path = nix_store_path
        self._nix_bin_path = nix_bin_path
        self._compression_type = compression_type
        # Cache mapping object hashes to store paths.
        self._hashes_to_paths = {}
        # Cache mapping store paths to object info.
        self._paths_to_info = {}
        # A static string telling a nix client what this store serves.
        self._cache_info = "\n".join([
            "StoreDir: {}".format(self._nix_store_path),
            "WantMassQuery: 1",
            "Priority: 30"
        ])
        if self._compression_type == "bzip2":
            self._content_type = "application/x-bzip2"
            self._nar_extension = ".nar.bz2"
        else:
            self._content_type = "application/x-xz"
            self._nar_extension = ".nar.xz"

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
        store_objects = os.listdir(self._nix_store_path)
        try:
            for obj in store_objects:
                if hasattr(obj, "decode"):
                    obj = obj.decode("utf-8")
                match = _PATH_REGEX.match(obj)
                if match is None:
                    continue
                full_path = join(self._nix_store_path, obj)
                _hash = match.group(1)
                self._hashes_to_paths[_hash] = full_path
                if _hash == store_object_hash:
                    return full_path
            raise NoSuchObject("No object with hash {} was found."
                               .format(store_object_hash))
        except TypeError as err:
            import pdb; pdb.set_trace()

    def get_object_info(self, store_path):
        """Given a store path, get some information about the path.

        :param store_path: Path to the object in the store.
        :type store_path: ``str``

        :return: A dictionary of store object information.
        :rtype: ``dict``
        """
        if store_path in self._paths_to_info:
            return self._paths_to_info[store_path]
        # Invoke nix-store with various queries to get package info.
        nix_store_q = lambda option: check_output_str([
            "{}/nix-store".format(self._nix_bin_path),
            "--query", option, store_path
        ]).strip()
        info = {
            "StorePath": store_path,
            "NarHash": nix_store_q("--hash"),
            "NarSize": nix_store_q("--size"),
        }
        references = nix_store_q("--references").replace("\n", " ")
        if references != "":
            info["References"] = references
        deriver = nix_store_q("--deriver")
        if deriver != "unknown-deriver":
            info["Deriver"] = deriver
        self._paths_to_info[store_path] = info
        return info

    def build_nar(self, store_path):
        """Build a nix archive (nar) and return the resulting path."""
        # Construct a nix expression which will produce a nar.
        nar_expr = "".join([
            "(import <nix/nar.nix> {",
            'storePath = "{}";'.format(store_path),
            'hashAlgo = "sha256";',
            'compressionType = "{}";'.format(self._compression_type),
            "})"])
        # Nix-build this expression, resulting in a store
        compressed_path = check_output_str([
            join(self._nix_bin_path, "nix-build"),
            "--expr", nar_expr
        ]).strip()

        # This path will contain a compressed file; return its path.
        contents = os.listdir(compressed_path)
        for filename in contents:
            if hasattr(filename, "decode"):
                filename = filename.decode("utf-8")
            if filename.endswith(self._nar_extension):
                return join(compressed_path, filename)

    def make_app(self):
        """Create a flask app and set up routes on it.

        :return: A flask app.
        :rtype: :py:class:`Flask`
        """
        app = Flask(__name__)

        @app.route('/')
        def hello_world():
            return 'Hello, World!'

        @app.route("/nix-cache-info")
        def nix_cache_info():
            """Return information about the binary cache."""
            return self._cache_info

        @app.route("/<obj_hash>.narinfo")
        def get_narinfo(obj_hash):
            if _HASH_REGEX.match(obj_hash) is None:
                 return ("Hash {} must match {}"
                         .format(obj_hash, _HASH_REGEX.pattern), 400)
            try:
                store_path = self.store_path_from_hash(obj_hash)
                store_info = self.get_object_info(store_path)
            except NoSuchObject as err:
                return (err.message, 404)
            # Add a few more keys to the store object, specific to the
            # compression type we're serving.
            store_info["Url"] = "nar/{}{}".format(obj_hash,
                                                  self._nar_extension)
            store_info["Compression"] = self._compression_type
            info_string = "\n".join("{}: {}".format(k, v)
                             for k, v in store_info.items()) + "\n"
            return make_response((info_string, 200,
                                 {"Content-Type": "text/x-nix-narinfo"}))

        @app.route("/nar/<obj_hash>{}".format(self._nar_extension))
        def serve_nar(obj_hash):
            """Return the compressed binary from the nix store."""
            try:
                store_path = self.store_path_from_hash(obj_hash)
            except NoSuchObject as err:
                return (err.message, 404)
            nar_path = self.build_nar(store_path)
            return send_file(nar_path, mimetype=self._content_type)

        return app


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="servenix")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port to listen on.")
    parser.add_argument("--compression-type", default="xz",
                        choices=("xz", "bzip2"),
                        help="How served objects should be compressed.")
    return parser.parse_args()

def main():
    """Main entry point."""
    try:
        NIX_BIN_PATH = os.environ["NIX_BIN_PATH"]
        assert exists(join(NIX_BIN_PATH, "nix-store"))
        NIX_STORE_PATH = os.environ["NIX_STORE_PATH"]
        assert isdir(NIX_STORE_PATH)
    except KeyError as err:
        exit("Invalid environment: variable {} must be set.".format(err))
    args = _get_args()
    nixserver = NixServer(nix_store_path=NIX_STORE_PATH,
                          nix_bin_path=NIX_BIN_PATH,
                          compression_type=args.compression_type)
    app = nixserver.make_app()
    app.run(port=args.port)

if __name__ == "__main__":
    main()
