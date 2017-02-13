"""Some utility functions to support store operations."""
import base64
import os
from os import getenv
from os.path import exists, join, dirname, isdir, realpath
from subprocess import check_output, PIPE, Popen

from pysodium import (crypto_sign_SECRETKEYBYTES, crypto_sign_PUBLICKEYBYTES)

def decode_str(string):
    """Convert a bytestring to a string. Is a no-op for strings.

    This is necessary because python3 distinguishes between
    bytestrings and unicode strings, and uses the former for
    operations that read from files or other operations. In general
    programmatically we're fine with just using unicode, so we decode
    everything. This function also makes backwards-compatibility with
    python2, since this will have no effect.

    :param string: Either a string or bytes.
    :type string: ``str`` or ``bytes``

    :return: A unicode string.
    :rtype: ``str``
    """
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    else:
        return string

def strip_output(command, input=None, hide_stderr=False):
    """Execute a bash command, and return its stripped output.

    :param command: A command, either a string or list.
    :type command: ``str`` or ``list`` of ``str``
    :param input: If specified, text to send to the process stdin.
    :type input: ``str`` or ``NoneType``
    :param hide_stderr: If true, stderr will be hidden.
    :type hide_stderr: ``bool``

    :return: The resulting stdout, stripped of trailing whitespace.
    :rtype: ``str``
    """
    kwargs = {"shell": isinstance(command, str)}
    if hide_stderr is True:
        kwargs["stderr"] = PIPE
    if input is not None:
        kwargs["input"] = input
    output = check_output(command, **kwargs)
    return decode_str(output).strip()

# Load nix paths from environment
if "NIX_BIN_PATH" in os.environ:
    NIX_BIN_PATH = os.environ["NIX_BIN_PATH"]
else:
    NIX_BIN_PATH = dirname(realpath(strip_output("type -p nix-env")))
assert exists(join(NIX_BIN_PATH, "nix-build")), \
    "Couldn't determine a valid nix binary path. Set NIX_BIN_PATH"
# The store path can be given explicitly, or else it will be
# inferred to be 2 levels up from the bin path. E.g., if the
# bin path is /foo/bar/123-nix/bin, the store directory will
# be /foo/bar.
NIX_STORE_PATH = getenv("NIX_STORE", dirname(dirname(NIX_BIN_PATH)))
assert isdir(NIX_STORE_PATH), \
    "Nix store directory {} doesn't exist".format(NIX_STORE_PATH)
# The state path can be given explicitly, or else it will be
# inferred to be sibling to the store directory.
NIX_STATE_PATH = getenv("NIX_STATE_PATH", join(dirname(NIX_STORE_PATH), "var"))
assert isdir(NIX_STATE_PATH), \
    "Nix state directory {} doesn't exist".format(NIX_STATE_PATH)

# Some paths to binaries that the library wants to call. If any of
# these are not available, instantiation of this module will fail.
GZIP = strip_output("type -p gzip")
BZIP2 = strip_output("type -p bzip2")
XZ = strip_output("type -p xz")
PV = strip_output("type -p pv")
DU = strip_output("type -p du")
NIX_STORE = join(NIX_BIN_PATH, "nix-store")
NIX_BUILD = join(NIX_BIN_PATH, "nix-build")
NIX_ENV = join(NIX_BIN_PATH, "nix-env")
NIX_HASH = join(NIX_BIN_PATH, "nix-hash")

def query_store(store_path, query, hide_stderr=False):
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
    command = [NIX_STORE, "-q", query, store_path]
    result = strip_output(command, hide_stderr=hide_stderr)
    return result

def parse_key_file(path):
    """Given path to a key file, return a key name and key.

    :param path: Path to a key file.
    :type path: ``str``
    :param key_length: The expected length of the key.
    :type key_length: ``int``

    :return: A key name, and key contents.
    :rtype: (``str``, ``bytes``)
    """
    with open(path, "rb") as f:
        contents_split = f.read().strip().split(b":")
    if len(contents_split) != 2:
        raise ValueError("Key file {} has invalid contents. "
                         "Should contain a key name and base64-"
                         "encoded key separated by ':'".format(path))
    key_name, key_b64 = contents_split
    key_name = key_name.decode("utf-8")
    key = base64.b64decode(key_b64)
    return key_name, key

class KeyInfo(object):
    """Stores public and secret keys for the server."""
    def __init__(self, key_name, public_key, secret_key):
        self.key_name = key_name
        self.public_key = public_key
        if len(self.public_key) != crypto_sign_PUBLICKEYBYTES:
            raise ValueError("Invalid public key: should be length {}"
                             .format(crypto_sign_PUBLICKEYBYTES))
        self.secret_key = secret_key
        if len(self.secret_key) != crypto_sign_SECRETKEYBYTES:
            raise ValueError("Invalid secret key: should be length {}"
                             .format(crypto_sign_SECRETKEYBYTES))

    @classmethod
    def load(cls, public_key_file, secret_key_file):
        """Load up public and secret key files.

        :param public_key_file: Path to a file containing public key info.
        :type public_key_file: ``str``
        :param secret_key_file: Path to a file containing secret key info.
        :type secret_key_file: ``str``

        :return: The key information.
        :rtype: :py:class:`KeyInfo`
        """
        s_key_name, s_key = parse_key_file(secret_key_file)
        p_key_name, p_key = parse_key_file(public_key_file)
        if s_key_name != p_key_name:
            raise ValueError("Different key names: public key is named '{}' "
                             "and secret key is named '{}'"
                             .format(s_key_name, p_key_name))
        return cls(key_name=s_key_name, public_key=p_key, secret_key=s_key)


def decompress(program, data):
    """Decompresses the given data by via the given program."""
    proc = Popen([program, "-d"], stdin=PIPE, stdout=PIPE)
    out = proc.communicate(input=data)[0]
    if proc.wait() != 0:
        raise ServerError("Decompression with '{}' failed"
                          .format(program))
    return out
