"""Some utility functions to support store operations."""
import base64
import os
from os import getenv
from os.path import exists, join, dirname, isdir, realpath
from subprocess import check_output, PIPE, Popen

from pysodium import crypto_sign_SECRETKEYBYTES

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

def strip_output(command, shell=True, input=None, hide_stderr=False):
    """Execute a bash command, and return its stripped output.

    :param command: A command, either a string or list.
    :type command: ``str`` or ``list`` of ``str``
    :param shell: Execute the command as a shell command.
    :type shell: ``bool``
    :param input: If specified, text to send to the process stdin.
    :type input: ``str`` or ``NoneType``
    :param hide_stderr: If true, stderr will be hidden.
    :type hide_stderr: ``bool``

    :return: The resulting stdout, stripped of trailing whitespace.
    :rtype: ``str``
    """
    kwargs = {"shell": shell}
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
    nix_store = join(NIX_BIN_PATH, "nix-store")
    command = [nix_store, "-q", query, store_path]
    result = strip_output(command, shell=False, hide_stderr=hide_stderr)
    return result

def parse_secret_key_file(path):
    """Given path to a secret key file, return a key name and secret key.

    :param path: Path to a secret key file.
    :type path: ``str``

    :return: A secret key name, and secret key contents.
    :rtype: (``str``, ``bytes``)
    """
    with open(path, "rb") as f:
        contents_split = f.read().strip().split(b":")
    if len(contents_split) != 2:
        raise ValueError("Secret key file {} has invalid contents. "
                         "Should contain a key name and base64-"
                         "encoded key separated by ':'")
    secret_key_name, secret_key_b64 = contents_split
    secret_key_name = secret_key_name.decode("utf-8")
    secret_key = base64.b64decode(secret_key_b64)
    if len(secret_key) != crypto_sign_SECRETKEYBYTES:
        raise ValueError("Secret key at path {} must be length {}"
                         .format(path, crypto_sign_SECRETKEYBYTES))
    return secret_key_name, secret_key


def decompress(program, data):
    """Decompresses the given data by via the given program."""
    proc = Popen(program, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate(input=data)[0]
    if proc.wait() != 0:
        raise ServerError("Decompression with '{}' failed"
                          .format(program))
    return out
