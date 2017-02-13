"""Some utility functions to support store operations."""
import base64
import os
from os.path import exists, join, dirname, isdir
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

def find_nix_paths():
    """Load up the nix bin, store and state paths, from environment.

    :return: A dictionary with three keys, each mapping to paths:
        * nix_bin_path: path to where nix binaries live
        * nix_store_path: path to where nix store objects live
        * nix_state_path: path to where nix state objects live
    :rtype: ``dict``

    :raises:
    * ``KeyError`` if 'NIX_BIN_PATH' isn't in the environment.
    * ``AssertionError`` if any of these paths don't exist.
    """
    if "NIX_BIN_PATH" in os.environ:
        nix_bin_path = os.environ["NIX_BIN_PATH"]
    else:
        nix_env = check_output("which nix-env", shell=True).strip()
        nix_bin_path = dirname(decode_str(nix_env))
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
    return {
        "nix_bin_path": nix_bin_path,
        "nix_store_path": nix_store_path,
        "nix_state_path": nix_state_path,
    }

def query_store(store_path, query, hide_stderr=False, nix_bin_path=None):
    """Given a query (e.g. --hash or --size), perform the query.

    :param store_path: The store path to query.
    :type store_path: ``str``
    :param query: The query to perform. Must be a valid nix-store query.
    :type query: ``str``
    :param hide_stderr: If true, stderr will be hidden.
    :type hide_stderr: ``bool``
    :param nix_bin_path: Path to nix binaries. Default uses find_nix_paths.
    :type nix_bin_path: ``str`` or ``NoneType``

    :return: The result of the query.
    :rtype: ``str``
    """
    nix_bin_path = nix_bin_path or find_nix_paths()["nix_bin_path"]
    nix_store = join(nix_bin_path, "nix-store")
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
    if secret_key is not None and \
            len(secret_key) != crypto_sign_SECRETKEYBYTES:
        raise ValueError("Secret key must be length {}"
                         .format(crypto_sign_SECRETKEYBYTES))
    return secret_key_name, secret_key


def decompress(program, data):
    """Decompresses the given data by via the given program."""
    proc = Popen(program, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate(input=data)[0]
    if proc.wait() != 0:
        raise ServerError("Decompression with '{}' failed"
                          .format(program))
    return out
