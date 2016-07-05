"""Some utility functions to support store operations."""
import os
from os.path import exists, join, dirname, isdir
from subprocess import check_output

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

def strip_output(command, shell=True):
    """Execute a bash command, and return its stripped output.

    :param command: A command, either a string or list.
    :type command: ``str`` or ``list`` of ``str``
    :param shell: Execute the command as a shell command.
    :type shell: ``bool``

    :return: The resulting stdout, stripped of trailing whitespace.
    :rtype: ``str``
    """
    return decode_str(check_output(command, shell=shell)).strip()

def replace_quotes(string):
    """Replace unicode quotes with ASCII.

    Errors reported by nix use unicode quotes to wrap paths. This
    often results in escape sequences which are confusing to read.

    :param string: The input string, possibly containing unicode quotes.
    :type string: ``str`` or ``bytes``

    :return: The string without the unicode quotes.
    :rtype: ``str``
    """
    string = decode_str(string)
    return string.replace("‘", "'").replace("’", "'")

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
    return {
        "nix_bin_path": nix_bin_path,
        "nix_store_path": nix_store_path,
        "nix_state_path": nix_state_path,
    }
