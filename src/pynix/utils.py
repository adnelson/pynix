"""Some utility functions to support store operations."""
import base64
import os
from os import getenv
from os.path import exists, join, dirname, isdir, realpath
from subprocess import check_output, PIPE, Popen

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
    :param shell: Execute the command as a shell command.
    :type shell: ``bool``
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

NIX_DB_PATH = getenv("NIX_DB_PATH", join(NIX_STATE_PATH, "nix/db/db.sqlite"))

def nix_cmd(command_name, args=None):
    """Build a nix command, using the absolute path to the given nix binary.

    :param command_name: A nix command, it must live in the /bin dir of nix.
    :type command_name: ``str``
    :param args: Arguments to pass to the binary.
    :type args: ``str``
    """
    bin_path = join(NIX_BIN_PATH, command_name)
    if not exists(bin_path):
        raise ValueError("Invalid nix command {}".format(command_name))
    return [bin_path] + args

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
    result = strip_output(command, hide_stderr=hide_stderr)
    return result

def decompress(program, data):
    """Decompresses the given data by via the given program."""
    proc = Popen(program, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate(input=data)[0]
    if proc.wait() != 0:
        raise ServerError("Decompression with '{}' failed"
                          .format(program))
    return out
