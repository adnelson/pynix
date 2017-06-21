"""Some utility functions to support store operations."""
import base64
import logging
import os
from os import getenv
from os.path import exists, join, dirname, isdir, realpath
import sqlite3
from subprocess import call, check_output, PIPE, Popen, CalledProcessError

import six

from pynix.exceptions import NixInstantiationError

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

# This variable is true when we detect we're on a nixos linux.
if os.getenv("IS_NIXOS", "") != "":
    IS_NIXOS = True
else:
    IS_NIXOS = (call("nixos-version", shell=True, stderr=PIPE) == 0 or
                isdir("/etc/nixos"))

NIX_DB_ACCESSIBLE = None

def connect_nix_db():
    """Attempt to connect to the nix DB, otherwise return None."""
    global NIX_DB_ACCESSIBLE
    if NIX_DB_ACCESSIBLE is False:
        return None
    try:
        connection = sqlite3.connect(NIX_DB_PATH)
        if NIX_DB_ACCESSIBLE is None:
            # Case: we don't know if the DB is accessible. Test it.
            with connection:
                query = connection.execute("select * from ValidPaths limit 1")
                query.fetchall()
            # Set to True so that we don't test unnecessarily later.
            NIX_DB_ACCESSIBLE = True
        if NIX_DB_ACCESSIBLE is True:
            return connection
    except Exception as e:
        # An exception was raised trying to connect to the DB.
        NIX_DB_ACCESSIBLE = False
        return None

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

def instantiate(nix_file, attributes=None, show_trace=True):
    """Wraps a call to nix-instantiate."""
    attributes = [] if attributes is None else attributes
    command = nix_cmd("nix-instantiate", [nix_file, "--no-gc-warning"])
    if show_trace is True:
        command.append("--show-trace")
    for attr in attributes:
        command.extend(["-A", attr])
    try:
        return strip_output(command).split()
    except CalledProcessError as err:
        six.raise_from(NixInstantiationError(nix_file, attributes), err)

def tell_size(obj, word, suffix="s"):
    """Useful when you want to write a message to the user.

    :param obj: The object being described.
    :type obj: Anything that works with the len() function.
    :param word: Word to use to describe the object.
    :type word: ``str``
    :param suffix: What to append to the word if plural.
    :type suffix: ``str``

    :return: The length, followed by the possibly pluralized word.
    :rtype: ``str``
    """
    if len(obj) == 1:
        return "1 {}".format(word)
    else:
        return "{} {}{}".format(len(obj), word, suffix)

def is_path_in_store(store_path, db_con=None, hide_stderr=True):
    """Check if a path is in the nix store.

    Optionally provide a database connection which speeds things up.
    """
    db_con = db_con or connect_nix_db()
    # Ensure path is absolute
    store_path = join(NIX_STORE_PATH, store_path)
    # If we have a connection to the database, all we have to
    # do is look in the database.
    if db_con is not None:
        query = "select path from ValidPaths where path = ?"
        with db_con:
            results = db_con.execute(query, (store_path,)).fetchall()
        if len(results) > 0:
            return True
        else:
            logging.debug("Tried to look up {} in the nix DB, not there."
                          .format(store_path))
            return False
    else:
        # Otherwise we have to use the slower method :( Subprocess
        # into nix-store and execute a query.
        try:
            query_store(store_path, "--hash", hide_stderr=hide_stderr)
            return True
        except CalledProcessError:
            logging.debug("Tried to use nix-store to query path {}, but "
                          "got an error".format(store_path))
            return False
