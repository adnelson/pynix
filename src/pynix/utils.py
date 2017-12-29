"""Some utility functions to support store operations."""
import base64
import sys
if sys.version_info >= (3, 0):
    from io import BytesIO
else:
    from StringIO import StringIO as BytesIO
import logging
import os
from os import getenv
from os.path import exists, join, dirname, isdir, realpath, isfile, basename
import sqlite3
from subprocess import call, check_output, PIPE, Popen, CalledProcessError
import time

import six
import magic

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
    assert exists(join(NIX_BIN_PATH, "nix-build")), \
        "Couldn't determine a valid nix binary path. Set NIX_BIN_PATH"
else:
    for bin_path in os.environ["PATH"].split(os.pathsep):
        if isdir(bin_path) and "nix-env" in os.listdir(bin_path):
            NIX_BIN_PATH = realpath(bin_path)
            break
    else:
        raise RuntimeError("nix-env isn't in the PATH")

# The store path can be given explicitly, or else it will be
# inferred to be 2 levels up from the bin path. E.g., if the
# bin path is /foo/bar/123-nix/bin, the store directory will
# be /foo/bar.
NIX_STORE_PATH = getenv("NIX_STORE", dirname(dirname(NIX_BIN_PATH)))
assert isdir(NIX_STORE_PATH), \
    "Nix store directory {} doesn't exist".format(NIX_STORE_PATH)
# The state path can be given explicitly, or else it will be
# inferred to be sibling to the store directory.
NIX_STATE_PATH = getenv("NIX_STATE_PATH",
                        join(dirname(NIX_STORE_PATH), "var", "nix"))
assert isdir(NIX_STATE_PATH), \
    "Nix state directory {} doesn't exist".format(NIX_STATE_PATH)
# Nix reads this env variable; set it here
os.environ["NIX_STATE_DIR"] = NIX_STATE_PATH

NIX_DB_PATH = getenv("NIX_DB_PATH", join(NIX_STATE_PATH, "nix/db/db.sqlite"))

# Nix also reads this variable...
os.environ["NIX_DB_DIR"] = dirname(NIX_DB_PATH)

# This variable is true when we detect we're on a nixos linux.
if os.getenv("IS_NIXOS", "") != "":
    IS_NIXOS = True
else:
    result = call("nixos-version", shell=True, stdout=PIPE, stderr=PIPE)
    IS_NIXOS = result == 0 or isdir("/etc/nixos")

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

def instantiate(nix_file=None, attributes=None, nix_expr=None,
                show_trace=True):
    """Wraps a call to nix-instantiate."""
    if nix_expr is not None:
        command = nix_cmd("nix-instantiate", ["-E", nix_expr])
        logging.info("Instantiating nix expression {}"
                     .format(repr(nix_expr)))
    elif nix_file is not None:
        logging.info("Instantiating attribute{} {} from path {}"
                     .format("s" if len(attributes) > 1 else "",
                             ", ".join(attributes), nix_file))
        attributes = [] if attributes is None else attributes
        command = nix_cmd("nix-instantiate", [nix_file])
        for attr in attributes:
            command.extend(["-A", attr])
    else:
        raise ValueError("Either an expression or a nix file must be given.")
    command.append("--no-gc-warning")
    if show_trace is True:
        command.append("--show-trace")
    try:
        return strip_output(command).split()
    except CalledProcessError as err:
        six.raise_from(NixInstantiationError(nix_file=nix_file,
                                             nix_expr=nix_expr,
                                             attributes=attributes), err)

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

def is_path_in_store(store_path, db_con=None, hide_stderr=True,
                     ignore_db_con=False):
    """Check if a path is in the nix store.

    Optionally provide a database connection which speeds things up.
    """
    db_con = db_con or connect_nix_db()
    # Ensure path is absolute
    store_path = join(NIX_STORE_PATH, store_path)
    # If we have a connection to the database, all we have to
    # do is look in the database.
    if db_con is not None and ignore_db_con is False:
        query = "select path from ValidPaths where path = ?"
        try:
            with db_con:
                results = db_con.execute(query, (store_path,)).fetchall()
        except sqlite3.OperationalError as err:
            # This can happen under heavy disk load; if so fall back
            # to querying with the nix-store executable.
            logging.exception(err)
            return is_path_in_store(store_path,
                                    db_con=None,
                                    hide_stderr=hide_stderr,
                                    ignore_db_con=True)
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

# Mimetypes of tarball files
TARBALL_MIMETYPES = set(['application/x-gzip', 'application/x-xz',
                         'application/x-bzip2', 'application/zip'])


def is_tarball(store_path):
    """Return true if the path is a tarball, or a directory which only
       contains a tarball.
    :param store_path: A nix store path.
    :type store_path: ``str``

    :return: True if the store path appears to be a tarball.
    :rtype: ``bool``
    """
    if isfile(store_path):
        path = store_path
    elif isdir(store_path) and len(os.listdir(store_path)) == 1:
        path = join(store_path, os.listdir(store_path)[0])
    else:
        return False
    mimetype = decode_str(magic.from_file(path, mime=True))
    return mimetype in TARBALL_MIMETYPES


class Streamer(BytesIO):
    """Wrapper around BytesIO which show progress of reads."""
    def __init__(self, path, data, log_func):
        BytesIO.__init__(self, data)
        self._streamed = 0
        self._len = len(data)
        self._len_mb = len(data) / 1048576.0
        self._path = basename(path)
        self._log_func = log_func
        self._start_time = time.time()
        self._last_percent_ten = None
        self._last_print_time = self._start_time

    def read(self, *args, **kwargs):
        """Read from the source, printing progress.

        Only prints if at least a half-second has elapsed.
        """
        result = BytesIO.read(self, *args, **kwargs)
        self._streamed += len(result)
        bytes_per_sec = self._streamed / (time.time() - self._start_time)
        percent = 100.0 * (float(self._streamed) / self._len)
        percent_ten = int(percent) // 10
        if len(result) > 0:
            if time.time() - self._last_print_time > 0.5:
                streamed = self._streamed / 1048576.0
                self._log_func(
                    "{}: {:.2f}/{:.2f}MB ({:.2f}%), {:.2f} bytes/sec"
                    .format(self._path, streamed, self._len_mb,
                            percent, bytes_per_sec))
                self._last_print_time = time.time()
        else:
            self._log_func("{}: completed in {:2f} seconds"
                           .format(self._path, time.time() - self._start_time))
        return result
