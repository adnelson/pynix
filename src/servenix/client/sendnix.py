"""Module for sending store objects to a running servenix instance."""
import argparse
import concurrent
from concurrent.futures import ThreadPoolExecutor
from copy import copy
import getpass
import gzip
import json
import logging
from multiprocessing import cpu_count
import os
from os.path import join, isdir, isfile, expanduser, basename
import re
from subprocess import Popen, PIPE, check_output
import sys
# Special-case here to address a runtime bug I've encountered
try:
    import sqlite3
except ImportError as err:
    if "does not define init" in str(err):
        exit("Could not import sqlite3. This is probably due to PYTHONPATH "
             "corruption: make sure your PYTHONPATH is empty prior to "
             "running this command.")
    else:
        raise
from threading import BoundedSemaphore

import requests
import six

from servenix.common.utils import strip_output, find_nix_paths

class StoreObjectSender(object):
    """Wraps some state for sending store objects."""
    def __init__(self, endpoint, dry_run=False, username=None,
                 password=None, cache_location=None, cache_enabled=True,
                 max_jobs=cpu_count()):
        #: Server running servenix (string).
        self._endpoint = endpoint
        #: If true, no actual paths will be sent.
        self._dry_run = dry_run
        #: If not none, will use to authenticate with the repo.
        self._username = username
        #: Ignored if username is None.
        self._password = password
        #: Set the cache location.
        if cache_enabled is False:
            self._cache_location = None
        elif cache_location is not None:
            self._cache_location = cache_location
        else:
            self._cache_location = self.default_cache()
        #: Set at a later point, if username is not None.
        self._auth = None
        #: Cache of direct path references (string -> strings).
        self._path_references = self._load_cache("path_references", {})
        #: Set of paths known to exist on the server already (set of strings).
        self._objects_on_server = set()
        #: Semaphore limiting numbers of concurrent sends.
        self._connection_semaphore = BoundedSemaphore(max_jobs)

    @staticmethod
    def default_cache():
        """Default location of the cache."""
        if os.environ.get("SENDNIX_CACHE", "") != "":
            return os.environ["SENDNIX_CACHE"]
        else:
            return expanduser("~/.sendnix")

    def _load_cache(self, cache_file, default):
        """Retrieve a file from the cache (in JSON) if it exists.

        Return a default if the cache is disabled or not readable.

        :param cache_file: File within the folder to load as JSON.
        :type cache_file: ``str``
        :param default: If the file doesn't exist, is not writable, or
            caching is disabled, return this instead.
        :type default: ``object``

        :return: The contents of the cache parsed as JSON, or the default.
        :rtype: ``object``
        """
        full_path = join(self._cache_location, cache_file)
        if self._cache_location is None:
            return default
        elif isdir(self._cache_location):
            if not os.access(self._cache_location, os.W_OK):
                # Can't access cache. Disable it.
                logging.warn("Couldn't access cache location {}."
                             .format(self._cache_location))
                self._cache_location = None
                return default
            elif not isfile(join(self._cache_location, cache_file)):
                # Cache exists but file does not exist.
                return default
            else:
                # File exists in the cache. Parse it as JSON and return it.
                with gzip.open(full_path, "rb") as f:
                    return json.loads(f.read().decode("utf-8"))
        else:
            # Cache doesn't exist yet. Try to create it or bail.
            try:
                os.makedirs(self._cache_location)
                return default
            except PermissionError:
                logging.warn("Couldn't create cache {}. Skipping cache."
                             .format(self._cache_location))
                self._cache_location = None
                return default

    def _update_caches(self):
        """Update the various caches.

        This function must be called after caches have been initialized.
        However since that happens in __init__, we should be OK.
        """
        if self._cache_location is None:
            return
        with open(join(self._cache_location, "path_references"), "wb") as f:
            _json = json.dumps(self._path_references)
            f.write(gzip.compress(_json.encode("utf-8")))

    def get_references(self, path):
        """Get a path's direct references.

        :param path: A nix store path. It must exist in the store.
        :type path: ``str``

        :return: A list of paths that the path refers to directly.
        :rtype: ``list`` of ``str``

        Side effects:
        * Caches reference lists in `self._path_references`.
        """
        if path not in self._path_references:
            refs = strip_output("nix-store --query --references {}"
                                .format(path))
            refs = refs.split()
            self._path_references[path] = [r for r in refs if r != path]
        return self._path_references[path]

    def query_store_paths(self, paths):
        """Send a list of store paths to the server to see what it has already.

        Includes all paths listed as well as their closures (referenced paths),
        to try to get as much information as possible.

        :param paths: A list of store paths.
        :type paths: ``list`` of ``str``

        :return: The full set of paths that will be sent.
        :rtype: ``set`` of ``str``

        Side effects:
        * Adds 0 or more paths to `self._objects_on_server`.
        """
        total = len(paths)
        step = int(max(total / 1000, 1))
        full_path_set = set()
        def recur(_paths, top_level=False):
            """Loop for DFS'ing through the paths to generate full closures."""
            for i, path in enumerate(_paths):
                if top_level is True and i % step == 0:
                    sys.stderr.write("\r{}/{} references calculated"
                                     .format(i + 1, total))
                if path not in full_path_set:
                    recur(self.get_references(path))
                    full_path_set.add(path)
            if top_level is True and total > 0:
                sys.stderr.write("\n")
        recur(paths, top_level=True)
        logging.info("The full closure contains {} paths."
                     .format(len(full_path_set)))

        # Now that we have the full list built up, send it to the
        # server to see which paths are already there.
        url = "{}/query-paths".format(self._endpoint)
        data = json.dumps(list(full_path_set))
        headers = {"Content-Type": "application/json"}
        if len(full_path_set) == 0:
            # No point in making a request if we don't have any paths.
            return set()
        for p in full_path_set:
            logging.debug("Querying path {}".format(p))
        logging.info("Asking the nix server about {} paths."
                     .format(len(full_path_set)))
        auth = self._get_auth()
        response = requests.get(url, headers=headers, data=data, auth=auth)
        response.raise_for_status()

        # The set of paths that will be sent.
        to_send = set()

        # Store all of the paths which are listed as `True` (exist on
        # the server) in our cache.
        for path, is_on_server in six.iteritems(response.json()):
            if is_on_server is True:
                self._objects_on_server.add(path)
            else:
                to_send.add(path)
        return to_send

    def _get_auth(self):
        """Return HTTP basic auth, if username is set (else None).

        If password isn't set, reads the NIX_BINARY_CACHE_PASSWORD
        variable for the password. If it is not set, the user will
        be prompted.

        :return: Either None or an Auth object.
        :rtype: ``NoneType`` or :py:class:`requests.auth.HTTPBasicAuth`
        """
        if self._auth is not None or self._username is None:
            # Cache auth to avoid repeated prompts
            return self._auth
        logging.info("Authenticating as user {}".format(self._username))
        if self._password is not None:
            password = self._password
        elif os.environ.get("NIX_BINARY_CACHE_PASSWORD", "") != "":
            logging.debug("Using value in NIX_BINARY_CACHE_PASSWORD variable")
            password = os.environ["NIX_BINARY_CACHE_PASSWORD"]
        else:
            prompt = "Please enter the password for {}:".format(self._username)
            password = getpass.getpass(prompt)
        self._auth = requests.auth.HTTPBasicAuth(self._username, password)
        return self._auth

    def _send_object(self, path, remaining):
        """Send a store object to a nix server.

        :param path: The path to the store object to send.
        :type path: ``str``
        :param remaining: Set of remaining objects to send.
        :type remaining: ``set`` of ``str``

        Side effects:
        * Adds 0 or 1 paths to `self._objects_on_server`.
        """
        # Check if the object is already on the server; if so we can stop.
        if path in self._objects_on_server:
            logging.debug("{} is already on the server.".format(path))
            return
        # Spawn threads to fetch parents, and then wait for those to finish.
        threads = [Thread(target=self._send_object, args=(ref, remaining))
                   for ref in self.get_references(path)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Now we can send the object itself. Generate a dump of the
        # file and send it to the import url. For now we're not using
        # streaming because it's not entirely clear that this is
        # possible with current requests, or indeed possible in
        # general without knowing the file size.
        with self._connection_semaphore:
            msg = ("Sending {} ({} remaining)"
                   .format(basename(path), len(remaining)))
            logging.info(msg)
            export = check_output("nix-store --export {}".format(path),
                                  shell=True)
            data = gzip.compress(export)
            url = "{}/import-path".format(self._endpoint)
            headers = {"Content-Type": "application/x-gzip"}
            try:
                response = requests.post(url, data=data, headers=headers,
                                         auth=self._get_auth())
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                msg = response.content
                logging.error("{} returned error on path {}: {}"
                              .format(self._endpoint, basename(path), msg))
                raise
        # Check the response code.
        # Register that the store path has been sent.
        self._objects_on_server.add(path)
        if path in remaining:
            remaining.remove(path)

    def send_objects(self, paths):
        """Checks for which paths need to be sent, and sends those.

        :param paths: Store paths to be sent.
        :type paths: ``str``
        """
        to_send = self.query_store_paths(paths)
        remaining = copy(to_send)
        num_to_send = len(to_send)
        if num_to_send == 1:
            logging.info("1 path will be sent to {}".format(self._endpoint))
        elif num_to_send > 1:
            logging.info("{} paths will be sent to {}"
                         .format(num_to_send, self._endpoint))
        else:
            logging.info("No paths need to be sent. {} is up-to-date."
                         .format(self._endpoint))
        try:
            if self._dry_run is False:
                threads = {}
                for path in to_send:
                    thread = Thread(target=self._send_object,
                                    args=(path, remaining))
                    thread.start()
                for i, (path, thread) in enumerate(six.iteritems(threads)):
                    thread.join()
                logging.info("Sent {} paths to {}"
                             .format(num_to_send, self._endpoint))
        finally:
            self._update_caches()


    def sync_store(self, ignore):
        """Syncronize the local nix store to the endpoint.

        Reads all of the known paths in the nix SQLite database which
        don't match the ignore patterns, and passes them into
        :py:meth:`send_objects`.

        :param ignore: A list of regexes of objects to ignore.
        :type ignore: ``list`` of (``str`` or ``regex``)
        """
        nix_state_path = find_nix_paths()["nix_state_path"]
        db_path = os.path.join(nix_state_path, "nix", "db", "db.sqlite")
        ignore = [re.compile(r) for r in ignore]
        paths = []
        with sqlite3.connect(db_path) as con:
            query = con.execute("SELECT path FROM ValidPaths")
            for result in query.fetchall():
                path = result[0]
                include = True
                if any(ig.match(path) for ig in ignore):
                    logging.info("Path {} matches an ignore regex, skipping"
                                 .format(path))
                    continue
                paths.append(path)
        logging.info("Found {} paths in the store.".format(len(paths)))
        self.send_objects(paths)


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="sendnix")
    subparsers = parser.add_subparsers(title="Command", dest="command")
    subparsers.required = True
    # 'send' command used for sending particular paths.
    send = subparsers.add_parser("send", help="Send specific store objects.")
    send.add_argument("paths", nargs="+", help="Store paths to send.")
    # 'sync' command used for syncronizing an entire nix store.
    sync = subparsers.add_parser("sync", help="Send all store objects.")
    sync.add_argument("--ignore", nargs="*", default=[],
                      help="List of regexes of store paths to ignore.")
    for subparser in (send, sync):
        subparser.add_argument("-e", "--endpoint",
                               default=os.environ.get("NIX_REPO_HTTP"),
                               help="Endpoint of nix server to send to.")
        subparser.add_argument("-D", "--dry-run", action="store_true",
                               default=False,
                               help="If true, reports which paths would "
                                    "be sent.")
        subparser.add_argument("--log-level", help="Log messages level.",
                            default="INFO", choices=("CRITICAL", "ERROR",
                                                     "WARNING", "INFO",
                                                     "DEBUG"))
        subparser.add_argument("-u", "--username",
                               default=os.environ.get(
                                   "NIX_BINARY_CACHE_USERNAME"),
                               help="User to authenticate to the cache as.")
        subparser.add_argument("--no-cache", action="store_false",
                               dest="cache_enabled",
                               help="Disable caching of known paths.")
        subparser.add_argument("--cache-location",
                               default=StoreObjectSender.default_cache(),
                               help="Location of cache.")
        def pos_int(arg):
            """Parse a postive integer (fail if it's 0 or negative)"""
            i = int(arg)
            if i <= 0:
                sys.exit("Value can't be negative: {}".format(i))
            return i
        subparser.add_argument("--max-jobs", type=pos_int, default=cpu_count(),
                               help="Maximum number of concurrent fetches.")
    return parser.parse_args()

def main():
    """Main entry point."""
    args = _get_args()
    if args.endpoint is None:
        exit("Endpoint is required. Use --endpoint or set NIX_REPO_HTTP.")
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(message)s")
    # Hide noisy logging of some external libs
    for name in ("requests", "urllib", "urllib2", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    sender = StoreObjectSender(endpoint=args.endpoint, dry_run=args.dry_run,
                               username=args.username, max_jobs=args.max_jobs)
    if args.command == "send":
        sender.send_objects(args.paths)
    elif args.command == "sync":
        sender.sync_store(args.ignore)
    else:
        exit("Unknown command '{}'".format(args.command))
