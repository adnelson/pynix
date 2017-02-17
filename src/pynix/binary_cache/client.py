"""Module for interacting with a running servenix instance."""
import argparse
from datetime import datetime
import getpass
import gzip
import json
import logging
import os
from os.path import (join, exists, isdir, isfile, expanduser, basename,
                     getmtime)
import re
import shutil
from subprocess import (Popen, PIPE, check_output, CalledProcessError,
                        check_call)
import sys
import tempfile
from threading import Thread, RLock, BoundedSemaphore
from six.moves.urllib_parse import urlparse
from concurrent.futures import ThreadPoolExecutor, Future, wait, as_completed
from multiprocessing import cpu_count
import yaml

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
import time

import requests
import six

from pynix import __version__
from pynix.utils import (strip_output, decode_str, decompress, NIX_BIN_PATH,
                         NIX_STORE_PATH, NIX_STATE_PATH, NIX_DB_PATH, nix_cmd,
                         query_store, instantiate)
from pynix.exceptions import (CouldNotConnect, NixImportFailed, CliError)
from pynix.narinfo import NarInfo
from pynix.build import needed_to_build_multi, parse_deriv_paths

NIX_PATH_CACHE = os.environ.get("NIX_PATH_CACHE",
                                expanduser("~/.nix-path-cache"))
NIX_NARINFO_CACHE = os.environ.get("NIX_NARINFO_CACHE",
                                   expanduser("~/.nix-narinfo-cache"))
ENDPOINT_REGEX = re.compile(r"https?://([\w_-]+)(\.[\w_-]+)*(:\d+)?$")

# Limit of how many paths to show, so the screen doesn't flood.
SHOW_PATHS_LIMIT = int(os.environ.get("SHOW_PATHS_LIMIT", 25))

class NixCacheClient(object):
    """Wraps some state for sending store objects."""
    def __init__(self, endpoint, dry_run=False, username=None,
                 password=None, cache_location=None, cache_enabled=True,
                 max_jobs=cpu_count()):
        #: Server running servenix (string).
        self._endpoint = endpoint
        #: Base name of server (for caching).
        self._endpoint_server = urlparse(endpoint).netloc
        #: If true, no actual paths will be sent/fetched/built.
        self._dry_run = dry_run
        #: If not none, will use to authenticate with the repo.
        if username is not None:
            self._username = username
        elif os.environ.get("NIX_BINARY_CACHE_USERNAME", "") != "":
            self._username = os.environ["NIX_BINARY_CACHE_USERNAME"]
        else:
            self._username = None
        #: Ignored if username is None.
        self._password = password
        #: Set at a later point, if username is not None.
        self._auth = None
        #: Used to avoid unnecessary overhead in handshakes etc.
        self._session = None
        #: Set of paths known to exist on the server already (set of strings).
        self._objects_on_server = set()
        #: When sending objects, this can be used to count remaining.
        self._remaining_objects = None
        #: Cache of direct path references (string -> strings). This
        # is loaded asyncronously from an on-disk cache located in
        # NIX_PATH_CACHE.
        self._path_references = {}
        # Start the cache loading thread but don't block on it; this
        # prevents slow startup time due to the loading of a large
        # cache.
        self._cache_thread = Thread(target=self._load_path_cache)
        self._cache_thread.start()
        #: Cache of narinfo objects requested from the server.
        self._narinfo_cache = {}
        self._paths_fetched = set()
        self._max_jobs = max_jobs
        self._query_pool = ThreadPoolExecutor(max_workers=max_jobs)

        # A semaphore which will bound the number of concurrent fetches.
        self._fetch_semaphore = BoundedSemaphore(value=max_jobs)
        # A dictionary mapping nix store paths to threads fetching
        # those paths from a cache. Each fetch happens in a different
        # thread, and we use this dictionary to make sure that a fetch
        # only happens once.
        self._fetch_threads = {}
        # A lock which syncronizes access to the fetch_threads dictionary.
        self._fetch_lock = RLock()
        # Paths being fetched.
        self._current_fetches = {}

    def _load_path_cache(self):
        """Load the store reference path cache.
        :return: A mapping from store paths to their references.
        :rtype: ``dict`` of ``str`` to ``str``
        """
        if not isdir(NIX_PATH_CACHE):
            return {}
        logging.debug("Loading path cache...")
        # path_cache = {}
        for store_path in os.listdir(NIX_PATH_CACHE):
            refs_dir = join(NIX_PATH_CACHE, store_path)
            refs = [join(NIX_STORE_PATH, path) for path in os.listdir(refs_dir)
                    if path != store_path]
            self._path_references[join(NIX_STORE_PATH, store_path)] = refs
        logging.debug("Finished loading path cache.")
        # logging.debug("Loaded references of {} paths".format(len(path_cache)))
        # return path_cache

    def _update_narinfo_cache(self, narinfo, write_to_disk):
        """Write a narinfo entry to the cache.

        :param narinfo: Information about a nix archive.
        :type narinfo: :py:class:`NarInfo`
        :param write_to_disk: Write to the on-disk cache.
        :type write_to_disk: ``bool``
        """
        path = narinfo.store_path
        self._narinfo_cache[path] = narinfo
        if write_to_disk is False:
            return
        # The narinfo cache is indexed by the server name of the endpoint.
        server_cache = join(NIX_NARINFO_CACHE, self._endpoint_server)
        narinfo_path = join(server_cache, basename(path))
        if not isdir(server_cache):
            os.makedirs(server_cache)
        if isfile(narinfo_path):
            return
        tempfile_path = tempfile.mkstemp()[1]
        with open(tempfile_path, "w") as f:
            f.write(json.dumps(narinfo.as_dict()))
        shutil.move(tempfile_path, narinfo_path)

    def _update_reference_cache(self, store_path, references, write_to_disk):
        """Given a store path and its references, write them to a cache.

        Creates a directory for the base path of the store path, and
        touches files corresponding to paths of its dependencies.
        So for example, if /nix/store/xyz-foo depends on /nix/store/{a,b,c},
        then we will create
          NIX_PATH_CACHE/xyz-foo/a
          NIX_PATH_CACHE/xyz-foo/b
          NIX_PATH_CACHE/xyz-foo/c

        :param store_path: A nix store path.
        :type store_path: ``str``
        :param references: A list of that path's references.
        :type references: ``list`` of ``str``
        :param write_to_disk: If true, write the entry to disk.
        :type write_to_disk: ``bool``
        """
        self._path_references[store_path] = references
        if write_to_disk is False:
            return
        if not isdir(NIX_PATH_CACHE):
            os.makedirs(NIX_PATH_CACHE)
        ref_dir = join(NIX_PATH_CACHE, basename(store_path))
        if isdir(ref_dir):
            # The cache already has this path; nothing to do.
            return
        # Create path directory in a tempdir to avoid inconsistent state.
        tempdir = tempfile.mkdtemp()
        for ref in references:
            # Create an empty file with the name of the reference.
            fname = join(tempdir, basename(ref))
            with open(fname, 'a'):
                os.utime(fname, (0, 0))
        # Remove the directory just in case, and then move the tempdir
        # to the target location.
        shutil.rmtree(ref_dir, ignore_errors=True)
        shutil.move(tempdir, ref_dir)

    def get_narinfo(self, path):
        """Request narinfo from a server. These are cached in memory.

        :param path: Store path that we want info on.
        :type path: ``str``

        :return: Information on the archived path.
        :rtype: :py:class:`NarInfo`
        """
        if path not in self._narinfo_cache:
            write_to_disk = True
            cache_path = join(NIX_NARINFO_CACHE, self._endpoint_server,
                              basename(path))
            if isfile(cache_path):
                write_to_disk = False
                with open(cache_path) as f:
                    narinfo = NarInfo.from_dict(json.load(f))
            else:
                prefix = basename(path).split("-")[0]
                url = "{}/{}.narinfo".format(self._endpoint, prefix)
                logging.debug("hitting url {} (for path {})..."
                              .format(url, path))
                response = self._connect().get(url)
                logging.debug("response arrived from {}".format(url))
                response.raise_for_status()
                narinfo = NarInfo.from_string(response.content)
            self._update_narinfo_cache(narinfo, write_to_disk)
        return self._narinfo_cache[path]

    def get_references(self, path, query_server=False):
        """Get a path's direct references.

        :param path: A nix store path. It must either exist in the
                     local nix store or be available in the binary cache.
        :type path: ``str``
        :param query_server: If true, will attempt to query the server
                             for the paths if not on disk. This is
                             used when fetching a path.
        :type query_server: ``bool``

        :return: A list of absolute paths that the path refers to directly.
        :rtype: ``list`` of ``str``

        Side effects:
        * Caches reference lists in `self._path_references`.
        """
        if path not in self._path_references:
            write_to_disk = True
            # First see if it's in the on-disk cache.
            if isdir(join(NIX_PATH_CACHE, basename(path))):
                write_to_disk = False # Not necessary, already there.
                refs_dir = join(NIX_PATH_CACHE, basename(path))
                refs = [join(store, path) for path in os.listdir(refs_dir)
                        if path != basename(path)]
            # If it's not in the cache, try asking nix-store for it.
            try:
                refs = query_store(path, "--references",
                                   hide_stderr=query_server)
                refs = [r for r in refs.split() if r != path]
            # If nix-store gives an error and server querying is
            # enabled, query the binary cache.
            except CalledProcessError:
                if query_server is False:
                    raise
                narinfo = self.get_narinfo(path)
                refs = [r for r in narinfo.abs_references if r != path]
            self._update_reference_cache(path, refs, write_to_disk)
        return self._path_references[path]

    def query_paths(self, paths):
        """Given a list of paths, see which the server has.

        :param paths: A list of nix store paths.
        :type paths: ``str``

        :return: A dictionary mapping store paths to booleans (True if
                 on the server, False otherwise).
        :rtype: ``dict`` of ``str`` to ``bool``
        """
        paths = list(set(paths))
        if len(paths) == 0:
            # No point in making a request if we don't have any paths.
            return {}
        url = "{}/query-paths".format(self._endpoint)
        data = json.dumps(paths)
        headers = {"Content-Type": "application/json"}
        logging.debug("Asking the server about {} paths.".format(len(paths)))
        try:
            response = self._connect().get(url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as err:
            if err.response.status_code != 404:
                raise
            logging.warn("Endpoint {} does not support the /query-paths "
                         "route. Querying paths individually."
                         .format(self._endpoint))
            futures = {
                path: self._query_pool.submit(self.query_path_individually,
                                              path)
                for path in paths
            }
            result = {path: fut.result() for path, fut in futures.items()}
            return result

    def query_path_individually(self, path):
        """Send an individual query (.narinfo) for a store path.

        :param path: A store path, to ask a binary cache about.
        :type path: ``str``

        :return: True if the server has the path, and otherwise false.
        :rtype: ``bool``
        """
        logging.debug("Querying for path {}".format(path))
        prefix = basename(path).split("-")[0]
        url = "{}/{}.narinfo".format(self._endpoint, prefix)
        resp = self._connect().get(url)
        has_path = resp.status_code == 200
        if has_path:
            logging.debug("{} has path {}".format(self._endpoint, path))
        else:
            logging.debug("{} does not have path {}"
                          .format(self._endpoint, path))
        return has_path

    def query_path_closures(self, paths):
        """Given a list of paths, compute their whole closure and ask
        the server which of those paths it has.

        :param paths: A list of store paths.
        :type paths: ``list`` of ``str``

        :return: The full set of paths that will be sent.
        :rtype: ``set`` of ``str``

        Side effects:
        * Adds 0 or more paths to `self._objects_on_server`.
        """
        paths = [os.path.join(NIX_STORE_PATH, p) for p in paths]
        total = len(paths)
        step = max(total // 10, 1)
        full_path_set = set()
        counts = [0]
        def recur(_paths):
            """Loop for DFS'ing through the paths to generate full closures."""
            for path in _paths:
                if path not in full_path_set:
                    counts[0] += 1
                    recur(self.get_references(path))
                    full_path_set.add(path)
        logging.info("Computing path closure...")
        recur(paths)
        if len(full_path_set) > total:
            logging.info("{} {} given as input, but the full "
                         "dependency closure contains {} paths."
                         .format(total,
                                 "path was" if total == 1 else "paths were",
                                 len(full_path_set)))

        # Now that we have the full list built up, send it to the
        # server to see which paths are already there.
        on_server = self.query_paths(full_path_set)

        # The set of paths that will be sent.
        to_send = set()

        # Store all of the paths which are listed as `True` (exist on
        # the server) in our cache.
        for path, is_on_server in six.iteritems(on_server):
            if is_on_server is True:
                self._objects_on_server.add(path)
            else:
                to_send.add(path)
        return to_send

    def _connect(self, first_time=True):
        """Connect to a binary cache.

        Serves two purposes: verifying that the client can
        authenticate with the cache, and that the binary cache store
        directory matches the client's.

        If password isn't set, reads the NIX_BINARY_CACHE_PASSWORD
        variable for the password. If it is not set, the user will
        be prompted.

        :param first_time: Whether this is the first time it's being
            called, so that we can tailor the error messaging.
        :type first_time: ``bool``

        :return: Either None or a Session object.
        :rtype: ``NoneType`` or :py:class:`requests.sessions.Session`

        :raises: :py:class:`CouldNotConnect` if authentication fails.

        Side effects:
        * Will set the NIX_BINARY_CACHE_{USERNAME,PASSWORD} variables.
        """
        if self._session is not None:
            # Cache to avoid repeated prompts
            return self._session
        if self._password is not None:
            password = self._password
        elif self._username is None:
            password = None
        elif os.environ.get("NIX_BINARY_CACHE_PASSWORD", "") != "":
            logging.debug("Using value in NIX_BINARY_CACHE_PASSWORD variable")
            password = os.environ["NIX_BINARY_CACHE_PASSWORD"]
        elif sys.stdin.isatty():
            prompt = ("Please enter the \033[1mpassword\033[0m for {}: "
                      .format(self._username))
            password = getpass.getpass(prompt)
        else:
            logging.warn("Can't get password for user {}. Auth may fail."
                         .format(self._username))
        if self._username is not None:
            logging.info("Connecting as user {}".format(self._username))
        else:
            logging.info("Connecting...")
        if self._username is not None:
            auth = requests.auth.HTTPBasicAuth(self._username, password)
        else:
            auth = None
        # Create a session. Don't set it on the object yet.
        session = requests.Session()
        # Perform the actual request. See if we get a 200 back.
        url = "{}/nix-cache-info".format(self._endpoint)
        resp = session.get(url, auth=auth)
        if resp.status_code == 200:
            nix_cache_info = yaml.load(resp.content)
            cache_store_dir = nix_cache_info["StoreDir"]
            if cache_store_dir != NIX_STORE_PATH:
                raise ValueError("This binary cache serves packages from "
                                 "store directory {}, but this client is "
                                 "using {}"
                                 .format(cache_store_dir, NIX_STORE_PATH))
            logging.info("Successfully connected to {}".format(self._endpoint))
            self._password = password
            if password is not None:
                os.environ["NIX_BINARY_CACHE_PASSWORD"] = password
            self._auth = session.auth = auth
            self._session = session
            return self._session
        elif resp.status_code == 401 and sys.stdin.isatty():
            # Authorization failed. Give the user a chance to set new auth.
            msg = "\033[31mAuthorization failed!\033[0m\n" \
                  if not first_time else ""
            msg += "Please enter \033[1musername\033[0m"
            msg += " for {}".format(self._endpoint) if first_time else ""
            if self._username is not None:
                msg += " (default '{}'): ".format(self._username)
            else:
                msg += ": "
            try:
                username = six.moves.input(msg)
                if username != "":
                    self._username = username
                os.environ.pop("NIX_BINARY_CACHE_PASSWORD", None)
                self._password = None
            except (KeyboardInterrupt, EOFError):
                logging.info("\nBye!")
                sys.exit()
            return self._connect(first_time=False)
        else:
            raise CouldNotConnect(self._endpoint, resp.status_code,
                                  resp.content)

    def send_object(self, path, remaining_objects=None):
        """Send a store object to a nix server.

        :param path: The path to the store object to send.
        :type path: ``str``
        :param remaining_objects: Set of remaining objects to send.
        :type remaining: ``NoneType`` or ``set`` of ``str``

        Side effects:
        * Adds 0 or 1 paths to `self._objects_on_server`.
        """
        # Check if the object is already on the server; if so we can stop.
        if path in self._objects_on_server:
            return
        # First send all of the object's references. Skip self-references.
        for ref in self.get_references(path):
            self.send_object(ref, remaining_objects=remaining_objects)
        # Now we can send the object itself. Generate a dump of the
        # file and send it to the import url. For now we're not using
        # streaming because it's not entirely clear that this is
        # possible with current requests, or indeed possible in
        # general without knowing the file size.
        session = self._connect()
        export = check_output(nix_cmd("nix-store", ["--export", path]))
        # For large files, show progress when compressing
        if len(export) > 1000000:
            logging.info("Compressing {}".format(basename(path)))
            cmd = "pv -ptef -s {} | gzip".format(len(export))
            proc = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
            data = proc.communicate(input=export)[0]
        else:
            data = gzip.compress(export)
        url = "{}/import-path".format(self._endpoint)
        headers = {"Content-Type": "application/x-gzip"}
        try:
            logging.info("Sending {} ({} remaining)"
                         .format(basename(path), len(remaining_objects)))
            response = session.post(url, data=data, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            try:
                msg = json.loads(decode_str(response.content))["message"]
            except (ValueError, KeyError):
                msg = response.content
            logging.error("{} returned error on path {}: {}"
                          .format(self._endpoint, basename(path), msg))
            raise
        # Check the response code.
        # Register that the store path has been sent.
        self._objects_on_server.add(path)
        # Remove the path if it is still in the set.
        if remaining_objects is not None and path in remaining_objects:
            remaining_objects.remove(path)

    def send_objects(self, paths):
        """Checks for which paths need to be sent, and sends those.

        :param paths: Store paths to be sent.
        :type paths: ``str``
        """
        to_send = self.query_path_closures(paths)
        num_to_send = len(to_send)
        if num_to_send == 1:
            logging.info("1 path will be sent to {}".format(self._endpoint))
        elif num_to_send > 1:
            logging.info("{} paths will be sent to {}"
                         .format(num_to_send, self._endpoint))
        else:
            logging.info("No paths need to be sent. {} is up-to-date."
                         .format(self._endpoint))
        if self._dry_run is False:
            while len(to_send) > 0:
                self.send_object(to_send.pop(), to_send)
            if num_to_send > 0:
                logging.info("Sent {} paths to {}"
                             .format(num_to_send, self._endpoint))
        elif num_to_send <= SHOW_PATHS_LIMIT:
            for path in to_send:
                logging.info(basename(path))

    def have_fetched(self, path):
        """Checks if we've fetched a given path, or if it exists on disk.

        :param path: The path to the store object to check.
        :type path: ``str``

        :return: Whether we've fetched the path.
        :rtype: ``bool``

        Side effects:
        * Adds 0 or 1 paths to `self._paths_fetched`.
        """
        if path in self._paths_fetched:
            return True
        elif exists(path):
            self._paths_fetched.add(path)
            return True
        else:
            return False

    def fetch_object(self, path):
        """Fetch a store object from a nix server.

        This is obviously the inverse of a send, and quite a similar
        algorithm (first fetch parents, and then fetch the
        object). But it's a little different because although with a
        send you already know (or can derive) the references of the
        object, with fetching you need to ask the server for the
        references.

        :param path: The path to the store object to fetch.
        :type path: ``str``

        Side effects:
        * Adds 0 or 1 paths to `self._paths_fetched`.

        This function should be thread safe, since a nix-store import
        is idempotent.
        """
        # Check if the object has already been fetched; if so we can stop.
        if self.have_fetched(path):
            logging.debug("{} has already been fetched.".format(path))
            return
        # First fetch all of the object's references.
        refs = self.get_references(path, query_server=True)
        logging.debug("Waiting for parent paths of {} ({}) to fetch..."
                      .format(path, ", ".join(refs)))
        ref_fetches = {ref: self.start_fetching(ref) for ref in refs}
        for rpath, thread in ref_fetches.items():
            logging.debug("{} waiting for reference {} to fetch..."
                          .format(path, rpath))
            thread.join()
            logging.debug("Path {} (ref of {}) has fetched.".format(rpath, path))
        logging.debug("All parent paths of {} finished.".format(path))

        # Now we can fetch the object itself. Syncronize this with the
        # fetch semaphore to prevent too many simultaneous
        # connections.
        with self._fetch_semaphore:
            # Get the info of the store path.
            narinfo = self.get_narinfo(path)

            # Use the URL in the narinfo to fetch the object.
            url = "{}/{}".format(self._endpoint, narinfo.url)
            logging.info("Requesting {} from {}..."
                         .format(basename(path), self._endpoint))
            response = self._connect().get(url)
            response.raise_for_status()

            # Figure out how to extract the content.
            if narinfo.compression.lower() in ("xz", "xzip"):
                data = decompress("xz -d", response.content)
            elif narinfo.compression.lower() in ("bz2", "bzip2"):
                data = decompress("bzip2 -d", response.content)
            elif narinfo.compression.lower() in ("gzip", "gz"):
                data = decompress("gzip -d", response.content)
            else:
                raise ValueError("Unsupported narinfo compression type {}"
                                 .format(narinfo.compression))
            # Once extracted, convert it into a nix export object and pass
            # it into the nix-store --import command.
            proc = Popen([join(NIX_BIN_PATH, "nix-store"), "--import"],
                         stdin=PIPE, stderr=PIPE, stdout=PIPE)
            export = narinfo.nar_to_export(data)
            out, err = proc.communicate(input=export.to_bytes())
            if proc.wait() != 0:
                raise NixImportFailed(decode_str(err))
            logging.info("Imported {}".format(out.decode("utf-8")).strip())
            self._paths_fetched.add(path)

    def start_fetching(self, path):
        """Start a fetch thread. Syncronized so that a fetch of a
        single path will only happen once."""
        with self._fetch_lock:
            if path not in self._fetch_threads:
                thread = Thread(target=self.fetch_object, args=(path,))
                # Tell thread to terminate on keyboard interrupt.
                thread.daemon = True
                logging.debug("Putting fetch of path {} in thread {}"
                              .format(path, thread))
                thread.start()
                self._fetch_threads[path] = thread
                return thread
            else:
                return self._fetch_threads[path]

    def watch_store(self, ignore):
        """Watch the nix store's timestamp and sync whenever it changes.

        :param ignore: A list of regexes of objects to ignore when syncing.
        :type ignore: ``list`` of (``str`` or ``regex``)
        """
        prev_stamp = None
        num_syncs = 0
        try:
            while True:
                # Parse the timestamp of the nix store into a datetime
                stamp = datetime.fromtimestamp(getmtime(NIX_STORE_PATH))
                # If it's changed since last time, run a sync.
                if stamp == prev_stamp:
                    logging.debug("Store hasn't updated since last check ({})"
                                  .format(stamp.strftime("%H:%M:%S")))
                    time.sleep(1)
                    continue
                else:
                    logging.info("Store was modified at {}, syncing"
                                 .format(stamp.strftime("%H:%M:%S")))
                try:
                    self.sync_store(ignore)
                    prev_stamp = stamp
                    num_syncs += 1
                except requests.exceptions.HTTPError as err:
                    # Don't fail the daemon due to a failed sync.
                    pass
        except KeyboardInterrupt:
            exit("Successfully syncronized with {} {} times."
                 .format(self._endpoint, num_syncs))

    def sync_store(self, ignore):
        """Syncronize the local nix store to the endpoint.

        Reads all of the known paths in the nix SQLite database which
        don't match the ignore patterns, and passes them into
        :py:meth:`send_objects`.

        :param ignore: A list of regexes of objects to ignore.
        :type ignore: ``list`` of (``str`` or ``regex``)
        """
        ignore = [re.compile(r) for r in ignore]
        paths = []
        with sqlite3.connect(NIX_DB_PATH) as con:
            query = con.execute("SELECT path FROM ValidPaths")
            for result in query.fetchall():
                path = result[0]
                if any(ig.match(path) for ig in ignore):
                    logging.debug("Path {} matches an ignore regex, skipping"
                                  .format(path))
                    continue
                paths.append(path)
        logging.info("Found {} paths in the store.".format(len(paths)))
        self.send_objects(paths)

    def build_fetch(self, nix_file, attributes, verbose=False, show_trace=True,
                    keep_going=True, create_links=False, use_deriv_name=True):
        """Given a nix file, instantiate the given attributes within the file,
        query the server for which files can be fetched, and then
        build/fetch everything.

        :return: A dictionary mapping derivations to outputs that were built.
        :rtype: ``dict``
        """
        logging.info("Instantiating attribute{} {} from path {}"
                     .format("s" if len(attributes) > 1 else "",
                             ", ".join(attributes), nix_file))
        deriv_paths = instantiate(nix_file, attributes=attributes,
                                  show_trace=show_trace)
        derivs_to_outputs = parse_deriv_paths(deriv_paths)
        logging.info("Querying {} for which paths it has..."
                     .format(self._endpoint))
        need_to_build, need_to_fetch = self.preview_build(deriv_paths)
        self.print_preview(need_to_build, need_to_fetch, verbose)
        if self._dry_run is True:
            return
        # Build the list of paths to fetch from the remote store.
        path_fetches = {}
        for deriv, outputs in need_to_fetch.items():
            for output in outputs:
                path = deriv.output_path(output)
                path_fetches[path] = self.start_fetching(path)
        # Wait for each thread to complete.
        for deriv, outputs in need_to_fetch.items():
            for output in outputs:
                path = deriv.output_path(output)
                path_fetches[path].join()

        # Build up the command for nix store to build the remaining paths.
        if len(need_to_build) > 0:
            args = ["--max-jobs", str(self._max_jobs), "--no-gc-warning",
                    "--realise"]
            args.extend(d.path for d in need_to_build)
            if keep_going is True:
                args.append("--keep-going")
            cmd = nix_cmd("nix-store", args)
            strip_output(cmd).split()
        else:
            logging.info("No derivations needed to be built locally")
        if create_links is True:
            self._create_symlinks(derivs_to_outputs, use_deriv_name)
        return derivs_to_outputs

    def _create_symlinks(self, derivs_to_outputs, use_deriv_name):
        """Create symlinks to all built derivations.

        :param derivs_to_outputs: Maps derivations to sets of output names.
        :type derivs_to_outputs:
            ``dict`` of ``Derivation`` to ``set`` of ``str``
        :param use_deriv_name: If true, the symlink names will be
                               generated from derivation names.
                               Otherwise, `result` will be used.
        :type use_deriv_name: ``bool``
        """
        count = 0
        for deriv, outputs in derivs_to_outputs.items():
            for output in outputs:
                path = deriv.output_path(output)
                if use_deriv_name:
                    link_path = deriv.link_path(output)
                else:
                    link_path = join(os.getcwd(), "result")
                    if output != "out":
                        link_path += "-" + output
                    if count > 0:
                        link_path += "-" + str(count)
                args = ["--realise", path, "--add-root", link_path,
                        "--indirect"]
                check_output(nix_cmd("nix-store", args))
                count += 1

    def preview_build(self, paths):
        """Given some derivation paths, generate two sets:

        * Set of derivations which need to be built from scratch
        * Set of derivations which can be fetched from a binary cache

        Of course, the second set will be empty if no binary cache is given.
        """
        if isinstance(paths, dict):
            derivs_outs = paths
        else:
            derivs_outs = parse_deriv_paths(paths)
        existing = {}
        # Run the first time with no on_server argument.
        needed, need_fetch = needed_to_build_multi(derivs_outs, existing=existing)
        if len(needed) > 0:
            on_server = {}
            # Query the server for missing paths. Start by trying a
            # multi-query because it's faster; if the server doesn't
            # implement that behavior then try individual queries.
            paths_to_ask = []
            # Make a dictionary mapping paths back to the
            # derivations/outputs they came from.
            path_mapping = {}
            for deriv, outs in needed.items():
                for out in outs:
                    path = deriv.output_path(out)
                    paths_to_ask.append(path)
                    path_mapping[path] = (deriv, out)
            query_result = self.query_paths(paths_to_ask)
            for path, is_on_server in query_result.items():
                if is_on_server is not True:
                    continue
                deriv, out_name = path_mapping[path]
                # First, remove these from the `needed` set, because
                # we can fetch them from the server.
                needed[deriv].remove(out_name)
                if len(needed[deriv]) == 0:
                    del needed[deriv]
                # Then add them to the `on_server` set.
                if deriv not in on_server:
                    on_server[deriv] = set()
                on_server[deriv].add(out_name)
            if len(on_server) > 0:
                # Run the check again, this time using the information
                # collected from the server.
                needed, need_fetch = needed_to_build_multi(derivs_outs,
                                                           on_server=on_server,
                                                           existing=existing)
        return needed, need_fetch

    def print_preview(self, need_to_build, need_to_fetch, verbose=False):
        """Print the result of a `preview_build` operation."""
        if len(need_to_build) == 0 and len(need_to_fetch) == 0:
            logging.info("All paths have already been built.")
        if len(need_to_build) > 0:
            msg = ("{} derivations need to be built"
                   .format(len(need_to_build)) + (":" if verbose else "."))
            if verbose:
                msg += "\n  ".join(deriv.path for deriv in need_to_build)
            logging.info(msg)
        if len(need_to_fetch) > 0:
            msg = ("{} paths will be fetched from {}"
                   .format(len(need_to_fetch), self._endpoint) +
                   (":" if verbose else "."))
            if verbose:
                for deriv, outs in need_to_fetch.items():
                    for out in outs:
                        msg += "\n  " + deriv.output_path(out)
            logging.info(msg)

def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="nix-client")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(title="Command", dest="command")
    subparsers.required = True
    # 'send' command used for sending particular paths.
    send = subparsers.add_parser("send", help="Send specific store objects.")
    send.add_argument("paths", nargs="+", help="Store paths to send.")
    # 'sync' command used for syncronizing an entire nix store.
    sync = subparsers.add_parser("sync", help="Send all store objects.")
    daemon = subparsers.add_parser("daemon",
                                   help="Run as daemon, periodically "
                                        "syncing store.")
    fetch = subparsers.add_parser("fetch",
                                   help="Fetch objects from a nix server.")
    fetch.add_argument("paths", nargs="+", help="Paths to fetch.")
    build = subparsers.add_parser("build",
        help="Build a nix expression, using the server as a binary cache.")
    build.add_argument("-P", "--path", default=os.getcwd(),
                       help="Base path to evaluate.")
    build.add_argument("attributes", nargs="*",
                       help="Expressions to evaluate.")
    build.add_argument("--verbose", action="store_true", default=False,
                       help="Show verbose output.")
    build.add_argument("--no-trace", action="store_false", dest="show_trace",
                       help="Hide stack trace on instantiation error.")
    build.add_argument("-S", "--stop-on-failure", action="store_false",
                       dest="keep_going",
                       help="Stop all builders if any builder fails.")
    build.add_argument("--hide-paths", action="store_false",
                       dest="print_paths",
                       help="Don't print built paths to stdout")
    build.add_argument("-C", "--create-links", action="store_true",
                       default=False, help="Create symlinks to built objects.")
    build.add_argument("-g", "--generic-link-name", action="store_true",
                       default=False,
                       help="Use generic `result` name for symlinks.")
    build.set_defaults(show_trace=True, keep_going=True, print_paths=True)
    for subparser in (send, sync, daemon, fetch, build):
        subparser.add_argument("-e", "--endpoint",
                               default=os.environ.get("NIX_REPO_HTTP"),
                               help="Endpoint of nix server to send to.")
        subparser.set_defaults(log_level=os.getenv("LOG_LEVEL", "INFO"))
        for level in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
            subparser.add_argument("--" + level.lower(), dest="log_level",
                                   action="store_const", const=level)
        subparser.add_argument("-u", "--username",
            default=os.environ.get("NIX_BINARY_CACHE_USERNAME"),
            help="User to authenticate to the cache as.")
        subparser.add_argument("--max-jobs", type=int, default=cpu_count(),
                               help="For concurrency, max workers.")
        subparser.add_argument("-D", "--dry-run", action="store_true",
                               default=False,
                               help="If true, reports which paths would "
                                    "be sent/fetched/built.")
    for subparser in (sync, daemon):
        subparser.add_argument("--ignore", nargs="*", default=[],
                               help="Regexes of store paths to ignore.")
        # It doesn't make sense to have the daemon run in dry-run mode.
        subparser.set_defaults(dry_run=False)
    return parser.parse_args()

def main():
    """Main entry point."""
    args = _get_args()
    if args.endpoint is None:
        exit("Endpoint is required. Use --endpoint or set NIX_REPO_HTTP.")
    elif ENDPOINT_REGEX.match(args.endpoint) is None:
        exit("Invalid endpoint: '{}' does not match '{}'."
             .format(args.endpoint, ENDPOINT_REGEX.pattern))
    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(level=log_level, format="%(message)s")
    # Hide noisy logging of some external libs
    for name in ("requests", "urllib", "urllib2", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        client = NixCacheClient(
            endpoint=args.endpoint, dry_run=args.dry_run,
            username=args.username, max_jobs=args.max_jobs)
        if args.command == "send":
            client.send_objects(args.paths)
        elif args.command == "sync":
            client.sync_store(args.ignore)
        elif args.command == "daemon":
            client.watch_store(args.ignore)
        elif args.command == "fetch":
            wait(list(client.fetch_objects(args.paths).values()))
        elif args.command == "build":
            result_derivs = client.build_fetch(
                nix_file=args.path, attributes=args.attributes,
                verbose=args.verbose, show_trace=args.show_trace,
                keep_going=args.keep_going, create_links=args.create_links,
                use_deriv_name=not args.generic_link_name)
            if args.dry_run is False and args.print_paths is True:
                for deriv, outputs in result_derivs.items():
                    for output in outputs:
                        print(deriv.output_path(output))
        else:
            exit("Unknown command '{}'".format(args.command))
    except CliError as err:
        err.exit()
