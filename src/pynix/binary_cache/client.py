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
if sys.version_info >= (3, 0):
    import lzma
else:
    from backports import lzma
import gzip
import bz2

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
from pynix.utils import (strip_output, decode_str, NIX_STORE_PATH,
                         NIX_STATE_PATH, NIX_DB_PATH, nix_cmd,
                         query_store, instantiate, tell_size,
                         is_path_in_store)
from pynix.exceptions import (CouldNotConnect, NixImportFailed, CliError,
                              ObjectNotBuilt, NixBuildError, NoSuchObject)
from pynix.binary_cache.nix_info_caches import PathReferenceCache
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
                 max_jobs=cpu_count(), max_fetch_attempts=3):
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
        # A thread pool which handles queries for narinfo.
        self._query_pool = ThreadPoolExecutor(max_workers=max_jobs)
        # A thread pool which handles store object fetches.
        self._fetch_pool = ThreadPoolExecutor(max_workers=max_jobs)
        #: Cache of narinfo objects requested from the server.
        self._narinfo_cache = {}
        #: This will get filled up as we fetch paths; it lets avoid repeats.
        self._paths_fetched = set()
        self._max_jobs = max_jobs
        # A dictionary mapping nix store paths to futures fetching
        # those paths from a cache. Each fetch happens in a different
        # thread, and we use this dictionary to make sure that a fetch
        # only happens once.
        self._fetch_futures = {}
        # A lock which syncronizes access to the fetch state.
        self._fetch_lock = RLock()
        # Will be set to a non-None value when fetching.
        self._fetch_total = None
        # Connection to the nix state database.
        self._db_con = sqlite3.connect(NIX_DB_PATH)
        # Caches nix path references.
        self._reference_cache = PathReferenceCache(db_con=self._db_con)
        # How many times to attempt fetching a package
        self._max_fetch_attempts = max_fetch_attempts

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
        tempfile_fd, tempfile_path = tempfile.mkstemp()
        with os.fdopen(tempfile_fd, "w") as f:
            f.write(json.dumps(narinfo.as_dict()))
        shutil.move(tempfile_path, narinfo_path)

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
                try:
                    logging.debug("Loading {} narinfo from on-disk cache"
                                  .format(basename(path)))
                    with open(cache_path) as f:
                        narinfo = NarInfo.from_dict(json.load(f))
                    write_to_disk = False
                except json.decoder.JSONDecodeError:
                    logging.debug("Invalid cache JSON: {}".format(cache_path))
                    os.unlink(cache_path)
                    return self.get_narinfo(path)
            else:
                logging.debug("Requesting {} narinfo from server"
                              .format(basename(path)))
                prefix = basename(path).split("-")[0]
                url = "{}/{}.narinfo".format(self._endpoint, prefix)
                logging.debug("hitting url {} (for path {})..."
                              .format(url, path))
                response = self._request_get(url)
                logging.debug("response arrived from {}".format(url))
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
        """
        try:
            return self._reference_cache.get_references(
                path, hide_stderr=query_server)
        except NoSuchObject as err:
            if query_server is False:
                logging.error("Couldn't determine the references of {} "
                              "locally, and can't query the server"
                              .format(path))
                raise
            narinfo = self.get_narinfo(path)
            refs = [r for r in narinfo.abs_references if r != path]
            self._reference_cache.record_references(path, refs)
            return refs

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

    def _have_fetched(self, path):
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

    def _compute_fetch_order(self, paths):
        """Given a list of paths, compute an order to fetch them in.

        The returned order will respect the dependency tree; no child
        will appear before its parent in the list. In addition, the
        returned list may be larger as some dependencies of input
        paths might not be in the original list.

        :param paths: A list of store paths.
        :type paths: ``list`` of ``str``

        :return: A list of paths in dependency-first order.
        :rtype: ``list`` of ``str``
        """
        # Start by seeing if the server supports the
        # compute-fetch-order route. If it does, we can just use that
        # and save a lot of effort and network traffic.
        try:
            url = self._endpoint + "/compute-fetch-order"
            response = self._connect().get(url, data="\n".join(paths))
            response.raise_for_status()
            pairs = json.loads(decode_str(gzip.decompress(response.content)))
            # Server also returns the references for everything in the
            # list. We can store those in our cache.
            order = []
            for item in pairs:
                path, refs = item[0], item[1]
                self._reference_cache.record_references(path, refs)
                order.append(path)
            return order
        except (requests.HTTPError, AssertionError) as err:
            logging.info("Server doesn't support compute-fetch-order "
                         "route. Have to do it ourselves...")
            order = []
            order_set = set()
            def _order(path):
                if path not in order_set:
                    for ref in self.get_references(path, query_server=True):
                        _order(ref)
                    order.append(path)
                    order_set.add(path)
            logging.debug("Computing a fetch order for {}"
                          .format(tell_size(paths, "path")))
            for path in paths:
                _order(path)
            logging.debug("Finished computing fetch order.")
            return order

    def _fetch_ordered_paths(self, store_paths):
        """Given an ordered list of paths, fetch all from a cache."""
        logging.info("Beginning fetches. Total of {} to fetch."
                     .format(tell_size(store_paths, "store object")))
        for path in store_paths:
            self._start_fetching(path)
        for i, path in enumerate(store_paths):
            logging.info("{}/{} ({})"
                         .format(i + 1, len(store_paths), basename(path)))
            self._finish_fetching(path)
        logging.info("Finished fetching {}".format(
            tell_size(store_paths, "path")))

    def _request_get(self, url):
        """Make a request, with retry logic."""
        attempt = 1
        while True:
            try:
                response = self._connect().get(url)
                response.raise_for_status()
                return response
            except requests.HTTPError as err:
                if self._max_fetch_attempts is not None and \
                   attempt >= self._max_fetch_attempts:
                    raise
                else:
                    logging.warn("Received an error response ({}) from the "
                                 "server. Retrying (attempt {} out of {})"
                                 .format(attempt, self._max_fetch_attempts))
                    attempt += 1
            except requests.ConnectionError as cerr:
                logging.warn("Encountered connection error {}. Reinitializing "
                             "connection".format(cerr))
                self._session = None

    def _fetch_single(self, path):
        """Fetch a single path."""
        # Return if the path has already been fetched, or already exists.
        if self._have_fetched(path):
            return
        # First ensure that all referenced paths have been fetched.
        for ref in self.get_references(path):
            self._finish_fetching(ref)
        # Get the info of the store path.
        narinfo = self.get_narinfo(path)

        # Use the URL in the narinfo to fetch the object.
        url = "{}/{}".format(self._endpoint, narinfo.url)
        logging.debug("Requesting {} from {}..."
                     .format(basename(path), self._endpoint))
        response = self._request_get(url)

        # Figure out how to extract the content.
        if narinfo.compression.lower() in ("xz", "xzip"):
            data = lzma.decompress(response.content)
        elif narinfo.compression.lower() in ("bz2", "bzip2"):
            data = bz2.decompress(response.content)
        elif narinfo.compression.lower() in ("gzip", "gz"):
            data = gzip.decompress(response.content)
        else:
            raise ValueError("Unsupported narinfo compression type {}"
                             .format(narinfo.compression))
        # Once extracted, convert it into a nix export object and import.
        export = narinfo.nar_to_export(data)
        imported_path = export.import_to_store()
        self._register_as_fetched(path)

    def _register_as_fetched(self, path):
        """Register that a store path has been fetched."""
        self._paths_fetched.add(path)

    def _start_fetching(self, path):
        """Start a fetch thread. Syncronized so that a fetch of a
        single path will only happen once."""
        with self._fetch_lock:
            if path not in self._fetch_futures:
                future = self._fetch_pool.submit(self._fetch_single, path)
                logging.debug("Putting fetch of path {} in future {}"
                              .format(path, future))
                self._fetch_futures[path] = future
                return future
            else:
                return self._fetch_futures[path]

    def _finish_fetching(self, path):
        """Given a path, wait until that path's fetch has finished. It
        must already have been started."""
        with self._fetch_lock:
            if path not in self._fetch_futures:
                raise RuntimeError("Fetch of path {} has not been started."
                                   .format(path))
            future = self._fetch_futures[path]
        # Now that we have the future, wait for it to finish before returning.
        future.result()

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
        with self._db_con:
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

    def build_fetch(self, nix_file, attributes, show_trace=True, **kwargs):
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
        logging.info("Building {}".format(tell_size(deriv_paths, "derivation")))
        return self.build_derivations(deriv_paths, **kwargs)

    def build_derivations(self, deriv_paths, verbose=False, keep_going=True,
                          create_links=False, use_deriv_name=True):
        """Given one or more derivation paths, build the derivations."""
        if len(deriv_paths) == 0:
            logging.info("No paths given, nothing to build.")
            return
        derivs_to_outputs = parse_deriv_paths(deriv_paths)
        need_to_build, need_to_fetch = self.preview_build(deriv_paths)
        if self._dry_run is True:
            self.print_preview(need_to_build, need_to_fetch, verbose)
            return
        # Build the list of paths to fetch from the remote store.
        paths_to_fetch = []
        for deriv, outputs in need_to_fetch.items():
            for output in outputs:
                paths_to_fetch.append(deriv.output_path(output))
        if len(paths_to_fetch) > 0:
            # Figure out the order to fetch them in.
            logging.info("Computing fetch order...")
            fetch_order = self._compute_fetch_order(paths_to_fetch)
            # Perform the fetches.
            self._fetch_ordered_paths(fetch_order)
            self._verify(need_to_fetch)
        # Build up the command for nix store to build the remaining paths.
        if len(need_to_build) > 0:
            args = ["--max-jobs", str(self._max_jobs), "--no-gc-warning",
                    "--realise"]
            args.extend(d.path for d in need_to_build)
            if keep_going is True:
                args.append("--keep-going")
            logging.info("Building {} locally"
                         .format(tell_size(need_to_build, "derivation")))
            cmd = nix_cmd("nix-store", args)
            try:
                strip_output(cmd).split()
            except CalledProcessError as err:
                self._handle_build_failure(need_to_build)
        else:
            logging.info("No derivations needed to be built locally")
        if create_links is True:
            self._create_symlinks(derivs_to_outputs, use_deriv_name)
        return derivs_to_outputs

    def _handle_build_failure(self, derivs_to_outputs):
        """In a failure situation, report which derivations succeeded and
        which failed.
        """
        # TODO: report exactly which derivations succeeded/failed.
        raise NixBuildError()

    def _verify(self, derivs_to_outputs):
        """Given a derivation-output mapping, verify all paths."""
        logging.info("Verifying that we successfully created {}"
                     .format(tell_size(derivs_to_outputs, "store path")))
        for deriv, outputs in derivs_to_outputs.items():
            for output in outputs:
                path = deriv.output_path(output)
                logging.debug("Verifying path {}".format(basename(path)))
                if not is_path_in_store(path, db_con=self._db_con):
                    raise ObjectNotBuilt(path)

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
            logging.info("{} were not in the local nix store. Querying {} to "
                         "see which paths it has..."
                         .format(tell_size(needed, "needed object"),
                                 self._endpoint))
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
            verbose_ = verbose or len(need_to_build) < SHOW_PATHS_LIMIT
            msg = (("{} will be built" + (":" if verbose_ else "."))
                   .format(tell_size(need_to_build, "derivation")))
            if verbose_:
                for deriv in need_to_build:
                    msg += "\n  " + deriv.path
            logging.info(msg)
        if len(need_to_fetch) > 0:
            verbose_ = verbose or len(need_to_fetch) < SHOW_PATHS_LIMIT
            msg = (("{} will be fetched from {}" + (":" if verbose_ else "."))
                   .format(tell_size(need_to_fetch, "path"), self._endpoint))
            if verbose_:
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
    build.add_argument("--no-trace", action="store_false", dest="show_trace",
                       help="Hide stack trace on instantiation error.")
    build.set_defaults(show_trace=True)
    build_derivations = subparsers.add_parser("build-derivations",
        help="Build one or more derivations.")
    build_derivations.add_argument("derivations", nargs="*",
                                   help="Paths of derivation files")
    build_derivations.add_argument("-f", "--from-file",
                                   help="Read paths from the given file")
    for p in (build, build_derivations):
        p.add_argument("-v", "--verbose", action="store_true", default=False,
                       help="Show verbose output.")
        p.add_argument("-S", "--stop-on-failure", action="store_false",
                       dest="keep_going",
                       help="Stop all builders if any builder fails.")
        p.add_argument("--hide-paths", action="store_false",
                       dest="print_paths",
                       help="Don't print built paths to stdout")
        p.add_argument("-C", "--create-links", action="store_true",
                       default=False, help="Create symlinks to built objects.")
        p.add_argument("-g", "--generic-link-name", action="store_true",
                       default=False,
                       help="Use generic `result` name for symlinks.")
        p.add_argument("-1", "--one", action="store_true", default=False,
                       help="Alias for '--max-jobs=1 --stop-on-failure'")
        p.set_defaults(show_trace=True, keep_going=True, print_paths=True)

    for subparser in (send, sync, daemon, fetch, build, build_derivations):
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
    max_jobs = 1 if args.one else args.max_jobs
    client = NixCacheClient(endpoint=args.endpoint, dry_run=args.dry_run,
                            username=args.username, max_jobs=max_jobs)
    try:
        if args.command == "send":
            client.send_objects(args.paths)
        elif args.command == "sync":
            client.sync_store(args.ignore)
        elif args.command == "daemon":
            client.watch_store(args.ignore)
        elif args.command == "fetch":
            wait(list(client.fetch_objects(args.paths).values()))
        elif args.command == "build":
            keep_going = False if args.one else args.keep_going
            result_derivs = client.build_fetch(
                nix_file=args.path, attributes=args.attributes,
                verbose=args.verbose, show_trace=args.show_trace,
                keep_going=keep_going, create_links=args.create_links,
                use_deriv_name=not args.generic_link_name)
            if args.dry_run is False and args.print_paths is True:
                for deriv, outputs in result_derivs.items():
                    for output in outputs:
                        print(deriv.output_path(output))
        elif args.command == "build-derivations":
            keep_going = False if args.one else args.keep_going
            deriv_paths = args.derivations
            if args.from_file is not None:
                with open(args.from_file) as f:
                    deriv_paths.extend(f.read().split())
            result_derivs = client.build_derivations(
                deriv_paths=deriv_paths,
                verbose=args.verbose, keep_going=keep_going,
                create_links=args.create_links,
                use_deriv_name=not args.generic_link_name)
            if args.dry_run is False and args.print_paths is True:
                for deriv, outputs in result_derivs.items():
                    for output in outputs:
                        print(deriv.output_path(output))
        else:
            exit("Unknown command '{}'".format(args.command))
    except CliError as err:
        err.exit()
