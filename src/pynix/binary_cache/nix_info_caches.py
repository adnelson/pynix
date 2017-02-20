"""Provides abstractions for caching nix information."""
import logging
import os
from os.path import expanduser, join, basename, isdir
import shutil
import tempfile
from threading import RLock
from multiprocessing import cpu_count
from concurrent.futures import ThreadPoolExecutor
from subprocess import CalledProcessError

from pynix.exceptions import NoSuchObject
from pynix.utils import NIX_STORE_PATH, query_store

NIX_PATH_CACHE = os.environ.get("NIX_PATH_CACHE",
                                expanduser("~/.nix-path-cache"))

class PathReferenceCache(object):
    """Caches path references.

    Each object in a nix store is associated with 0 or more references,
    which are other objects that that object "refers to" (i.e. their paths
    appear somewhere in the text of that object). Nix stores these
    references in a SQLite database; this provides a python interface to
    that information.
    """
    def __init__(self, location=NIX_PATH_CACHE, max_jobs=cpu_count()):
        self._location = location
        # Start the cache loading thread but don't block on it; this
        # prevents slow startup time due to the loading of a large
        # cache.
        self.__path_references = None
        self._pool = ThreadPoolExecutor(max_workers=max_jobs)
        self._cache_load_future = self._pool.submit(self._load)
        self._cache_update_lock = RLock()
        self._cache_futures = {}

    def __del__(self):
        """Make sure writes have been completed."""
        for path, future in self._cache_futures.items():
            future.result(timeout=10)

    @property
    def _path_references(self):
        """Return the references, after waiting for the thread to complete."""
        if self.__path_references is None:
            self.__path_references = self._cache_load_future.result()
        return self.__path_references

    def has_record(self, store_path):
        """Return true if we have an entry for the given store path."""
        return store_path in self._path_references

    def record_references(self, store_path, references):
        """Update the in-memory and on-disk store path cache.

        This method is not considered private, because the information
        might come externally, e.g. from a client which has received
        this information from a server.

        :param store_path: The path whose references we're recording.
        :type store_path: ``str``
        :param references: The references of that path.
        :type references: ``str``

        :return: A future representing the recording of the entry on disk.
        """
        if not store_path.startswith(NIX_STORE_PATH):
            raise ValueError("Must record an absolute store path, and "
                             "must live in the nix store.")
        if store_path in self._path_references:
            # If it's already in this dictionary, then it's already on
            # disk and it must have an entry in cache_futures.
            return self._cache_futures[store_path]
        references = list(sorted(references))
        with self._cache_update_lock:
            self._path_references[store_path] = references
            if store_path not in self._cache_futures:
                future = self._pool.submit(self._write, store_path, references)
                self._cache_futures[store_path] = future
            return self._cache_futures[store_path]

    def _load(self):
        """Load the store reference path cache."""
        if not isdir(self._location):
            os.makedirs(self._location)
        logging.debug("Loading path cache...")
        path_cache = {}
        for store_basepath in os.listdir(self._location):
            refs_dir = join(self._location, store_basepath)
            refs = [join(NIX_STORE_PATH, path) for path in os.listdir(refs_dir)
                    if path != store_basepath]
            refs.sort()
            store_path = join(NIX_STORE_PATH, store_basepath)
            path_cache[store_path] = refs
            self._cache_futures[store_path] = self._pool.submit(lambda: ())
        logging.debug("Finished loading path cache: {}".format(path_cache))
        return path_cache

    def _write(self, store_path, references):
        """Given a store path and its references, write them to a cache.

        Creates a directory for the base path of the store path, and
        touches files corresponding to paths of its dependencies.
        So for example, if /nix/store/xyz-foo depends on /nix/store/{a,b,c},
        then we will create
          self._location/xyz-foo/a
          self._location/xyz-foo/b
          self._location/xyz-foo/c

        :param store_path: A nix store path.
        :type store_path: ``str``
        :param references: A list of that path's references.
        :type references: ``list`` of ``str``
        """
        logging.debug("Writing cache entry for {}".format(store_path))
        if not isdir(self._location):
            os.makedirs(self._location)
        # Create path directory in a tempdir to avoid inconsistent state.
        tempdir = tempfile.mkdtemp()
        for ref in references:
            # Create an empty file with the name of the reference.
            open(join(tempdir, basename(ref)), "w").close()
        # Remove the directory just in case, and then move the tempdir
        # to the target location.
        ref_dir = join(self._location, basename(store_path))
        shutil.rmtree(ref_dir, ignore_errors=True)
        shutil.move(tempdir, ref_dir)
        logging.debug("Finished writing cache entry for {}".format(store_path))

    def get_references(self, path, hide_stderr=False):
        """Return the references of a path.

        :param store_path: A path expected to exist in the nix store.
        :type store_path: ``str``
        :param references: The references of that path.
        :type references: ``str``

        :raises: :py:class:`NoSuchObject` if the object doesn't exist.
        """
        if path not in self._path_references:
            try:
                refs = query_store(path, "--references",
                                   hide_stderr=hide_stderr)
                refs = [r for r in refs.split() if r != path]
                self.record_references(path, refs)
            except CalledProcessError:
                raise NoSuchObject("No path {} recorded".format(path))
        return self._path_references[path]
