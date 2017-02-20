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
import sqlite3

from pynix.exceptions import NoSuchObject
from pynix.utils import NIX_STORE_PATH, NIX_DB_PATH, query_store

NIX_REFERENCE_CACHE_PATH = os.environ.get("NIX_REFERENCE_CACHE",
                                          expanduser("~/.nix-path-cache"))

# Query to return the store object ID from a store path.
GET_ID_QUERY = "select id from ValidPaths where path = ?"

# Query which given a store object ID returns its references.
GET_REFERENCES_QUERY = ("select path from Refs join ValidPaths "
                        "on reference = id where referrer = ?")


class PathReferenceCache(object):
    """Caches path references.

    Each object in a nix store is associated with 0 or more references,
    which are other objects that that object "refers to" (i.e. their paths
    appear somewhere in the text of that object). Nix stores these
    references in a SQLite database; this provides a python interface to
    that information.

    This class can operate without a direct connection to a nix
    database; the operations can be performed by nix-store. This is
    slow, however.
    """
    def __init__(self, location=NIX_REFERENCE_CACHE_PATH, max_jobs=cpu_count(),
                 direct_db=True, db_con=None):
        self._location = location
        self._pool = ThreadPoolExecutor(max_workers=max_jobs)
        self._cache_update_lock = RLock()
        if self._location is not None:
            # Start the cache loading thread but don't block on it; this
            # prevents slow startup time due to the loading of a large cache.
            self._cache_load_future = self._pool.submit(self._load)
            self.__path_references = None
        else:
            self._cache_load_future = None
            self.__path_references = {}
        # Test connect to the nix database; if successful, then we
        # will use a direct connection to the database rather than
        # using nix-store. This is much faster, but is unavailable on
        # some systems.
        if direct_db is not True:
            self._db_con = None
        elif db_con is not None:
            self._db_con = db_con
        else:
            try:
                query = "select * from ValidPaths limit 1"
                db_con = sqlite3.connect(NIX_DB_PATH)
                db_con.execute(query).fetchall()
                # If this succeeds, assign the db_con attribute.
                self._db_con = db_con
            except Exception as err:
                logging.warn("Couldn't connect to the database ({}). Can't "
                             "operate in direct-database mode :(".format(err))
                self._db_con = None

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

        The on-disk cache will be updated iff it has been configured.

        :param store_path: The path whose references we're recording.
        :type store_path: ``str``
        :param references: The references of that path.
        :type references: ``str``
        """
        if not store_path.startswith(NIX_STORE_PATH):
            raise ValueError("Must record an absolute store path, and "
                             "must live in the nix store.")
        if store_path in self._path_references:
            # If it's already in this dictionary, then it's already on disk.
            return
        references = list(sorted(references))
        with self._cache_update_lock:
            self._path_references[store_path] = references
            if self._location is not None:
                self._write(store_path, references)

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
        logging.debug("Finished loading path cache".format(path_cache))
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

    def get_references(self, path, hide_stderr=False):
        """Return the references of a path.

        :param store_path: A path expected to exist in the nix store.
        :type store_path: ``str``
        :param references: The references of that path.
        :type references: ``str``
        :param hide_stderr: Suppress stderr from nix-store command.
        :type hide_stderr: ``bool``
        :param db_con: A connection to a local nix sqlite db. It will
                       be used if available, with a fallback of
                       subprocessing into nix-store, which is much slower.
        :type db_con: :py:class:`sqlite3.Connection` or ``NoneType``

        :raises: :py:class:`NoSuchObject` if the object doesn't exist.
        """
        if path not in self._path_references:
            if self._db_con is not None:
                with self._db_con as con:
                    obj_id = con.execute(GET_ID_QUERY, (path,)).fetchone()
                    if obj_id is None:
                        raise NoSuchObject("No path {} recorded".format(path))
                    resp = con.execute(GET_REFERENCES_QUERY, obj_id).fetchall()
                    refs = list(sorted(p for (p,) in resp if p != path))
                    self.record_references(path, refs)
            else:
                try:
                    refs = query_store(path, "--references",
                                       hide_stderr=hide_stderr)
                    refs = [r for r in refs.split() if r != path]
                    self.record_references(path, refs)
                except CalledProcessError:
                    raise NoSuchObject("No path {} recorded".format(path))
        return self._path_references[path]
