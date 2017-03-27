"""Test the nix information caches."""
import os
from os.path import exists, join, isdir, basename, dirname
import shutil
import tempfile
import unittest
from multiprocessing import cpu_count
import uuid

from pynix.exceptions import NoSuchObject
from pynix.utils import NIX_STORE_PATH, NIX_BIN_PATH
from pynix.binary_cache.nix_info_caches import PathReferenceCache

class TestPathReferenceCache(unittest.TestCase):
    """Tests for the PathReferenceCache class"""
    def setUp(self):
        self.location = tempfile.mkdtemp()
    def tearDown(self):
        pass # shutil.rmtree(self.location)

    def test_init(self):
        """Tests initialization."""
        cache = PathReferenceCache(self.location)
        self.assertEqual(cache._path_references, {})
        self.assertEqual(cache._location, self.location)

    def test_load(self):
        """Test that on-disk cache is loaded correctly."""
        path = join(NIX_STORE_PATH, "some_path")
        refs = [join(NIX_STORE_PATH, "ref1"), join(NIX_STORE_PATH, "ref2")]
        os.makedirs(join(self.location, basename(path)))
        for ref in refs:
            open(join(self.location, basename(path),
                      basename(ref)), "w").close()
        cache = PathReferenceCache(self.location)
        self.assertEqual(cache._path_references[path], refs)

    def test_record_references(self):
        """Test recording references."""
        path = join(NIX_STORE_PATH, "some_path")
        refs = [join(NIX_STORE_PATH, "ref1"), join(NIX_STORE_PATH, "ref2")]
        cache = PathReferenceCache(location=self.location)
        cache.record_references(path, refs)
        self.assertEqual(cache._path_references[path], refs)
        assert isdir(join(self.location, basename(path))), \
            "No cache created for {}".format(path)
        for ref in refs:
            assert exists(join(self.location, basename(path), basename(ref))), \
                "Ref {} wasn't created in cache".format(ref)

    def test_get_references(self):
        """Test the fetching of references.

        Use nix because we know it's there.
        """
        cache = PathReferenceCache(location=self.location)
        nix_refs = cache.get_references(dirname(NIX_BIN_PATH))
        self.assertGreater(len(nix_refs), 0)

    def test_get_references_bad_path(self):
        """Test the fetching of references.

        Use nix because we know it's there.
        """
        bad_path = join(NIX_STORE_PATH, uuid.uuid1().hex)
        cache = PathReferenceCache(location=self.location)
        with self.assertRaises(NoSuchObject):
            cache.get_references(bad_path, hide_stderr=True)
