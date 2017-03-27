# Test the NixCacheClient class.
import unittest

from pynix.binary_cache.client import NixCacheClient

class TestNixClient(unittest.TestCase):
    """Tests for the NixCacheClient class"""
    def test_init(self):
        client = NixCacheClient("https://www.example.com")
