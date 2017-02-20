# Test the NixServer class.
import os
import unittest

import yaml

from pynix.binary_cache.server import NixServer

class TestNixServer(unittest.TestCase):
    """Tests for the NixServer class"""
    def test_nix_cache_info(self):
        """Test that the nix cache info is rendered correctly."""
        server = NixServer(direct_db=False)
        cache_info = yaml.load(server._cache_info)
        self.assertEqual(cache_info, {
            "StoreDir": os.environ["NIX_STORE"],
            "WantMassQuery": 1,
            "Priority": 30
        })
