# Creates a nix server flask app which can be run with uwsgi.
import logging
import os

from servenix.common.utils import find_nix_paths
from servenix.server.servenix import NixServer

# Set up some options through the environment.
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, log_level), format="%(message)s")
compression_type = os.environ.get("COMPRESSION_TYPE", "xz")

nix_paths = find_nix_paths()
nixserver = NixServer(nix_store_path=nix_paths["nix_store_path"],
                      nix_state_path=nix_paths["nix_state_path"],
                      nix_bin_path=nix_paths["nix_bin_path"],
                      compression_type=compression_type,
                      debug=False)

app = nixserver.make_app()
