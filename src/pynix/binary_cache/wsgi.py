# Creates a nix server flask app which can be run with uwsgi.
import logging
import os

from pynix.binary_cache.server import NixServer

# Set up some options through the environment.
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, log_level), format="%(message)s")
compression_type = os.getenv("COMPRESSION_TYPE", "xz")
nixserver = NixServer(compression_type=compression_type,
                      direct_db=os.getenv("NO_DIRECT_DB", "") == "")

app = nixserver.make_app()
