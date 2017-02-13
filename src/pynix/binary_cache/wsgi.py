# Creates a nix server flask app which can be run with uwsgi.
import logging
import os

from pynix.binary_cache.server import NixServer

# Set up some options through the environment.
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, log_level), format="%(message)s")
compression_type = os.getenv("COMPRESSION_TYPE", "xz")
secret_key_file = os.getenv("NIX_SECRET_KEY_FILE")
if secret_key_file is not None:
    key_name, key = parse_secret_key_file(secret_key_file)
else:
    key_name, key = None, None
nixserver = NixServer(compression_type=compression_type,
                      debug=False,
                      direct_db=os.getenv("NO_DIRECT_DB", "") == "",
                      secret_key_name=key_name,
                      secret_key=key)

app = nixserver.make_app()
