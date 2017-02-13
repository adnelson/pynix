# Creates a nix server flask app which can be run with uwsgi.
import logging
import os

from pynix.utils import KeyInfo
from pynix.binary_cache.server import NixServer

# Set up some options through the environment.
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, log_level), format="%(message)s")
compression_type = os.getenv("COMPRESSION_TYPE", "xz")
secret_key_file = os.getenv("NIX_SECRET_KEY_FILE")
public_key_file = os.getenv("NIX_PUBLIC_KEY_FILE")
if (secret_key_file is None) != (public_key_file is None):
    raise ValueError("Must supply public key and secret key together.")
elif secret_key_file is not None and public_key_file is not None:
    key_info = KeyInfo.load(
        secret_key_file=secret_key_file,
        public_key_file=public_key_file)
else:
    key_info = None
nixserver = NixServer(compression_type=compression_type, key_info=key_info)

app = nixserver.make_app()
