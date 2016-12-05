import os
from servenix.client.sendnix import StoreObjectSender

path = "/nix/store/aa9asgngyisnfcxk3hcqlpy8qcapf1lg-hello-2.10"

sender = StoreObjectSender(os.environ["NIX_REPO_HTTP"])

sender.get_references(path)
