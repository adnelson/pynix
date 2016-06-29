"""Module for sending store objects to a running servenix instance."""
import argparse
import json
import logging
import os
from subprocess import Popen, PIPE, check_output

import requests
import six

from servenix.common.utils import strip_output

class StoreObjectSender(object):
    """Wraps some state for sending store objects."""
    def __init__(self, endpoint, dry_run):
        #: Server running servenix (string).
        self._endpoint = endpoint
        #: If true, no actual paths will be sent.
        self._dry_run = dry_run
        #: Cache of direct path references (string -> strings).
        self._path_references = {}
        #: Set of paths known to exist on the server already (set of strings).
        self._objects_on_server = set()

    def get_references(self, path):
        """Get a path's direct references.

        :param path: A nix store path. It must exist in the store.
        :type path: ``str``

        :return: A list of paths that the path refers to directly.
        :rtype: ``list`` of ``str``

        Side effects:
        * Caches reference lists in `self._path_references`.
        """
        if path not in self._path_references:
            refs = strip_output("nix-store --query --references {}"
                                .format(path))
            refs = refs.split()
            self._path_references[path] = [r for r in refs if r != path]
        return self._path_references[path]

    def query_store_paths(self, paths):
        """Send a list of store paths to the server to see what it has already.

        Includes all paths listed as well as their closures (referenced paths),
        to try to get as much information as possible.

        :param paths: A list of store paths.
        :type paths: ``list`` of ``str``

        :return: The full set of paths that will be sent.
        :rtype: ``set`` of ``str``

        Side effects:
        * Adds 0 or more paths to `self._objects_on_server`.
        """
        full_path_set = set()
        def recur(_paths):
            """Loop for DFS'ing through the paths to generate full closures."""
            for path in _paths:
                if path not in full_path_set:
                    recur(self.get_references(path))
                    full_path_set.add(path)
        recur(paths)

        # Now that we have the full list built up, send it to the
        # server to see which paths are already there.
        url = "{}/query-paths".format(self._endpoint)
        data = json.dumps(list(full_path_set))
        headers = {"Content-Type": "application/json"}
        if len(full_path_set) == 0:
            # No point in making a request if we don't have any paths.
            return set()
        logging.info("Asking the nix server about {} paths."
                     .format(len(full_path_set)))
        response = requests.get(url, headers=headers, data=data)
        response.raise_for_status()

        # The set of paths that will be sent.
        to_send = set()

        # Store all of the paths which are listed as `True` (exist on
        # the server) in our cache.
        for path, is_on_server in six.iteritems(response.json()):
            if is_on_server is True:
                self._objects_on_server.add(path)
            else:
                to_send.add(path)
        return to_send

    def send_object(self, path):
        """Send a store object to a nix server.

        :param path: The path to the store object to send.
        :type path: ``str``
        :param endpoint: The endpoint to the remote servenix server.
        :type endpoint: ``str``

        Side effects:
        * Adds 0 or 1 paths to `self._objects_on_server`.
        """
        # Check if the object is already on the server; if so we can stop.
        if path in self._objects_on_server:
            logging.debug("{} is already on the server.".format(path))
            return
        # First send all of the object's references. Skip self-references.
        for ref in self.get_references(path):
            self.send_object(ref)
        # Now we can send the object itself. Generate a dump of the
        # file and send it to the import url. For now we're not using
        # streaming because it's not entirely clear that this is
        # possible with current requests, or indeed possible in
        # general without knowing the file size.
        logging.info("Sending server a new store path {}".format(path))
        out = check_output("nix-store --export {}".format(path), shell=True)
        url = "{}/import-path".format(self._endpoint)
        response = requests.post(url, data=out)
        # Check the response code.
        response.raise_for_status()
        # Register that the store path has been sent.
        self._objects_on_server.add(path)

    def send_objects(self, paths):
        """Checks for which paths need to be sent, and sends those.

        :param paths: Store paths to be sent.
        :type paths: ``str``
        """
        to_send = self.query_store_paths(paths)
        num_to_send = len(to_send)
        if self._dry_run is True:
            for path in to_send:
                logging.debug(path)
        if num_to_send > 0:
            logging.info("Total of {} paths will be sent."
                         .format(len(to_send)))
        else:
            logging.info("No paths need to be sent. Server is up-to-date.")
        if self._dry_run is False:
            for path in paths:
                self.send_object(path)


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="sendnix")
    parser.add_argument("-e", "--endpoint",
                        default=os.environ.get("NIX_REPO_HTTP"),
                        help="Endpoint of nix server to send to.")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="If true, reports which paths would be sent.")
    parser.add_argument("paths", nargs="+", help="Store paths to send.")
    parser.add_argument("--log-level", help="Log messages level.",
                        default="INFO", choices=("CRITICAL", "ERROR", "INFO",
                                                 "WARNING", "DEBUG"))
    return parser.parse_args()


def main():
    """Main entry point."""
    args = _get_args()
    if args.endpoint is None:
        exit("Endpoint is required. Use --endpoint or set NIX_REPO_HTTP.")
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(message)s")
    sender = StoreObjectSender(endpoint=args.endpoint, dry_run=args.dry_run)
    sender.send_objects(args.paths)
