"""Module for sending store objects to a running servenix instance."""
import argparse
import json
import logging
import os
from subprocess import Popen, PIPE, check_output
import sqlite3

import requests
import six

from servenix.common.utils import strip_output, find_nix_paths

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
        for p in full_path_set:
            logging.debug("Querying path {}".format(p))
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
        export_proc = Popen("nix-store --export {}".format(path), shell=True, 
                            stdout=PIPE)
        # Pipe the result of the export into gzip.
        out = check_output("gzip", shell=True, stdin=export_proc.stdout)
        url = "{}/import-path".format(self._endpoint)
        headers = {"Content-Type": "application/x-gzip"}
        response = requests.post(url, data=out, headers=headers)
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

    def sync_store(self):
        """Syncronize the local nix store to the endpoint.

        Reads all of the known paths in the nix SQLite database, and
        passes them into :py:meth:`send_objects`.
        """
        nix_state_path = find_nix_paths()["nix_state_path"]
        db_path = os.path.join(nix_state_path, "nix", "db", "db.sqlite")
        with sqlite3.connect(db_path) as con:
            query = con.execute("SELECT path FROM ValidPaths")
            paths = [res[0] for res in query.fetchall()]
        self.send_objects(paths)


def _get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(prog="sendnix")
    parser.add_argument("-e", "--endpoint",
                        default=os.environ.get("NIX_REPO_HTTP"),
                        help="Endpoint of nix server to send to.")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="If true, reports which paths would be sent.")
    parser.add_argument("--log-level", help="Log messages level.",
                        default="INFO", choices=("CRITICAL", "ERROR", "INFO",
                                                 "WARNING", "DEBUG"))
    subparsers = parser.add_subparsers(title="Command", dest="command")
    subparsers.required = True
    # 'send' command used for sending particular paths.
    send = subparsers.add_parser("send", help="Send specific store objects.")
    send.add_argument("paths", nargs="+", help="Store paths to send.")
    # 'sync' command used for syncronizing an entire nix store.
    sync = subparsers.add_parser("sync", help="Send all store objects.")
    return parser.parse_args()

def main():
    """Main entry point."""
    args = _get_args()
    if args.endpoint is None:
        exit("Endpoint is required. Use --endpoint or set NIX_REPO_HTTP.")
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(message)s")
    sender = StoreObjectSender(endpoint=args.endpoint, dry_run=args.dry_run)
    if args.command == "send":
        sender.send_objects(args.paths)
    elif args.command == "sync":
        sender.sync_store()
    else:
        exit("Unknown command '{}'".format(args.command))
