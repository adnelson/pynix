    def fetch_object(self, path):
        """Fetch a store object from a nix server.

        This is obviously the inverse of a send, and quite a similar
        algorithm (first fetch parents, and then fetch the
        object). But it's a little different because although with a
        send you already know (or can derive) the references of the
        object, with fetching you need to ask the server for the
        references.

        :param path: The path to the store object to send.
        :type path: ``str``

        Side effects:
        * Adds 0 or 1 paths to `self._objects_on_server`.
        """
        # Check if the object has already been fetched; if so we can stop.
        if path in self._objects_on_server:
            return
        # First fetch all of the object's references.
        for ref in self.get_references_from_server(path):
            self.fetch_object(ref, remaining_objects=remaining_objects)
        # Now we can send the object itself. Generate a dump of the
        # file and send it to the import url. For now we're not using
        # streaming because it's not entirely clear that this is
        # possible with current requests, or indeed possible in
        # general without knowing the file size.
        auth = self._get_auth()
        export = check_output("nix-store --export {}".format(path), shell=True)
        # For large files, show progress when compressing
        if len(export) > 1000000:
            logging.info("Compressing {}".format(basename(path)))
            cmd = "pv -ptef -s {} | gzip".format(len(export))
            proc = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
            data = proc.communicate(input=export)[0]
        else:
            data = gzip.compress(export)
        url = "{}/import-path".format(self._endpoint)
        headers = {"Content-Type": "application/x-gzip"}
        try:
            logging.info("Sending {} ({} remaining)"
                         .format(basename(path), len(remaining_objects)))
            response = requests.post(url, data=data, headers=headers, auth=auth)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            try:
                msg = json.loads(decode_str(response.content))["message"]
            except (ValueError, KeyError):
                msg = response.content
            logging.error("{} returned error on path {}: {}"
                          .format(self._endpoint, basename(path), msg))
            raise
        # Check the response code.
        # Register that the store path has been sent.
        self._objects_on_server.add(path)
        # Remove the path if it is still in the set.
        if remaining_objects is not None and path in remaining_objects:
            remaining_objects.remove(path)
