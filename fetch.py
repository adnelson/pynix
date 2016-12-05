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
        if path in self._objects_fetched:
            return
        # First fetch all of the object's references.
        for ref in self.get_references(path, query_server=True):
            self.fetch_object(ref)
        # Now we can fetch the object itself. Get its info first.
        narinfo = self.get_narinfo(path)

        # Use the URL in the narinfo to fetch the object.
        url = "{}/{}".format(self._endpoint, narinfo.url)

        print("I'll be hitting this url: {}".format(url))
        self._objects_fetched.add(path)
