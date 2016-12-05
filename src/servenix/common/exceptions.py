"""Exceptions specific to the servenix module."""

class BaseHTTPError(Exception):
    """Base class for all HTTP errors."""
    def __init__(self, message, status_code=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        elif not hasattr(self, "status_code"):
            self.status_code = 500

    def __repr__(self):
        return "{}: {}".format(type(self).__name__, self.message)

    def __str__(self):
        return repr(self)

    def to_dict(self):
        """Render error as a dictionary."""
        return {"message": self.message}


class ClientError(BaseHTTPError):
    """Base class for errors on the client side."""
    status_code = 400


class ServerError(BaseHTTPError):
    """Base class for errors on the server side."""
    status_code = 500


class NoSuchObject(BaseHTTPError):
    """Raised when a store object can't be found.

    This isn't necessarily an error (the client will ask the server
    for many paths which it might not have).
    """
    status_code = 404
    def __init__(self, message):
        BaseHTTPError.__init__(self, message=message)


class NoNarGenerated(ServerError):
    """Raised when the expected NAR wasn't created."""
    def __init__(self, path, extension):
        message = ("Folder {} did not contain a file with extension {}"
                   .format(path, extension))
        ServerError.__init__(self, message=message)


class CouldNotUpdateHash(ServerError):
    """Raised when we couldn't update an invalid hash."""
    def __init__(self, path, stored_hash, valid_hash, message):
        message = ("Couldn't update the hash of path {} from {} to {}: {}"
                   .format(path, stored_hash, valid_hash, message))
        ServerError.__init__(self, message=message)


class NixImportFailed(BaseHTTPError):
    """Raised when we couldn't import a store object."""
    def __init__(self, err_message):
        message = "Couldn't perform the import: {}".format(err_message)
        BaseHTTPError.__init__(self, message=message)

class CouldNotConnect(Exception):
    def __init__(self, endpoint, status_code, content):
        self._endpoint = endpoint
        self._status_code = status_code
        self._content = content
        self._message = ("Could not connect to {} ({}): {}"
                         .format(endpoint, status_code, content))

    def __str__(self):
        return self._message
