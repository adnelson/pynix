"""Exceptions specific to the servenix module."""

class NoSuchObject(IOError):
    """Raises when a store object can't be found."""
    def __init__(self, message):
        self.message = message


class NoNarGenerated(IOError):
    """Raised when the expected NAR wasn't created."""
    def __init__(self, path, extension):
        self.message = ("Folder {} did not contain a file with extension {}"
                        .format(path, extension))

class CouldNotUpdateHash(RuntimeError):
    """Raised when we couldn't update an invalid hash."""
    def __init__(self, path, stored_hash, valid_hash, message):
        self.message = ("Couldn't update the hash of path {} from {} to {}: {}"
                        .format(path, stored_hash, valid_hash, message))
