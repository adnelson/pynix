"""Exceptions specific to the servenix module."""

class NoSuchObject(IOError):
    """Raises when a store object can't be found."""
    def __init__(self, message):
        self.message = message
