"""A python embedding of a NarInfo object."""
import os
import yaml

class NarInfo(object):
    def __init__(self, store_path, url, compression,
                 nar_size, nar_hash, file_size, file_hash,
                 references, deriver):
        """Initializer.

        :param url: The URL at which this NAR can be fetched.
        :type url: ``str``
        :param store_path: The nix store path the NAR compresses.
        :type store_path: ``str``
        :param compression: How the nix store path has been compressesed.
        :type compression: ``str``
        :param nar_size: The size of the nix archive, in bytes.
        :type nar_size: ``int``
        :param nar_hash: The hash of the nix archive, in <type>:<hash> format.
        :type nar_hash: ``str``
        :param file_size: The size of the archived nix store object, in bytes.
        :type file_size: ``int``
        :param file_hash: The hash of the store object in <type>:<hash> format.
        :type file_hash: ``str``
        :param references: A list of the base paths of other store
                           paths the object references.
        :type references: ``list`` of ``str``
        :param deriver: Path to the derivation used to build path (optional).
        :type deriver: ``str`` or ``NoneType``
        """
        self.url = url
        self.store_path = store_path
        self.compression = compression
        self.nar_size = nar_size
        self.nar_hash = nar_hash
        self.file_size = file_size
        self.file_hash = file_hash
        self.references = references
        self.deriver = deriver

    def __repr__(self):
        return "NarInfo({})".format(self.store_path)

    def __str__(self):
        args = ",".join("{}={}".format(k, repr(v))
                        for k, v in vars(self).items())
        return "NarInfo({})".format(args)

    def as_dict(self):
        """Generate a dictionary representation."""
        result = {
            "Url": self.url,
            "StorePath": self.store_path,
            "Compression": self.compression,
            "NarHash": self.nar_hash,
            "NarSize": self.nar_size,
            "FileSize": self.file_size,
            "FileHash": self.file_hash,
            "References": self.references,
            "Deriver": self.deriver
        }
        if self.deriver is not None:
            result["Deriver"] = self.deriver
        return result

    def to_string(self):
        """Generate a string representation."""
        as_dict = self.as_dict()
        as_dict["References"] = " ".join(as_dict["References"])
        if as_dict["Deriver"] is None:
            del as_dict["Deriver"]
        return "\n".join("{}: {}".format(k, v) for k, v in as_dict.items())

    def fullpath_references(self, circular=False):
        """Return full paths of references.

        :param circular: Include self-references.
        :type circular: ``bool``

        :return: A list of store paths.
        """
        store_dir, basename = os.path.split(self.store_path)
        references = [r for r in self.references if circular or r != basename]
        return [os.path.join(store_dir, r) for r in references]

    @classmethod
    def from_dict(cls, dictionary):
        """Given a dictionary representation, convert it to a NarInfo.

        :param dictionary: Dictionary representation, in the form
                           given by `self.as_dict()`, except that keys
                           are case insensitive.
        :type dictionary: ``dict``

        :return: A ``NarInfo`` object.
        :rtype: :py:class:`NarInfo`
        """
        # Convert keys to lower case
        dictionary = {k.lower(): v for k, v in dictionary.items()}
        def get(key, parser=None, optional=False, default=None):
            optional = optional or default is not None
            if key not in dictionary and optional is False:
                raise ValueError("Dictionary must have key {}".format(key))
            val = dictionary.get(key, default)
            return val if parser is None else parser(val)
        def split_refs(refs):
            return refs.split() if isinstance(refs, str) else refs
        return cls(
            url= get("url"),
            store_path=get("storepath"),
            compression=get("compression"),
            nar_size=get("narsize", parser=int),
            nar_hash=get("narhash"),
            file_size=get("filesize", parser=int),
            file_hash=get("filehash"),
            references=get("references", default=[], parser=split_refs),
            deriver=get("deriver", optional=True)
        )

    @classmethod
    def from_string(cls, string):
        """Parse a string into a NarInfo."""
        return cls.from_dict(yaml.load(string))
