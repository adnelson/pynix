"""A python embedding of a NarInfo object."""
import os
from io import BytesIO
import yaml

from pynix.utils import call_nix_store

# Magic 8-byte number that comes at the beginning of the export's bytes.
EXPORT_INITIAL_MAGIC = b"\x01\x00\x00\x00\x00\x00\x00\x00"
# Magic 8-byte number that comes after the NAR, before export metadata.
EXPORT_METADATA_MAGIC = b"NIXE\x00\x00\x00\x00"
# A bytestring of 8 zeros, used below.
EIGHT_ZEROS = bytes(8)

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

    def abspath_of(self, path):
        """Join a path with the nix store path to make it absolute.

        :param path: A path in the nix store.
        :type path: ``str``

        :return: The absolute path of that path, in the nix store.
        :rtype: ``str``
        """
        store_dir = os.path.dirname(self.store_path)
        return os.path.join(store_dir, path)

    @property
    def abs_references(self):
        """Return absolute paths of references.

        :return: A list of store paths.
        :rtype: ``list`` of ``str``
        """
        return [self.abspath_of(r) for r in self.references]

    @property
    def abs_deriver(self):
        """Return the absolute path of the deriver, if it is set.

        :return: A store path or None.
        :rtype: ``str`` or ``NoneType``
        """
        if self.deriver is not None:
            return self.abspath_of(self.deriver)
        else:
            return None

    def nar_to_export(self, nar_bytes):
        """Use the narinfo metadata to convert a nar bytestring to an export.

        :param nar_bytes: Raw bytes of a nix archive.
        :type nar_bytes: ``bytes``

        :return: A nar export.
        :rtype: :py:class:`NarExport`
        """
        return NarExport(self.store_path, nar_bytes=nar_bytes,
                         references=self.abs_references,
                         deriver=self.abs_deriver)
    @classmethod
    def from_row(cls, store_dir, row):
        """Parse a narinfo from a row in a sqlite table.

        Nix caches NarInfo's in this way, so it's useful to parse it.

        :param store_dir: Path to the nix store, since this
                          information isn't stored in the row.
        :type store_dir: ``str``
        :param row: A tuple of 12 elements, which is the info nix stores.
        :type row: ``tuple``

        :return: A ``NarInfo`` object.
        :rtype: :py:class:`NarInfo`
        """
        if len(row) != 12:
            raise ValueError("Expected a tuple of 12 elements, got {}"
                             .format(len(row)))
        (_, store_path, url, compression, file_hash,
         file_size, nar_hash, nar_size, refs, deriver, _, _) = row
        return cls(store_path=os.path.join(store_dir, store_path),
                   url=url, compression=compression, file_hash=file_hash,
                   file_size=file_size, nar_hash=nar_hash, nar_size=nar_size,
                   references=refs.split(), deriver=(deriver or None))

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

class NarExport(object):
    """A nix archive augmented with some metadata.

    A nix export is a nix archive coupled with some metadata, created
    with the `nix-store --export` command. Specifically, it adds
    information about references and optionally a deriver path.
    """
    def __init__(self, store_path, nar_bytes, references, deriver=None):
        """Initializer.

        :param store_path: Path to the object being encoded.
        :type store_path: ``str``
        :param nar: The bytes of a nix archive.
        :type nar: ``bytes``
        :param references: A list of paths that the object refers
                           to. These should be absolute paths.
        :type references: ``list`` of ``str``
        :param deriver: The absolute path to the derivation that
                        built the object. Optional.
        :type deriver: ``str`` or ``NoneType``
        """
        self.store_path = store_path
        self.nar_bytes = nar_bytes
        # Convert references to absolute paths, to be sure.
        for ref_path in references:
            if not os.path.isabs(ref_path):
                raise TypeError("Reference path {} must be absolute."
                                .format(ref_path))
        self.references = list(sorted(references))
        self.deriver = deriver

        _paths = [store_path] + references
        if deriver is not None:
            _paths.append(deriver)
        for path in _paths:
            if not os.path.isabs(path):
                raise ValueError("Paths must be absolute ({}).".format(path))

    @classmethod
    def load(cls, path):
        """Load a store path into a nar export."""
        nar = call_nix_store("--dump", path, decode=False)
        references = call_nix_store("--query", "--references", path).split()
        deriver = call_nix_store("--query", "--deriver", path)
        if deriver == "unknown-deriver":
            deriver = None
        return NarExport(store_path=path, nar_bytes=nar, references=references,
                         deriver=deriver)


    def to_bytes(self):
        """Convert a nar export into bytes.

        Nix exports are a binary format. The logic of this function
        serializes the NarExport, including:

        * An 8-byte magic header, which nix-store reads when it imports.
        * The bytes of the NAR itself.
        * Another magic bytestring, which is 'NIXE' followed by four nulls.
        * The path to the object in the nix store being imported.
        * The number of references.
        * The path of each reference.
        * The deriver path, if known (else an empty string).
        * 8 empty bytes, to indicate we're not including a signature.
        * 8 empty bytes, for reasons unknown to me but needed by nix-store.

        Each string referenced above (e.g. paths) is represented by
        first writing its length as an integer encoded in
        little-endian 8 bytes, then the string itself, and then as
        many null bytes as are needed to get to the nearest multiple
        of 8 bytes. So for example, the string "hello" would be
        represented as

          "\x05\x00\x00\x00\x00\x00\x00\x00hello\x00\x00\x00"

        Note that there are three zeros following the "hello" text, in
        order to pad it to eight bytes.
        """
        def addstr(bytesio, bstring):
            """Utility function, adds a string with padding to the bytes."""
            _len = len(bstring)
            bytesio.write(_len.to_bytes(8, "little"))
            bytesio.write(bstring)
            if _len % 8 != 0:
                bytesio.write(EIGHT_ZEROS[:8 - (_len % 8)])

        # Start with the magic header and nar bytes.
        bio = BytesIO()
        bio.write(EXPORT_INITIAL_MAGIC)
        bio.write(self.nar_bytes)

        # Write the magic value for the metadata.
        bio.write(EXPORT_METADATA_MAGIC)

        # Write the store path of the object.
        addstr(bio, self.store_path.encode("utf-8"))

        # Write the number of references, and each reference.
        bio.write(len(self.references).to_bytes(8, "little"))
        for ref in self.references:
            addstr(bio, ref.encode("utf-8"))

        if self.deriver is not None:
            addstr(bio, self.deriver.encode("utf-8"))
        else:
            addstr(bio, b"")

        # Add a 0 to indicate no signature, and then another 0 (not sure why).
        bio.write(EIGHT_ZEROS)
        bio.write(EIGHT_ZEROS)

        # Return the contents of the bytesio as the resulting bytestring.
        return bio.getvalue()