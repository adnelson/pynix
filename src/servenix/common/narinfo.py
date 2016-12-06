"""A python embedding of a NarInfo object."""
import os
from io import BytesIO
import yaml

# Magic 8-byte number that comes at the beginning of the export's bytes.
EXPORT_INITIAL_MAGIC = b"\x01" + (b"\x00" * 7)
# Magic 8-byte number that comes after the NAR, before export metadata.
EXPORT_METADATA_MAGIC = b"NIXE\x00\x00\x00\x00"

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

    def convert_nar_to_export(self, nar_bytes):
        """Add metadata to a nar bytestring, turning it into an export.

        A nix export is a nix archive coupled with some
        metadata. Specifically, it adds information about references
        and optionally deriver. This information is contained in a
        NarInfo, so we can augment a nar here.

        Nix exports are a binary format. The input to this function is
        a bytestring intended to have been created from a call to
        `nix-store --dump`, or equivalently, as returned by a nix
        binary cache. The logic of this function adds a few things:

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
        # We'll build the string using a BytesIO for efficiency
        bio = BytesIO()
        def addstr(bstring):
            """Utility function, adds a string with padding to the bytes."""
            _len = len(bstring)
            bio.write(_len.to_bytes(8, "little"))
            bio.write(bstring)
            if _len % 8 != 0:
                bio.write(bytes(8)[:8 - (_len % 8)])

        # Start with the magic header and nar bytes.
        bio.write(EXPORT_INITIAL_MAGIC)
        bio.write(nar_bytes)

        # Write the magic value for the metadata.
        bio.write(EXPORT_METADATA_MAGIC)

        # Write the store path of the object.
        addstr(self.store_path.encode("utf-8"))

        # Write the number of references, and each reference.
        refs = self.fullpath_references(circular=True)
        bio.write(len(refs).to_bytes(8, "little"))
        for ref in refs:
            addstr(ref.encode("utf-8"))

        if self.deriver is not None:
            addstr(self.deriver.decode("utf-8"))
        else:
            addstr(b"")

        # Add a 0 to indicate no signature, and then another 0 (not sure why).
        bio.write((0).to_bytes(8, "little"))
        bio.write((0).to_bytes(8, "little"))

        # Return the contents of the bytesio as the resulting bytestring.
        return bio.getvalue()

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
