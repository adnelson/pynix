"""A python embedding of a NarInfo object."""
import base64
import sys
if sys.version_info >= (3, 0):
    from functools import lru_cache
else:
    from repoze.lru import lru_cache
from io import BytesIO
import logging
import os
from os.path import join, basename, dirname
import yaml
from subprocess import check_output, CalledProcessError

from pynix.derivation import Derivation
from pynix.utils import decode_str, strip_output, nix_cmd, query_store
from pynix.exceptions import NoNarGenerated

# Magic 8-byte number that comes at the beginning of the export's bytes.
EXPORT_INITIAL_MAGIC = b"\x01" + (b"\x00" * 7)
# Magic 8-byte number that comes after the NAR, before export metadata.
EXPORT_METADATA_MAGIC = b"NIXE\x00\x00\x00\x00"
# A bytestring of 8 zeros, used below.
EIGHT_ZEROS = bytes(8)

# Compression types which are allowed for NARs.
COMPRESSION_TYPES = ("xz", "bzip2")
COMPRESSION_TYPE_ALIASES = {"xzip": "xz", "bz2": "bzip2"}

def resolve_compression_type(compression_type):
    """Turn a compression type string into a valid one.

    :raises: ``ValueError`` if the compression type is invalid.
    """
    if compression_type in COMPRESSION_TYPE_ALIASES:
        return COMPRESSION_TYPE_ALIASES[compression_type]
    elif compression_type in COMPRESSION_TYPES:
        return compression_type
    else:
        raise ValueError("Invalid compression type: {}"
                         .format(compression_type))

class NarInfo(object):
    # Cache of narinfo's that have been parsed, to avoid duplicate work.
    NARINFO_CACHE = {"xz": {}, "bzip2": {}}

    # Cache mapping store objects to their compressed NAR paths.
    NAR_PATH_CACHE = {"xz": {}, "bzip2": {}}

    def __init__(self, store_path, url, compression,
                 nar_size, nar_hash, file_size, file_hash,
                 references, deriver, signature):
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
        :param signature: Signature guaranteeing correctness (optional).
        :type signature: ``str`` or ``NoneType``
        """
        # We require a particular nar_hash.
        if not nar_hash.startswith("sha256:"):
            raise ValueError("NAR hash must be sha256.")
        elif len(nar_hash) != 59:
            raise ValueError("Hash must be encoded in base-32 (length 59)")

        self.url = url
        self.store_path = store_path
        self.compression = compression
        self.nar_size = nar_size
        self.nar_hash = nar_hash
        self.file_size = file_size
        self.file_hash = file_hash
        self.references = list(sorted(basename(r) for r in references))
        self.deriver = basename(deriver) if deriver else None
        self.signature = signature

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
        }
        if self.deriver is not None:
            result["Deriver"] = self.deriver
        if self.signature is not None:
            result["Sig"] = self.signature
        return result

    def to_string(self):
        """Generate a string representation."""
        as_dict = self.as_dict()
        as_dict["References"] = " ".join(as_dict["References"])
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
                         deriver=self.abs_deriver, signature=self.signature)

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
        url = dictionary["url"]
        store_path = dictionary["storepath"]
        compression = dictionary["compression"]
        nar_size = int(dictionary["narsize"])
        nar_hash = dictionary["narhash"]
        file_size = int(dictionary["filesize"])
        file_hash = dictionary["filehash"]
        references = dictionary.get("references") or []
        if isinstance(references, str):
            references = references.split()
        deriver = dictionary.get("deriver") or None
        signature = dictionary.get("sig")
        return cls(url=url, store_path=store_path, compression=compression,
                   nar_size=nar_size, nar_hash=nar_hash, file_size=file_size,
                   file_hash=file_hash, references=references, deriver=deriver,
                   signature=signature)

    @classmethod
    def from_string(cls, string):
        """Parse a string into a NarInfo."""
        return cls.from_dict(yaml.load(string))

    @classmethod
    def build_nar(cls, store_path, compression_type="xz", quiet=False):
        """Build a nix archive (nar) and return the resulting path."""
        if compression_type not in cls.NAR_PATH_CACHE:
            raise ValueError("Unsupported compression type: {}"
                             .format(compression_type))
        if store_path in cls.NAR_PATH_CACHE[compression_type]:
            return cls.NAR_PATH_CACHE[compression_type][store_path]

        logging.info("Kicking off NAR build of {}, {} compression"
                     .format(basename(store_path), compression_type))

        # Construct a nix expression which will produce a nar.
        nar_expr = "".join([
            "(import <nix/nar.nix> {",
            'storePath = "{}";'.format(store_path),
            'hashAlgo = "sha256";',
            'compressionType = "{}";'.format(compression_type),
            "})"])

        # Nix-build this expression, resulting in a store object.
        nar_dir = strip_output(
            nix_cmd("nix-build", ["--expr", nar_expr, "--no-out-link"]),
            hide_stderr=quiet)

        return cls.register_nar_path(nar_dir, store_path, compression_type)

    @classmethod
    def register_nar_path(cls, nar_dir, store_path, compression_type):
        """After a NAR has been built, this adds the path to the cache."""
        # There should be a file with this extension in the directory.
        extension = ".nar." + ("bz2" if compression_type == "bzip2" else "xz")
        contents = map(decode_str, os.listdir(nar_dir))
        for filename in contents:
            if filename.endswith(extension):
                nar_path = join(nar_dir, filename)
                cls.NAR_PATH_CACHE[compression_type][store_path] = nar_path
                return nar_path
        # This  might happen if we run out of disk space or something
        # else terrible.
        raise NoNarGenerated(nar_dir, extension)

    @classmethod
    @lru_cache(1024)
    def get_nar_dir(cls, store_path, compression_type):
        """Get the directory of a nix archive without building it."""
        if compression_type not in ("xz", "bzip2"):
            raise ValueError("Unsupported compression type: {}"
                             .format(compression_type))

        # Construct a nix expression which will produce a nar.
        nar_expr = "".join([
            "(import <nix/nar.nix> {",
            'storePath = "{}";'.format(store_path),
            'hashAlgo = "sha256";',
            'compressionType = "{}";'.format(compression_type),
            "})"])

        # Nix-build this expression, resulting in a store object.
        derivation_path = strip_output(
            nix_cmd("nix-instantiate", ["--expr", nar_expr, "--no-gc-warning"]))
        derivation = Derivation.parse_derivation_file(derivation_path)
        return derivation.outputs["out"]

    @classmethod
    def from_store_path(cls, store_path, compression_type="xz"):
        """Load a narinfo from a store path.

        :param store_path: Path in the nix store to load info on.
        :type store_path: ``str``
        :param compression_type: What type of compression to use on the NAR.

        :return: A NarInfo for the path.
        :rtype: :py:class:`NarInfo`
        """
        if store_path in cls.NARINFO_CACHE[compression_type]:
            return cls.NARINFO_CACHE[compression_type][store_path]

        # Build the compressed version. Compute its hash and size.
        nar_path = cls.build_nar(store_path, compression_type=compression_type)
        du = strip_output("du -sb {}".format(nar_path))
        file_size = int(du.split()[0])
        file_hash = strip_output(nix_cmd("nix-hash", ["--type", "sha256",
                                         "--base32", "--flat", nar_path]))
        nar_size = query_store(store_path, "--size")
        nar_hash = query_store(store_path, "--hash")
        references = query_store(store_path, "--references").split()
        deriver = query_store(store_path, "--deriver")
        extension = ".nar." + ("bz2" if compression_type == "bzip2" else "xz")
        narinfo = cls(
            url="nar/{}{}".format(basename(store_path)[:32], extension),
            compression=compression_type,
            store_path=store_path,
            nar_hash=nar_hash,
            nar_size=nar_size,
            file_size=str(file_size),
            file_hash="sha256:{}".format(file_hash),
            references=references,
            deriver=None if deriver == "unknown-deriver" else deriver,
            signature=None
        )
        cls.NARINFO_CACHE[compression_type][store_path] = narinfo
        return narinfo


class NarExport(object):
    """A nix archive augmented with some metadata.

    A nix export is a nix archive coupled with some metadata, created
    with the `nix-store --export` command. Specifically, it adds
    information about references and optionally a deriver path.
    """
    def __init__(self, store_path, nar_bytes, references, deriver, signature):
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
        :param signature: Signature of the binary cache. Optional, but
                          might be required depending on the nix settings.
        :type signature: ``str`` or ``NoneType``
        """
        self.store_path = store_path
        self.nar_bytes = nar_bytes
        self.references = references
        self.deriver = deriver
        self.signature = signature

        _paths = [store_path] + references
        if deriver is not None:
            _paths.append(deriver)
        for path in _paths:
            if not os.path.isabs(path):
                raise ValueError("Paths must be absolute ({}).".format(path))

    def import_to_store(self):
        """Import this NarExport into the local nix store."""
        try:
            return strip_output(nix_cmd("nix-store", ["--import"]),
                                input=self.to_bytes())
        except CalledProcessError:
            raise NixImportFailed("See above stderr")

    def to_bytes(self):
        """Convert a nar export into bytes.

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

        if self.signature is not None:
            # First write a '1' to tell nix that we have a signature.
            bio.write((1).to_bytes(8, "little"))
            # Then write the signature.
            addstr(bio, self.signature.encode("utf-8"))
        else:
            # Write a zero here so that nix doesn't look for a signature.
            bio.write(EIGHT_ZEROS)

        # Write a final zero to indicate the end of the export.
        bio.write(EIGHT_ZEROS)

        # Return the contents of the bytesio as the resulting bytestring.
        return bio.getvalue()
