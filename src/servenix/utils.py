"""Some utility functions to support store operations."""
from subprocess import check_output

def decode_str(string):
    """Convert a bytestring to a string. Is a no-op for strings.

    This is necessary because python3 distinguishes between
    bytestrings and unicode strings, and uses the former for
    operations that read from files or other operations. In general
    programmatically we're fine with just using unicode, so we decode
    everything. This function also makes backwards-compatibility with
    python2, since this will have no effect.

    :param string: Either a string or bytes.
    :type string: ``str`` or ``bytes``

    :return: A unicode string.
    :rtype: ``str``
    """
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    else:
        return string

def strip_output(command, shell=True):
    """Execute a bash command, and return its stripped output.

    :param command: A command, either a string or list.
    :type command: ``str`` or ``list`` of ``str``
    :param shell: Execute the command as a shell command.
    :type shell: ``bool``

    :return: The resulting stdout, stripped of trailing whitespace.
    :rtype: ``str``
    """
    return decode_str(check_output(command, shell=shell)).strip()
