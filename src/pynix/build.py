"""Build nix derivations."""
import json
import sys
from os.path import basename

import requests
from pynix.derivation import Derivation
from pynix.utils import is_path_in_store

def needed_to_build(deriv, outputs=None, needed=None, need_fetch=None,
                    existing=None, on_server=None):
    """Return derivations needed to build the given output of this derivation.

    If the outputs exists already, returns an empty set. Otherwise,
    the derivation itself is added. In addition, we look at all of
    its input paths that come from derivations. Whichever have
    output paths which don't exist already will be recurred on.

    :param deriv: The derivation to check.
    :param outputs: Outputs of the derivation needed to build. If not
                    specified, all outputs are built.
    :type outputs: ``list`` of ``str``
    :param needed: Derivation outputs that need to be built.
    :type needed: ``dict`` of ``Derivation`` to ``set`` of ``str``
    :param need_fetch: Derivation outputs that need to be fetched
                       from a binary cache.
    :type need_fetch: ``dict`` of ``Derivation`` to ``set`` of ``str``
    :param on_server: Derivations and outputs known to be in a
                      binary cache. This is a read-only object in
                      this function; the check to see if an output
                      is in the cache is done in a separate step.
    :type on_server: ``dict`` of ``Derivation`` to ``set`` of ``str``
    :param existing: Derivations and outputs known to exist on disk.
    :param existing: ``dict`` of ``Derivation`` to ``set`` of ``str``

    :return: Two sets: one giving derivations needed to be built, and
             another giving derivations and outputs on disk.
    :rtype: (``dict`` of ``Derivation`` to ``set`` of ``str``,
             ``dict`` of ``Derivation`` to ``set`` of ``str``)
    """
    outputs = outputs or deriv.outputs.keys()
    if needed is None:
        needed = {}
    if need_fetch is None:
        need_fetch = {}
    if existing is None:
        existing = {}
    if on_server is None:
        on_server = {}
    # First check to see if we already have the information we need.
    if deriv in needed:
        for output in outputs:
            needed[deriv].add(output)
        return needed, need_fetch
    else:
        # For each requested output, check to see if it's either
        # on the filesystem or on the server; if so we don't need
        # to build it.
        prebuilt = existing.get(deriv, set()) | need_fetch.get(deriv, set())
        if all(output in prebuilt for output in outputs):
            return needed, need_fetch
    # So then, we don't know if we need to build this derivation.
    # We can see by checking the outputs.
    for output in outputs:
        if is_path_in_store(deriv.output_mapping[output]):
            if deriv not in existing:
                existing[deriv] = set()
            existing[deriv].add(output)
        elif deriv in on_server and output in on_server[deriv]:
            if deriv not in need_fetch:
                need_fetch[deriv] = set()
            need_fetch[deriv].add(output)
        else:
            if deriv not in needed:
                needed[deriv] = set()
            needed[deriv].add(output)
            # Even though we're doing this repeatedly, it will exit
            # early on subsequent invocations, so it will be fast.
            for path, outputs in deriv.input_derivations.items():
                subderiv = Derivation.parse_derivation_file(path)
                needed_to_build(subderiv, outputs=outputs,
                                needed=needed, need_fetch=need_fetch,
                                on_server=on_server, existing=existing)
    return needed, need_fetch


def needed_to_build_multi(deriv_outputs, existing=None, on_server=None):
    """

    :param deriv_outputs: A mapping from derivations to sets of outputs.
    :type deriv_outputs: ``dict`` of ``Derivation`` to ``set`` of ``str``
    """
    if existing is None:
        existing = {}
    if on_server is None:
        on_server = {}
    needed, need_fetch = {}, {}
    for deriv, outputs in deriv_outputs.items():
        needed_to_build(deriv, outputs, needed=needed, need_fetch=need_fetch,
                        existing=existing, on_server=on_server)
    return needed, need_fetch


def parse_deriv_paths(paths):
    """Given a list of derivation paths, parse them into a mapping.

    Paths can optionally have a ! after them followed by
    comma-separated output names, indicating that the given outputs of
    the derivation are desired.

    :param paths: A list of paths, optionally with output names.
    :type paths: ``list`` of ``str``

    :return: Mapping from derivations to sets of output names.
    :rtype: ``dict`` of ``Derivation`` to ``set`` of ``str``,
    """
    result = {}
    for path in paths:
        if "!" in path:
            # This syntax allows the user to specify particular
            # output(s) of a derivation to check, rather than just
            # the derivation itself.
            path, out = path.split("!")
            outputs = out.split(",")
        else:
            outputs = None
        deriv = Derivation.parse_derivation_file(path)
        if outputs is None:
            outputs = [deriv.default_output]
        if deriv not in result:
            result[deriv] = set()
        for output in outputs:
            result[deriv].add(output)
    return result
