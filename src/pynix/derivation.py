"""Python class for nix derivations."""
import ast
import os
import json
import sys

import datadiff
import yaml
import rtyaml


class Derivation(object):
    """A Python representation of a derivation."""
    # Cache of parsed derivations, to avoid duplicat parsing.
    CACHE = {}

    def __init__(self, path, raw, outputs, input_derivations,
                 input_files, system, builder, builder_args, environment):
        """Initializer.

        :param path: The path to this derivation file.
        :type path: ``str``
        :param raw: Raw nix derivation.
        :type raw: ``str``
        :param outputs: The outputs this derivation will produce. Keys are
            output names, and values are EITHER nix store paths, OR
            nix store paths plus some output hash information.
        :type outputs: ``dict`` of ``str`` -> ``str``
        :param input_derivations: Derivations required to build the
            expression. Keys are derivation paths, and values are lists of
            output names that this derivation will use.
        :type input_derivations: ``dict`` of ``str`` -> ``list`` of ``str``
        :param input_files: Store paths that aren't derivations, which
            are needed to build the expression.
        :type input_files: ``set`` of ``str``
        :param system: Architecture and OS the derivation is built on.
        :type system: ``str``
        :param builder: Store path of the derivation's builder executable.
        :type builder: ``str``
        :param builder_args: Command-line arguments for the builder.
        :type builder_args: ``list`` of ``str``
        :param environment: Environment variables to set for the builder.
        :type environment: ``dict`` of ``str`` to ``str``
        """
        self.outputs = outputs
        self.input_derivations = input_derivations
        self.input_files = input_files
        self.system = system
        self.builder = builder
        self.builder_args = builder_args
        self.environment = environment

        # Hidden since they're not considered part of a nix derivation,
        # but accessible via property.
        self._raw = raw
        self._path = path

        # Built lazily.
        self._input_paths = None
        self._input_derivation_paths = None
        self._output_mapping = None
        self._as_dict = None

    @property
    def path(self):
        """Path to the derivation file."""
        return self._path

    @property
    def raw(self):
        """The raw derivation string."""
        return self._raw

    @property
    def default_output(self):
        """Name of the output that is built by default (usually 'out')."""
        return self.environment["outputs"].split()[0]

    @property
    def output_mapping(self):
        """A dictionary mapping output names to their paths."""
        if self._output_mapping is None:
            result = {}
            for name, _path in self.outputs.items():
                if isinstance(_path, str):
                    result[name] = _path
                else:
                    # The path is actually a tuple combining the path with
                    # some hash data. Just take the path part.
                    result[name] = _path[0]
            self._output_mapping = result
        return self._output_mapping

    @property
    def name(self):
        """Get the name of the derivation by reading its environment.

        `name` is a required attribute of derivations, so this should be safe.
        """
        return self.environment["name"]

    @property
    def input_derivation_paths(self):
        """Set of all store paths needed to build this derivation,
        that are themselves the result of derivations.

        :return: A set of paths.
        :rtype: ``set`` of ``str``
        """
        if self._input_derivation_paths is None:
            paths = set()
            for deriv_path, outputs in self.input_derivations.items():
                input_deriv = Derivation.parse_derivation_file(deriv_path)
                for output in outputs:
                    paths.add(input_deriv.output_mapping[output])
            self._input_derivation_paths = paths
        return self._input_derivation_paths

    @property
    def input_paths(self):
        """Set of all store paths needed to build the derivation.

        :return: A set of paths.
        :rtype: ``set`` of ``str``
        """
        if self._input_paths is None:
            paths = set(self.input_files) | self.input_derivation_paths
            self._input_paths = paths
        return self._input_paths

    @property
    def output_names(self):
        """Return the names of outputs that this derivation produces.

        :return: A set of output names.
        :rtype: ``set`` of ``str``
        """
        return set(self.outputs.keys())

    @property
    def as_dict(self):
        """Convert to a JSON-compatible dictionary."""
        if self._as_dict is None:
            items = vars(self).items()
            res = {k: v for k, v in items if not k.startswith("_")}
            for key, val in res.items():
                if isinstance(val, set):
                    res[key] = list(sorted(val))
                elif isinstance(val, tuple):
                    res[key] = list(val)
            self._as_dict = res
        return self._as_dict

    def __eq__(self, other):
        """Test if one derivation is equal to another."""
        if isinstance(other, str):
            other = Derivation.parse_derivation_file(other)
        return self.as_dict == other.as_dict

    def __hash__(self):
        """Use the derivation's path as a hash."""
        return hash(self.path)

    def __repr__(self):
        return "Derivation({})".format(repr(self.path))

    def diff(self, other):
        """Get a naive diff between two derivations, just comparing
        their dictionary representation."""
        selfdict, otherdict = vars(self), vars(other)
        # Convert outputs to a format that doesn't include the output
        # file path, since we know this will be different if the two
        # derivations are different.
        selfdict["outputs"] = list(sorted(selfdict["outputs"].keys()))
        otherdict["outputs"] = list(sorted(otherdict["outputs"].keys()))
        return datadiff.diff(selfdict, otherdict)

    def diff_env(self, other):
        """Diff the environments of two derivations."""
        return datadiff.diff(self.environment, other.environment)

    def diff_inputs(self, other):
        """Diff the inputs of two derivations."""
        return datadiff.diff(self.input_paths, other.input_paths)

    def display(self, attribute=None, env_var=None, output=None,
                format="json", pretty=False):
        """Return a string representation in the given format.

        :param attribute: If given, only show that attribute.
        :type attribute: ``str`` or ``NoneType``
        :param env_var: If given, only show that environment variable.
        :type env_var: ``str`` or ``NoneType``
        :param output: If given, show the output path of that output.
        :type output: ``str``
        :param format: The output format. Valid options are 'string',
                       'json' and 'yaml'. 'string' is limited in that it can
                       only show strings and lists of strings.
        :type format: ``str``
        :param pretty: Pretty-print.
        :type pretty: ``bool``

        :rtype: ``str``
        """
        if attribute is None and env_var is None and output is None:
            to_print = self.raw if format == "string" else self.as_dict
        elif attribute is not None:
            to_print = getattr(self, attribute)
            if isinstance(to_print, set):
                to_print = list(sorted(to_print))
        elif output is not None:
            to_print = self.output_mapping[output]
        else:
            to_print = self.environment[env_var]
        if format == "string":
            if isinstance(to_print, str):
                return to_print
            elif isinstance(to_print, list) and \
                   all(isinstance(x, str) for x in to_print):
                return "\n".join(to_print)
            else:
                raise TypeError("Can't convert {} to a string (try --json "
                                "or --yaml).".format(type(to_print)))
        elif format == "json":
            if pretty is True:
                return json.dumps(to_print, indent=2, sort_keys=True)
            else:
                return json.dumps(to_print, sort_keys=True)
        elif format == "yaml":
            if pretty is True:
                return rtyaml.dump(to_print)
            else:
                return yaml.dump(to_print)
        else:
            raise ValueError("Invalid format: {}".format(format))

    @staticmethod
    def parse_derivation(derivation_string, derivation_path):
        """Parse a derivation string into a Derivation.

        :param derivation_string: A string representation of a
            derivation, as returned by a call to `nix-instantiate`.
        :type derivation_string: ``str``
        :param derivation_path: Path to the derivation file.
        :type derivation_path: ``str``

        :return: The parsed Derivation object.
        :rtype: :py:class:`Derivation`
        """
        if derivation_string.startswith("Derive(["):
            # Then trim off the initial 'Derive(' and final ')'
            derivation_string = derivation_string[7:-1]
        # Parse the string as a python literal; this is a safe
        # operation because the derivation will not contain any
        # function calls, or anything which isn't a valid python literal.
        derivation_list =  ast.literal_eval(derivation_string)
        output_list= derivation_list[0]
        outputs = {name: path if hashtype == "" else (path, hashtype, hash_)
                   for name, path, hashtype, hash_ in output_list}
        input_derivations = dict(derivation_list[1])
        input_files = set(derivation_list[2])
        system = derivation_list[3]
        builder = derivation_list[4]
        builder_args = derivation_list[5]
        environment = dict(derivation_list[6])
        return Derivation(path=derivation_path,
                          raw=derivation_string,
                          outputs=outputs,
                          input_derivations=input_derivations,
                          input_files=input_files,
                          system=system,
                          builder=builder,
                          builder_args=builder_args,
                          environment=environment)

    @staticmethod
    def parse_derivation_file(derivation_path):
        """Parse a derivation from a file path.

        :param derivation_path: Path to a file containing a string
            representation of a derivation.
        :type derivation_path: ``str``

        :return: The parsed Derivation object.
        :rtype: :py:class:`Derivation`
        """
        if not os.path.exists(derivation_path) and \
           not os.path.isabs(derivation_path) and "NIX_STORE" in os.environ:
            derivation_path = os.path.join(os.environ["NIX_STORE"],
                                           derivation_path)
        if derivation_path in Derivation.CACHE:
            return Derivation.CACHE[derivation_path]
        with open(derivation_path, "rb") as f:
            source = f.read().decode("utf-8")
            try:
                deriv = Derivation.parse_derivation(source, derivation_path)
                Derivation.CACHE[derivation_path] = deriv
                return deriv
            except Exception as e:
                raise ValueError("Couldn't parse derivation at path {}: {}"
                                 .format(derivation_path, repr(e)))
