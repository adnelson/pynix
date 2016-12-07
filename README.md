# pynix

This is a suite of tools for interacting with nix. In some cases it
provides alternatives to the existing set of tools, and in other cases
it adds new functionality. The tools provided include:

* A zero-configuration nix binary cache server, supporting binary
  downloads as well as uploads.
* A client for a nix binary cache with fetch and upload capability.
* Python representations of some nix objects, such as derivations and
  nix archives, and useful tooling around these.
