# pynix

**NOTE:** This project used to be called `servenix` and consisted
  solely of the server and client. As the functionality has been
  expanded, it's developing into more of a general tool, and hence the
  name and structure change.

This is a suite of tools for interacting with nix. In some cases it
provides alternatives to the existing set of tools, and in other cases
it adds new functionality. The tools provided include:

* Python representations of some nix objects, such as derivations and
  nix archives, and useful tooling around these such as diffs and
  pretty-printing.
* A zero-configuration nix binary cache server, supporting:
  * Prebuilt binary hosting. Adheres to the nixos cache API so that
    the server can serve packages to a standard nix-build process.
  * Binary package uploads. Clients can upload packages they've built
    to the server, so that the server can be continuously updated and
    used with any arbitrary CI system.
  * Fast, server-side computation of download order. This enables a
    far faster response rate when downloading a large set of packages.
  * Batch fetching, which minimizes the number of HTTP requests and
    can speed up fetches.
* A client for the above server, which can provide a lot of the
  functionality of standard nix tooling at a big speedup.
  * In addition, the client enables use of HTTPS for secure
    communication with the cache server.
