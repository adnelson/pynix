# servenix

A small nix server written in python.

The server can serve either `xz` or `bz2`-compressed store
objects. Compressed objects are put in the nix store so that repeated
fetches are fast.

## Installation

```bash
$ nix-env -f . -i
```

## Usage

```bash
$ servenix [--port PORT] [--compression-type (xz|bzip2)]
```