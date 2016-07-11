# servenix

A small nix HTTP server (binary cache) written in python.

`servenix` aims to reproduce the performance of a traditional
statically-served binary cache with the ease of use of the `nix-serve`
utility, along with a few additional features.

## The Quick and Dirty:

To go from zero to a nix server:

```bash
# Clone the repo
$ git clone https://github.com/adnelson/servenix

# Install servenix
$ nix-env -f servenix -i

# Run servenix (see --help for more options)
$ servenix
```

Now you can use it on another machine:

```bash
$ nix-build my_package --option binary-caches http://my_nix_server:5000
```

## Serving Nix Objects

Nix has a concept of *binary substitution*, where a pre-built package
can be fetched from a remote server rather than being built from
scratch. These objects can be served over HTTP or SSH. See [the nix
manual](http://nixos.org/nix/manual/) for more details.

Serving packages over SSH is the simplest method, requiring for the
server only a machine with nix installed and for the client the
ability to SSH into the server. However, fetching over SSH is slow,
with each fetch requiring a lengthy handshake (often taking longer
than the actual fetch) and all fetches done serially. In addition
using SSH requires maintaining appropriate key management and
permissions on the server's nix directory.  HTTP fetches are much
faster and can also be run concurrently. However, setting up an HTTP
server requires a bit more effort.

## Comparison with Existing Binary Cache Methods

At present, to my knowledge, there are two primary ways of doing this:

1. Create a binary cache with `nix-push`. This command will compress
binaries and dump them along with some metadata files into a directory
which can be served with a fast static assets server like Apache or
nginx. The upside is that binaries can be served reliably and at high
speed, and the size and state of the binary cache can be easily
controlled. However, the downside is that the cache requires more
effort to maintain: prebuilt binaries must be built explicitly, the
static assets server must be set up and configured by the
administrator, and if binaries are built on one machine, they must be
`rsync`'d or otherwise shared with the binary cache.

2. Run a `nix-serve` process on a machine to host binaries that
already exist in its nix store. The advantage here is that it's zero
configuration: simply run `nix-serve` and you have a binary cache up
and running. The primary downside is performance; compressed store
objects are generated on-the-fly, so if the same object is requested
100 times, it will be compressed 100 times. In addition only `bzip2`
compression is supported, since `xz` compression is too
costly. Furthermore, the server is unable to inform the client how
large the compressed file will be, or what its hash is, which makes
fetches less reliable.

The goal of `servenix` is to be a compromise between the two:

* Zero configuration: running `servenix` out of the box "just
  works". Of course, there is some configuration that can be done
  (port, host, compression type, etc), but the default settings should
  work in the majority of cases. No knowledge of how to set up a
  static asset server or use `nix-push` is necessary.

* Compressed binaries are cached on the server. When `servenix`
  receives a request for a package, and the package is on the server,
  it generates that package's compressed serialization via a call to
  `nix-build`, so that it appears in the nix store on the server. When
  a subsequent request comes for the same package, it has already been
  built, so the server can send it very quickly.

## HTTP Uploads

There are a few "extras" to `servenix` which aren't found in either of
the alternatives. Chief among these is the ability to *upload*
packages from a client to the repo over HTTP. Nix itself comes with
the `nix-copy-closure` utility which can copy store objects and their
closures to a remote server over SSH. However, there are the same
problems with speed and user issues that exist in the SSH fetching
model. `servenix` provides a `POST` route that accepts serialized
store objects, letting store objects be sent over HTTP. This allows,
for example, packages to be built on CI slaves (e.g. Jenkins) and
subsequently sent to the repo so as to reduce duplicated work.

`servenix` provides a python library for sending binaries to a running
`servenix` instance, and a `sendnix` command which can be called from
the command line. For example, to upload a single path to a `servenix`
server, you can use

```bash
$ export NIX_REPO_HTTP=https://my.nix.server
$ sendnix send /nix/store/my-store-object /nix/store/my-other-store-object
```

And to upload everything in your nix store to the server:

```bash
$ export NIX_REPO_HTTP=https://my.nix.server
$ sendnix sync
```

## License

MIT

## Contributing

I welcome pull requests and issues, just submit 'em :)
