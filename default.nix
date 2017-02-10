{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {},
  pythonPackages ? pkgs.python3Packages,
  passthru ? {},
}:

let
  # Use .out so we have the binaries callable
  inherit (builtins) replaceStrings readFile;
  version = replaceStrings ["\n"] [""] (readFile ./version.txt);
  # Script to write all of the pythonpaths of this package to a file.
  writePaths = pkgs.writeScript "write-servenix-pythonpaths" ''
    #!${pythonPackages.python.interpreter}
    import os, site, sys, json
    # Invoke addsitedir on each path in sys.path.
    for path in [p for p in sys.path if os.path.exists(p)]:
        site.addsitedir(path)
    # Write paths to $out/pythonpaths.
    nix_store = os.environ["NIX_STORE"]
    with open(os.path.join(os.environ["out"], "pythonpaths.ini"), "w") as f:
        f.write("[uwsgi]\n")
        f.write("\n".join("pythonpath = " + p for p in sys.path
                          if p.startswith(nix_store + "/")))
  '';
in

pythonPackages.buildPythonPackage {
  name = "servenix-${version}";
  buildInputs = [pythonPackages.ipython];
  propagatedBuildInputs = [
    pkgs.coreutils
    pkgs.gzip
    pkgs.nix.out
    pkgs.pv
    pkgs.which
    pythonPackages.flask
    pythonPackages.requests2
    pythonPackages.ipdb
    pythonPackages.six
  ];
  src = ./.;
  postInstall = writePaths;
  passthru = {inherit pythonPackages;} // passthru;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${pkgs.lib.makeBinPath [pkgs.nix.out]}"
  ];
}
