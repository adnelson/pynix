{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {},
  pythonPackages ? pkgs.python3Packages,
}:

let
  # Use .out so we have the binaries callable
  inherit (builtins) replaceStrings readFile;
  version = replaceStrings ["\n"] [""] (readFile ./version.txt);
in

pythonPackages.buildPythonPackage rec {
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
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${pkgs.lib.makeBinPath [pkgs.nix.out]}"
  ];
}
