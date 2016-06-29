{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {}
}:

let
  # Use .out so we have the binaries callable
  nix = pkgs.nix.out;
  inherit (pkgs) lib coreutils sqlite gzip;
  pythonPackages = pkgs.python3Packages;
in

pythonPackages.buildPythonPackage rec {
  name = "servenix-local";
  version = "0.0.0.dev0";
  buildInputs = [
    pythonPackages.ipython
  ];
  propagatedBuildInputs = [
    coreutils
    gzip
    nix
    pythonPackages.flask
    pythonPackages.ipdb
    pythonPackages.requests2
    pythonPackages.six
    sqlite
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
  ];
}
