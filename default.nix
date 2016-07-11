{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {}
}:

let
  # Use .out so we have the binaries callable
  nix = pkgs.nix.out;
  inherit (pkgs) lib coreutils sqlite gzip;
  inherit (builtins) replaceStrings readFile;
  pythonPackages = pkgs.python3Packages;
  version = replaceStrings ["\n"] [""] (readFile ./version.txt);
in

pythonPackages.buildPythonPackage rec {
  name = "servenix-${version}";
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
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
  ];
}
