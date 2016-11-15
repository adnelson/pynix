{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {},
  python3 ? true,
}:

let
  # Use .out so we have the binaries callable
  inherit (builtins) replaceStrings readFile;
  pythonPackages = if python3 then pkgs.python3Packages
                   else pkgs.python2Packages;
  version = replaceStrings ["\n"] [""] (readFile ./version.txt);
in

pythonPackages.buildPythonPackage rec {
  name = "servenix-${version}";
  buildInputs = [
    pythonPackages.ipython
  ];
  propagatedBuildInputs = [
    pkgs.coreutils
    pkgs.gzip
    pkgs.nix.out
    pkgs.pv
    pkgs.which
    pythonPackages.flask
    pythonPackages.ipdb
    pythonPackages.requests2
    pythonPackages.six
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${pkgs.lib.makeBinPath [pkgs.nix.out]}"
  ];
}
