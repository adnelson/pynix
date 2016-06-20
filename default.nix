{
  pkgsPath ? <nixpkgs>,
}:

let
  pkgs = import pkgsPath {};
  inherit (pkgs) nix lib coreutils;
  pythonPackages = pkgs.python3Packages;
  inherit (pythonPackages) buildPythonPackage flask;
in


buildPythonPackage rec {
  name = "servenix";
  version = "0.0.0.dev0";
  buildInputs = [
    pythonPackages.ipython
  ];
  propagatedBuildInputs = [
    nix
    coreutils
    flask
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
    "--set NIX_STORE_PATH ${builtins.storeDir}"
  ];
}
