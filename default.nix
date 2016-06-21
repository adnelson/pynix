{
  pkgsPath ? <nixpkgs>,
}:

let
  pkgs = import pkgsPath {};
  inherit (pkgs) nix lib coreutils sqlite;
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
    sqlite
    coreutils
    flask
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
  ];
}
