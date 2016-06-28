{
  pkgsPath ? <nixpkgs>,
  pkgs ? (import <nsnix> {}).external.pkgs
}:

let
  nix = (import <nsnix> {}).external.pkgs.nix.out;
  inherit (pkgs) lib coreutils sqlite;
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
    nix
    pythonPackages.ipdb
    pythonPackages.flask
    pythonPackages.six
    sqlite
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
  ];
}
