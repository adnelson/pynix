{
  pkgsPath ? <nixpkgs>,
}:

let
  pkgs = import pkgsPath {};
  inherit (pkgs) nix lib coreutils sqlite;
  pythonPackages = pkgs.python3Packages;
in

pythonPackages.buildPythonPackage rec {
  name = "servenix-local-dev";
  version = "0.0.0.dev0";
  buildInputs = [
    pythonPackages.ipython
  ];
  propagatedBuildInputs = [
    coreutils
    nix
    pythonPackages.flask
    pythonPackages.six
    sqlite
  ];
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${lib.makeBinPath [nix]}"
  ];
}
