{
  pkgsPath ? <nixpkgs>,
  pkgs ? import pkgsPath {},
  pythonPackages ? pkgs.python3Packages,
}:

let
  inherit (builtins) replaceStrings readFile;
  version = replaceStrings ["\n"] [""] (readFile ./version.txt);
in

pythonPackages.buildPythonPackage rec {
  name = "pynix-${version}";
  buildInputs = [pythonPackages.ipython];
  propagatedBuildInputs = with pythonPackages; [
    pkgs.coreutils
    pkgs.gzip
    pkgs.nix.out
    pkgs.pv
    pkgs.which
    flask
    requests2
    ipdb
    six
    datadiff
    # pythonPackages.curio
    # curio-http
    rtyaml
  ] ++ (if pythonPackages.isPy3k or false then [] else [
    pythonPackages.futures
  ]);
  src = ./.;
  makeWrapperArgs = [
    "--set NIX_BIN_PATH ${pkgs.lib.makeBinPath [pkgs.nix.out]}"
  ];
}
