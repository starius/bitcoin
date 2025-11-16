{
  description = "Bitcoin Core developer shell";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        nativeDeps = with pkgs; [
          autoconf
          automake
          capnproto
          cmake
          ninja
          libtool
          pkg-config
          python3
          gnumake
          git
        ];
        runtimeDeps = with pkgs; [
          boost
          libevent
          zeromq
          miniupnpc
          sqlite
          openssl
          qrencode
          protobuf
          qt6.qtbase
          qt6.qttools
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = nativeDeps;
          buildInputs = runtimeDeps;
        };
      });
}
