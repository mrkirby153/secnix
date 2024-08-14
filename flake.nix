{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
    in rec {
      packages = rec {
        secnix = pkgs.callPackage ./secnix.nix {};
        default = secnix;
      };
      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [packages.default sops];
        shellHook = ''
          export RUST_LOG=debug
          # export RUST_BACKTRACE=1
        '';
      };
      formatter = pkgs.alejandra;
    })
    // {
      homeManagerModule = import ./modules/home.nix;
    };
}
