{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: 
    let
      pkgs = import nixpkgs { inherit system; };
    in
    rec {
      packages = {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "secnix";
          version = "0.1.0";
          src = ./.;
          cargoHash = "sha256-+623hYkgAjraYJUoIynrB3e14l00W22n0XYblHW1mfY=";
          meta = {
            description = "A sops secret manager for nix";
            license = pkgs.lib.licenses.mit;
            maintainers = [];
          };
        };
      };
      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [ packages.default sops];
        shellHook = ''
          export RUST_LOG=debug
          # export RUST_BACKTRACE=1
        '';
      };
    });
}
