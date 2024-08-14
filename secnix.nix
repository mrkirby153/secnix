{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "secnix";
  version = "0.1.0";
  src = ./.;
  cargoHash = "sha256-bm6/IF8nL4C3oQT6pV3zLZWnEBr7wAaRQJYodneL3fM=";
  meta = {
    description = "A sops secret manager for nix";
    license = lib.licenses.mit;
    maintainers = [];
  };
}
