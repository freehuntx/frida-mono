{
  description = "frida-mono development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs [ "x86_64-linux" ] (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (
        pkgs:
        let
          # Frida client and server/gadget must match. Keep in sync with "frida" in package.json and with the
          # frida-server / frida-gadget you inject. Hash: `nix hash convert --to sri <sha256 of the PyPI wheel>`.
          fridaVersion = "17.23.3";
          fridaWheelHash = "sha256-6e1VVdFfpajcFon7ghb+x63hpA/3vV1YOMJqPvCX7Ec=";

          python = pkgs.python3.override {
            self = python;
            packageOverrides = _: prev: {
              frida-python = prev.frida-python.overridePythonAttrs {
                version = fridaVersion;
                src = prev.fetchPypi {
                  pname = "frida";
                  version = fridaVersion;
                  format = "wheel";
                  abi = "abi3";
                  python = "cp37";
                  dist = "cp37";
                  platform = "manylinux1_x86_64";
                  hash = fridaWheelHash;
                };
              };
            };
          };

          frida-tools = pkgs.frida-tools.override { python3Packages = python.pkgs; };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nodejs_24
              frida-tools
            ];
          };
        }
      );
    };
}
