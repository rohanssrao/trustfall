{
  description = "Trustfall: transparent IoT TLS cert-validation test harness";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { system = system; }));
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./package.nix { };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            libpcap
            uv
            python3
            iproute2
            iptables
            nftables
            conntrack-tools
            tcpdump
            openssl
          ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.libpcap ];
          shellHook = ''
            echo "Trustfall Nix shell. Run: sudo -E env PATH=\"\$PATH\" LD_LIBRARY_PATH=\"\$LD_LIBRARY_PATH\" uv run trustfall"
          '';
        };
      });
    };
}
