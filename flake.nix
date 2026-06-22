{
  description = "Trustfall: transparent IoT TLS cert-validation test harness";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      runtimeDeps = pkgs: with pkgs; [ uv python3 iproute2 iptables nftables conntrack-tools tcpdump openssl ];
    in {
      # `sudo nix run .` — just works. The wrapper sets LD_LIBRARY_PATH (for
      # libpcap) inside the program, so sudo stripping it is irrelevant. Run from
      # the repo so uv can find pyproject.toml.
      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${pkgs.writeShellScript "trustfall" ''
            export PATH=${pkgs.lib.makeBinPath (runtimeDeps pkgs)}:$PATH
            export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [ pkgs.libpcap ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
            exec uv run trustfall "$@"
          ''}";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = (runtimeDeps pkgs) ++ [ pkgs.libpcap ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.libpcap ];
          shellHook = ''
            echo "Trustfall Nix shell. Run: sudo -E env PATH=\"\$PATH\" LD_LIBRARY_PATH=\"\$LD_LIBRARY_PATH\" uv run trustfall"
          '';
        };
      });
    };
}
