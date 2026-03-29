{
  description = "argocd-verify-cmp development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zot = pkgs.stdenv.mkDerivation {
          name = "zot";
          src = pkgs.fetchurl {
            url = "https://github.com/project-zot/zot/releases/download/v2.1.15/zot-linux-amd64";
            hash = "sha256-a8CsTdz/c1F0tsc45u6cNXmYwjxVRlC+hhNdI3IN3Yw=";
          };
          unpackPhase = ":";
          installPhase = ''
            mkdir -p $out/bin
            cp $src $out/bin/zot
            chmod +x $out/bin/zot
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Go toolchain
            go
            golangci-lint

            # Integration test tools
            cosign
            oras
            (bats.withLibraries (p: [
              p.bats-support
              p.bats-assert
            ]))
            zot

            # Utilities used in test scripts
            apacheHttpd # provides htpasswd (bcrypt-capable; Zot requires bcrypt)
            jq
          ];

          shellHook = ''
            echo "verify-cmp dev shell ready"
            echo "  go $(go version | awk '{print $3}')"
            echo "  cosign $(cosign version --json 2>/dev/null | jq -r .gitVersion || echo unavailable)"
            echo "  oras $(oras version 2>/dev/null | head -1 || echo unavailable)"
          '';
        };
      }
    );
}
