{
  description = "cv2-fido development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          # Nix's daemon defaults to /etc; use its packaged session configuration.
          dbus = pkgs.writeShellScriptBin "dbus-daemon" ''
            args=()
            for arg in "$@"; do
              if [ "$arg" = --session ]; then
                arg="--config-file=${pkgs.dbus}/share/dbus-1/session.conf"
              fi
              args+=("$arg")
            done
            exec ${pkgs.dbus}/bin/dbus-daemon "''${args[@]}"
          '';
        in {
          default = pkgs.mkShell {
            packages = [ dbus ] ++ (with pkgs; [
              go gopls golangci-lint govulncheck
              gnumake gcc pkg-config
              swtpm dpkg
              shellcheck actionlint
            ]);
          };
        });
    };
}
