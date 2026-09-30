# Development

Run commands from the project directory. With Nix (flakes enabled), no separate
Go installation is needed:

```sh
nix develop
make test
```

The shell provides Go, gopls, linters, swtpm, D-Bus and deb build tools on Linux
amd64/arm64. `flake.lock` pins the tools; update them with `nix flake update`.
Alternatively, install Go 1.24+, make and the tools listed below.

`make test-deb` additionally requires a Debian/Ubuntu host with systemd,
`init-system-helpers` and GJS; the Nix shell does not emulate a Debian installation.

| Command | Purpose / additional requirements |
| --- | --- |
| `make` | Build `./cv2-fido` |
| `make test` | Unit tests with the race detector |
| `make check` | `go vet` |
| `make lint` | golangci-lint v2 checks and formatting verification |
| `make test-integration` | TPM emulator and private D-Bus tests; needs `swtpm` and `dbus-daemon` |
| `make fuzz` | Four fuzz targets; `FUZZTIME=5m FUZZWORKERS=2` overrides defaults |
| `make vulncheck` | govulncheck; needs access to the Go vulnerability database |
| `make deb VERSION=…` | Build a deb in `dist/`; needs `dpkg-deb`, supports `DEB_ARCH=amd64` or `arm64` |
| `make test-deb` | Package contents and lifecycle checks |
| `make install` | Copy the binary to `PREFIX/bin` (default `~/.local/bin`) |
| `make clean` | Remove the local binary |

Install golangci-lint v2 built with at least the project's Go version. The enabled
linters are listed in `.golangci.yml`. Install govulncheck with
`go install golang.org/x/vuln/cmd/govulncheck@latest` and put the Go bin directory
on PATH, or set `GOVULNCHECK` to its path.

A binary-only install does not configure the service, accounts or permissions;
use the deb for operation. Cross-compilation does not establish hardware support.

Integration tests use temporary swtpm state and private D-Bus instances, never
host TPM/fprintd/logind or real credentials. Missing test tools fail the suite.
See [TESTING.md](TESTING.md) for test scope.

## GitHub releases

Pushes and pull requests run unit, integration and package tests on native amd64 and arm64 runners, then
save deb files as workflow artifacts.

Push a tag in the form `vMAJOR.MINOR.PATCH` to publish a release. The tag supplies
the Debian package version. After both builds pass, CI creates a draft, attaches
the two deb files and `SHA256SUMS`, then publishes it. A failed upload can be
retried while the release is a draft; published releases are not overwritten.
The workflow uses the built-in `GITHUB_TOKEN`; no personal token is required.

Local builds default to `0.0.0~dev`; use `make deb VERSION=…` to override it.
