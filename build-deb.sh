#!/bin/sh
set -eu
umask 022

cd "$(dirname "$0")"
version=${VERSION:-0.0.0~dev}
arch=${DEB_ARCH:-$(dpkg --print-architecture)}
dpkg --validate-version "$version"
case "$arch" in
    amd64) goarch=amd64 ;;
    arm64) goarch=arm64 ;;
    *) echo "Unsupported package architecture: $arch (use amd64 or arm64)" >&2; exit 1 ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
chmod 755 "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" dist
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build \
    -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w' \
    -o "$stage/usr/bin/cv2-fido" ./cmd/cv2-fido

install -Dm644 packaging/70-cv2-fido.rules "$stage/usr/lib/udev/rules.d/70-cv2-fido.rules"
install -Dm644 packaging/71-cv2-fido-isolation.rules "$stage/usr/lib/udev/rules.d/71-cv2-fido-isolation.rules"
install -Dm644 packaging/cv2-fido.service "$stage/usr/lib/systemd/system/cv2-fido.service"
install -Dm644 packaging/cv2-fido-agent.desktop "$stage/etc/xdg/autostart/cv2-fido-agent.desktop"
install -Dm644 packaging/cv2-fido.conf "$stage/etc/cv2-fido.conf"
install -Dm644 packaging/cv2-fido.sysusers "$stage/usr/lib/sysusers.d/cv2-fido.conf"
install -Dm644 packaging/49-cv2-fido.rules "$stage/usr/share/polkit-1/rules.d/49-cv2-fido.rules"
install -Dm644 packaging/uhid.conf "$stage/usr/lib/modules-load.d/cv2-fido.conf"
install -Dm644 README.md "$stage/usr/share/doc/cv2-fido/README.md"
for doc in docs/*.md; do
    install -Dm644 "$doc" "$stage/usr/share/doc/cv2-fido/$doc"
done
install -Dm644 LICENSE "$stage/usr/share/doc/cv2-fido/LICENSE"
install -Dm644 LICENSE "$stage/usr/share/doc/cv2-fido/copyright"
install -m755 packaging/postinst packaging/postrm "$stage/DEBIAN/"
install -m755 packaging/prerm "$stage/DEBIAN/prerm"
printf '/etc/cv2-fido.conf\n' > "$stage/DEBIAN/conffiles"

# Static binaries distribute Go and dependency code along with this project.
licenses="$stage/usr/share/doc/cv2-fido/licenses"
mkdir -p "$licenses"
golicense="$(go env GOROOT)/LICENSE"
if [ ! -f "$golicense" ]; then golicense=packaging/Go.LICENSE; fi
install -m644 "$golicense" "$licenses/Go.LICENSE"
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' ./cmd/cv2-fido > "$stage/modules.unsorted"
sort -u "$stage/modules.unsorted" > "$stage/modules"
while IFS= read -r module; do
    test -n "$module" || continue
    directory=$(go list -m -f '{{.Dir}}' "$module")
    name=$(printf '%s' "$module" | tr / _)
    # Every currently pinned dependency provides LICENSE at its module root.
    install -m644 "$directory/LICENSE" "$licenses/$name.LICENSE"
done < "$stage/modules"
rm "$stage/modules" "$stage/modules.unsorted"

size=$(du -sk "$stage/usr" | cut -f1)
cat > "$stage/DEBIAN/control" <<EOF
Package: cv2-fido
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Maintainer: cv2-fido contributors <cv2-fido@localhost>
Depends: fprintd, dbus, udev, systemd, libpam-systemd, polkitd, kmod, init-system-helpers (>= 1.52)
Installed-Size: $size
Description: Experimental fingerprint and TPM FIDO2 authenticator
 Exposes a virtual security key to browsers through Linux UHID, verifies the
 configured owner's fingerprint with fprintd, and signs using TPM 2.0.
 Requires a working fingerprint driver and TPM; neither is included.
EOF

output="dist/cv2-fido_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$stage" "$output"
printf 'Built %s\n' "$output"
