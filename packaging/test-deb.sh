#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

arch=$(dpkg --print-architecture)
version=${VERSION:-0.0.0~dev}
VERSION="$version" DEB_ARCH="$arch" ./build-deb.sh
deb="dist/cv2-fido_${version}_${arch}.deb"
test "$(dpkg-deb -f "$deb" Package)" = cv2-fido
test "$(dpkg-deb -f "$deb" Version)" = "$version"
test "$(dpkg-deb -f "$deb" Architecture)" = "$arch"
test "$(dpkg-deb -f "$deb" Depends)" = 'fprintd, dbus, udev, systemd, libpam-systemd, polkitd, kmod, init-system-helpers (>= 1.52)'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-deb -x "$deb" "$tmp/root"
dpkg-deb -e "$deb" "$tmp/control"

test -x "$tmp/root/usr/bin/cv2-fido"
"$tmp/root/usr/bin/cv2-fido" --help > "$tmp/help"
grep -q doctor "$tmp/help"
go version -m "$tmp/root/usr/bin/cv2-fido" > "$tmp/buildinfo"
grep -q 'CGO_ENABLED=0' "$tmp/buildinfo"
grep -q "GOARCH=$arch" "$tmp/buildinfo"
for license in Go.LICENSE github.com_google_go-tpm.LICENSE; do
    test -f "$tmp/root/usr/share/doc/cv2-fido/licenses/$license"
done
test -f "$tmp/root/usr/share/doc/cv2-fido/copyright"
for doc in README.md LICENSE docs/*.md; do
    test -f "$tmp/root/usr/share/doc/cv2-fido/$doc"
done
test -f "$tmp/root/usr/lib/systemd/system/cv2-fido.service"
test -f "$tmp/root/etc/xdg/autostart/cv2-fido-agent.desktop"
grep -Fxq 'Exec=/usr/bin/cv2-fido agent' "$tmp/root/etc/xdg/autostart/cv2-fido-agent.desktop"
test ! -e "$tmp/root/usr/lib/systemd/user/cv2-fido.service"
test -f "$tmp/root/usr/lib/udev/rules.d/71-cv2-fido-isolation.rules"
test -f "$tmp/root/usr/share/polkit-1/rules.d/49-cv2-fido.rules"
test -f "$tmp/root/usr/lib/sysusers.d/cv2-fido.conf"
grep -qx 'CV2_FIDO_USER=' "$tmp/root/etc/cv2-fido.conf"
grep -qx '/etc/cv2-fido.conf' "$tmp/control/conffiles"
test ! -e "$tmp/root/var/lib/cv2-fido"
test ! -e "$tmp/root/home"

# An unconfigured install must exit with the status excluded from restarts.
status=0
CV2_FIDO_USER= "$tmp/root/usr/bin/cv2-fido" run > "$tmp/unconfigured.log" 2>&1 || status=$?
test "$status" -eq 78
unit="$tmp/root/usr/lib/systemd/system/cv2-fido.service"
grep -Fxq 'RestartPreventExitStatus=78' "$unit"
grep -Fxq 'StartLimitIntervalSec=5min' "$unit"
grep -Fxq 'StartLimitBurst=5' "$unit"
# Verify against the extracted executable; no installed service is required.
mkdir "$tmp/verify"
sed "s@ExecStart=/usr/bin/cv2-fido@ExecStart=$tmp/root/usr/bin/cv2-fido@" \
    "$unit" > "$tmp/verify/cv2-fido.service"
systemd-analyze verify "$tmp/verify/cv2-fido.service"
for setting in 'User=cv2-fido' 'Group=cv2-fido' 'EnvironmentFile=/etc/cv2-fido.conf' 'StateDirectory=cv2-fido' 'StateDirectoryMode=0700' 'DevicePolicy=closed' 'DeviceAllow=/dev/tpmrm0 rw' 'DeviceAllow=/dev/uhid rw' 'ProtectHome=yes' 'ProtectSystem=strict' 'RestrictAddressFamilies=AF_UNIX' 'NoNewPrivileges=yes' 'SystemCallFilter=@system-service' 'SystemCallErrorNumber=EPERM' 'SystemCallArchitectures=native' 'ProtectProc=invisible' 'ProcSubset=pid' 'RestrictRealtime=yes' 'PrivateIPC=yes'; do
    grep -Fxq "$setting" "$unit"
done
grep -Fxq 'ExecStart=/usr/bin/cv2-fido run' "$unit"
grep -Fxq 'RuntimeDirectory=cv2-fido' "$unit"
grep -Fxq 'RuntimeDirectoryMode=0755' "$unit"

rules="$tmp/root/usr/lib/udev/rules.d/71-cv2-fido-isolation.rules"
for device in 'SUBSYSTEM=="misc", KERNEL=="uhid"' 'SUBSYSTEM=="tpmrm", KERNEL=="tpmrm0"' 'SUBSYSTEM=="tpm", KERNEL=="tpm0"'; do
    grep -Fq "$device" "$rules"
done
test "$(grep -c 'TAG-="uaccess"' "$rules")" -eq 3
grep -Fxq 'SUBSYSTEM=="misc", KERNEL=="uhid", TAG-="uaccess", OWNER="root", GROUP="cv2-fido", MODE="0660"' "$rules"
grep -Fxq 'SUBSYSTEM=="tpmrm", KERNEL=="tpmrm0", TAG-="uaccess", OWNER="root", GROUP="cv2-fido", MODE="0660"' "$rules"
grep -Fxq 'SUBSYSTEM=="tpm", KERNEL=="tpm0", TAG-="uaccess", OWNER="root", GROUP="root", MODE="0600"' "$rules"
grep -q 'TAG+="uaccess"' "$tmp/root/usr/lib/udev/rules.d/70-cv2-fido.rules"

policy="$tmp/root/usr/share/polkit-1/rules.d/49-cv2-fido.rules"
grep -q 'net.reactivated.fprint.device.verify' "$policy"
grep -q 'net.reactivated.fprint.device.setusername' "$policy"
grep -q 'net.reactivated.fprint.device.enroll' "$policy"
grep -q 'AUTH_ADMIN' "$policy"
if command -v gjs >/dev/null 2>&1; then
    env -u GI_TYPELIB_PATH -u GIO_EXTRA_MODULES gjs packaging/test-policy.js "$policy"
fi

for hook in postinst postrm prerm; do
    test -x "$tmp/control/$hook"
    sh -n "$tmp/control/$hook"
done

# All hooks run against an extracted root. Stubs detect host-effect commands.
mkdir "$tmp/bin"
export CV2_HOOK_LOG="$tmp/hook.log"
: > "$CV2_HOOK_LOG"
for command in modprobe udevadm systemctl deb-systemd-invoke; do
    cat > "$tmp/bin/$command" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "$CV2_HOOK_LOG"
exit 1
STUB
    chmod 755 "$tmp/bin/$command"
done
export DPKG_ROOT="$tmp/root" DPKG_MAINTSCRIPT_PACKAGE=cv2-fido
mkdir -p "$DPKG_ROOT/etc" "$DPKG_ROOT/var/lib/cv2-fido"
: > "$DPKG_ROOT/etc/passwd"
: > "$DPKG_ROOT/etc/group"
state="$DPKG_ROOT/var/lib/cv2-fido/credentials.json"
printf 'test credential\n' > "$state"
PATH="$tmp/bin:$PATH" "$tmp/control/postinst" configure
grep -q '^cv2-fido:' "$DPKG_ROOT/etc/passwd"
grep -q '^cv2-fido-users:' "$DPKG_ROOT/etc/group"
test "$(cat "$state")" = 'test credential'
test ! -s "$CV2_HOOK_LOG"

# Replace only the runtime-manager probe in temporary hook copies. This lets
# the host branch run without creating /run/systemd/system on the test host.
runtime_dir="$tmp/runtime/systemd/system"
mkdir -p "$runtime_dir"
for hook in postinst postrm; do
    sed "s@/run/systemd/system@$runtime_dir@g" "$tmp/control/$hook" > "$tmp/$hook-host-test"
    chmod 755 "$tmp/$hook-host-test"
done

link="$DPKG_ROOT/etc/systemd/system/multi-user.target.wants/cv2-fido.service"
test -L "$link"
PATH="$tmp/bin:$PATH" "$tmp/control/postinst" configure 0.1.0
test -L "$link"
rm "$link"
PATH="$tmp/bin:$PATH" "$tmp/control/postinst" configure 0.1.0
test ! -L "$link"
ln -s /dev/null "$DPKG_ROOT/etc/systemd/system/cv2-fido.service"
PATH="$tmp/bin:$PATH" "$tmp/control/postinst" configure 0.1.0
test ! -L "$link"
test "$(readlink "$DPKG_ROOT/etc/systemd/system/cv2-fido.service")" = /dev/null
PATH="$tmp/bin:$PATH" "$tmp/control/prerm" remove
PATH="$tmp/bin:$PATH" "$tmp/control/postrm" purge
test "$(cat "$state")" = 'test credential'
grep -q '^cv2-fido:' "$DPKG_ROOT/etc/passwd"
test "$(readlink "$DPKG_ROOT/etc/systemd/system/cv2-fido.service")" = /dev/null
test ! -s "$CV2_HOOK_LOG"
preset_root="$tmp/preset-root"
dpkg-deb -x "$deb" "$preset_root"
mkdir -p "$preset_root/etc/systemd/system-preset"
: > "$preset_root/etc/passwd"
: > "$preset_root/etc/group"
printf 'disable cv2-fido.service\n' > "$preset_root/etc/systemd/system-preset/00-local.preset"
ln -s "$(command -v systemctl)" "$preset_root/usr/bin/systemctl"
DPKG_ROOT="$preset_root" PATH=/usr/bin:/bin "$tmp/control/postinst" configure
test ! -L "$preset_root/etc/systemd/system/multi-user.target.wants/cv2-fido.service"
grep -qx 'CV2_FIDO_USER=' "$DPKG_ROOT/etc/cv2-fido.conf"
test ! -s "$CV2_HOOK_LOG"

# Installed-host branches use Debian's policy-rc.d aware service helper.
for command in systemd-sysusers deb-systemd-helper; do
    cat > "$tmp/bin/$command" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "$CV2_HOOK_LOG"
exit 0
STUB
    chmod 755 "$tmp/bin/$command"
done
: > "$CV2_HOOK_LOG"
env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/postinst-host-test" configure
if grep -q '^deb-systemd-invoke ' "$CV2_HOOK_LOG"; then
    echo 'Fresh installation started an unconfigured service' >&2
    exit 1
fi
: > "$CV2_HOOK_LOG"
env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/postinst-host-test" configure 0.1.0
env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/control/prerm" remove
awk '/^systemctl --system daemon-reload$/ {reload=NR} /^deb-systemd-invoke try-restart cv2-fido.service$/ {if (!reload || reload>=NR) exit 1; found=1} END {if (!found) exit 1}' "$CV2_HOOK_LOG"
grep -q '^deb-systemd-invoke stop cv2-fido.service$' "$CV2_HOOK_LOG"
for action in remove purge; do
    : > "$CV2_HOOK_LOG"
    env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/postrm-host-test" "$action"
    grep -q '^systemctl --system daemon-reload$' "$CV2_HOOK_LOG"
done
rmdir "$runtime_dir"
: > "$CV2_HOOK_LOG"
env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/postinst-host-test" configure 0.1.0
env -u DPKG_ROOT PATH="$tmp/bin:$PATH" "$tmp/postrm-host-test" remove
if grep -q '^systemctl ' "$CV2_HOOK_LOG"; then
    echo 'Hook reloaded a system manager when none was present' >&2
    exit 1
fi
if grep -E '^(udevadm|modprobe) ' "$CV2_HOOK_LOG"; then
    echo 'Lifecycle hook bypassed Debian helpers or changed host devices' >&2
    exit 1
fi

dpkg-deb -c "$deb" > "$tmp/contents"
if grep -v ' root/root ' "$tmp/contents"; then
    echo 'Non-root archive ownership' >&2
    exit 1
fi
if grep -E 'credentials\.json|/lock$|\.so$' "$tmp/contents"; then
    echo 'Unexpected credential or driver' >&2
    exit 1
fi
echo "Package checks passed: $deb"
