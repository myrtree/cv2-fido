# Debian package

Installation, compatibility restrictions and recovery commands are in
[README.md](../README.md#installation-on-debianubuntu). Packages support amd64
and arm64 and are built with `CGO_ENABLED=0`, so account lookup does not use NSS.

| Path | Purpose |
| --- | --- |
| `/usr/bin/cv2-fido` | Service and desktop helper |
| `/etc/cv2-fido.conf` | Administrator-selected `CV2_FIDO_USER` |
| `/usr/lib/systemd/system/cv2-fido.service` | Isolated system service |
| `/etc/xdg/autostart/cv2-fido-agent.desktop` | Helper at graphical login |
| `/var/lib/cv2-fido` | Credentials |
| `/run/cv2-fido/notify.sock` | UID-checked notification bridge |
| `/usr/share/doc/cv2-fido` | Documentation and licenses |

The package creates the service account and owner group, installs udev/polkit
rules and configures UHID loading. First installation follows systemd preset
policy but does not start the service; an upgrade restarts it only if running.
Maintainer scripts do not start desktop processes. Removal stops the service;
purge preserves its identity and credentials.

The unit restricts capabilities, devices, filesystems, network families, procfs,
realtime scheduling and IPC. Native syscalls in `@system-service` are allowed;
others fail with EPERM. Unix sockets remain available for D-Bus and the helper.
Explicit configuration errors exit with 78, excluded from automatic restart.

There is no package conflict with `tpm2-abrmd`: an installed broker may be disabled
or use another TPM or simulator. Access to TPM 0 remains restricted as documented
in the installation requirements.

`make test-deb` verifies the package and unit in a disposable root without changing
host accounts or services. This does not test hardware operation under the sandbox.
