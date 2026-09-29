# Debian package

For installation, see [README.md](../README.md#installation-on-debianubuntu).
The package supports amd64 and arm64.

| Path | Purpose |
| --- | --- |
| `/usr/bin/cv2-fido` | Service and desktop helper executable |
| `/etc/cv2-fido.conf` | Administrator-selected `CV2_FIDO_USER` |
| `/usr/lib/systemd/system/cv2-fido.service` | Isolated system service |
| `/etc/xdg/autostart/cv2-fido-agent.desktop` | Notification helper at graphical login |
| `/var/lib/cv2-fido` | Credentials; service-owned, mode 0700 |
| `/run/cv2-fido/notify.sock` | Notification bridge; kernel peer UID checks |
| `/usr/share/doc/cv2-fido` | Documentation and licenses |

The package creates the `cv2-fido` service account and `cv2-fido-users` owner
group, installs udev/polkit rules and configures UHID loading. An administrator
must select the owner before starting the service.

TPM resource-manager and UHID devices are `root:cv2-fido` mode 0660; raw TPM is
root-only. Desktop access applies only to the virtual FIDO hidraw device.
Polkit permits fingerprint verification by the service, denies its enrollment,
and requires fresh administrator authorization for fingerprint changes by owners.

The system unit has no capabilities, hidden homes, a read-only system tree,
Unix-only sockets and a device allowlist. The desktop helper receives only the
requested site and action; it cannot read credentials or access the TPM.

Enablement follows systemd preset policy. Removal stops the service; purge keeps
the service identity and credentials. Package scripts do not launch desktop
processes. `make test-deb` checks package contents and lifecycle in a disposable
root without modifying host accounts, devices or services.
