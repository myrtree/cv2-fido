# cv2-fido

Experimental FIDO2 authenticator for Linux: a virtual HID key, TPM 2.0 signing,
and a fresh fingerprint through fprintd for registration and login.

The service is deliberately simple: one executable, an isolated system service,
a desktop notification helper, and a private JSON file. It needs no browser
extension and works with fingerprint readers supported by fprintd.

Built using components from Peter Sanford's tpm-fido, via
[tpm-fido2-thinkpad-linux](https://github.com/mc256/tpm-fido2-thinkpad-linux/tree/49222c60dbbf0c5ec4356240cbd92789e41945da).

## Installation on Debian/Ubuntu

Requires TPM 2.0, a working fingerprint driver, fprintd, and a systemd/logind
X11 or Wayland desktop. One administrator-selected owner is supported per laptop.

The packaged binary reads accounts and groups from `/etc/passwd` and `/etc/group`.
NSS-only identities or memberships (LDAP/SSSD, systemd-homed) are unsupported.
Installation also removes the `tss` group's access to TPM 0: the usual
`tpm2-abrmd` service and direct `tpm2-tools` clients relying on that group cannot
use it. Restoring their device access would weaken the service's isolation.

Run these commands from the owner's ordinary terminal. Download the deb for your
architecture from GitHub Releases and substitute its filename below.

1. Install the package and dependencies:

   ```sh
   sudo apt install ./cv2-fido_VERSION_ARCH.deb
   ```

2. Enroll and verify your fingerprint. Skip enrollment if already done:

   ```sh
   fprintd-enroll
   fprintd-verify
   ```

3. Authorize the owner and edit the configuration:

   ```sh
   sudo adduser "$(id -un)" cv2-fido-users
   sudoedit /etc/cv2-fido.conf
   ```

   Set your login name, for example:

   ```ini
   CV2_FIDO_USER=alice
   ```

   Do not join the private `cv2-fido` group. `cv2-fido-users` grants no device
   access; it requires administrator authorization for fingerprint enrollment
   and deletion. The service itself can only verify fingerprints.

4. Reboot to apply membership, load UHID and establish device permissions.
   The service is enabled unless administrator policy has disabled or masked it.
   After logging into your graphical desktop, check:

   ```sh
   sudo systemctl start cv2-fido.service
   sudo -u cv2-fido /usr/bin/cv2-fido doctor -user "$(id -un)"
   systemctl status cv2-fido.service
   sudo journalctl -u cv2-fido.service -b -n 50
   ```

   The service creates its own state directory, initially with zero credentials.
   `doctor` checks prerequisites, not signing or the systemd sandbox; a real
   browser login is still needed.

5. Open your site's security settings and try adding a security key. Registration
   has been tested in Chrome. Register separately for each authentication domain
   and keep an independent recovery authenticator.

## Service management

Follow logs with `sudo journalctl -u cv2-fido.service -f`.
Explicit configuration errors stop the service without automatic restart.
Other failures are limited to five starts per five minutes. After fixing the
cause, run:

```sh
sudo systemctl reset-failed cv2-fido.service
sudo systemctl start cv2-fido.service
```

Owner configuration and membership are read at startup. To revoke access, stop
`cv2-fido.service`, remove the owner from `cv2-fido-users`, clear or replace
`CV2_FIDO_USER` in `/etc/cv2-fido.conf`, then start the service. A blank owner
prevents operation. After changing owners, log out and back in as the new owner
to start their notification helper.

Disable autostart with `sudo systemctl disable --now cv2-fido.service`; use
`sudo systemctl mask --now cv2-fido.service` to forbid manual starts too.
Removal/purge preserve credentials and the service identity.

## Browser use and diagnostics

Registration has been tested in Chrome and login in Chrome and Firefox.
Test a wrong finger and cancellation as well as successful login. Native distro
browsers are the initial target; Snap/Flatpak may restrict HID discovery.
The package does not install browser-sandbox exceptions or impersonate a YubiKey.

A desktop notification names the site and action before scanning; no extra click
is required. Touch the reader only for an operation you started. Dismissing the
notification does not cancel scanning; cancel in the browser.

The service uses your existing fprintd enrollment and requires an active, local,
unlocked graphical session. Each actual login requires a fresh fingerprint.
Silent browser preflight is a limited exception described in [DESIGN.md](docs/DESIGN.md).
Reader contention, mismatch, cancellation or timeout fails the request.

If the desktop helper or notification daemon is unavailable, scanning is denied.
Failed attempts impose a cooldown of up to 30 seconds; rapid requests are also
limited. Wait before retrying. Limits and notification behavior are described in
[REQUEST-GUARD.md](docs/REQUEST-GUARD.md).

For request metadata, run `sudo systemctl edit cv2-fido.service` and add:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/cv2-fido run -debug
```

Restart the service and view its journal. Remove these override lines and restart
when done. Debug logs contain RP IDs, statuses and verification/cancellation events,
but no credential IDs, keys, user handles, challenges or signatures.
`0x00` means the service succeeded, not that the site accepted the response;
`0x27` includes biometric/session denial, `0x2e` means no credential,
`0x2d` cancellation and `0x2f` timeout.

## Storage and limits

State is stored in `/var/lib/cv2-fido`, owned by the service, with directory mode
0700 and file mode 0600. It contains RP IDs, credential IDs, user handles and
TPM-wrapped keys, never plaintext signing keys or fingerprint templates.
Clearing the TPM or losing this state invalidates registrations. Copying it to
another laptop does not migrate keys. Protect backups like the live store.

At most 64 credentials and one discoverable credential per RP are supported.
A second discoverable registration for that RP is rejected, even for the same
account. Non-discoverable credentials can coexist. There is no deletion UI.
Cancellation after a registration has been saved can leave an unused credential;
a discoverable one occupies that RP's slot.

Implemented: CTAP 2.0 GetInfo, MakeCredential and GetAssertion, ES256 and packed
self attestation. No PIN, PRF/hmac-secret, credential management, GetNextAssertion,
sync, enterprise attestation or legacy U2F. The signature counter is zero.
This is an experimental, uncertified implementation with limited protocol support;
providers requiring trusted attestation or an approved model may reject it.

## Security boundary

The OS isolates credentials and direct TPM/UHID access from desktop users; only
the virtual FIDO hidraw device is accessible to the active desktop. TPM protects
key extraction; the service enforces biometric authorization. Root, the kernel,
logind, fprintd, the driver, administrator configuration and the service are trusted.
This is not the security boundary of an independent hardware authenticator.

Desktop malware can initiate misleading requests, spoof notifications, steal
browser sessions or deny service. A displayed RP ID is not proof of the requesting
application's identity. Notification delivery does not guarantee visibility
(e.g. Do Not Disturb), and logind's lock hint can be changed by the desktop user.
Neither is a trusted confirmation or screen-lock boundary.

A TPM operation exceeding 60 seconds terminates the service, subject to the restart
policy above. A kernel or hardware hang may still require a reboot.

## Development and documentation

Use `nix develop`, or install Go 1.24+ and make.
`run`/`doctor` accept `-user`, `-state`, `-tpm` and `-debug`; custom device paths
require matching device rules and system-unit permissions. Use separate state
directories for experiments, not edits to the live store.

- [DESIGN.md](docs/DESIGN.md): architecture, protocol and authorization.
- [DEB.md](docs/DEB.md): package layout and lifecycle.
- [DEVELOPMENT.md](docs/DEVELOPMENT.md): build, test and release commands.
- [TESTING.md](docs/TESTING.md): test coverage and limitations.
- [REQUEST-GUARD.md](docs/REQUEST-GUARD.md): notifications and request limits.
- [PLAN.md](docs/PLAN.md): fuzzy extractor research.
