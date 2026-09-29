# cv2-fido

Experimental FIDO2 authenticator for Linux: a virtual HID key, TPM 2.0 signing,
and a fresh fingerprint through fprintd for registration and login.

The service is deliberately simple: one executable, an isolated system service,
a desktop notification helper, and a private JSON file. No browser extension,
network service, PIN fallback or software-key fallback. Works with fingerprint
readers supported by fprintd.

Built using components from Peter Sanford's tpm-fido, via
[tpm-fido2-thinkpad-linux](https://github.com/mc256/tpm-fido2-thinkpad-linux/tree/49222c60dbbf0c5ec4356240cbd92789e41945da).
The TPM backend remains derived code, and the HID descriptor/framing also have
upstream ancestry. See [UPSTREAM.md](docs/UPSTREAM.md) for the component-level account
and retained license notices.

## Installation on Debian/Ubuntu

Requires TPM 2.0, a working fingerprint driver supported by fprintd, and a
systemd/logind desktop running X11 or Wayland. The driver is installed separately.
One administrator-selected desktop owner is supported per laptop.

Run these commands from the owner's ordinary terminal, using sudo where shown.
Download the deb for your architecture from GitHub Releases and run the installation
command in its download directory, substituting the downloaded filename.

1. Install the package and its dependencies:

   ```sh
   sudo apt install ./cv2-fido_VERSION_ARCH.deb
   ```

   It installs the binary, system service, device/polkit rules and service
   account. There is no need to copy udev rules or systemd units manually.

2. Enroll and verify a fingerprint under your desktop account:

   ```sh
   fprintd-enroll
   fprintd-verify
   ```

   If your fingerprint is already enrolled, run only `fprintd-verify`.

3. Authorize the owner and edit the service configuration:

   ```sh
   sudo adduser "$(id -un)" cv2-fido-users
   sudoedit /etc/cv2-fido.conf
   ```

   Set your actual login name (the output of `id -un`), for example:

   ```ini
   CV2_FIDO_USER=alice
   ```

   Do not add your desktop user to the private `cv2-fido` service group.
   `cv2-fido-users` marks owners whose fingerprint enrollment/deletion requires
   fresh administrator authorization; it does not grant device access.

4. Reboot to apply group membership, load UHID and establish device permissions.
   The system service is enabled by default unless administrator policy has
   disabled or masked it. After logging into your graphical desktop, check:

   ```sh
   sudo systemctl start cv2-fido.service
   sudo -u cv2-fido /usr/bin/cv2-fido doctor -user "$(id -un)"
   systemctl status cv2-fido.service
   sudo journalctl -u cv2-fido.service -b -n 50
   ```

   A fresh installation starts with zero credentials. The service creates its
   private state directory; no files need to be copied or created manually.

5. Open the security settings of your chosen site and try adding a security key.
   Registration has been tested in Chrome. Register separately for each site or
   authentication domain, and keep an independent recovery authenticator.

Follow live logs with `sudo journalctl -u cv2-fido.service -f`.
A blank owner in `/etc/cv2-fido.conf` prevents operation. The service can verify
fingerprints but cannot enroll/delete them. Other users' normal fprintd policy is
unchanged; administrator policy overrides remain trusted configuration.

`doctor` checks isolation of device permissions, opening TPM/UHID, enrolled fingers
for the configured owner, and an active local unlocked graphical session. It
neither signs nor asks for a scan. Passing it is not a browser compatibility test.
The command above runs with the service UID but does not test systemd sandboxing;
the service journal and real browser acceptance are required too.

The service listens across login/logout but rejects credential operations when
the owner has no active local unlocked X11/Wayland session. Screen lock detection
uses logind's `LockedHint`, which depends on the desktop and can be falsified by
processes of that user. It is a cooperative check, not a malware-resistant lock
boundary, trusted display or proof of which application requested an operation.

Disable autostart with `sudo systemctl disable --now cv2-fido.service`; use
`sudo systemctl mask --now cv2-fido.service` to forbid manual starts as well.
Removal/purge preserve credentials and the service identity. Package lifecycle
and checks are described in [DEB.md](docs/DEB.md).

## Browser use and diagnostics

Registration has been tested in Chrome and login in Chrome and Firefox.
Other hardware/browser combinations need testing. Test a wrong finger and
cancellation as well as successful login.

Each site or authentication domain needs its own registration. Requests log the RP ID and ask
for the enrolled finger. A desktop notification names the requested site and
action before scanning starts; there is no extra confirmation click. The service uses the existing
fprintd enrollment of the configured owner, not a separate service-account print.

Browser preflight with explicit `up=false`, no UV requirement and a nonempty
allowList can sign with UP=0/UV=0 without a scan. This response cannot serve as a
valid WebAuthn login. It exposes credential presence to a client knowing the RP
and credential ID, returns no user handle, and never authorizes a later request.
Preflight also requires the owner's active session. Every actual login requires
a fresh fingerprint; nothing is cached. Reader contention, mismatch, cancellation
or timeout fails the request. Retry after other fingerprint clients release it.

For request metadata, configure a system-unit override:

```sh
sudo systemctl edit cv2-fido.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/cv2-fido run -debug
```

Then `sudo systemctl restart cv2-fido.service` and view its journal. Remove those
override lines and restart after diagnosis. Debug logs include RP IDs, CTAP/HID
statuses, UP/UV flags, verification and cancellation, but no credential IDs, keys,
user handles, challenges or signatures. A successful `status=0x00` is not proof
the site accepted the response. `0x27` includes biometric/session denial, `0x2e`
means no credential, `0x2d` cancellation and `0x2f` timeout.

Native distro/deb browsers are the initial target. Snap/Flatpak may restrict HID
discovery independently of our permissions. The device has unassigned IDs; this
package does not impersonate a YubiKey or install browser-sandbox exceptions.

## Request notifications and throttling

The package autostarts `cv2-fido agent` at graphical login. It runs as your desktop
user, connects to your notification daemon and receives only the requested RP ID
and action through `/run/cv2-fido/notify.sock`. The isolated service keeps exclusive
access to keys, credentials and TPM. No new GUI toolkit is required.

A notification says, for example, `Sign-in: login.example.com`. This is the
RP ID supplied by the client, not proof that Firefox or Chrome sent the request.
Touch the reader only for an operation you started. Domains are displayed in
ASCII/punycode; markup and control characters are rejected. Closing a notification
is not cancellation; cancel in the browser. The helper requests removal of the
notification when scanning finishes or the request is cancelled.

If the helper or notification daemon is unavailable, the service refuses to scan.
A daemon accepting a notification does not prove it was visible: Do Not Disturb
and desktop settings can hide it. Ordinary desktop malware can spoof notifications
or the helper, so this is a user-awareness aid, not a trusted confirmation UI.
The existing `doctor` checks do not test desktop notification delivery.

The service allows a burst of 3 scan attempts and replenishes one every 10 seconds.
Failures/cancellations impose a 2, 4, 8, 16, then 30-second cooldown. Rejected attempts
do not extend it. Success resets the failure delay but not the scan budget.
Silent browser preflight uses no notification or scan budget. All commands except
GetInfo share a separate burst of 20 requests, replenished at 10 requests/second.
Limits apply across sites/channels and reset when the system service restarts.
A throttled request fails promptly; wait before retrying in the browser.
See [REQUEST-GUARD.md](docs/REQUEST-GUARD.md) for architecture and tests.

## State and security boundary

State lives in `/var/lib/cv2-fido`, mode 0700, owned by the service. Files use 0600.
The JSON contains RP IDs, opaque credential IDs, user handles and TPM-wrapped key
material, never plaintext signing keys or fingerprint templates. Clearing the TPM or losing the file
invalidates registrations; copying it to another laptop does not migrate keys.

The OS separates the service and its data from desktop processes. Ordinary users
must not have direct access to `/dev/uhid`, `/dev/tpmrm0` or `/dev/tpm0`. Only the
resulting virtual FIDO hidraw device remains accessible to the active desktop
through uaccess. Startup rejects extended device ACLs or unsafe ownership/modes.

TPM protects extraction, while the service enforces biometric authorization.
Root, the kernel, logind, fprintd, the driver, package configuration and this
service remain trusted. A compromised trusted component can bypass authorization.
This is not the security boundary of an independent YubiKey Bio. Desktop malware
can still initiate requests, mislead the user into touching the reader, steal
browser sessions, or deny service. Session checks do not authenticate the browser
or provide an unspoofable prompt. Protect backups with the same care as the live
store; moving a file cannot revoke copies that have already been stolen.

## Development

Requires Go 1.24+ and make. See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for
Makefile targets, tooling and package builds.

`run`/`doctor` accept `-user`, `-state`, `-tpm`, and `-debug`. Custom device paths
require matching administrator device rules and system-unit permissions.

## Protocol scope

Implemented: CTAP 2.0 GetInfo, MakeCredential, GetAssertion; ES256; packed self
attestation; CTAPHID INIT/PING/CBOR/CANCEL/KEEPALIVE. At most 64 credentials,
with one discoverable credential per RP. A second discoverable registration for
that RP returns KEY_STORE_FULL, even for the same account. Non-discoverable keys
can coexist and are selected through the browser's allowList. There is no
credential deletion UI yet; test new registrations with separate `-state`
directories rather than editing a live store. A cancelled registration or session change after a durable commit may leave an
unused credential; a resident one occupies that RP's slot. The precommit session
check narrows this window but cannot make disk commit and browser delivery atomic.

No PIN, PRF/hmac-secret, credential management, GetNextAssertion, sync, enterprise
attestation or legacy U2F. Signature counter is always zero (unsupported).
This is a limited prototype, not a certified or fully conformant FIDO product.
An identity provider may reject it if your organization requires trusted attestation or an
approved authenticator model.

## Documentation

- [DESIGN.md](docs/DESIGN.md): architecture and security boundary.
- [DEB.md](docs/DEB.md): package layout and lifecycle.
- [DEVELOPMENT.md](docs/DEVELOPMENT.md): build and test commands.
- [REQUEST-GUARD.md](docs/REQUEST-GUARD.md): notifications and request limits.
- [UPSTREAM.md](docs/UPSTREAM.md): code provenance and licenses.
- [PLAN.md](docs/PLAN.md): fuzzy extractor research.
