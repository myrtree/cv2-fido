# Current architecture

Usage is in [README.md](../README.md); code ancestry is in [UPSTREAM.md](UPSTREAM.md).

## Scope and execution

The project is one Go module with these package boundaries:

```text
cmd/cv2-fido/            CLI, process lifecycle, startup identity/device checks
internal/authenticator/  CTAP authorization, credentials and private storage
internal/hid/            HID framing and Linux UHID transport
internal/fingerprint/    fprintd verification and enrollment checks
internal/session/        logind session checks
internal/notification/   UID-checked Unix-socket bridge and desktop notifications
internal/tpm/            TPM key creation and signing
docs/                    design, provenance and research notes
packaging/               Debian hooks, systemd, udev and polkit configuration
```

The CLI connects the packages. Authenticator accepts a signer interface and
notification/verification/session callbacks; it does not import the platform implementations.
HID accepts a command-handler callback and does not import the authenticator.
Storage stays private to the authenticator. Tests live beside their packages;
there is no separate module or public library API for these components.

A small Linux Go program exposes a virtual FIDO2 key through UHID. One foreground
process runs as the dedicated `cv2-fido` account; a separate invocation of the
same binary (`agent`) runs in the desktop session and displays notifications. The deb enables a system
service with a root-owned configuration selecting one desktop owner; no owner is
selected automatically. State is private to the service in `/var/lib/cv2-fido`.
The owner must be in `cv2-fido-users`, which protects fingerprint enrollment,
and must not be in the private device-access group `cv2-fido`.
There is no tray, browser extension, network service, PIN fallback or software
signing-key fallback. Dependencies supply CBOR, D-Bus, TPM and Go system helpers.
The fingerprint driver is separate and accessed through fprintd.

`cmd/cv2-fido/main.go` handles signals and exit status; `cmd/cv2-fido/cli.go`
wires the CLI; `cmd/cv2-fido/access.go` checks service identity and device
isolation. `internal/session` checks logind. `internal/hid/uhid_linux.go`
implements the Linux device ABI; `internal/hid/hid.go` owns framing and transport
state in one event loop. One worker processes
a CTAP command at a time, with cancellation and a 30-second context deadline.
Fingerprint waits are cancellable; synchronous TPM calls do not themselves take
that context. A cancelled worker cannot publish a successful HID response.
Resynchronization waits for the current worker to release ownership.

## Authorization and protocol

`internal/authenticator/ctap.go` implements CTAP 2.0 GetInfo, MakeCredential and GetAssertion using ES256.
Registration uses packed self attestation. UP/UV are set after fresh fingerprint
verification; verification is never cached across requests. Only a terminal
verify-match from fprintd's unique D-Bus owner authorizes the operation. Claim
and enrollment-list calls explicitly select the configured desktop owner.

Before each credential request, after verification, before registration commit,
and before releasing a successful response, logind must report the same active,
local, unlocked graphical session of that owner. GetInfo remains public. Missing
logind/properties or a changed session fails closed. LockedHint is a cooperative
desktop hint, writable by the session owner's processes; it is not a trusted
screen-lock boundary against malicious desktop code. Sampling cannot detect a
switch away and back between checks. The fresh biometric requirement and OS
separation of credentials/devices are the actual desktop-malware boundary.

If a session changes or a request is cancelled after a registration has already
been durably committed, the response is discarded but an unused credential can
remain. A precommit session check narrows this window; persistence and response
delivery are not atomic. A resident orphan can occupy that RP's one slot; there
is no credential-management UI yet.

The narrow preflight exception is explicit up=false, no UV requirement, and a
nonempty allowList. A known credential can sign with UP=0/UV=0 without a scan.
The owner-session gate still applies. No user handle is returned, and this response cannot serve as a valid WebAuthn
login. A client knowing both the RP and credential ID can test its presence
without consent. Discovery without an allowList still requires verification.
This avoids two consecutive reader sessions for a single browser login.

No PIN, PRF/hmac-secret, enterprise attestation, legacy U2F, GetNextAssertion or
credential-management commands are supported. The signature counter is zero
(unsupported). Self attestation proves key possession, not a certified identity.

## Keys and storage

`internal/tpm/` creates non-migratable P-256 signing keys under an owner-hierarchy primary.
Primary derivation and templates retain upstream compatibility. RegisterKey reads
CreateKey's public output directly. SignASN1 recreates the parent, loads the
wrapped key and signs; temporary handles are explicitly flushed on return.
The fixed credential encoding contains private blob, public blob and a 20-byte
seed, each prefixed by TPM and a one-byte length.

`internal/authenticator/store.go` saves opaque credential IDs, RP IDs, user handles, resident flags and
TPM-wrapped material in a versioned private JSON file. It uses ownership/mode
checks, exclusive process locking, and atomic replacement with file/directory
sync. Uncertain commits stop further credential operations until restart.
No plaintext signing key or fingerprint template is stored by cv2-fido.

The store holds at most 64 credentials and one discoverable credential per RP.
A second discoverable registration for that RP is rejected. Non-discoverable
credentials can coexist and are selected using allowLists. There is no deletion
UI, synchronization or cross-TPM migration.

## Security boundary and validation

TPM protects key extraction; the isolated Linux process enforces fingerprint
authorization. Desktop-user processes are denied the service's files and direct
TPM/UHID access. Root, the kernel, logind, fprintd, the driver and the service
remain trusted. This is not an independent YubiKey Bio security boundary.
Desktop malware can still initiate a misleading request, steal browser sessions
or cause denial of service. No trusted display or caller-authenticated browser
channel is provided.

The system unit uses an empty capability set, no privilege gain, read-only system
files, hidden homes, AF_UNIX-only sockets and a device allowlist. The polkit rule
allows verify/setusername to the service, forbids its enrollment, and requires
fresh administrator authentication for fingerprint changes by protected owners.
Existing local administrator rules can override package defaults.

Udev grants TPM resource-manager 0 and UHID to root/service only; raw TPM 0 is
root-only. Only the virtual FIDO hidraw device has desktop uaccess. Startup
checks actual ownership/modes and rejects extended ACLs. Clearing TPM or
losing state invalidates registrations. UHID access permits other virtual HID
devices too, so compromise of the service remains significant.

Unit/race tests cover protocol/storage, authorization and session failures.
Opt-in tests exercise real swtpm create/sign/restart/tamper behavior and private
D-Bus logind/fprintd interactions. Packaging tests use disposable roots and hook
stubs, not host changes. See [DEVELOPMENT.md](DEVELOPMENT.md) for commands.

## Request guard and desktop helper

See [REQUEST-GUARD.md](REQUEST-GUARD.md) for notification delivery, global
request/scan budgets, cooldowns and the nontrusted nature of desktop notifications.
The service rechecks the owner session after notification delivery and before
starting the fingerprint reader.
