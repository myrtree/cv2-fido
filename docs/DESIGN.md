# Architecture

User-facing behavior and security limits are in [README.md](../README.md).

## Components

```text
cmd/cv2-fido/            CLI, lifecycle and startup identity/device checks
internal/authenticator/  CTAP, authorization and private credential storage
internal/hid/            HID framing and Linux UHID transport
internal/fingerprint/    fprintd verification and enrollment checks
internal/session/        logind session checks
internal/notification/   Unix-socket bridge and desktop notifications
internal/rpid/           shared RP ID validation
internal/tpm/            TPM key creation and signing
packaging/               Debian, systemd, udev and polkit configuration
```

The CLI wires the packages. Authenticator accepts a signer interface and
notification, verification and session callbacks. HID accepts a command handler.
Storage is internal to authenticator; tests live beside their packages.

The system process runs as `cv2-fido`; `cv2-fido agent` runs as the selected desktop
owner. Root-owned configuration selects that owner. The owner must belong to
`cv2-fido-users`, but not the private device-access group `cv2-fido`.
TPM resource-manager 0 and UHID are root/service-only; raw TPM 0 is root-only.
Startup rejects unsafe ownership, modes and extended ACLs. Only the virtual FIDO
hidraw device receives desktop uaccess. Polkit permits the service to verify
fingerprints, not enroll them; protected owners' enrollment changes require fresh
administrator authorization. Local administrator policy can override these rules.

## Transport

One event loop owns transport state and writes; one worker processes a CTAP command
with a 30-second context deadline. An eventfd wakes the loop when a result is ready,
independently of the keepalive tick. Cancellation is checked before response delivery;
INIT resynchronization waits for the worker to release ownership. Malformed OUTPUT
reports are discarded without stopping the device or skipping periodic work.

Messages are bounded to 7609 bytes, assembly to three seconds, and channel state
to 128 entries. Channels expire after five idle minutes. At capacity, allocation
evicts the least recently active idle channel, excluding the current command and
message assembly. Sequential CIDs are routing identifiers, not authorization tokens.
Eviction does not prevent continuous INIT flooding by a local client.

## Authorization and CTAP

CTAP 2.0 GetInfo, MakeCredential and GetAssertion use ES256 and packed self
attestation. UP/UV require fresh verification; no biometric result is cached.
Only a terminal `verify-match` from fprintd's unique D-Bus owner is accepted.
Claim and enrollment checks explicitly name the configured desktop owner.
Fingerprint RPCs and match waiting have a 30-second deadline, or the caller's
earlier deadline. Cleanup has a separate two-second budget; the initial system-bus
connection is outside this RPC deadline guarantee.

Logind must report the same active, local, unlocked graphical owner session before
the request, after notification/verification, before registration commit and before
a successful response. Missing properties or a changed session deny access.
Sampling cannot detect a switch away and back between checks; LockedHint is a
cooperative hint, not a trusted lock boundary. GetInfo remains public.

Silent preflight requires explicit `up=false`, no UV requirement and a nonempty
allowList. A known credential can sign with UP=0/UV=0, returning no user handle.
This cannot satisfy a valid WebAuthn login but reveals presence to a client knowing
the RP and credential ID. The session gate still applies. Discovery without an
allowList, exclusion checks and resident-credential conflicts require authorization.

CTAP and notifications share ASCII/punycode RP validation. Invalid RP IDs consume
the general request budget, not the prompt budget or failure cooldown. Missing
required fields are distinguished from present invalid values. The CTAP 2.1
enterpriseAttestation parameter is recognized by presence and rejected with
INVALID_PARAMETER; only FIDO_2_0 is advertised. Supported features and remaining
protocol restrictions are listed in [README.md](../README.md#storage-and-limits).

Notification delivery and throttling are described in [REQUEST-GUARD.md](REQUEST-GUARD.md).

## Keys and persistence

Non-migratable P-256 signing keys are created under an owner-hierarchy primary.
Primary derivation and templates retain upstream compatibility. RegisterKey reads
CreateKey's public output; SignASN1 recreates the parent, loads the wrapped key and
signs. Temporary handles are flushed. The fixed encoding stores private/public
blobs and a 20-byte seed, each prefixed by TPM and a one-byte length.

TPM calls are synchronous and do not take the CTAP context. Each operation has a
60-second process watchdog, covering device open/close and handle cleanup. Expiry
terminates the service; the unit's restart policy applies. No replacement operation
runs over a stalled one. This cannot guarantee recovery from a kernel/hardware hang.

The private JSON store uses ownership/mode checks, exclusive process locking and
atomic replacement with file/directory sync. Uncertain commits block further
credential operations until restart. No plaintext signing keys or fingerprint
templates are stored. Capacity is 64 credentials, with one discoverable key per RP.

Persistence and browser delivery are not atomic. Cancellation or a session change
after durable commit suppresses the response but can leave an unused credential;
a discoverable one occupies its RP's slot. A precommit session check narrows this
window. There is no deletion UI or cross-TPM migration.

Compromise of the service bypasses application-enforced biometric authorization;
UHID access also permits creating other virtual HID devices. Tests and their
limits are described in [TESTING.md](TESTING.md).
