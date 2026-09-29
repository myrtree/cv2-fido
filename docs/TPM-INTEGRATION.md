# TPM integration test design

Implemented in `internal/tpm/integration_test.go`, enabled by the `integration` build tag
on Linux. Installation and invocation are in the
[DEVELOPMENT.md](DEVELOPMENT.md).

`make test-integration` requires swtpm on PATH and fails if it is absent. It
starts an independent TPM 2.0 emulator with private temporary state and a Unix
socket, using the production backend unchanged. No environment variable can
select a hardware TPM device for this suite.

The suite checks key creation and independent ECDSA verification, writes/reloads
a wrapped key after an emulator restart, rejects another RP and tampered
private/public/seed records, and rejects loading the key on a separate emulator.
It verifies subsequent valid signing and checks for leaked transient handles.

Each emulator has a 45-second lifetime bound; shutdown signals its process and
forces termination if necessary. Test cleanup removes temporary state. The make
target also applies an overall two-minute test timeout. No root access, fprintd
or user credentials are required. A sandbox that forbids Unix sockets cannot run
these tests unchanged.

These tests establish software TPM interoperability, not biometric behavior or
physical key-extraction resistance. Ordinary unit tests and runtime package
dependencies do not require swtpm.

The integration target also runs private D-Bus tests for session checks,
fingerprint verification and notifications. These require `dbus-daemon` and
never contact host services.
