# Test scope

Commands and dependencies are listed in [DEVELOPMENT.md](DEVELOPMENT.md).
Unit tests run with the race detector. Integration tests require `swtpm` and
`dbus-daemon`; missing tools fail the suite. They use temporary state and private
Unix sockets/D-Bus instances, never host TPM, fprintd, logind or real credentials.
A sandbox that forbids Unix sockets cannot run these tests unchanged.

## Integration and packaging

The production TPM backend is tested for key creation, independent ECDSA
verification, signing after emulator restart, rejection of another RP, tampered
key records and a different TPM, and cleanup of transient handles. Emulator
processes are bounded and cleaned up. Three watchdog subprocess tests use the
production 60-second deadline against stalled sockets for startup, registration
and signing. The integration target has an overall two-minute test timeout.

Private D-Bus and Unix-socket tests cover session checks, fingerprint verification,
notification delivery/cancellation, peer UID rejection and helper reconnection.
Package tests inspect artifacts and execute lifecycle hooks against disposable
roots with host-effect commands stubbed.

## Fuzzing and dependencies

`make fuzz` runs these targets sequentially. `FUZZTIME` defaults to 30 seconds
per target and `FUZZWORKERS` to 2.

| Target | Properties checked |
| --- | --- |
| `FuzzHIDSequence` | Framing/resource bounds, cancellation and resynchronization |
| `FuzzUHIDOutput` | OUTPUT body size, report kind and returned payload |
| `FuzzCTAPAuthorization` | Session/biometric gates, silent-probe flags and error payloads |
| `FuzzDecodeKey` | Wrapped-key decoding and round trips |

CTAP fuzzing uses fake signatures and in-memory state, not disk commits or real
cryptography. Seeds run with ordinary tests; active fuzzing caches additional
inputs. Keep failing `testdata/fuzz/` reproducers when fixing bugs.

`make vulncheck` checks source dependencies and the Go toolchain against the Go
vulnerability database. Re-run before releases and after dependency updates.
It does not cover the kernel, driver, fprintd or undisclosed vulnerabilities.

Passing tests or bounded fuzzing does not establish physical TPM extraction
resistance or eliminate the [security limits](../README.md#security-boundary).
After installation, verify notification rendering, registration, login, wrong-finger
rejection and cancellation in a real browser under the systemd service.
