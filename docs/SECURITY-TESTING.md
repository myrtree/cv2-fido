# Security test scope

`make fuzz` runs four independent Go fuzz targets. `FUZZTIME` is the duration
per target (default 30s); `FUZZWORKERS` limits workers per target (default 2).
The targets run sequentially. None uses host TPM/fprintd/logind or real credentials.

| Target | Properties checked |
| --- | --- |
| `FuzzHIDSequence` | Arbitrary reports and report sequences do not panic; channel/assembly bounds hold; cancelled workers cannot release stale success; INIT resync and expiry release state. |
| `FuzzUHIDOutput` | Only sufficiently long OUTPUT bodies with the expected report kind and 64/65-byte declared payload are accepted; returned bytes match that payload. |
| `FuzzCTAPAuthorization` | Arbitrary CBOR/commands cannot use a key after session denial or cancellation; ordinary assertions require fresh successful verification; explicit known-ID silent probes carry no UP/UV flags or user handle; error responses carry no payload. |
| `FuzzDecodeKey` | Existing TPM wrapped-key parser/round-trip checks. |

The CTAP fuzzer uses an in-memory store containing one resident credential. Its
fake signer refuses key creation and returns dummy assertion signatures. It tests
authorization and response structure, not cryptographic validity or disk commits.
Existing unit and swtpm integration tests cover those separate responsibilities.
The HID worker deliberately returns a stale success after cancellation to check
that the transport suppresses or replaces it. Inputs are bounded to keep each
iteration inexpensive, including inputs above the production message limit.

Seed cases are deterministic regression tests and run with `go test -race ./...`.
Active fuzzing explores additional inputs and keeps interesting cases in Go's
build cache. Failures are saved under the package's `testdata/fuzz/` directory;
retain a reproducer when fixing a bug. A bounded run without findings is not
evidence that all input sequences or races are safe.

## Dependency check

`make vulncheck` runs [govulncheck](https://go.dev/doc/security/vuln/) against
the source packages, current dependency versions and selected Go toolchain.
Install the tool separately; it is not a runtime dependency. The check needs
the Go vulnerability database. Use `govulncheck -show verbose ./...` to distinguish
reachable symbols, imported packages and other packages in required modules.

The check does not cover fprintd, the driver, kernel, system configuration or
undisclosed vulnerabilities. Re-run before releases and after dependency or
toolchain changes.

## Architectural limits

These checks do not remove the risks described in the README: a desktop process
can initiate HID requests, fingerprint verification does not prove which request
the user intended to approve, logind's LockedHint is cooperative, and compromise
of the service account can bypass application-enforced biometric checks. There
is no trusted confirmation UI or TPM-enforced fingerprint policy.
