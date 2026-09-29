# Provenance

cv2-fido is a smaller, specialized derivative using components from
[Peter Sanford's tpm-fido](https://github.com/psanford/tpm-fido), obtained through
[mc256/tpm-fido2-thinkpad-linux](https://github.com/mc256/tpm-fido2-thinkpad-linux/tree/49222c60dbbf0c5ec4356240cbd92789e41945da)
at revision `49222c60dbbf0c5ec4356240cbd92789e41945da`.
It is not an implementation written entirely from scratch. The original MIT
copyright and license notice are retained in [LICENSE](../LICENSE) and the deb.

## What remains derived

| Component | Relationship to the referenced revision |
| --- | --- |
| `internal/tpm/tpm.go` | Derived backend, retaining substantial original code: primary/child key templates, HKDF derivation, owner hierarchy, authorization choices, and the core create/load/sign flow. |
| `internal/hid/uhid_linux.go` report descriptor | The same 34 descriptor bytes, reformatted. This describes the standard FIDO HID interface. |
| `internal/hid/hid.go` | Framing was adapted from upstream. The current implementation uses a serialized event loop, one cancellable worker, bounded assembly/channels, and delayed resynchronization acknowledgement. |
| `internal/tpm/key.go` | Locally written fixed-format codec replacing the imported `lencode` package. The inherited three-record format is intentionally preserved. |

The TPM wrapper now rejects invalid inputs and public points/signature responses,
uses standard-library ASN.1, and decodes CreateKey's public area directly rather
than loading the child only to call ReadPublic. The parent derivation still uses
`tpm-fido-application-key`, the RP hash and a 20-byte seed. These are compatibility
parameters, not branding to remove during renaming.

The CTAP handler, direct fprintd integration, private JSON store, direct UHID
adapter, CLI, tests and deb packaging were developed or substantially reworked
for this smaller implementation. The architecture remains closely related:
browser -> virtual HID -> CTAP -> TPM, with fingerprint verification via fprintd.
Upstream tray, physical-key auto-switching, native messaging and PRF/hmac-secret
features are not included.

## Other notices

`packaging/Go.LICENSE` is the Go Authors' BSD license, obtained from
https://raw.githubusercontent.com/golang/go/master/LICENSE.
It is a fallback for toolchain distributions that omit GOROOT/LICENSE.
The deb also includes licenses for the Go modules linked into its binary.
