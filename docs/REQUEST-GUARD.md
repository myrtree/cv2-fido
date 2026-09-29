# Request guard

The service displays a passive system notification naming the site and action,
followed by a fresh fingerprint. No approval button, notification action, biometric
cache or fallback to silent scanning is added.

## Service guard

`internal/authenticator/guard.go` holds constant-memory token buckets under the
existing authenticator mutex. The general bucket admits a burst of 20 requests,
refilling one token per 100ms. GetInfo stays available for discovery. Actual
notification/scan starts have a separate burst of 3, refilling one per 10 seconds.
Limits are global; changing the RP ID or HID channel does not reset them.

The notification/scan bucket is checked only in authorization, so silent known-ID
preflight does not trigger it. Failed notification delivery, fingerprint failure,
cancellation or a session change during authorization triggers exponential backoff
from 2 to 30 seconds. Rejected requests neither queue nor extend the cooldown.
Success resets only the backoff, never the buckets. State is in memory and resets
on service restart. This limits prompts but cannot guarantee fair access against
another process deliberately consuming the owner's shared device.

## Notification bridge

The service creates a Unix stream socket in its systemd RuntimeDirectory. The
parent is service-owned 0755; the socket is 0666 and kernel SO_PEERCRED selects
only the configured desktop UID. At most one idle connection is retained. The
helper independently requires the server's peer UID to match `cv2-fido`.

Each connection carries exactly one bounded JSON request containing RP/action.
The helper calls `org.freedesktop.Notifications.Notify` on its session bus and
acknowledges only after that call succeeds. The service waits at most two seconds
for a helper and at most two seconds for delivery, bounded by request cancellation.
Only then does it recheck the owner session and start fprintd verification.

A reconnect replaces any queued idle connection without disturbing an active
request. The helper monitors connection closure while Notify is pending. It keeps
a late daemon reply so it can close the returned notification ID after cancellation,
and does not begin another delivery until that reply has been handled. There is
at most one pending Notify call per helper; an unresponsive daemon blocks that
helper until it recovers or the helper exits.

The connection stays open while verifying. Completion/cancellation closes it;
the helper calls CloseNotification and reconnects. A failed delivery returns no
acknowledgement and prevents scanning. Expiration is a fallback if the helper
crashes. The service does not gain access to the desktop bus or user's home.
The helper receives neither credentials, challenges, key material nor fingerprints.

Untrusted RP IDs must consist of ASCII hostname characters with length 1..253;
Unicode hostnames use punycode. The title includes the action and RP ID even on
desktops that hide the body. No client-supplied markup, control characters, program
names or command lines reach the notification daemon.

The helper autostarts through XDG desktop autostart, using the same executable's
`agent` command. No desktop processes are started by maintainer scripts. The intended
setup is one configured owner and one graphical session with a notification daemon.

## Verification and limits

Unit tests exercise burst/refill/backoff, recovery, no scan after notification
failure, silent-preflight exemption, text validation and helper lifecycle. Private
Unix-socket integration tests exercise delivery, cancellation, reconnect and
rejection of a different peer UID. They run without real desktop notifications.
Regression tests also cover idle-helper replacement and closing delayed Notify
replies on a private D-Bus daemon.
Existing CTAP tests and fuzz seeds retain authorization and response-flag checks.
Package tests inspect runtime-directory and desktop-autostart configuration.

The notification is not a trusted UI: desktop malware under the owner UID can
impersonate the helper or draw an identical notification. The claimed site comes
from CTAP, not verified browser identity. Notify success only confirms daemon
acceptance; Do Not Disturb may suppress display. Dismissing a notification does
not cancel scanning. Browser cancellation does. Real notification rendering,
Chrome registration and Firefox login still require acceptance testing on the
user’s desktop after installation.
