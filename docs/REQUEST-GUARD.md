# Notifications and request limits

A passive desktop notification names the site and action before fresh fingerprint
verification. There is no approval button, biometric cache or silent-scanning
fallback. User-facing limits are in [README.md](../README.md#browser-use-and-diagnostics).

## Budgets

Constant-memory token buckets are accessed under the authenticator mutex:

| Budget | Burst | Refill |
| --- | --- | --- |
| Commands except GetInfo | 20 | One per 100 ms |
| Notification/scan starts | 3 | One per 10 seconds |

Silent known-ID preflight does not spend the prompt budget. Failed delivery,
verification failure, cancellation or a session change during authorization starts
exponential backoff: 2, 4, 8, 16, then 30 seconds. Success resets backoff, not buckets.
Rejected attempts neither queue nor extend the cooldown. Limits are global across
RPs/channels and reset on restart; they cannot ensure fairness against local malware.

## Notification bridge

The service-owned runtime directory is 0755 and its socket 0666. The parent and
ancestors require trusted ownership/permissions; symlinks are rejected. SO_PEERCRED
checks both ends: the service accepts only the configured owner, and the helper
requires the service UID. Rejected non-owner helpers exit. A new idle helper
connection replaces the previous one.

Each connection carries one bounded JSON RP/action request. RP IDs contain only
ASCII hostname characters, length 1..253; Unicode names use punycode. The helper
receives no credentials, challenges, keys or fingerprints. It autostarts through
XDG at graphical login and alone connects to the desktop notification bus.

The service allows two seconds to obtain a helper and two seconds for delivery,
subject to request cancellation. The helper acknowledges only after Notify succeeds;
then the service rechecks the session and starts verification. Closing the request
connection cancels it, and the helper requests CloseNotification when it knows the ID.

One Notify call is pending per helper, bounded to 30 seconds. Replies received after
request cancellation but before that timeout are closed. After timeout the ID is
lost: a delayed notification depends on the daemon honoring the requested 30-second
expiry. Cancelling the D-Bus call does not cancel work queued in the daemon.

## Trust limits

Notify success confirms acceptance, not visibility; Do Not Disturb may hide it.
Desktop malware can impersonate the helper or display an identical prompt. The RP
comes from CTAP, not authenticated browser identity. Dismissing a notification does
not cancel scanning; browser cancellation does. This is an awareness aid, not a
trusted confirmation UI. See [TESTING.md](TESTING.md) for automated and manual checks.
