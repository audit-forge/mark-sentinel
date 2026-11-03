# Session Timeouts

Arckon currently enforces an eight-hour absolute login lifetime. This is not
an inactivity timeout: leaving a tab untouched does not shorten the lifetime,
and background requests do not extend it. Shared admin cookies and their JWTs
expire eight hours after login. Standalone dashboard sessions have the same
absolute database expiry. Support impersonation uses its shorter token expiry.

Browser pages must separately detect expiration to stop displaying an old
rendered dashboard. Both the authenticated admin template and main customer
dashboard check their same-origin session endpoint on load, every 60 seconds,
on focus, on becoming visible, on reconnecting, and on pageshow restoration.
Confirmed 401 responses navigate to login, preserving the return location.
Checks do not issue replacement cookies or renew sessions.

The admin /api/auth/session probe is distinct from /auth/verify: a valid
unscoped platform administrator can use the former, while the customer
gateway correctly refuses to route that administrator through the latter.
Probe responses are not cacheable and expose no credentials.

Network errors, timeouts, permission denials, and server failures are not
treated as proof of expiry. Probes are bounded and deduplicated. Browser/OS
suspension prevents timers from running; the page revalidates when resumed
and connected. Expired server authorization remains rejected regardless of
whether the old page is still visible.

Changing the eight-hour limit or adding a shorter inactivity policy requires
a separate server-enforced policy decision. A client-only inactivity timer
would not revoke authorization and must not be represented as doing so.
