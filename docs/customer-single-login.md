# Customer Single Login

Cloud customers authenticate once at the central login service. Its Secure,
HttpOnly shared-domain cookie is verified by the gateway, which selects the
customer backend from authenticated identity. Tenant backends must not offer
an independent credential prompt, local session, or local setup flow.

A successful credential POST normally returns HTTP 303 to the dashboard.
That browser transition is intentional; single login means one credential
prompt, not the absence of HTTP redirects. A signed-in customer revisiting
the central login page returns to the requested safe dashboard destination
or their default dashboard without re-entering credentials. Login, logout,
and setup pages cannot be successful post-login return destinations.

Cloud-mode login/setup handoffs use configured public HTTPS URLs, never
request Host or forwarded headers. A configured but unavailable proxy
capability fails closed instead of turning on standalone authentication.
Standalone deployments retain their local credential/setup flow.

## Verification

Run scripts/smoke_customer_single_login.py inside sentinel-admin with an
explicit --expected-tenants list. It creates temporary users, each with a
generated password and its own cookie jar, and verifies one credential POST,
shared-cookie handoff, direct dashboard HTTP 200, matching tenant identity,
login-page revisits without another form, and logout. It deletes its test
users on normal completion, exceptions, and handled termination signals.
Uncatchable termination can still leave a test identity; check cleanup after
an interrupted run. Never reset real customer passwords for this test.

The smoke does not call enrollment APIs, modify customer settings, or queue
endpoint work. Privileged dashboard responses contain deployment credentials;
they remain in memory and are never printed or saved. The test is not read-only
because it inserts/deletes users. It exercises real public HTTPS and HTTP cookie
handling, but is not a browser-engine test of SameSite behavior or JavaScript.
