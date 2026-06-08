# Brief for hash: build out a full audit trail (super-admin + customer-facing)

## What we're building
A "who did what, when" activity log — distinct from the existing `alert_log`
(which tracks security findings from scans, not user/admin actions). Two views:

1. **Super-admin audit log** — platform-wide actions (customer add/renew/upgrade/
   delete/restore, admin logins, license/seat changes, deploy actions, etc.)
   visible only to `super_admin` in the admin dashboard.
2. **Customer-facing audit log** — per-tenant actions (logins, user add/remove,
   settings changes, alert acknowledgements, scans triggered, config edits, etc.)
   visible to customers in their own dashboard.

**Decision already made — no tier gating.** Unlike remediation reports / evidence
packages / live scans (which are Plus-only per `license.py`'s `has_technical_reports`
/ `has_evidence_package` / `has_live_scan` properties), the audit log must be fully
available to BOTH `standard` and `plus` tiers. Do not add any `license.plan` check
that hides or limits it. Reasoning: this is a transparency/trust feature (visibility
into your own account), not premium analysis content — gating it would actively hurt
sales to compliance-conscious customers (SOC 2 / ISO 27001 / HIPAA buyers expect an
audit trail regardless of plan) and would feel punitive to Standard customers during
a dispute or incident review.

## Reuse the alert_log pattern — don't reinvent it
We just shipped an almost-identical feature (`alert_log`) — mirror its shape exactly:

- DB table + indexes added via `executescript` in `_init_db()`
- Store methods: `log_alert()`, `get_alert_log()`, `acknowledge_alert()` etc. on
  `AgentStore` in `/Users/keithferguson/sentinel/storage.py`
- API routes `/api/alerts/log` (GET) and `/api/alerts/ack` (POST) in
  `/Users/keithferguson/sentinel/server.py`, using the LOCAL IMPORT pattern
  `from urllib.parse import parse_qs` (NOT `urllib.parse.parse_qs` — that caused a
  `NameError: name 'urllib' is not defined` bug last time; match the existing
  handlers' import style exactly)
- Nav button + full `<div class="page" id="page-alerts">` with filter buttons,
  table, and JS (`loadAlertLog()`, `renderAlertLog()`, etc.) in `server.py`'s
  HTML template — copy this structure for the audit log page/tab

Read `alerts.py`, the `alert_log` table definition and `AgentStore` methods in
`storage.py`, and the `page-alerts` / `nav-alerts` blocks in `server.py` BEFORE
writing any code — match indentation, naming conventions, and JS style exactly.

## Schema (two tables — same shape, two locations)

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at  INTEGER NOT NULL,       -- unix epoch, matches alert_log's fired_at
    actor_id     TEXT NOT NULL DEFAULT '',   -- user id
    actor_name   TEXT NOT NULL DEFAULT '',   -- email or display name (denormalized for display)
    actor_role   TEXT NOT NULL DEFAULT '',   -- 'super_admin' | 'admin' | 'user' etc.
    customer_id  TEXT NOT NULL DEFAULT '',   -- '' for platform-wide super-admin actions
    action       TEXT NOT NULL DEFAULT '',   -- e.g. 'login', 'user.add', 'customer.renew'
    target       TEXT NOT NULL DEFAULT '',   -- e.g. user email, customer id, alert id
    details      TEXT NOT NULL DEFAULT '',   -- short human-readable description
    ip_address   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_customer ON audit_log(customer_id, occurred_at DESC);
```

- **Per-customer copy**: add to the `_init_db()` executescript in `storage.py`
  (lives inside each tenant's isolated `agents.db` — same isolation model as
  `alert_log`). Add `AgentStore.log_action(...)` and `AgentStore.get_audit_log(...)`.
- **Central copy**: add to the `executescript` in `/Users/keithferguson/sentinel/admin/db.py`
  (`init_db()`, alongside the existing `customers`/`users`/`license_alerts`/
  `password_resets` tables — same `sentinel_admin.db`). Add equivalent helper
  functions there (the admin side uses plain `get_conn()` + raw SQL, not an
  `AgentStore` class — match that style, don't introduce a new abstraction).

## Centralize the write path — don't scatter raw INSERTs
Write ONE helper per side:
- `AgentStore.log_action(actor_id, actor_name, actor_role, action, target='', details='', ip_address='')`
  in `storage.py` (customer side — `customer_id` is implicit, it's that tenant's own DB)
- A module-level `log_audit(actor_id, actor_name, actor_role, customer_id, action, target='', details='', ip_address='')`
  helper in `admin/app.py` or `admin/db.py` (central side)

Then call it from every state-changing endpoint — one line each. This keeps
instrumentation mechanical and consistent rather than copy-pasted SQL everywhere.

## Where to instrument

**`admin/app.py`** (central audit log — ~30 POST/state-changing routes, grep
`^@app\.\(get\|post\|delete\|put\)` to enumerate them). Priority actions:
- `/login`, `/logout` (success AND failure — failed logins matter for security review)
- `/customers/add`, `/renew`, `/seats`, `/upgrade`, `/remove`, `/restore`, `/delete`, `/rotate-token`
- `/users/add`, `/edit`, `/password`, `/remove` and the `/api/users/*` equivalents
- `/admin/deploy`, `/admin/dismiss-alert`, `/admin/refresh-seats`, `/admin/test-email`
- `/account/password`, `/forgot-password` / `/reset-password` flows

**`server.py`** (per-customer audit log — grep for POST routes / state mutations):
- Customer login/logout
- User add/remove/edit within the tenant
- Settings/config changes (alert config save, etc.)
- `acknowledge_alert` / `acknowledge_all_alerts` calls (already-existing alert
  actions — log that someone acted on them)
- Scan triggers, license/seat-relevant actions visible to the customer

For each: capture `actor_id`/`actor_name`/`actor_role` from `get_current_user(request)`
(admin side, via `from auth import get_current_user`) or whatever session/user lookup
`server.py` already uses — do NOT invent a new auth lookup, reuse what's there.

## UI — mirror the Alerts tab exactly
- **Customer side**: new nav item + `<div class="page" id="page-audit">` in
  `server.py`'s template, same filter-buttons/table/pagination shape as
  `page-alerts`. New API routes `/api/audit/log` (GET, with `customer_id` scoping
  already implicit since it's that tenant's own DB).
- **Admin side**: new page in `admin/app.py` + a template (check `admin/templates/`
  for the existing pattern — e.g. `customers.html`) showing the central audit log,
  filterable by customer, action type, date range. Gated to `super_admin` only via
  `require_super_admin(request)` — same as every other admin-only route.

## Verification checklist (don't skip — this is what VERIFICATION RULE means in practice)
1. After writing the DB migration, restart the relevant service and confirm the
   table was created — query it directly via `sqlite3` / `docker exec ... python3 -c "..."`
   the same way the alert_log non-population bug was diagnosed last time.
2. Trigger one of each instrumented action manually and confirm a row appears.
3. Load both UI pages and confirm rows render with correct actor/action/timestamp.
4. Confirm a `standard`-tier customer can see their audit log (no gating applied) —
   check this explicitly since the whole point is "available to everyone."
5. Read back the changed sections of `server.py` / `admin/app.py` / `storage.py` /
   `admin/db.py` after editing to confirm syntax and indentation are correct
   (`python3 -c "import ast; ast.parse(open(f).read())"` for each).

## Deploy
Same pattern as every other change to this app:
`scp <file> neepai@35.255.19.236:/opt/sentinel/<file>` (or `docker cp` into the
running container for files that live inside it — check how `alerts.py`/`storage.py`
were deployed last time), then `docker restart sentinel-mfdynamicsllc` and/or
`sentinel-admin` as appropriate. Verify containers come back healthy with `docker ps`.
