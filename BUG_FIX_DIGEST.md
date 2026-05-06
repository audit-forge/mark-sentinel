# M.A.R.K. Sentinel — Bug Fix Digest
**All 28 confirmed bugs fixed across the codebase**
*(Critical → High, in order of severity)*

---

## CRITICAL BUGS (5)

---

### C-1 — Wrong CLI flag broke the scan command entirely
**File:** `server.py`

**What was wrong:**
The server was calling `audit.py` with the target passed as a plain word after the command, like:
`python audit.py 192.168.1.1`
But `audit.py`'s argument parser expects `--target 192.168.1.1`. Think of it like filling out a form — if the form says "Name: ___" and you write your name in the wrong box, it gets ignored or causes an error. Every remote scan launched from the server dashboard was silently broken.

**Why it's bad:**
The scan would run but scan the wrong thing (or nothing at all), producing misleading compliance results without any error message.

**What was fixed:**
Changed the subprocess call to pass `--target <value>` as a named argument. The server now correctly hands the target off to the scanner.

---

### C-2 — Compliance report was reading the wrong field names
**File:** `output/compliance.py`

**What was wrong:**
Every finding in a Sentinel scan has two key fields: `check_id` (the rule identifier, like `AI-DEPLOY-001`) and `status` (PASS/FAIL/WARN). The compliance report generator was looking for fields named `id` and `result` — names that don't exist. It got back `None` every time, so every check appeared as "UNKNOWN" status and the wrong ID.

**Why it's bad:**
The compliance PDF/text report would show every check as unknown regardless of scan results, making it useless for audits.

**What was fixed:**
Updated all references in `compliance.py` to use the correct field names: `check_id` and `status`.

---

### C-3 — Multi-device token system was completely disconnected
**File:** `server.py` + `tokens.py`

**What was wrong:**
Sentinel has two token systems: a simple single-token file (`agent_token.txt`) and a full multi-token store (`agent_tokens.json`) that supports multiple agents with expiry dates. The server's authentication code only checked the simple file — the multi-token store was built but never wired in. Any device using a token from the store was rejected as unauthorized.

**Why it's bad:**
If you enrolled multiple agents via `tokens.py`, none of them could authenticate. The fleet management feature was built but non-functional.

**What was fixed:**
Created a single `_check_agent_token()` function that checks the simple token first, then falls through to the store, respecting expiry dates. Both paths now contribute to authentication.

---

### C-4 — Self-update downloaded bundles without verifying integrity
**File:** `agent.py`

**What was wrong:**
When an agent updated itself, it downloaded a new bundle and installed it without checking if the file was tampered with in transit. Imagine downloading software and running it without checking the checksum — anyone who could intercept or modify the response (man-in-the-middle) could push malicious code to all your agents.

**Why it's bad:**
A supply-chain attack. Compromised update = compromised agents on every device running Sentinel.

**What was fixed:**
The server now sends an `X-Bundle-SHA256` header with the hash of the legitimate bundle. The agent computes SHA-256 of what it downloaded and refuses to install if the hashes don't match.

---

### C-5 — Tar extraction allowed path traversal (tar slip attack)
**File:** `agent.py`

**What was wrong:**
During self-update, the agent extracted a `.tar.gz` archive. It checked for paths like `../../evil` to prevent directory traversal, but it didn't check for **symbolic links**. An attacker could craft a tar archive with a symlink that points outside the extraction directory. The code would happily follow that symlink and write files anywhere on disk.

**Why it's bad:**
An attacker with control over the update bundle could overwrite system files, SSH keys, or cron jobs — full system compromise through a symlink.

**What was fixed:**
Added `member.issym()` and `member.islnk()` checks. Any archive member that is a symlink or hard link is now skipped during extraction.

---

## HIGH SEVERITY BUGS (23)

---

### H-1 — SARIF output used scan results to set severity instead of intrinsic severity
**File:** `output/sarif.py`

**What was wrong:**
SARIF is a standardized format security tools use to share findings (GitHub, VS Code, Azure DevOps all read it). Each rule in a SARIF file has a `defaultConfiguration.level` that says how severe that rule *inherently is*. The code was setting this to the result of the current scan — if a check passed this run, the rule was marked `note`-level, even if it's a CRITICAL rule by nature.

**Why it's bad:**
The same check would appear as different severity levels in different SARIF reports. Tools that consume SARIF for risk scoring would get wrong data.

**What was fixed:**
Added a `_SEV_LEVEL` mapping (`CRITICAL/HIGH → error`, `MEDIUM → warning`, `LOW → note`) that sets rule severity from the check's intrinsic severity, not the scan result.

---

### H-2 — SKIP results contaminated the findings array
**File:** `output/json_report.py`

**What was wrong:**
When a check is skipped (not applicable to this target), it was included in the JSON findings output as a `SKIP` result. Downstream tools — the comparison reporter, the dashboard, external security platforms — all received these SKIPs and tried to process them as real findings. The dashboard math was inflated. Comparison reports showed false "resolved" items. SARIF importers got confused.

**Why it's bad:**
One wrong value in one place caused a cascade of bad data across every output format.

**What was fixed:**
One-line filter in `json_report.py`: `if r.status != "SKIP"`. SKIPs are excluded from the findings array but still counted correctly in the summary.

---

### H-3 — Content-Length header was read without bounds checking (4 places)
**File:** `server.py`

**What was wrong:**
When the server received an HTTP request, it read the `Content-Length` header and used it directly to decide how many bytes to read. This happened in four different endpoints. An attacker could send `Content-Length: 999999999999` and cause the server to try to allocate gigabytes of memory.

**Why it's bad:**
Denial of service — one malformed request could crash the server or exhaust memory on the host.

**What was fixed:**
Created a `_content_length()` helper that clamps the value to a safe maximum (65,536 bytes for scan requests) and handles malformed values gracefully.

---

### H-4 — Server used private storage internals directly
**File:** `server.py` + `storage.py`

**What was wrong:**
The server's device dashboard endpoint reached into `AgentStore`'s private attributes (`_lock` and `_conn()`) to run its own SQL query. This bypasses the storage layer's thread-safety guarantees — imagine two workers both trying to access the same file drawer without checking if it's already open.

**Why it's bad:**
Race condition under load. With multiple simultaneous dashboard requests, the SQLite connection could be used from two threads at once, causing data corruption or crashes.

**What was fixed:**
Added a `get_device_timeseries()` public method on `AgentStore` that properly holds the lock. The server now calls this clean interface instead of reaching into private attributes.

---

### H-5 — Read operations in storage didn't hold the thread lock
**File:** `storage.py`

**What was wrong:**
`AgentStore` has a `_lock` to protect SQLite from concurrent access. But the lock was only used in *write* methods (`store_report`, `update_device`). All five read methods (`get_device`, `list_devices`, `recent_reports`, etc.) accessed the database without the lock. Reads and writes happening simultaneously can return half-written data.

**Why it's bad:**
SQLite in WAL mode handles concurrent readers, but without the lock, a read could interleave with a write at the Python object level (e.g., connection reuse), causing incorrect query results or crashes under concurrent load.

**What was fixed:**
Added `with self._lock` to all five read methods. All database access — reads and writes — now goes through the lock.

---

### H-6 — Dashboard injected raw JSON into HTML without escaping
**File:** `output/dashboard.py`

**What was wrong:**
The dashboard HTML page embeds scan data as a JavaScript variable: `var data = {...}`. The code was dumping the JSON directly into the `<script>` tag. If any finding's `details` or `title` contained `</script>`, the browser would end the script block early and execute anything that followed as raw HTML — a stored XSS attack.

**Why it's bad:**
If an attacker controls finding data (e.g., via a malicious file or config that Sentinel scans), they could inject JavaScript into the dashboard page and steal session tokens.

**What was fixed:**
Used `ensure_ascii=True` to force all Unicode through safe escape sequences, and replaced `</script>` (case-insensitive) with `<\/script>` — the backslash makes it invisible to the HTML parser while still valid JavaScript.

---

### H-7 — Login page `next` parameter allowed open redirect
**File:** `server.py`

**What was wrong:**
The server's login page accepts a `?next=` parameter to redirect after login (standard UX). The code was passing it straight through without validation. An attacker could send a link like `/login?next=https://evil.com` — after the victim logs in, they're immediately sent to the attacker's site, which can impersonate the Sentinel dashboard to steal credentials.

**Why it's bad:**
Phishing vector. The Sentinel server becomes a trusted launchpad for redirecting authenticated users to attacker-controlled sites.

**What was fixed:**
`next` is now validated to only allow paths starting with `/` (internal redirects only). External URLs are rejected. The value is also HTML-escaped before being embedded in the login form.

---

### H-8 — All token comparisons used `==` (timing side-channel)
**File:** `server.py`

**What was wrong:**
When comparing a submitted token against the stored token, the code used plain string equality (`submitted == stored`). Python's `==` returns `False` as soon as it finds the first mismatched character — it doesn't take the same time for every comparison. An attacker making thousands of requests can measure response times to guess the token one character at a time.

**Why it's bad:**
Timing oracle attack. Given enough requests, an attacker can recover the token without ever having seen it. This is a known class of cryptographic attack.

**What was fixed:**
All token comparisons now use `hmac.compare_digest()`, which always takes the same amount of time regardless of where the strings differ.

---

### H-9 — LLM response parser crashed on JSON with a text preamble
**File:** `agent.py`

**What was wrong:**
When an LLM returns a structured response, it sometimes adds a preamble like "Sure! Here's the JSON:" before the actual JSON. The parser was calling `json.loads()` directly on the full response, which would fail because of the preamble text.

**Why it's bad:**
Any LLM response with a conversational intro would cause the agent to crash and log a confusing error, breaking agentic scan workflows.

**What was fixed:**
The parser now finds the first `{` character in the response and starts parsing from there, gracefully ignoring any text preamble.

---

### H-10 — Email alert subject allowed header injection
**File:** `alerts.py`

**What was wrong:**
The email alert subject line included the hostname of the scanned device: `"Sentinel Alert: ... on {hostname}"`. If a device's hostname contained `\r\n` (carriage return + newline), an attacker could inject additional email headers like `Bcc:` or `Content-Type:`, potentially turning Sentinel alerts into a spam relay.

**Why it's bad:**
Email header injection. An attacker who controls a device's hostname could cause Sentinel to send emails to arbitrary targets, or poison the headers of security alerts.

**What was fixed:**
The hostname is now stripped of `\r`, `\n`, and null bytes, and capped at 253 characters (the DNS hostname limit) before being used in the subject line.

---

### H-11 — Gemini connector sent the API key in the URL
**File:** `connectors/gemini_connector.py`

**What was wrong:**
The Google Gemini API key was appended to the URL as a query parameter: `?key=AIzaSy...`. URLs appear in server logs, browser history, nginx access logs, and HTTP `Referer` headers — everywhere that gets logged is a place your API key would be permanently stored in plaintext.

**Why it's bad:**
API key exposure in logs. Any log aggregator, proxy, or CDN between Sentinel and Google would capture the key. Rotation is painful and leaks can go unnoticed.

**What was fixed:**
The API key is now sent in the `x-goog-api-key` HTTP request header, which is not logged by standard infrastructure.

---

### H-12 — `plain_english.py` crashed when `details` was None
**File:** `output/plain_english.py`

**What was wrong:**
The plain English report generator tried to format the `details` field of each finding. For some checks, `details` is `None`. The code attempted string operations on `None`, causing an `AttributeError` crash.

**Why it's bad:**
Any scan that included a check with no details (which is valid) would crash the plain English output formatter entirely.

**What was fixed:**
Added `or ""` fallback: `r.details or ""`. If details is None, an empty string is used instead.

---

### H-13 — `deploy.py` had a registered check that was never run
**File:** `checks/deploy.py`

**What was wrong:**
`check_inp_005_config` was defined — a check that validates AI configuration settings — but the `run_all()` function that runs all deployment checks didn't include it in its list. The check existed but was silently skipped every time.

**Why it's bad:**
A security control that appears in the check catalog but never actually runs. The scan would report a clean result for a category it never examined.

**What was fixed:**
Added `check_inp_005_config(ctx)` to the `run_all()` return list.

---

### H-14 — Device ID was random on containers and VMs
**File:** `agent.py`

**What was wrong:**
Sentinel uses a device ID to uniquely identify each agent in the fleet. The ID was derived from the MAC address via `uuid.getnode()`. On containers, VMs, and some cloud instances, `uuid.getnode()` returns a random value because there's no stable hardware MAC. Every restart would generate a different device ID, making each restart look like a new device.

**Why it's bad:**
Fleet database pollution. An agent that restarts 10 times shows up as 10 devices. Historical scan data is lost because each "new device" has no history.

**What was fixed:**
The device ID is now persisted to `output/.device_id` on first run. Subsequent runs load the stored ID. The MAC address detection also checks the multicast bit to detect random MACs and falls back to `"random"` for deterministic hashing.

---

### H-15 — `_LEAST_PRIV_RE` regex matched any quoted value
**File:** `checks/agentic.py`

**What was wrong:**
A regex was supposed to detect when an AI agent's permission scope used safe, narrow values like `"read"` or `"query"`. But the pattern was too broad — it matched any quoted string after `"permissions"`, including `"admin"` or `"*"`. A wildcard permission like `"permissions": "*"` would pass this check as "least privilege compliant."

**Why it's bad:**
False PASS on a security check. Agents with full or wildcard permissions would not be flagged.

**What was fixed:**
The regex now only matches a specific allowlist of safe permission words: `read`, `write`, `query`, `view`, `limited`, `custom`, `specific`, `minimal`, `narrow`. Anything else fails the check.

---

### H-16 — Discovery used deprecated `asyncio.get_event_loop()`
**File:** `discovery.py`

**What was wrong:**
The network discovery module used `asyncio.get_event_loop()` to get the event loop. This function is deprecated in Python 3.10 and raises a `DeprecationWarning`, and in Python 3.12 it can raise a `RuntimeError` if called outside of an async context.

**Why it's bad:**
Silent DeprecationWarning in Python 3.10-3.11; hard crash in Python 3.12+. Discovery would silently fail on newer Python versions.

**What was fixed:**
Replaced with `asyncio.get_running_loop()` which is the correct modern API when already inside an async context. The fix also uses the UDP socket trick to detect the real LAN IP instead of relying on `gethostbyname()` which returns `127.0.0.1` on Linux systems.

---

### H-17 — `load_alert_config` didn't catch JSON parse errors
**File:** `alerts.py`

**What was wrong:**
The alert config loader only caught `FileNotFoundError`. If the alerts config file existed but contained invalid JSON (e.g., accidentally truncated, or edited with a syntax error), `json.JSONDecodeError` would propagate unhandled, crashing the alert dispatcher.

**Why it's bad:**
A misconfigured alerts file would crash the entire alert subsystem at runtime, silently dropping security alerts.

**What was fixed:**
Added `json.JSONDecodeError` and `OSError` to the except clause, with a warning log instead of a crash.

---

### H-18 — `audit.py` `history` subcommand intercepted by argparse
**File:** `audit.py`

**What was wrong:**
`audit.py` delegates the `history` subcommand to `audit_history.py`. But the delegation check happened *after* `argparse.parse_args()`. Argparse would see `history` as an unrecognized subcommand and exit with an error before the delegation code ever ran.

**Why it's bad:**
`python audit.py history list-devices` always fails with "invalid choice: history" even though it's a valid command. The entire audit history feature was inaccessible via the main entry point.

**What was fixed:**
Moved the `sys.argv` check for `history` to *before* `parse_args()`. The delegation now happens before argparse ever sees the argument.

---

### H-19 — `audit.py` left file handles open and used SHA-1
**File:** `audit.py`

**What was wrong:**
Two issues: (1) File handles opened for reading scan targets were not always closed — if an exception occurred mid-scan, the file descriptor would leak. (2) The code computed SHA-1 hashes of scan artifacts as part of integrity checking, even though SHA-1 has been cryptographically broken since 2017.

**Why it's bad:**
File descriptor leaks accumulate over time on long-running systems. SHA-1 weaknesses mean hash comparisons can be fooled by crafted inputs.

**What was fixed:**
File handles are now opened with context managers (`with open(...)`). SHA-1 replaced with SHA-256 throughout.

---

### H-20 — `tokens.py` used wrong default path and insecure file permissions
**File:** `tokens.py`

**What was wrong:**
The default path for the token store was computed with `Path('output/agent_tokens.json')` — a relative path that depends on whatever directory you run the script from. If run from a different directory, it would create a token file in the wrong place. Additionally, the token file was created with default permissions (readable by all users on the system).

**Why it's bad:**
Token file ends up in unpredictable locations. Even when found, any local user on a multi-user system could read all the agent tokens.

**What was fixed:**
Default path now uses `Path(__file__).parent / 'output' / 'agent_tokens.json'` — always relative to the script file, regardless of working directory. `chmod(0o600)` is applied on save so only the owner can read the token file.

---

### H-21 — Kyverno policy used `AnyIn` for glob matching (never works)
**File:** `output/kyverno.py`

**What was wrong:**
The generated Kyverno policy for detecting plaintext credentials used the `AnyIn` operator with glob-style patterns like `"*API_KEY*"`. Kyverno's `AnyIn` does exact string matching — it checks if the value is literally in the list. `"OPENAI_API_KEY"` is not literally equal to `"*OPENAI*"`, so this check never matched anything.

**Why it's bad:**
The Kubernetes admission policy for blocking plaintext API keys in environment variables was completely non-functional. Workloads with exposed secrets would pass admission.

**What was fixed:**
Replaced `AnyIn` with `Match` using a combined case-insensitive regex: `(?i).*(API_KEY|SECRET|TOKEN|...).*`. The `Match` operator in Kyverno uses proper regex, which works correctly.

---

### H-22 — Kyverno pinned-image policy used invalid patterns
**File:** `output/kyverno.py`

**What was wrong:**
Two bugs in the image-pinning policy: (1) `operator: Equals, value: "*:latest"` — `Equals` is exact match, so this only blocks an image literally named `*:latest`. `nginx:latest` passes through fine. (2) `operator: NotMatch, value: "*:*"` — `NotMatch` uses regex, and `*` at the start of a regex is invalid syntax (quantifier with nothing to repeat). This would cause a Kyverno policy error.

**Why it's bad:**
The policy meant to enforce pinned image tags did nothing. `latest`-tagged images were freely admitted, and the invalid regex caused a policy processing error.

**What was fixed:**
(1) `Match` with `".*:latest$"` — regex correctly matches any image ending in `:latest`. (2) `NotMatch` with `".+:.+"` — valid regex that denies images with no tag separator.

---

### H-23 — Rego generator produced invalid package names and corrupt string literals
**File:** `output/rego.py`

**What was wrong:**
Two issues: (1) The Rego package name was derived from the profile name using only `replace(" ", "_")` and `replace("-", "_")`. Characters like `/`, `.`, `@`, or `\` would pass through and produce an invalid Rego `package` declaration. (2) The per-check rule strings only escaped double quotes — backslashes in `check_id` or `title` fields would produce invalid Rego escape sequences (e.g., `\f` instead of a literal backslash).

**Why it's bad:**
Generated Rego files would be syntactically invalid and fail to load in OPA. CI/CD gates using these policies would error out rather than enforce security controls.

**What was fixed:**
Package name is now sanitized with a regex that allows only `[a-z0-9_]` characters. String escaping now handles backslashes first (`\\` → `\\\\`) before quoting double quotes.

---

## MEDIUM / ARCHITECTURAL — Fixed

---

### M-1 — All fleet traffic was unencrypted (no TLS)
**File:** `server.py`

**What was wrong:**
Every byte of data sent between the Sentinel server and its agents — scan results, device reports, auth tokens — traveled over plain HTTP. Anyone on the same network (coffee shop, corporate LAN, compromised router) could read or tamper with the traffic. This is like sending a security audit report through regular mail in a see-through envelope.

**Why it's bad:**
An attacker on the network could capture agent tokens, read scan findings, or inject fake reports — completely undermining the integrity of the audit system.

**What was fixed:**
The server now reads two environment variables: `SENTINEL_TLS_CERT` (path to your TLS certificate) and `SENTINEL_TLS_KEY` (path to your private key). If both are set, the server wraps its socket with TLS and serves HTTPS. If neither is set, a prominent warning is printed at startup reminding you to either configure TLS or put nginx/Caddy in front as a reverse proxy.

To enable:
```bash
export SENTINEL_TLS_CERT=/etc/sentinel/cert.pem
export SENTINEL_TLS_KEY=/etc/sentinel/key.pem
python server.py
```

---

### M-2 — `datetime.utcnow()` deprecated — crashes Python 3.12
**File:** `output/compliance.py`

**What was wrong:**
The compliance report generator used `datetime.utcnow()` to timestamp reports. Python officially deprecated this function in 3.12 because it returns a "naive" datetime (one with no timezone information) that looks like UTC but carries no proof of it. In Python 3.14 it will be removed entirely and will crash.

**Why it's bad:**
Silent wrong behavior today (naive datetime could be misinterpreted as local time); hard crash on Python 3.14+.

**What was fixed:**
Replaced with `datetime.now(timezone.utc)` which returns a timezone-aware UTC datetime. The ISO format string is normalized to the standard `Z` suffix instead of `+00:00`.

---

### M-3 — Presidio connector crashed on missing spaCy model
**File:** `connectors/presidio_connector.py`

**What was wrong:**
The connector catches `ImportError` at startup — if `presidio-analyzer` isn't installed, it gracefully sets `HAS_PRESIDIO = False` and skips. But if presidio *is* installed but the required spaCy language model (`en_core_web_lg`) isn't downloaded yet, presidio raises an `OSError` when it tries to load the model file. That `OSError` was not caught — it would propagate and crash the scan at import time.

**Why it's bad:**
A user who installed `presidio-analyzer` but forgot `python -m spacy download en_core_web_lg` would get a hard crash when running any scan, even scans that don't use PII detection.

**What was fixed:**
Added `OSError` to the except clause. Both `ImportError` (package missing) and `OSError` (model files missing) now result in a graceful `HAS_PRESIDIO = False` with no crash.

---

### M-4 — Docker Compose list-format env vars bypassed API key scan
**File:** `connectors/docker_connector.py`

**What was wrong:**
Docker Compose supports two formats for environment variables. The *dict format* (`environment: {KEY: value}`) was handled correctly. The *list format* (`environment: ["KEY=value"]`) was silently skipped — the scanner only called `.items()` if the value was a dict. A compose file using list format would never be scanned for exposed API keys.

**Why it's bad:**
The check that detects plaintext API keys in container environment variables would always pass for list-format compose files, regardless of what secrets they contained.

**What was fixed:**
Before scanning, list-format env vars are normalized into a dict by splitting each `"KEY=value"` string on the first `=`. Both formats now get the same security scan.

---

### M-5 — Temp file leaked when dashboard generation failed
**File:** `server.py`

**What was wrong:**
The device dashboard endpoint generates HTML by writing to a temporary file, reading it back, then deleting it. The delete call was on the happy path only — if `generate()` raised an exception (corrupt report data, rendering bug), the temp file would never be deleted. Each failed dashboard request permanently left a `.html` file in the OS temp directory.

**Why it's bad:**
File descriptor and disk space leak. On a busy server with repeated failures (e.g., a corrupt device report), temp files accumulate indefinitely. The temp files also contain customer scan data and could be read by other processes on a shared system.

**What was fixed:**
Wrapped the generate + read block in `try/finally`. The unlink now always runs, even on exception. A failed `unlink` itself is also caught so it doesn't mask the original error.

---

### M-6 — Academy docs taught users to embed PAT in git remote URLs
**File:** `academy.py`

**What was wrong:**
The installation instructions showed users how to clone the repo using a Personal Access Token embedded directly in the URL: `https://YOUR_TOKEN@github.com/...`. When users follow this pattern with a real token, the token gets:
1. Stored permanently in `.git/config` (visible to anyone who reads the file)
2. Stored in shell history
3. Visible in `ps aux` process listings while git is running

The troubleshoot section also showed `git remote add private https://YOUR_TOKEN@github.com/...`.

**Why it's bad:**
Token exposure via filesystem, shell history, and process list. On a shared server, other users can read the token by listing processes or reading `.git/config`. Rotating the token requires manually editing every installed instance.

**What was fixed:**
All three platform sections (macOS, Windows, Linux) and the troubleshoot section now use `git credential.helper` instead of embedding the token in the URL. The credential helper prompts once and stores the token securely (in the system keychain on macOS/Windows, in `~/.git-credentials` on Linux). The URL never contains the token.

---

### M-7 — `audit_history.py` opened SQLite read-write, bypassing server's lock
**File:** `audit_history.py`

**What was wrong:**
`audit_history.py` is a standalone CLI tool that opens the `agents.db` SQLite file directly. It always opened it in read-write mode, even though it only ever reads. This meant: (1) if run while the server is writing a new report, SQLite's locking could cause one of the two processes to fail with "database is locked"; (2) a bug in the history CLI could accidentally corrupt the database the server depends on.

**Why it's bad:**
Risk of database contention during concurrent server writes, and unnecessary write access to a production database for a read-only reporting tool.

**What was fixed:**
The connection is now opened in read-only mode using SQLite's URI syntax: `file:path?mode=ro`. A read-only connection can never write, even if a query accidentally tries to. It also holds a shared read lock (not an exclusive write lock), so the server can continue writing reports without contention.

---

*Generated by M.A.R.K. Sentinel code review — 2026-05-06*
*All 35 confirmed bugs fixed (5 Critical + 23 High + 7 Medium)*
