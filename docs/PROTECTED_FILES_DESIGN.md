# Protected Files Monitoring — FedRAMP-Aligned Design Spec

**Status:** Draft
**Last updated:** 2026-09-04
**Feature:** AI file-access monitoring + server access monitoring with alerting

## 1. Objective

Detect and alert when an AI-related process (Claude, Cursor, Copilot, Ollama,
Aider, etc.) accesses a user-designated "protected" file or directory, or when
an AI-related process initiates a server access event (SSH/RDP login).

## 2. Scope

### In scope (MVP)
- Per-device protected-path policy managed via dashboard
- File read/write/open events correlated with AI process identity
- SSH (Linux/macOS) and RDP (Windows) login events correlated with AI process identity
- Real-time alerting through existing channels (Slack, Teams, GChat, webhook, email, PSA, Notion, SIEM)
- Audit log of all access events (reviewable in dashboard)
- Three platforms: Linux (auditd), Windows (ETW + Event Log), macOS (OpenBSM)

### Out of scope (future)
- Blocking / prevention (detection only — no in-path interception)
- Network file access (NFS/SMB) — endpoint-local files only
- macOS Endpoint Security framework (requires Apple entitlement approval)
- Real-time streaming to SIEM (batch reporting via existing agent poll)

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Dashboard (server.py)                                        │
│  • Settings → Protected Files (per-device policy UI)         │
│  • Alerts → Access Events log                                │
│  • API: /api/protected-paths/* (auth-protected)              │
│  • API: /api/agent/access-events (agent ingestion)           │
└──────────┬──────────────────────────────┬───────────────────┘
           │ policy push (command poll)    │ event ingest
           ▼                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Agent (agent.py)                                              │
│  • Receives protected_paths via command poll                 │
│  • Runs platform collector daemon:                           │
│    - Linux:   auditd rules + ausearch                        │
│    - Windows: ETW + Windows Event Log (4663, 4624)          │
│    - macOS:   OpenBSM auditpipe                              │
│  • Correlates events with AI process list                    │
│  • Reports access events to server via POST                  │
└──────────────────────────────────────────────────────────────┘
```

## 4. Data Flow

1. **Policy definition:** Operator designates protected paths in dashboard
   → server stores in `protected_paths` table (encrypted at rest)
   → server pushes policy to agent via existing command poll
   (`set_protected_paths:<json>`)

2. **Event collection:** Platform collector watches for file/server access events
   → filters to protected paths only
   → correlates process name against `_AI_PROCESS_NAMES`
   → if match: creates access event with process, path, action, timestamp

3. **Event reporting:** Agent batches access events
   → POST `/api/agent/access-events` (TLS, auth token)
   → server stores in `access_events` table (encrypted at rest)
   → server fires alert through existing pipeline

4. **Alert delivery:** `alerts.py:fire_access_alert()` → existing channels
   → Slack/Teams/GChat/webhook/email/PSA/Notion/SIEM
   → 24h dedup cooldown per (device, path, process)

## 5. FedRAMP Control Mapping

| Control | Description | Implementation |
|---------|-------------|----------------|
| AC-2   | Account management | Agent enrollment requires server-side approval; per-device policy |
| AC-3   | Access enforcement | Protected-path policy enforced by collector; agent runs with least privilege |
| AC-6   | Least privilege | Collector reads audit events only; no write/modify capability |
| AU-2   | Audit events | All access events logged to `access_events` table with tamper-evident hash chain |
| AU-6   | Audit review | Dashboard UI for reviewing access events; mark as reviewed |
| AU-12  | Audit generation | Collector generates events on every protected-path access by AI process |
| SC-8   | Transmission confidentiality | All agent↔server communication over TLS (HTTPS) |
| SC-13  | Cryptographic protection | Protected-path policy encrypted at rest (AES-256-GCM); event hash chain (SHA-256) |
| SI-4   | System monitoring | Continuous collector monitoring for AI process access to protected files |
| CM-2   | Baseline configuration | Protected-path policy is versioned; changes audit-logged |
| CM-6   | Configuration settings | Policy stored server-side; agent receives via signed command poll |
| IA-2   | Identification & authentication | Agent authenticates to server via enrollment token; API endpoints require session auth |
| MP-3   | Media storage | Access events contain no file contents — only path, process, action metadata |

## 6. Security Requirements

### 6.1 Encryption at rest
- `protected_paths` policy: AES-256-GCM encrypted in database
- `access_events` table: event metadata stored as-is (no PII/file contents), but
  the hash chain is SHA-256 to detect tampering
- Encryption key: derived from server-side master key (env var `ARCKON_MASTER_KEY`),
  never written to disk, rotated periodically

### 6.2 Encryption in transit
- All agent→server communication over HTTPS (existing Cloudflare TLS)
- Agent validates server certificate (existing `requests` with `verify=True`)

### 6.3 Authentication & authorization
- Agent→server: existing enrollment token in `Authorization` header
- Dashboard→API: existing session-based auth (cookie)
- Protected-path policy changes: require authenticated dashboard session only
- Access event ingestion: requires valid agent enrollment token

### 6.4 Input validation
- Protected paths: validated against path traversal (`..`), null bytes, symlinks resolved
- Access events from agent: validated against schema before storage
- Path canonicalization: all paths resolved to absolute, symlink-resolved form

### 6.5 Audit log integrity
- `access_events` table includes `prev_hash` and `event_hash` columns
- Hash = SHA-256(prev_hash + event_data_json)
- Tampering detection: server verifies chain on read

### 6.6 No file contents
- Access events store ONLY: path, process name, PID, action (read/write/open), timestamp
- NEVER file contents, file metadata, or user data

### 6.7 Rate limiting
- Agent access-event reporting: max 100 events per batch, max 1 batch per 30s
- Server-side rate limit on ingestion endpoint per device_id

## 7. Database Schema

### `protected_paths` table
```sql
CREATE TABLE IF NOT EXISTS protected_paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,          -- '*' for all devices
    path        TEXT NOT NULL,          -- canonical absolute path
    path_hash   TEXT NOT NULL,          -- SHA-256 of canonical path (for lookup)
    recursive   INTEGER NOT NULL DEFAULT 1,  -- 1 = include subdirectories
    actions     TEXT NOT NULL DEFAULT 'read,write,open',  -- which actions to monitor
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE(device_id, path_hash)
);
```

### `access_events` table
```sql
CREATE TABLE IF NOT EXISTS access_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,           -- epoch seconds
    device_id   TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    platform    TEXT NOT NULL DEFAULT '',
    process     TEXT NOT NULL,              -- AI process name (e.g. "claude")
    pid         INTEGER NOT NULL DEFAULT 0,
    path        TEXT NOT NULL,              -- protected path accessed
    action      TEXT NOT NULL,              -- read | write | open | login
    source      TEXT NOT NULL DEFAULT '',   -- auditd | etw | openbsm
    prev_hash   TEXT NOT NULL DEFAULT '',
    event_hash  TEXT NOT NULL,              -- SHA-256(prev_hash + event_data)
    reviewed    INTEGER NOT NULL DEFAULT 0
);
```

### `protected_paths_audit` table (policy change log)
```sql
CREATE TABLE IF NOT EXISTS protected_paths_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    action      TEXT NOT NULL,              -- add | update | remove
    device_id   TEXT NOT NULL,
    path        TEXT NOT NULL,
    changed_by  TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT ''
);
```

## 8. API Endpoints

### Dashboard-facing (session auth required)
- `GET  /api/protected-paths` — list all protected paths
- `GET  /api/protected-paths/<device_id>` — list for specific device
- `POST /api/protected-paths` — add protected path
- `PUT  /api/protected-paths/<id>` — update protected path
- `DELETE /api/protected-paths/<id>` — remove protected path
- `GET  /api/access-events?limit=300` — list access events
- `POST /api/access-events/<id>/review` — mark event as reviewed
- `POST /api/access-events/review-all` — mark all as reviewed
- `GET  /api/access-events/unreviewed-count` — count for badge

### Agent-facing (enrollment token auth)
- `POST /api/agent/access-events` — ingest batch of access events
- Agent receives protected_paths via existing command poll:
  `set_protected_paths:<json>`

## 9. AI Process Names

Reuses `discovery.py:_PROCESS_SIGS` and `discovery.py:_MCP_PROCESS_SIGS`:
```
ollama, lms, lm-studio, text-generation-launcher, text-generation-server,
vllm, localai, llama-server, llama.cpp, koboldcpp, comfyui, sd_webui,
tabby, jan, claude, claude.exe, cursor, copilot, continue, codeium, aider,
uvx mcp, @modelcontextprotocol, mcp-server, fastmcp, mcp serve, python -m mcp, mcp run
```

Additional SaaS AI client processes:
```
ChatGPT, ChatGPT.exe, Gemini, Gemini.exe, Copilot.exe, Poe, Poe.exe
```

## 10. Platform Collectors

### Linux (auditd)
- Install audit rules for each protected path: `-w <path> -p rwa -k arckon_protected`
- Parse `ausearch -k arckon_protected --raw` for events
- Correlate PID with `ps` to get process name
- Parse `/var/log/auth.log` (or journalctl) for SSH login events
- Runs as a daemon thread in agent.py

### Windows (ETW + Event Log)
- Enable file audit on protected paths via `auditpol /set /subcategory:"File System"`
- Subscribe to Security Event Log: Event ID 4663 (file access), 4624 (login)
- Correlate Process ID from event with process name
- Runs as a daemon thread in agent.py

### macOS (Endpoint Security framework)
- Uses `com.apple.developer.endpoint-security.client` entitlement (obtained)
- Small **Swift helper binary** (`arckon-es-collector`):
  - Signed with Developer ID + ES entitlement, notarized
  - Subscribes to `ES_EVENT_TYPE_NOTIFY_OPEN`, `NOTIFY_WRITE`, `NOTIFY_RENAME`, `NOTIFY_UNLINK`, `NOTIFY_EXEC`
  - Filters to protected paths (path-based substring matching on resolved path)
  - Emits JSON events to local Unix domain socket `/var/run/arckon-es.sock` (0600 perms)
  - Runs as root (launchd `io.riskraven.arckon-es-collector` daemon)
- Python agent reads from Unix socket, correlates process audit token against AI process list, reports to server
- **Agent itself needs no entitlement** — reduces attack surface; privileged code isolated in signed helper
- Process identity verified via audit token (UID, signing ID, team ID, code signature status) — not just process name
- Login events: `ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN` and `NOTIFY_AUTHENTICATION`
- Helper binary is signed and notarized; agent verifies its code signature before trusting events

## 11. Threat Model

| Threat | Mitigation |
|--------|------------|
| Attacker tampers with protected_paths policy | Policy changes audit-logged; agent re-receives policy on each poll |
| Attacker tampers with access_events | Hash chain (SHA-256) detects tampering on read |
| Attacker floods server with fake events | Agent enrollment token required; rate limited per device |
| Attacker reads protected_paths from DB | AES-256-GCM encryption at rest |
| Attacker kills collector process | Agent self-heals collector thread; reports collector status |
| Attacker exploits path traversal in policy | Path canonicalization + validation before storage |
| Attacker accesses file contents | No file contents ever stored — only path + process + action |
| Agent compromised | Agent has no write access to policy; policy is server-pushed, read-only on agent |
| Server compromised | Policy encrypted at rest; master key in env var, not disk |