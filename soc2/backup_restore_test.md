# Backup Restore Test

## Test Record

| Field | Value |
|---|---|
| Test Date | 2026-11-19T16:35:00Z |
| Tester | Keith Ferguson |
| Environment | Production (mark-sentinel VM, mfdynamicsllc tenant) |
| Result | **PASS** |
| Next Test Due | 2027-02-19 (quarterly) |

## Procedure

### Step 1: Create Backup Copy
Created a copy of the live production database:
- Source: `/opt/sentinel-data/mfdynamicsllc/agents.db` (815 MB)
- Backup: `/tmp/agents-backup-test.db`
- WAL checkpoint performed before copy to ensure consistency

### Step 2: Verify Backup Integrity
Ran SQLite integrity check on the backup:
- `PRAGMA integrity_check;` → **ok**
- Table count: **33 tables**
- Device records: **4**
- Cloud asset events: **21**
- Findings: **0**

### Step 3: Restore to DR Test Location
Copied the backup to a simulated disaster recovery location:
- Restore path: `/tmp/dr-test-restore/agents.db`
- File size: 815 MB (matches original)

### Step 4: Verify Restored Data
Ran integrity check and data verification on restored copy:
- Integrity check: **ok**
- Table count: **33** (matches original)
- Device records: **4** (matches original)

### Step 5: Cleanup
Test artifacts removed:
- `/tmp/agents-backup-test.db` — deleted
- `/tmp/dr-test-restore/` — deleted

## GCP Snapshot Status
No GCP persistent disk snapshots are currently configured.

**Recommendation:** Enable scheduled GCP disk snapshots (daily, 7-day retention)
for the mark-sentinel VM boot disk. This provides off-VM backup in addition
to the on-VM database copies created during deployments.

## Test Cadence
- Quarterly restore tests: required by SOC 2 (CC7.5, A1.2)
- Next test: 2027-02-19
- Test results are retained as audit evidence for the observation period
