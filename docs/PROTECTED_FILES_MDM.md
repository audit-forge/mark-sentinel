# Protected Files Monitoring — MDM Deployment Guide for macOS

**Last updated:** 2026-09-04
**Audience:** IT admins deploying Arckon to managed macOS fleets via MDM
(Jamf, Kandji, Intune, Mosyle, Apple Business Manager, etc.)

## Overview

Protected Files monitoring on macOS uses Apple's Endpoint Security framework,
which requires:
1. A signed, notarized helper app (`ArckonESCollector.app`)
2. Full Disk Access (TCC permission)

When deployed via MDM, **both are installed silently with no user interaction**.
The PPPC profile pre-grants Full Disk Access, and the `.pkg` installer deploys
the helper app + LaunchDaemon.

## Artifacts

All artifacts are in `monitors/macos-esf/`:

| File | Purpose |
|------|---------|
| `Arckon-ES-Collector-1.0.34.pkg` | Signed, notarized installer (.pkg) — deploys the ES helper + LaunchDaemon |
| `arckon-es-collector.pppc.mobileconfig` | MDM configuration profile — pre-grants Full Disk Access |
| `ai.mfdynamics.arckon-es-collector.plist` | LaunchDaemon plist (included in the .pkg) |

## MDM Deployment — Exact Steps

### Step 1: Upload the PPPC Profile

Upload `arckon-es-collector.pppc.mobileconfig` as a **Custom Profile** (also
called Configuration Profile) in your MDM:

**Jamf Pro:**
1. Computers → Configuration Profiles → New
2. Name: `Arckon ES Collector — Full Disk Access`
3. Level: Computer-level
4. Scroll to **Custom Settings** (or "Application & Custom Settings")
5. Upload the `.mobileconfig` file
6. Scope to the same devices that will receive the Arckon agent
7. Save → Deploy

**Kandji:**
1. Library → New Profile → Custom Profile
2. Name: `Arckon ES Collector — Full Disk Access`
3. Upload the `.mobileconfig` file
4. Scope to target devices
5. Save → Deploy

**Microsoft Intune:**
1. Devices → macOS → Configuration profiles → Create profile
2. Platform: macOS → Profile type: Templates → Custom
3. Name: `Arckon ES Collector — Full Disk Access`
4. Custom configuration settings → upload the `.mobileconfig`
5. Assign to device groups
6. Create

**Mosyle Fuse:**
1. Management → Profiles → Custom Profile
2. Name: `Arckon ES Collector — Full Disk Access`
3. Upload the `.mobileconfig` file
4. Scope to devices
5. Save → Deploy

**Apple Business Manager (ABM) / MDM Server:**
Upload the `.mobileconfig` as a Device Configuration Profile via your MDM
vendor's ABM integration.

### Step 2: Deploy the .pkg Installer

Deploy `Arckon-ES-Collector-1.0.34.pkg` via your MDM's package deployment:

**Jamf Pro:**
1. Computer Management → Packages → New → Upload the `.pkg`
2. Create a Policy: trigger = `enrollment` or `recurring check-in`
3. Action: Install
4. Scope to the same devices as the PPPC profile
5. Save → Deploy

**Kandji:**
1. Library → New App → Custom App → upload the `.pkg`
2. Distribution method: auto-install
3. Scope to devices
4. Save → Deploy

**Intune:**
1. Apps → macOS → Add → Line-of-business app
2. Upload the `.pkg`
3. Assign to device groups
4. Create

**Mosyle Fuse:**
1. Management → Apps → Custom App → upload the `.pkg`
2. Auto-install: enabled
3. Scope to devices
4. Save → Deploy

### Step 3: Deploy the Arckon Agent

Deploy the Arckon agent itself via your MDM (same package deployment method
as Step 2, using the agent installer). The agent installer will detect the
already-installed ES helper and start monitoring automatically.

Alternatively, users can run the standard install command:
```bash
curl -sSL https://arckon.riskraven.ai/install.sh | sudo bash -s -- --server https://arckon.riskraven.ai --token YOUR_TOKEN
```

### Step 4: Verify

On a managed Mac, verify the ES collector is running:
```bash
# Check the LaunchDaemon is loaded
sudo launchctl print system/ai.mfdynamics.arckon-es-collector | head -5

# Check the process is running
pgrep -fl arckon-es-collector

# Check Full Disk Access was granted by the PPPC profile
# (no manual System Settings action needed)
```

## What Happens on Each Managed Mac

1. **MDM pushes the PPPC profile** → Full Disk Access pre-granted for
   `ai.mfdynamics.arckon.agent` (silently, no user prompt)
2. **MDM pushes the `.pkg`** → `ArckonESCollector.app` installed to
   `/Library/Arckon/`, LaunchDaemon loaded, ES daemon starts
3. **MDM pushes (or user installs) the Arckon agent** → agent connects to
   the ES daemon's Unix socket, begins monitoring
4. **Admin adds protected paths in dashboard** → policy pushed to agent
   within 15 seconds, monitoring active

**No user interaction required at any point.**

## Non-Managed (Standalone) Macs

For Macs NOT enrolled in MDM, the Full Disk Access step requires a manual
GUI action (Apple's TCC system does not allow non-MDM profiles to silently
grant permissions):

1. Install the `.pkg`: `sudo installer -pkg Arckon-ES-Collector-1.0.34.pkg -target /`
2. Open **System Settings → Privacy & Security → Full Disk Access**
3. Click **+** and add `arckon-es-collector` from `/Library/Arckon/ArckonESCollector.app`
4. Install the Arckon agent

## Code Signing Details

- **Bundle ID:** `ai.mfdynamics.arckon.agent`
- **Team ID:** `SWRJ6ZV39K` (M. F. Dynamics LLC)
- **Signing identity:** Developer ID Application: M. F. Dynamics LLC (SWRJ6ZV39K)
- **Installer signing:** Developer ID Installer: M. F. Dynamics LLC (SWRJ6ZV39K)
- **Notarization:** Apple status: Accepted (stapled ticket included)
- **Entitlement:** `com.apple.developer.endpoint-security.client` (approved 2026-07-10)
- **Code requirement (for PPPC):**
  ```
  identifier "ai.mfdynamics.arckon.agent" and anchor apple_generic and
  certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and
  certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and
  certificate leaf[subject.OU] = SWRJ6ZV39K
  ```

## Troubleshooting

### ES daemon won't start
```bash
# Check if Full Disk Access was granted
sudo log show --predicate 'process == "arckon-es-collector"' --last 5m

# Common error: "not permitted — grant this daemon Full Disk Access"
# → PPPC profile not deployed or wrong bundle ID in the profile
# → Verify the profile is installed: profiles show -type configuration
```

### PPPC profile shows "not installed"
```bash
# List installed configuration profiles
profiles show -type configuration

# Look for: ai.mfdynamics.arckon.pppc
```

### ES daemon running but no events
```bash
# Check if the agent is connected to the ES socket
ls -la /var/run/arckon-es-collector.sock

# Check agent logs for "ES daemon connected"
tail -50 /var/log/arckon-agent.log | grep -i "es\|protected"
```