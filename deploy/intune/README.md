# RiskRaven Arckon — Intune Deployment Guide

Deploy the Arckon agent to Windows and macOS endpoints via Microsoft Intune.

---

## What gets installed

| Platform | Binary path | Config path | Service |
|----------|-------------|-------------|---------|
| Windows | `C:\Program Files\Arckon\agent.exe` | `C:\ProgramData\Arckon\agent_config.json` | NSSM service `ArckonAgent` |
| macOS | `/opt/arckon/agent` | `/etc/arckon/agent_config.json` | launchd `ai.mfdynamics.arckon-agent` |

The agent is a Nuitka-compiled binary — no Python runtime is needed on the endpoint. The installer downloads the signed release from your Arckon server and verifies the SHA256 hash.

---

## Prerequisites

1. **Arckon server reachable** from endpoint devices (e.g. `https://arckon.riskraven.ai`)
2. **Agent token** — provisioned per customer in the admin panel at `https://admin.riskraven.ai`
3. **Microsoft Intune** with Endpoint Management (MEM) admin access
4. **Win32 Content Prep Tool** (`IntuneWinAppUtil.exe`) for packaging the Windows installer — download from https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool

---

## Windows Deployment

### Step 1 — Package the Win32 app

Create a source folder containing only the Intune installer scripts:

```
arckon-intune-win/
├── install-intune.ps1
├── detect-intune.ps1
└── uninstall-intune.ps1
```

Run the Win32 Content Prep Tool:

```cmd
IntuneWinAppUtil.exe -c arckon-intune-win -s install-intune.ps1 -o output
```

This produces `output\install-intune.intunewin`.

### Step 2 — Create the Win32 app in Intune

1. Go to **Microsoft Endpoint Manager** → **Apps** → **Windows** → **+ Add**
2. Select **Windows app (Win32)**
3. Upload the `install-intune.intunewin` package

### Step 3 — App information

| Field | Value |
|-------|-------|
| Name | Arckon Agent |
| Publisher | RiskRaven |
| Category | Security |
| Show as featured app | Yes (optional) |
| Information URL | https://arckon.riskraven.ai/academy/overview |
| Privacy URL | https://arckon.riskraven.ai/privacy |

### Step 4 — Program settings

| Field | Value |
|-------|-------|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install-intune.ps1 -Server "https://arckon.riskraven.ai" -Token "YOUR_CUSTOMER_TOKEN"` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File uninstall-intune.ps1` |
| Install behavior | **System** |
| Device restart behavior | **No specific action** |
| Maximum execution time | **60 minutes** |

> **Replace** `YOUR_CUSTOMER_TOKEN` with the token provisioned for this customer in the admin panel.

### Step 5 — Detection rules

Use a **custom PowerShell script** detection rule:

| Field | Value |
|-------|-------|
| Rule type | Custom script |
| Script file | `detect-intune.ps1` |
| Run script as | 32-bit on 64-bit: No |
| Enforce script signature check: No |
| Run script with logged-on user credentials: No |

The script returns exit code `0` when `agent.exe` + config + service are all present.

### Step 6 — Return codes

| Code | Classification |
|------|---------------|
| 0 | Success |
| 1603 | Failure |
| 3010 | Soft reboot |
| 1707 | Success (already installed) |

### Step 7 — Assignments

1. **Required** assignment to the device group(s) for the customer
2. For phased rollout, use **Available for enrolled devices** and let users self-install

---

## macOS Deployment

Intune deploys macOS shell scripts as a **Shell script** device configuration profile (not a Win32 app).

### Step 1 — Upload the install script

1. Go to **Microsoft Endpoint Manager** → **Devices** → **macOS** → **Scripts** → **+ Add**
2. Upload `install-intune.sh`

### Step 2 — Script settings

| Field | Value |
|-------|-------|
| Script name | Arckon Agent Install |
| Run script as | **Root** |
| Hide script notifications on device | **Yes** |
| Script frequency | **Not configured** (runs once) |
| Max retries | 3 |

### Step 3 — Command-line arguments

Intune shell scripts can't pass arguments directly. Instead, edit the server URL and token directly into the script before uploading:

```bash
# In install-intune.sh, add these after the while loop (line ~25):
SERVER_URL="https://arckon.riskraven.ai"
AGENT_TOKEN="YOUR_CUSTOMER_TOKEN"
```

Or use Intune's **shell script variables** feature if available in your tenant.

### Step 4 — Detection (macOS)

Intune doesn't have a separate detection rule for shell scripts. Instead:

1. The install script itself is idempotent — it stops any existing daemon, reinstalls, and restarts.
2. To verify deployment, check the **device script status** in MEM → Devices → macOS → select device → **Device script status**
3. For ongoing compliance, upload `detect-intune.sh` as a second script with frequency **Every 1 day** — Intune reports its pass/fail status in the console.

### Step 5 — Uninstall

Upload `uninstall-intune.sh` as a separate shell script and assign it to a device group when you want to remove the agent from specific endpoints.

---

## Assigning to Device Groups

1. Create an **Entra ID (Azure AD) device group** for the customer (e.g. `OPCO-All-Devices`)
2. Add the customer's devices to the group (via Intune enrollment or dynamic device rules)
3. Assign both the Windows Win32 app and the macOS shell script to this group as **Required**

For dynamic membership, use an Entra ID dynamic device group with a filter like:
```
device.devicePhysicalIDs -any (_ -contains "[OrderID]:OPCO-001")
```

---

## Post-Deployment Verification

### Windows
```powershell
# Check service
Get-Service ArckonAgent

# Check agent binary
Test-Path "C:\Program Files\Arckon\agent.exe"

# Check config
Get-Content "C:\ProgramData\Arckon\agent_config.json"

# Check agent log
Get-Content "C:\ProgramData\Arckon\arckon-agent.log" -Tail 20
```

### macOS
```bash
# Check daemon
launchctl list | grep arckon

# Check agent binary
ls -la /opt/arckon/agent

# Check config
cat /etc/arckon/agent_config.json

# Check agent log
tail -20 /var/log/arckon-agent.log
```

### Dashboard
The device should appear in the Arckon Command Center within 5 minutes of the agent's first scan cycle.

---

## Troubleshooting

### Agent not appearing in dashboard

1. Verify the token matches the customer's token in the admin panel
2. Check the agent can reach the server: `curl -s https://arckon.riskraven.ai/health`
3. Check the agent log for errors
4. Verify the service/daemon is running

### Windows: service won't start

1. Check `C:\ProgramData\Arckon\arckon-agent.log`
2. Run the repair script: `cmd.exe /c "C:\ProgramData\Arckon\repair-arckon.cmd"`
3. Restart the service: `Start-Service ArckonAgent`

### macOS: daemon not loading

1. Check `/var/log/arckon-agent.log`
2. Verify the plist: `plutil -p /Library/LaunchDaemons/ai.mfdynamics.arckon-agent.plist`
3. Reload: `sudo launchctl load -w /Library/LaunchDaemons/ai.mfdynamics.arckon-agent.plist`

### Intune deployment failures

1. Check **MEM → Devices → select device → Device install status** for the Win32 app
2. For macOS, check **MEM → Devices → macOS → select device → Device script status**
3. Collect Intune diagnostic logs from the device if needed

---

## Files

| File | Platform | Purpose |
|------|----------|---------|
| `install-intune.ps1` | Windows | Win32 app install command (downloads binary, creates service) |
| `detect-intune.ps1` | Windows | Win32 app detection rule |
| `uninstall-intune.ps1` | Windows | Win32 app uninstall command |
| `install-intune.sh` | macOS | Shell script installer (downloads binary, creates launchd daemon) |
| `detect-intune.sh` | macOS | Compliance verification script |
| `uninstall-intune.sh` | macOS | Removal script |