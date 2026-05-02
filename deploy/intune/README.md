# M.A.R.K. Sentinel — Intune Deployment Guide (Windows)

Deploy the Sentinel agent to Windows endpoints via Microsoft Intune as a Win32 app.

---

## Prerequisites

- Python 3.11+ installed on target endpoints (deploy via Intune before Sentinel, or bundle in source folder)
- Microsoft Win32 Content Prep Tool (`IntuneWinAppUtil.exe`) on your packaging machine
- NSSM (Non-Sucking Service Manager) — optional, for running agent as a Windows service

---

## 1. Package as Win32 App

### Source folder layout

```
sentinel-intune/
├── install.ps1
├── uninstall.ps1
├── agent.py
├── agent_config.json
└── requirements.txt    (empty or stdlib-only — no pip install needed)
```

### Build the .intunewin package

```cmd
IntuneWinAppUtil.exe -c sentinel-intune -s install.ps1 -o output
```

This produces `install.intunewin` in the `output` folder. Upload that file to Intune.

---

## 2. Intune Win32 App Settings

### App information

| Field | Value |
|---|---|
| Name | M.A.R.K. Sentinel Agent |
| Publisher | Hash / M.A.R.K. |
| Version | (your release tag) |

### Program

| Field | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Server "https://sentinel.corp.com:7331" -Token "YOUR_TOKEN"` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1` |
| Install behavior | System |
| Device restart behavior | No specific action |

### Return codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1603 | Fatal error during installation |
| 3010 | Success, soft reboot required |

### Detection rule

| Type | Path | File | Detection method |
|---|---|---|---|
| File | `C:\Program Files\Sentinel` | `agent.py` | File exists |

---

## 3. Setting Environment Variables via Intune

The agent reads `SENTINEL_SERVER` and `SENTINEL_AGENT_TOKEN` from machine environment variables.

### Option A — Custom OMA-URI (machine scope)

Create a custom Configuration Profile with:

- OMA-URI: `./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/<package>/EnvironmentVariables`

For a simpler approach, use a PowerShell script deployed via Intune:

```powershell
[System.Environment]::SetEnvironmentVariable('SENTINEL_SERVER', 'https://sentinel.corp.com:7331', 'Machine')
[System.Environment]::SetEnvironmentVariable('SENTINEL_AGENT_TOKEN', 'YOUR_TOKEN_HERE', 'Machine')
```

Deploy this as a PowerShell script under **Devices > Scripts** in Intune, set to run in **System** context.

### Option B — Settings Catalog

In Intune > Devices > Configuration > Create > Settings Catalog:

1. Search for "Environment Variables" (requires Windows 11 23H2+ or the Administrative Templates category)
2. Add machine-scoped entries for `SENTINEL_SERVER` and `SENTINEL_AGENT_TOKEN`

---

## 4. GPO Alternative (on-premises / hybrid)

For environments using Group Policy instead of or alongside Intune:

**Path:** `Computer Configuration > Preferences > Windows Settings > Environment`

1. Right-click > New > Environment Variable
2. Action: **Update**
3. Name: `SENTINEL_SERVER`
4. Value: `https://sentinel.corp.com:7331`
5. Repeat for `SENTINEL_AGENT_TOKEN`

These apply at machine scope and take effect at next Group Policy refresh (`gpupdate /force`).

---

## 5. Verify Deployment

After the app installs, confirm on the endpoint:

```powershell
Test-Path "C:\Program Files\Sentinel\agent.py"
python "C:\Program Files\Sentinel\agent.py" --scan-only
```

Check the central Sentinel dashboard — the device should appear in the fleet view within one scan interval.

---

## 6. Scheduled Scans (daemon mode)

`install.ps1` should register a Scheduled Task or NSSM service to run the agent on a recurring schedule:

```powershell
$action  = New-ScheduledTaskAction -Execute 'python.exe' -Argument '"C:\Program Files\Sentinel\agent.py" --daemon --interval 3600'
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 0)
Register-ScheduledTask -TaskName 'SentinelAgent' -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force
```

For NSSM:

```cmd
nssm install SentinelAgent python.exe "C:\Program Files\Sentinel\agent.py" --daemon --interval 3600
nssm set SentinelAgent AppEnvironmentExtra SENTINEL_SERVER=https://sentinel.corp.com:7331
nssm start SentinelAgent
```
