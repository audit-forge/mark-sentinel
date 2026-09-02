# Windows Agent Binary Recovery

## Customer-visible symptom

- The **Arckon Agent** Windows service is stopped and will not start.
- The device appears offline in the Arckon fleet dashboard.
- Windows Event Viewer may show event ID `7034`: *"The Arckon Agent service terminated unexpectedly."*
- The service exit code may be `3` or `1066`.

## Root cause

The Arckon Windows service runs `C:\Program Files\Arckon\agent.exe`. During a signed
self-update the agent downloads a newer `agent.exe.new` and then stops the service and
swaps the files. If that swap is interrupted — for example by antivirus/EDR quarantine,
Windows file locking, or an unexpected reboot — the live `agent.exe` can be removed while
`agent.exe.new` (or `agent.exe.bak`) remains. The service then cannot start because its
executable is missing.

## On-device remediation (no backend access required)

### Option 1: Run the local repair script (fastest)

Open an **Administrator Command Prompt** or PowerShell and run:

```cmd
C:\ProgramData\Arckon\repair-arckon.cmd
```

The script will:

1. Check whether `C:\Program Files\Arckon\agent.exe` exists.
2. If it is missing, restore it from `agent.exe.new` or `agent.exe.bak`.
3. Start the `ArckonAgent` service.
4. Log every step to `C:\ProgramData\Arckon\arckon-agent.log`.

If the script reports success and the service starts, the device will reappear in the
dashboard within one or two poll cycles (the agent polls every 15 seconds).

### Option 2: Restart the device

A restart also resolves the issue on installs that have the **ArckonRepairWatchdog**
scheduled task (created automatically by the installer starting with v1.0.31). The
watchdog runs every 5 minutes as `SYSTEM` and will restore `agent.exe` if it is missing,
then start the service.

If the watchdog is not present, the service will still fail after a restart and you
should use Option 1 or Option 3.

### Option 3: Re-run the installer

Download the latest `install.ps1` from your Arckon server and run it as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -Server https://arckon.riskraven.ai -Token <YOUR_TOKEN>
```

This will:

- Download the current signed `agent.exe`.
- Restore the service and config.
- Re-register the 5-minute repair watchdog.

## Prevention / built-in safeguards

Starting with agent release **v1.0.31**, the installer and agent include several layers of
protection:

| Safeguard | What it does |
|-----------|--------------|
| Backup before update | `agent.exe` is copied to `agent.exe.bak` before any self-update. |
| Robust activation script | Waits for the service to fully stop, attempts the swap, restores from backup if the swap fails or leaves `agent.exe` missing, and only starts the service after verifying the binary exists. |
| Daemon startup repair | When the agent starts, it checks whether `agent.exe` is missing and restores it from `.new` or `.bak`. |
| `repair-arckon.cmd` | A customer-facing script that restores the binary and starts the service without backend access. |
| `ArckonRepairWatchdog` | A `SYSTEM` scheduled task that runs the repair script every 5 minutes, so a stranded binary is repaired automatically. |

## Verify the fix

After running the repair script or rebooting:

```powershell
Get-Service ArckonAgent
Get-Content C:\ProgramData\Arckon\arckon-agent.log -Tail 20
```

You should see:

- `Status: Running` for the `ArckonAgent` service.
- Recent log lines such as `Report accepted (HTTP 200)` or `self_update: release X is not newer than X`.

## Notes for support staff

- The repair script intentionally does **not** require an Arckon admin token; it only
  touches local files and the local service.
- If both `agent.exe` and `agent.exe.new`/`agent.exe.bak` are missing, the script exits
  with an error and the customer must re-run the installer.
- Do not delete `agent.exe.new` or `agent.exe.bak` manually; they are the recovery
  sources for the repair script and watchdog.
