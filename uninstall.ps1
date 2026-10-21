#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RiskRaven Arckon Agent - Windows Uninstaller

.DESCRIPTION
    Stops and removes the Arckon Windows Service, deletes the install
    directory (C:\Program Files\Arckon) and config directory (C:\ProgramData\Arckon),
    and removes the repair watchdog scheduled task.

.EXAMPLE
    .\uninstall.ps1
#>
[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir      = "C:\Program Files\Arckon"
$ConfigDir       = "C:\ProgramData\Arckon"
$ServiceName     = "ArckonAgent"
$LegacyService   = "SentinelAgent"
$WatchdogTask    = "ArckonRepairWatchdog"

Write-Host ""
Write-Host "RiskRaven Arckon Agent - Windows Uninstaller" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "This will remove:"
Write-Host "  $InstallDir"
Write-Host "  $ConfigDir"
Write-Host "  Windows Service: $ServiceName"
Write-Host "  Scheduled Task:  $WatchdogTask"
if (Get-Service -Name $LegacyService -ErrorAction SilentlyContinue) {
    Write-Host "  Legacy Service:  $LegacyService (will also be removed)" -ForegroundColor DarkYellow
}
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Are you sure? [y/N]"
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# -- Stop and remove services --------------------------------------------------

$nssmCmd = Get-Command "nssm" -ErrorAction SilentlyContinue; $nssmPath = if ($nssmCmd) { $nssmCmd.Source } else { $null }

foreach ($svc in @($ServiceName, $LegacyService)) {
    $existingSvc = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if (-not $existingSvc) { continue }

    Write-Host "  Stopping service '$svc' ..." -ForegroundColor Cyan
    if ($nssmPath) {
        & $nssmPath stop $svc 2>$null
        Start-Sleep -Seconds 2
        & $nssmPath remove $svc confirm 2>$null
    } else {
        if ($existingSvc.Status -eq "Running") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        sc.exe delete $svc | Out-Null
    }
    Write-Host "  [OK] Service '$svc' removed" -ForegroundColor Green
}

# -- Remove repair watchdog scheduled task --------------------------------------

$task = Get-ScheduledTask -TaskName $WatchdogTask -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "  Removing scheduled task '$WatchdogTask' ..." -ForegroundColor Cyan
    Unregister-ScheduledTask -TaskName $WatchdogTask -Confirm:$false
    Write-Host "  [OK] Scheduled task removed" -ForegroundColor Green
} else {
    Write-Host "  Scheduled task '$WatchdogTask' not found, skipping." -ForegroundColor DarkGray
}

# Installations where NSSM was unavailable use this startup task instead of a
# Windows service. Remove it too so it cannot recreate the agent after reboot.
$agentTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($agentTask) {
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    Write-Host "  [OK] Startup task removed" -ForegroundColor Green
}

# -- Remove directories --------------------------------------------------------

$needReboot = $false

foreach ($dir in @($InstallDir, $ConfigDir)) {
    if (Test-Path $dir) {
        try {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Write-Host "  [OK] Removed $dir" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not fully delete $dir (file may be locked by AV/EDR)." -ForegroundColor Yellow
            Write-Host "         Reboot the computer, then delete $dir manually." -ForegroundColor Yellow
            $needReboot = $true
        }
    } else {
        Write-Host "  $dir not found, skipping." -ForegroundColor DarkGray
    }
}

Write-Host ""
if ($needReboot) {
    Write-Host "RiskRaven Arckon Agent uninstalled. Please reboot to complete file cleanup." -ForegroundColor Yellow
} else {
    Write-Host "RiskRaven Arckon Agent has been uninstalled." -ForegroundColor Green
}

# -- Remove Programs and Features entries ---------------------------------------
# The PowerShell installer writes the native registry view while older NSIS
# installers wrote the 32-bit view. Remove both so Settings cannot retain a
# stale Arckon Agent entry after uninstall.

$UninstallKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ArckonAgent"
$removedRegistryEntry = $false
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        if ($baseKey.OpenSubKey($UninstallKey)) {
            $baseKey.DeleteSubKeyTree($UninstallKey, $false)
            $removedRegistryEntry = $true
        }
        $baseKey.Dispose()
    } catch {
        # The 64-bit view is unavailable on 32-bit Windows; the other view is sufficient.
    }
}
if ($removedRegistryEntry) {
    Write-Host "  [OK] Removed Programs and Features entry" -ForegroundColor Green
}
