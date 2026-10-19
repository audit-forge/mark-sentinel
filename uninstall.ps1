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
param()

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

$confirm = Read-Host "Are you sure? [y/N]"
if ($confirm -notmatch '^[Yy]$') {
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
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

# -- Remove the uninstall registry entry ----------------------------------------

$RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ArckonAgent"
if (Test-Path $RegKey) {
    Remove-Item -Path $RegKey -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed Programs and Features entry" -ForegroundColor Green
}
