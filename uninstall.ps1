#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RiskRaven Arckon Agent - Windows Uninstaller

.DESCRIPTION
    Stops and removes the Arckon background service or scheduled-task fallback,
    then deletes its configuration, logs, binaries, and repair watchdog.
#>
[CmdletBinding()]
param([switch]$Force)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir  = "C:\Program Files\Arckon"
$ConfigDir   = "C:\ProgramData\Arckon"
$ServiceName = "ArckonAgent"

Write-Host ""
Write-Host "RiskRaven Arckon Agent - Windows Uninstaller" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "This will remove:"
Write-Host "  $InstallDir"
Write-Host "  $ConfigDir"
Write-Host "  Windows Service: $ServiceName"
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Are you sure? [y/N]"
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# -- Stop and remove service ---------------------------------------------------

$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingSvc) {
    Write-Host "  Stopping service '$ServiceName' ..." -ForegroundColor Cyan
    if ($existingSvc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "  [OK] Service removed" -ForegroundColor Green
} else {
    Write-Host "  Service '$ServiceName' not found, skipping." -ForegroundColor DarkGray
}

# The installer falls back to this task when NSSM is blocked by EDR or a proxy.
Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "ArckonRepairWatchdog" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "  [OK] Scheduled tasks removed" -ForegroundColor Green

# -- Remove directories --------------------------------------------------------

if (Test-Path $InstallDir) {
    # The NSIS uninstaller executable can still be running from this directory.
    # Ignore its locked file; NSIS removes it after this script exits.
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed $InstallDir" -ForegroundColor Green
} else {
    Write-Host "  $InstallDir not found, skipping." -ForegroundColor DarkGray
}

if (Test-Path $ConfigDir) {
    Remove-Item -Path $ConfigDir -Recurse -Force
    Write-Host "  [OK] Removed $ConfigDir" -ForegroundColor Green
} else {
    Write-Host "  $ConfigDir not found, skipping." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "RiskRaven Arckon Agent has been uninstalled." -ForegroundColor Green
