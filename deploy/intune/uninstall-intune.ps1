#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Arckon Agent — Intune uninstall script (Windows)
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$InstallDir  = "C:\Program Files\Arckon"
$ConfigDir   = "C:\ProgramData\Arckon"
$ServiceName = "ArckonAgent"

# Stop and remove the service
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>&1 | Out-Null
}

# Remove the repair watchdog scheduled task
Unregister-ScheduledTask -TaskName "ArckonRepairWatchdog" -Confirm:$false -ErrorAction SilentlyContinue

# Remove install directory
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Remove config directory (logs + config)
if (Test-Path $ConfigDir) {
    Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0