#Requires -RunAsAdministrator
<#
.SYNOPSIS
    M.A.R.K. Sentinel Agent — Windows Uninstaller

.DESCRIPTION
    Stops and removes the Sentinel Windows Service, then deletes the install
    directory (C:\Program Files\Sentinel) and config directory (C:\ProgramData\Sentinel).
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir  = "C:\Program Files\Sentinel"
$ConfigDir   = "C:\ProgramData\Sentinel"
$ServiceName = "SentinelAgent"

Write-Host ""
Write-Host "M.A.R.K. Sentinel Agent — Windows Uninstaller" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "This will remove:"
Write-Host "  $InstallDir"
Write-Host "  $ConfigDir"
Write-Host "  Windows Service: $ServiceName"
Write-Host ""

$confirm = Read-Host "Are you sure? [y/N]"
if ($confirm -notmatch '^[Yy]$') {
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

# ── Stop and remove service ───────────────────────────────────────────────────

$nssmPath = (Get-Command "nssm" -ErrorAction SilentlyContinue)?.Source
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingSvc) {
    Write-Host "  Stopping service '$ServiceName' ..." -ForegroundColor Cyan

    if ($nssmPath) {
        & nssm stop $ServiceName 2>$null
        Start-Sleep -Seconds 2
        & nssm remove $ServiceName confirm 2>$null
        Write-Host "  [OK] Service removed via NSSM" -ForegroundColor Green
    } else {
        if ($existingSvc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        sc.exe delete $ServiceName | Out-Null
        Write-Host "  [OK] Service removed via sc.exe" -ForegroundColor Green
    }
} else {
    Write-Host "  Service '$ServiceName' not found, skipping." -ForegroundColor DarkGray
}

# ── Remove directories ────────────────────────────────────────────────────────

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
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
Write-Host "M.A.R.K. Sentinel Agent has been uninstalled." -ForegroundColor Green
