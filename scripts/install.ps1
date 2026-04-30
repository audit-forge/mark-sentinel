<#
.SYNOPSIS
    M.A.R.K. Sentinel -- Windows installer (PowerShell)
.DESCRIPTION
    Creates a Python virtual environment and installs runtime dependencies.
    Requires Python 3.9+ (python.exe must be in PATH).
    Run from the repository root:  .\scripts\install.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  M.A.R.K. Sentinel -- Windows Installer (PowerShell)" -ForegroundColor Cyan
Write-Host "  ====================================================" -ForegroundColor Cyan
Write-Host ""

# ── Find Python 3.9+ ─────────────────────────────────────────────────────────
$PythonExe = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $raw = & $cmd --version 2>&1
        $ver = "$raw"
        if ($ver -match "Python 3\.([9]|1[0-9])") {
            $PythonExe = $cmd
            Write-Host "  Python found : $ver  ($cmd)" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $PythonExe) {
    Write-Host ""
    Write-Host "  ERROR: Python 3.9+ not found in PATH." -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

# ── Create virtual environment ────────────────────────────────────────────────
Write-Host "  Creating virtual environment (.venv)..." -ForegroundColor Yellow
& $PythonExe -m venv .venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to create virtual environment." -ForegroundColor Red
    exit 1
}

# ── Upgrade pip ───────────────────────────────────────────────────────────────
Write-Host "  Upgrading pip..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: pip upgrade failed (non-fatal)." -ForegroundColor Yellow
}

# ── Install dependencies ──────────────────────────────────────────────────────
Write-Host "  Installing dependencies..." -ForegroundColor Yellow
& .\.venv\Scripts\pip.exe install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: pip install failed. Check requirements.txt and your network connection." -ForegroundColor Red
    exit 1
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Installation complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Quick scan (plain-English report):" -ForegroundColor Cyan
Write-Host '    .\.venv\Scripts\python.exe audit.py --mode config --profile smb --target test\fixtures\deploy-hardened --output plain' -ForegroundColor White
Write-Host ""
Write-Host "  Scan your own directory:" -ForegroundColor Cyan
Write-Host '    .\.venv\Scripts\python.exe audit.py --mode config --target C:\path\to\your\project --profile smb --output plain' -ForegroundColor White
Write-Host ""
