#Requires -RunAsAdministrator
<#
.SYNOPSIS
    M.A.R.K. Sentinel — Windows Code Signing Pipeline

.DESCRIPTION
    Signs the PowerShell installer and optionally a PyInstaller-built .exe
    using an Authenticode code signing certificate from the Windows cert store.

    Prerequisites:
      1. EV or OV Code Signing certificate installed in cert store
           Recommended: DigiCert EV Code Signing (~$300/yr) — digicert.com
           EV gets immediate SmartScreen trust; OV requires reputation buildup
      2. signtool.exe — ships with Windows SDK / Visual Studio Build Tools
           winget install Microsoft.WindowsSDK.10.0.22621
      3. For EV certs: the USB hardware token must be plugged in

    Usage:
      .\scripts\sign_windows.ps1
      .\scripts\sign_windows.ps1 -SkipExe          # sign PS scripts only
      .\scripts\sign_windows.ps1 -TimestampUrl http://custom-tsa.example.com

.PARAMETER CertThumbprint
    SHA-1 thumbprint of the cert to use. If omitted, the script selects the
    first valid code-signing cert in CurrentUser\My automatically.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server URL. Defaults to DigiCert's public TSA.

.PARAMETER SkipExe
    Skip signing sentinel-agent.exe (use if not building a PyInstaller bundle).
#>
[CmdletBinding()]
param(
    [string]$CertThumbprint = "",
    [string]$TimestampUrl   = "http://timestamp.digicert.com",
    [switch]$SkipExe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path $PSScriptRoot -Parent
$DistDir  = Join-Path $RepoRoot "dist"

function Write-Step { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "M.A.R.K. Sentinel — Windows Signing Pipeline" -ForegroundColor White
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Locate signtool.exe ───────────────────────────────────────────────────────

Write-Step "Locating signtool.exe ..."

$SignTool = (Get-Command "signtool.exe" -ErrorAction SilentlyContinue)?.Source
if (-not $SignTool) {
    $sdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    foreach ($root in $sdkRoots) {
        $found = Get-ChildItem -Path $root -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match "x64" } |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
        if ($found) { $SignTool = $found.FullName; break }
    }
}
if (-not $SignTool) {
    Write-Error "signtool.exe not found.`nInstall Windows SDK: winget install Microsoft.WindowsSDK.10.0.22621"
    exit 1
}
Write-OK "Found: $SignTool"

# ── Select certificate ────────────────────────────────────────────────────────

Write-Step "Selecting code signing certificate ..."

if ($CertThumbprint -ne "") {
    $Cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Thumbprint -eq $CertThumbprint } |
            Select-Object -First 1
    if (-not $Cert) {
        Write-Error "Certificate with thumbprint '$CertThumbprint' not found in CurrentUser\My."
        exit 1
    }
} else {
    $Cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object {
                $_.NotAfter -gt (Get-Date) -and
                ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" })
            } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

    if (-not $Cert) {
        Write-Error "No valid code signing certificate found in CurrentUser\My.`nImport your cert or specify -CertThumbprint."
        exit 1
    }
}

Write-OK "Using: $($Cert.Subject)"
Write-OK "Expires: $($Cert.NotAfter.ToString('yyyy-MM-dd'))"
$Thumbprint = $Cert.Thumbprint

# ── Sign PowerShell installer ─────────────────────────────────────────────────

Write-Step "Signing install.ps1 ..."

$InstallPs1 = Join-Path $RepoRoot "install.ps1"
if (-not (Test-Path $InstallPs1)) {
    Write-Warn "install.ps1 not found at $InstallPs1 — skipping."
} else {
    Set-AuthenticodeSignature `
        -FilePath    $InstallPs1 `
        -Certificate $Cert `
        -TimestampServer $TimestampUrl `
        -HashAlgorithm SHA256 | Out-Null

    $sig = Get-AuthenticodeSignature -FilePath $InstallPs1
    if ($sig.Status -ne "Valid") {
        Write-Error "Signature verification failed for install.ps1: $($sig.StatusMessage)"
        exit 1
    }
    Write-OK "install.ps1 signed and verified"
}

# ── Sign install.bat wrapper (via catalog — .bat files use Authenticode via catalog) ──
# Note: .bat files can't be directly signed with Set-AuthenticodeSignature.
# The recommended approach is to embed the batch logic in a signed PS wrapper,
# which install.ps1 already is. The .bat is just a bootstrap that calls it.
Write-Warn "install.bat: .bat files cannot carry an Authenticode signature directly."
Write-Warn "  Mitigation: the signed install.ps1 is the authoritative installer."
Write-Warn "  install.bat calls Set-ExecutionPolicy Bypass and invokes install.ps1."

# ── Sign PyInstaller .exe (if present) ───────────────────────────────────────

if (-not $SkipExe) {
    $ExePath = Join-Path $DistDir "sentinel-agent.exe"
    if (Test-Path $ExePath) {
        Write-Step "Signing sentinel-agent.exe ..."

        & $SignTool sign `
            /sha1      $Thumbprint `
            /fd        sha256 `
            /tr        $TimestampUrl `
            /td        sha256 `
            /d         "M.A.R.K. Sentinel Agent" `
            /du        "https://mark-sentinel.com" `
            $ExePath

        & $SignTool verify /pa /v $ExePath
        Write-OK "sentinel-agent.exe signed and verified"
    } else {
        Write-Warn "dist\sentinel-agent.exe not found — skipping .exe signing."
        Write-Warn "  To build: pip install pyinstaller && pyinstaller scripts\sentinel_agent.spec"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  Cert subject : $($Cert.Subject)"
Write-Host "  Cert expires : $($Cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "Signed files:"
foreach ($f in @("install.ps1", "dist\sentinel-agent.exe")) {
    $p = Join-Path $RepoRoot $f
    if (Test-Path $p) {
        $s = Get-AuthenticodeSignature -FilePath $p
        Write-Host "  $f — $($s.Status)"
    }
}
Write-Host ""
Write-Host "Windows Defender and SmartScreen will trust signed files from a known publisher."
Write-Host "EV certificates get immediate SmartScreen trust; OV certs build reputation over time."
