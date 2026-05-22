#Requires -RunAsAdministrator
<#
.SYNOPSIS
    M.A.R.K. Sentinel Agent — Windows Installer

.DESCRIPTION
    Installs the Sentinel Agent to C:\Program Files\Sentinel\, creates config at
    C:\ProgramData\Sentinel\agent_config.json, and optionally registers a Windows Service.

.PARAMETER Server
    Sentinel server URL (e.g. http://10.0.1.50:7331)

.PARAMETER Token
    Agent authentication token

.PARAMETER NoService
    Skip Windows Service registration

.EXAMPLE
    .\install.ps1 -Server http://10.0.1.50:7331 -Token mysecrettoken
#>
[CmdletBinding()]
param(
    [string]$Server     = "",
    [string]$Token      = "",
    [switch]$NoService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir  = "C:\Program Files\Sentinel"
$ConfigDir   = "C:\ProgramData\Sentinel"
$ConfigFile  = "$ConfigDir\agent_config.json"
$ServiceName = "SentinelAgent"
$ScriptDir   = $PSScriptRoot

function Write-Step {
    param([string]$Msg)
    Write-Host "  $Msg" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Msg)
    Write-Host "  [OK] $Msg" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "  [WARN] $Msg" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "M.A.R.K. Sentinel Agent — Windows Installer" -ForegroundColor White
Write-Host "============================================" -ForegroundColor DarkGray
Write-Host ""

# ── Python 3.11+ check ────────────────────────────────────────────────────────

Write-Step "Checking for Python 3.11+ ..."

$PythonExe = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $verOutput = & $candidate --version 2>&1
        if ($verOutput -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 11)) {
                $PythonExe = (Get-Command $candidate -ErrorAction SilentlyContinue).Source
                if (-not $PythonExe) { $PythonExe = $candidate }
                Write-OK "Found $candidate — Python $major.$minor"
                break
            }
        }
    } catch { }
}

if (-not $PythonExe) {
    Write-Error "Python 3.11 or later is required but was not found in PATH.`nInstall from https://www.python.org/downloads/ then re-run."
    exit 1
}

# ── Install pip dependencies ──────────────────────────────────────────────────

Write-Step "Installing Python dependencies ..."
$ReqFile = Join-Path $ScriptDir "requirements.txt"
if (Test-Path $ReqFile) {
    & $PythonExe -m pip install --quiet --upgrade pip
    & $PythonExe -m pip install --quiet -r $ReqFile
    Write-OK "Dependencies installed"
} else {
    Write-Warn "requirements.txt not found, skipping."
}

# ── Copy files ────────────────────────────────────────────────────────────────

Write-Step "Copying files to $InstallDir ..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$FilesToCopy = @("agent.py", "audit.py", "storage.py", "server.py", "requirements.txt")
foreach ($f in $FilesToCopy) {
    $src = Join-Path $ScriptDir $f
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $InstallDir -Force
    }
}

$DirsToCopy = @("checks", "connectors", "profiles")
foreach ($d in $DirsToCopy) {
    $src = Join-Path $ScriptDir $d
    if (Test-Path $src) {
        $dst = Join-Path $InstallDir $d
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Copy-Item -Path $src -Destination $dst -Recurse -Force
    }
}

Write-OK "Files copied to $InstallDir"

# ── Create config ─────────────────────────────────────────────────────────────

Write-Step "Configuring $ConfigFile ..."
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

if (-not (Test-Path $ConfigFile)) {
    $ExampleConfig = Join-Path $ScriptDir "agent_config.json.example"
    if (Test-Path $ExampleConfig) {
        Copy-Item -Path $ExampleConfig -Destination $ConfigFile -Force
    } else {
        @{
            server   = "http://localhost:7331"
            token    = "replace-with-your-secret-token"
            target   = "."
            profile  = "default"
            interval = 3600
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
    }
    Write-OK "Created default config"
}

if ($Server -ne "" -or $Token -ne "") {
    $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    if ($Server -ne "")  { $cfg.server = $Server }
    if ($Token  -ne "")  { $cfg.token  = $Token  }
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-OK "Config updated"
}

# Lock config file permissions to Administrators + SYSTEM only
$acl = Get-Acl $ConfigFile
$acl.SetAccessRuleProtection($true, $false)
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow")
$acl.AddAccessRule($rule1)
$acl.AddAccessRule($rule2)
Set-Acl -Path $ConfigFile -AclObject $acl

# ── Windows Service registration ──────────────────────────────────────────────

if (-not $NoService) {
    Write-Step "Registering Windows Service '$ServiceName' ..."

    $nssmCmd = Get-Command "nssm" -ErrorAction SilentlyContinue; $nssmPath = if ($nssmCmd) { $nssmCmd.Source } else { $null }

    if ($nssmPath) {
        Write-Step "Using NSSM to create service ..."

        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            Write-Step "Stopping existing service ..."
            & nssm stop $ServiceName 2>$null
            & nssm remove $ServiceName confirm 2>$null
        }

        & nssm install $ServiceName $PythonExe
        & nssm set $ServiceName AppParameters "`"$InstallDir\agent.py`" --daemon --config `"$ConfigFile`""
        & nssm set $ServiceName AppDirectory $InstallDir
        & nssm set $ServiceName DisplayName "M.A.R.K. Sentinel Agent"
        & nssm set $ServiceName Description "Distributed security audit agent (M.A.R.K. Sentinel)"
        & nssm set $ServiceName Start SERVICE_AUTO_START
        & nssm set $ServiceName AppRestartDelay 30000
        & nssm set $ServiceName AppStdout "$env:ProgramData\Sentinel\sentinel-agent.log"
        & nssm set $ServiceName AppStderr "$env:ProgramData\Sentinel\sentinel-agent.log"
        & nssm set $ServiceName AppEnvironmentExtra "PYTHONUTF8=1" "SENTINEL_SERVER=" "SENTINEL_AGENT_TOKEN="
        & nssm start $ServiceName
        Write-OK "Service registered and started via NSSM"

    } else {
        Write-Warn "NSSM not found; falling back to sc.exe wrapper script."

        $WrapperScript = "$InstallDir\sentinel-service.ps1"
        @"
# Auto-generated service wrapper for M.A.R.K. Sentinel Agent
Set-Location '$InstallDir'
`$env:PYTHONUNBUFFERED = '1'
`$env:PYTHONUTF8 = '1'
& '$PythonExe' '$InstallDir\agent.py' --daemon --config '$ConfigFile' 2>&1 |
    Tee-Object -FilePath '$ConfigDir\sentinel-agent.log' -Append
"@ | Set-Content -Path $WrapperScript -Encoding UTF8

        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
        }

        $pwshCmd = Get-Command "pwsh" -ErrorAction SilentlyContinue; $pwshExe = if ($pwshCmd) { $pwshCmd.Source } else { $null }
        if (-not $pwshExe) {
            $pwshExe = (Get-Command "powershell" -ErrorAction SilentlyContinue).Source
        }

        sc.exe create $ServiceName `
            binPath= "`"$pwshExe`" -NonInteractive -NoProfile -File `"$WrapperScript`"" `
            start= auto `
            DisplayName= "M.A.R.K. Sentinel Agent" | Out-Null

        sc.exe description $ServiceName "Distributed security audit agent (M.A.R.K. Sentinel)" | Out-Null
        sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/30000/restart/30000 | Out-Null

        Start-Service -Name $ServiceName
        Write-OK "Service registered and started via sc.exe"
        Write-Warn "For production use, install NSSM (https://nssm.cc) for better service management."
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-OK "Service is running"
    } else {
        Write-Warn "Service may not have started — check Event Viewer or $ConfigDir\sentinel-agent.log"
    }
} else {
    Write-Host "  Skipping service registration (--NoService)." -ForegroundColor DarkGray
    Write-Host "  To start manually: & '$PythonExe' '$InstallDir\agent.py' --config '$ConfigFile' --daemon" -ForegroundColor DarkGray
}

# ── Desktop shortcut → opens fleet dashboard in browser ──────────────────────
$ShortcutPath = [Environment]::GetFolderPath('Desktop') + '\Sentinel Dashboard.url'
$DashUrl = if ($Server) { $Server.TrimEnd('/') + '/fleet' } else { 'http://localhost:7331/fleet' }
try {
    Set-Content -Path $ShortcutPath -Value "[InternetShortcut]`r`nURL=$DashUrl`r`nIconIndex=0`r`n" -Encoding ASCII
    Write-OK "Desktop shortcut created: $ShortcutPath"
} catch {
    Write-Warn "Could not create desktop shortcut: $_"
}

Write-Host ""
Write-Host "M.A.R.K. Sentinel Agent installed successfully." -ForegroundColor Green
Write-Host "  Install dir : $InstallDir"
Write-Host "  Config      : $ConfigFile"
Write-Host "  Shortcut    : $ShortcutPath"
Write-Host ""
Write-Host "Edit $ConfigFile to set your server URL and token, then restart the service."
Write-Host "Or open the fleet dashboard and use Settings to update the config without a terminal."
