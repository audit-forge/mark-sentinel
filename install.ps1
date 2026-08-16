#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Arckon Agent - Windows Installer

.DESCRIPTION
    Installs the Arckon Agent to C:\Program Files\Arckon\, creates config at
    C:\ProgramData\Arckon\agent_config.json, and optionally registers a Windows Service.

.PARAMETER Server
    Arckon server URL (e.g. http://10.0.1.50:7331)

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

$InstallDir  = "C:\Program Files\Arckon"
$ConfigDir   = "C:\ProgramData\Arckon"
$ConfigFile  = "$ConfigDir\agent_config.json"
$InstallLog  = "$ConfigDir\install.log"
$ServiceName = "ArckonAgent"
$LegacyServiceName = "SentinelAgent"
$ScriptDir   = if ($PSScriptRoot -and $PSScriptRoot -ne "") { $PSScriptRoot } else { $PWD.Path }

if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
Start-Transcript -Path $InstallLog -Append -Force | Out-Null

$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
function Write-FileNoBOM { param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom) }

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
Write-Host "Arckon Agent - Windows Installer" -ForegroundColor White
Write-Host "============================================" -ForegroundColor DarkGray
Write-Host ""

# -- Python 3.11+ check --------------------------------------------------------

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
                Write-OK "Found $candidate - Python $major.$minor"
                break
            }
        }
    } catch { }
}

if (-not $PythonExe) {
    Write-Warn "Python 3.11+ not found. It is only required if binary download fails."
}

# -- Prepare install directory -------------------------------------------------

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# -- Download Nuitka binary release from server (web install path) -------------

if ($Server -ne "") {
    Write-Step "Downloading Arckon agent from $Server ..."

    # Fetch the signed manifest
    $ManifestUrl = $Server.TrimEnd('/') + '/releases/windows/manifest.json'
    $Headers = @{ Authorization = "Bearer $Token" }
    try {
        $Manifest = Invoke-RestMethod -Uri $ManifestUrl -Headers $Headers -TimeoutSec 30
        $Artifact = $Manifest.artifact
        $ArtifactSha256 = $Manifest.sha256
        $ArtifactSize = $Manifest.size
        $Version = $Manifest.version
        Write-OK "Release v$Version found ($Artifact, $ArtifactSize bytes)"
    } catch {
        Write-Warn "Could not fetch manifest: $_"
        $Manifest = $null
    }

    if ($Manifest) {
        # Download the artifact
        $ArtifactUrl = $Server.TrimEnd('/') + '/releases/windows/' + $Artifact
        $ArtifactTmp = Join-Path $env:TEMP $Artifact
        try {
            Invoke-WebRequest -Uri $ArtifactUrl -Headers $Headers -OutFile $ArtifactTmp -UseBasicParsing -TimeoutSec 120
            Write-OK "Downloaded $Artifact"

            # Verify SHA256
            $DownloadedHash = (Get-FileHash $ArtifactTmp -Algorithm SHA256).Hash.ToLower()
            if ($DownloadedHash -ne $ArtifactSha256.ToLower()) {
                throw "SHA256 mismatch! Expected $ArtifactSha256, got $DownloadedHash"
            } else {
                Write-OK "SHA256 verified"
            }

            # Windows locks a running executable. Stop the current service only
            # after the replacement has downloaded and passed its hash check.
            $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($existingSvc -and $existingSvc.Status -ne "Stopped") {
                Write-Step "Stopping existing service before replacing agent.exe ..."
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $existingSvc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(15))
            }

            # Extract to a temp directory, then copy contents (strip sentinel/ prefix)
            $ExtractTmp = Join-Path $env:TEMP "arckon-extract"
            if (Test-Path $ExtractTmp) { Remove-Item $ExtractTmp -Recurse -Force }
            New-Item -ItemType Directory -Path $ExtractTmp -Force | Out-Null
            tar -xzf $ArtifactTmp -C $ExtractTmp
            $SentinelSubdir = Join-Path $ExtractTmp "sentinel"
            if (Test-Path $SentinelSubdir) {
                Get-ChildItem -Path $SentinelSubdir | Copy-Item -Destination $InstallDir -Recurse -Force
            } else {
                Get-ChildItem -Path $ExtractTmp | Copy-Item -Destination $InstallDir -Recurse -Force
            }
            Remove-Item $ExtractTmp -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $ArtifactTmp -Force -ErrorAction SilentlyContinue
            Write-OK "Agent extracted to $InstallDir"
        } catch {
            Write-Warn "Could not download artifact: $_"
            Write-Warn "Falling back to local file copy."
        }
    } else {
        Write-Warn "Falling back to local file copy."
    }
}

# -- Copy files (local fallback only; Nuitka binary download is preferred) ------

if (-not (Test-Path (Join-Path $InstallDir "agent.exe")) -and -not (Test-Path (Join-Path $InstallDir "agent.py"))) {
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
}

# -- Install pip dependencies (only if using Python fallback, not Nuitka) -------

$AgentExe = Join-Path $InstallDir "agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Step "Installing Python dependencies ..."
    $ReqFile = Join-Path $InstallDir "requirements.txt"
    if (Test-Path $ReqFile) {
        & $PythonExe -m pip install --quiet --upgrade pip
        & $PythonExe -m pip install --quiet -r $ReqFile
        Write-OK "Dependencies installed"
    }
}

# -- Create config -------------------------------------------------------------

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
            target   = "~"
            profile  = "default"
            interval = 3600
        } | ConvertTo-Json -Depth 5 | ForEach-Object { Write-FileNoBOM $ConfigFile $_ }
    }
    Write-OK "Created default config"
}

if ($Server -ne "" -or $Token -ne "") {
    $cfg = [System.IO.File]::ReadAllText($ConfigFile, $Utf8NoBom).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($Server -ne "")  { $cfg.server = $Server }
    if ($Token  -ne "")  { $cfg.token  = $Token  }
    Write-FileNoBOM $ConfigFile ($cfg | ConvertTo-Json -Depth 5)
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

# -- Verify agent files are present --------------------------------------------

$AgentExe = "$InstallDir\agent.exe"
$AgentScript = "$InstallDir\agent.py"
if (-not (Test-Path $AgentExe) -and -not (Test-Path $AgentScript)) {
    Write-Host ""
    Write-Host "  [FAIL] Neither agent.exe nor agent.py found at $InstallDir" -ForegroundColor Red
    Write-Host "         Download may have failed. Check network connectivity and token." -ForegroundColor Yellow
    Stop-Transcript | Out-Null
    if ([Environment]::UserInteractive) { Read-Host "`n  Press Enter to close" }
    exit 1
}
if (Test-Path $AgentExe) {
    Write-OK "Agent binary (agent.exe) present at $InstallDir"
} else {
    Write-OK "Agent script (agent.py) present at $InstallDir"
}

# -- Windows Service registration ----------------------------------------------

if (-not $NoService) {
    Write-Step "Registering Windows Service '$ServiceName' ..."

    $nssmCmd = Get-Command "nssm" -ErrorAction SilentlyContinue; $nssmPath = if ($nssmCmd) { $nssmCmd.Source } else { $null }

    if (-not $nssmPath) {
        Write-Step "NSSM not found -- downloading it for proper Windows Service support ..."
        try {
            $nssmDir = "$env:ProgramData\Arckon\nssm"
            $nssmExe = "$nssmDir\nssm.exe"
            if (-not (Test-Path $nssmExe)) {
                New-Item -ItemType Directory -Path $nssmDir -Force | Out-Null
                $nssmZip     = "$env:TEMP\nssm-$([guid]::NewGuid()).zip"
                $nssmExtract = "$env:TEMP\nssm-extract-$([guid]::NewGuid())"
                Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60
                Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
                $arch   = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
                $nssmSrc = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" |
                    Where-Object { $_.FullName -like "*\$arch\*" } | Select-Object -First 1
                if ($nssmSrc) {
                    Copy-Item -Path $nssmSrc.FullName -Destination $nssmExe -Force
                    $nssmPath = $nssmExe
                    Write-OK "NSSM downloaded to $nssmPath"
                } else {
                    Write-Warn "Downloaded NSSM archive but couldn't find nssm.exe for $arch inside it."
                }
                Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
                Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                $nssmPath = $nssmExe
                Write-OK "NSSM already present at $nssmPath"
            }
        } catch {
            Write-Warn "Could not download NSSM automatically: $_"
        }
    }

    if ($nssmPath) {
        Write-Step "Using NSSM to create service ..."

        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            Write-Step "Stopping existing service ..."
            $ErrorActionPreference = "Continue"
            & $nssmPath stop $ServiceName 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            & $nssmPath remove $ServiceName confirm 2>&1 | Out-Null
            $ErrorActionPreference = "Stop"
        }

        # Use compiled agent.exe if present, otherwise fall back to python agent.py
        $AgentExe = Join-Path $InstallDir "agent.exe"
        if (Test-Path $AgentExe) {
            & $nssmPath install $ServiceName $AgentExe
            & $nssmPath set $ServiceName AppParameters "--daemon --config `"$ConfigFile`""
        } else {
            if (-not $PythonExe) {
                throw "agent.exe was not installed and Python 3.11+ is unavailable for the source fallback."
            }
            & $nssmPath install $ServiceName $PythonExe
            & $nssmPath set $ServiceName AppParameters "`"$InstallDir\agent.py`" --daemon --config `"$ConfigFile`""
        }
        & $nssmPath set $ServiceName AppDirectory $InstallDir
        & $nssmPath set $ServiceName DisplayName "Arckon Agent"
        & $nssmPath set $ServiceName Description "Distributed security audit agent (Arckon)"
        & $nssmPath set $ServiceName Start SERVICE_AUTO_START
        & $nssmPath set $ServiceName AppRestartDelay 30000
        & $nssmPath set $ServiceName AppStdout "$env:ProgramData\Arckon\arckon-agent.log"
        & $nssmPath set $ServiceName AppStderr "$env:ProgramData\Arckon\arckon-agent.log"
        & $nssmPath set $ServiceName AppEnvironmentExtra "PYTHONUTF8=1" "SENTINEL_SERVER=" "SENTINEL_AGENT_TOKEN=" "SENTINEL_ALLOW_HTTP_UPDATE=1"
        & $nssmPath start $ServiceName
        Write-OK "Service registered and started via NSSM"

    } else {
        throw "NSSM is required for a Windows service. Installation stopped rather than creating a non-SCM-compliant PowerShell service wrapper."
    }

    # The product was formerly branded Sentinel. Remove only the obsolete
    # service after the canonical ArckonAgent service has been registered.
    $legacySvc = Get-Service -Name $LegacyServiceName -ErrorAction SilentlyContinue
    if ($legacySvc) {
        & $nssmPath stop $LegacyServiceName 2>&1 | Out-Null
        & $nssmPath remove $LegacyServiceName confirm 2>&1 | Out-Null
        if (Get-Service -Name $LegacyServiceName -ErrorAction SilentlyContinue) {
            sc.exe stop $LegacyServiceName | Out-Null
            sc.exe delete $LegacyServiceName | Out-Null
        }
        Write-OK "Removed obsolete $LegacyServiceName service"
    }

    # -- Verify service is running (retry up to 3x) ---------------------------
    $started = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            $started = $true
            break
        }
        if ($attempt -lt 3) {
            Write-Warn "Service not yet running (attempt $attempt/3) - retrying ..."
            try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch {}
        }
    }

    if ($started) {
        Write-OK "Service is running"
    } else {
        Write-Host ""
        Write-Host "  [FAIL] Service failed to start." -ForegroundColor Red
        $logFile = "$ConfigDir\arckon-agent.log"
        if (Test-Path $logFile) {
            Write-Host "  Last log entries:" -ForegroundColor Yellow
            Get-Content $logFile -Tail 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
        } else {
            Write-Host "  No log file found at $logFile" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  To diagnose: Get-Content '$logFile' -Tail 50" -ForegroundColor DarkGray
        Stop-Transcript | Out-Null
        if ([Environment]::UserInteractive) { Read-Host "`n  Press Enter to close" }
        exit 1
    }

    # -- Verify server connectivity --------------------------------------------
    if ($Server -ne "") {
        Write-Step "Verifying agent can reach server ..."
        $healthUrl = $Server.TrimEnd('/') + '/health'
        try {
            $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                Write-OK "Server reachable at $Server"
            } else {
                Write-Warn "Server returned HTTP $($resp.StatusCode) - agent may not connect"
            }
        } catch {
            Write-Host "  [WARN] Cannot reach $healthUrl - check firewall or server URL" -ForegroundColor Yellow
            Write-Host "         Error: $_" -ForegroundColor DarkYellow
        }
    }

} else {
    Write-Host "  Skipping service registration (--NoService)." -ForegroundColor DarkGray
    Write-Host "  To start manually: & '$PythonExe' '$InstallDir\agent.py' --config '$ConfigFile' --daemon" -ForegroundColor DarkGray
}

# -- Desktop shortcut -> opens fleet dashboard in browser ----------------------
$ShortcutPath = [Environment]::GetFolderPath('Desktop') + '\Sentinel Dashboard.url'
$DashUrl = if ($Server) { $Server.TrimEnd('/') + '/fleet' } else { 'http://localhost:7331/fleet' }
try {
    Set-Content -Path $ShortcutPath -Value "[InternetShortcut]`r`nURL=$DashUrl`r`nIconIndex=0`r`n" -Encoding ASCII
    Write-OK "Desktop shortcut created: $ShortcutPath"
} catch {
    Write-Warn "Could not create desktop shortcut: $_"
}

Write-Host ""
Write-Host "Arckon Agent installed successfully." -ForegroundColor Green
Write-Host "  Install dir : $InstallDir"
Write-Host "  Config      : $ConfigFile"
Write-Host "  Shortcut    : $ShortcutPath"
Write-Host ""
if ($Server -eq "" -or $Token -eq "") {
    Write-Host "Edit $ConfigFile to set your server URL and token, then restart the service." -ForegroundColor Yellow
}
Write-Host "Or open the fleet dashboard and use Settings to update the config without a terminal."
Write-Host "  Install log : $InstallLog"

Stop-Transcript | Out-Null
if ([Environment]::UserInteractive) { Read-Host "`n  Press Enter to close" }
