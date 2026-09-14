#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Arckon Agent — Intune Win32 App installer (Windows)

.DESCRIPTION
    Downloads and installs the Arckon agent binary from the Arckon server,
    creates the config file, registers the NSSM service, and verifies
    connectivity. Designed for Microsoft Intune Win32 app deployment
    (System context, no user interaction).

.PARAMETER Server
    Arckon server URL (e.g. https://arckon.riskraven.ai)

.PARAMETER Token
    Agent authentication token (provisioned per customer in the admin panel)

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File install-intune.ps1 -Server "https://arckon.riskraven.ai" -Token "YOUR_TOKEN"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [string]$Token
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir  = "C:\Program Files\Arckon"
$ConfigDir   = "C:\ProgramData\Arckon"
$ConfigFile  = "$ConfigDir\agent_config.json"
$InstallLog  = "$ConfigDir\install.log"
$ServiceName = "ArckonAgent"

if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
Start-Transcript -Path $InstallLog -Append -Force | Out-Null

$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
function Write-FileNoBOM { param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom) }

Write-Host "Arckon Agent — Intune installation starting"

# -- Stop and remove existing service if present -------------------------------
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "Stopping existing $ServiceName service ..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# -- Prepare install directory -------------------------------------------------
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# -- Fetch signed release manifest from server ---------------------------------
Write-Host "Fetching release manifest from $Server ..."
$ManifestUrl = $Server.TrimEnd('/') + '/releases/windows/manifest.json'
$Headers = @{ Authorization = "Bearer $Token" }

try {
    $Manifest = Invoke-RestMethod -Uri $ManifestUrl -Headers $Headers -TimeoutSec 30
} catch {
    Write-Error "Cannot fetch manifest from $ManifestUrl : $_"
    Stop-Transcript | Out-Null
    exit 1
}

$Artifact    = $Manifest.artifact
$ArtifactSha = $Manifest.sha256
$Version     = $Manifest.version
Write-Host "Release v$Version — artifact: $Artifact"

# -- Download artifact ---------------------------------------------------------
$ArtifactUrl  = $Server.TrimEnd('/') + '/releases/windows/' + $Artifact
$ArtifactTmp  = Join-Path $env:TEMP $Artifact
Write-Host "Downloading $ArtifactUrl ..."

try {
    Invoke-WebRequest -Uri $ArtifactUrl -Headers $Headers -OutFile $ArtifactTmp -UseBasicParsing -TimeoutSec 120
} catch {
    Write-Error "Download failed: $_"
    Stop-Transcript | Out-Null
    exit 1
}

# -- Verify SHA256 -------------------------------------------------------------
$DownloadedHash = (Get-FileHash $ArtifactTmp -Algorithm SHA256).Hash.ToLower()
if ($DownloadedHash -ne $ArtifactSha.ToLower()) {
    Write-Error "SHA256 mismatch! Expected $ArtifactSha, got $DownloadedHash"
    Remove-Item $ArtifactTmp -Force -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
    exit 1
}
Write-Host "SHA256 verified"

# -- Extract -------------------------------------------------------------------
$ExtractTmp = Join-Path $env:TEMP "arckon-intune-extract"
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
Write-Host "Agent extracted to $InstallDir"

# -- Create config -------------------------------------------------------------
if (-not (Test-Path $ConfigFile)) {
    $ConfigJson = @{
        server   = $Server.TrimEnd('/')
        token    = $Token
        target   = "~"
        profile  = "default"
        interval = 3600
    }
    Write-FileNoBOM $ConfigFile ($ConfigJson | ConvertTo-Json -Depth 5)
} else {
    $cfg = [System.IO.File]::ReadAllText($ConfigFile, $Utf8NoBom).TrimStart([char]0xFEFF) | ConvertFrom-Json
    $cfg.server = $Server.TrimEnd('/')
    $cfg.token  = $Token
    Write-FileNoBOM $ConfigFile ($cfg | ConvertTo-Json -Depth 5)
}

$acl = Get-Acl $ConfigFile
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")))
Set-Acl -Path $ConfigFile -AclObject $acl
Write-Host "Config written to $ConfigFile"

# -- Verify agent.exe is present -----------------------------------------------
$AgentExe = Join-Path $InstallDir "agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Error "agent.exe not found at $InstallDir after extraction"
    Stop-Transcript | Out-Null
    exit 1
}
Write-Host "agent.exe present"

# -- Download and install NSSM -------------------------------------------------
$nssmDir  = "$env:ProgramData\Arckon\nssm"
$nssmExe  = "$nssmDir\nssm.exe"
if (-not (Test-Path $nssmExe)) {
    New-Item -ItemType Directory -Path $nssmDir -Force | Out-Null
    $nssmZip     = "$env:TEMP\nssm-intune.zip"
    $nssmExtract = "$env:TEMP\nssm-intune-extract"
    try {
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $arch   = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
        $nssmSrc = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" |
            Where-Object { $_.FullName -like "*\$arch\*" } | Select-Object -First 1
        if ($nssmSrc) { Copy-Item -Path $nssmSrc.FullName -Destination $nssmExe -Force }
        Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Could not download NSSM: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
}

# -- Register Windows Service via NSSM -----------------------------------------
Write-Host "Registering service $ServiceName ..."
& $nssmExe install $ServiceName $AgentExe
& $nssmExe set $ServiceName AppParameters "--daemon --config `"$ConfigFile`""
& $nssmExe set $ServiceName AppDirectory $InstallDir
& $nssmExe set $ServiceName DisplayName "Arckon Agent"
& $nssmExe set $ServiceName Description "AI security audit agent (Arckon by RiskRaven)"
& $nssmExe set $ServiceName Start SERVICE_AUTO_START
& $nssmExe set $ServiceName AppRestartDelay 30000
& $nssmExe set $ServiceName AppStdout "$env:ProgramData\Arckon\arckon-agent.log"
& $nssmExe set $ServiceName AppStderr "$env:ProgramData\Arckon\arckon-agent.log"
& $nssmExe set $ServiceName AppEnvironmentExtra "PYTHONUTF8=1" "SENTINEL_SERVER=" "SENTINEL_AGENT_TOKEN=" "SENTINEL_ALLOW_HTTP_UPDATE=1"
& $nssmExe start $ServiceName
Write-Host "Service registered and started"

# -- Verify service is running -------------------------------------------------
Start-Sleep -Seconds 5
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "Service is running"
} else {
    Write-Warning "Service not running after install — will retry ..."
    Start-Sleep -Seconds 5
    try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch {}
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "Service is running (retry succeeded)"
    } else {
        Write-Warning "Service failed to start — check $ConfigDir\arckon-agent.log"
    }
}

# -- Verify server connectivity -------------------------------------------------
Write-Host "Verifying server connectivity ..."
try {
    $healthUrl = $Server.TrimEnd('/') + '/health'
    $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    if ($resp.StatusCode -eq 200) {
        Write-Host "Server reachable at $Server"
    }
} catch {
    Write-Warning "Cannot reach $Server — agent will retry on its own"
}

# -- Repair watchdog (same as interactive install) -----------------------------
$RepairScript = "$ConfigDir\repair-arckon.cmd"
$RepairBody = @"
@echo off
setlocal enabledelayedexpansion
set "INSTALLDIR=C:\Program Files\Arckon"
set "LIVE=%INSTALLDIR%\agent.exe"
set "STAGED=%INSTALLDIR%\agent.exe.new"
set "BACKUP=%INSTALLDIR%\agent.exe.bak"
set "SVC=ArckonAgent"
set "REPAIRED=0"
if exist "%LIVE%" goto :check_service
if exist "%STAGED%" ( copy /y "%STAGED%" "%LIVE%" >nul 2>&1 && set REPAIRED=1 )
if "%REPAIRED%"=="0" if exist "%BACKUP%" ( copy /y "%BACKUP%" "%LIVE%" >nul 2>&1 && set REPAIRED=1 )
if "%REPAIRED%"=="0" exit /b 1
:check_service
sc start "%SVC%" >nul 2>&1
timeout /t 3 /nobreak >nul
sc query "%SVC%" | find "RUNNING" >nul || sc start "%SVC%" >nul 2>&1
exit /b 0
"@
[System.IO.File]::WriteAllText($RepairScript, $RepairBody, $Utf8NoBom)

$taskName = "ArckonRepairWatchdog"
$taskAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$RepairScript`""
$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
try {
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force | Out-Null
    Write-Host "Repair watchdog registered"
} catch {
    Write-Warning "Could not register repair watchdog: $_"
}

Write-Host "Arckon Agent installed successfully (v$Version)"
Stop-Transcript | Out-Null
exit 0