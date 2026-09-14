# Arckon Agent — Intune detection script (Windows)
# Intune runs this to check if the agent is installed.
# Returns exit code 0 if detected, 1 if not.

$AgentExe = "C:\Program Files\Arckon\agent.exe"
$ConfigFile = "C:\ProgramData\Arckon\agent_config.json"

if ((Test-Path $AgentExe) -and (Test-Path $ConfigFile)) {
    # Verify the service exists
    $svc = Get-Service -Name "ArckonAgent" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "Detected: agent.exe + config + service"
        exit 0
    }
}

Write-Host "Not detected"
exit 1