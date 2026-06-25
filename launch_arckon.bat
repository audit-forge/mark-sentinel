@echo off
:: Arckon by RiskRaven — Windows Launcher
:: Double-click to start the dashboard server silently and open your browser.
:: The server runs in the background — close this window at any time.

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Python not found. Install from https://python.org and try again.', 'Arckon by RiskRaven')"
  exit /b 1
)

:: Check if server is already running
curl -sf http://localhost:7331/ >nul 2>&1
if not errorlevel 1 (
  start "" http://localhost:7331
  exit /b 0
)

:: Start server hidden in background
SET PYTHONUTF8=1
start "" /b python server.py --no-browser > .arckon.log 2>&1

:: Wait for server to respond (up to 6 seconds)
for /l %%i in (1,1,20) do (
  timeout /t 1 /nobreak >nul
  curl -sf http://localhost:7331/ >nul 2>&1
  if not errorlevel 1 (
    start "" http://localhost:7331
    exit /b 0
  )
)

:: Server didn't start — show error
powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Arckon failed to start. Check .arckon.log in the project folder.', 'Arckon by RiskRaven', 'OK', 'Error')"
exit /b 1
