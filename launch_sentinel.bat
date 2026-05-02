@echo off
:: M.A.R.K. Sentinel — Windows Launcher
:: Double-click to start the dashboard server silently and open your browser.
:: The server runs in the background — close this window at any time.

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Python not found. Install from https://python.org and try again.', 'M.A.R.K. Sentinel')"
  exit /b 1
)

:: Check if server is already running
curl -sf http://localhost:7331/ >nul 2>&1
if not errorlevel 1 (
  start "" http://localhost:7331
  exit /b 0
)

:: Start server hidden in background
start "" /b python server.py --no-browser > .sentinel.log 2>&1

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
powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Sentinel failed to start. Check .sentinel.log in the project folder.', 'M.A.R.K. Sentinel', 'OK', 'Error')"
exit /b 1
