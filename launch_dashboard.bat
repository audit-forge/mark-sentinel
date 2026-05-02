@echo off
:: M.A.R.K. Sentinel — Dashboard Launcher (Windows)
:: Double-click this file to start the dashboard server and open your browser.

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python not found. Install from https://python.org and try again.
  pause
  exit /b 1
)

echo   M.A.R.K. Sentinel — starting dashboard server...
echo   Open: http://localhost:7331
echo   Press Ctrl+C to stop
echo.

python server.py
pause
