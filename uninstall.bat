@echo off
:: M.A.R.K. Sentinel Agent -- Windows Uninstaller (Batch)
:: Run as Administrator: uninstall.bat
:: For richer output and NSSM support, use uninstall.ps1 instead.

setlocal EnableDelayedExpansion

set "INSTALL_DIR=C:\Program Files\Sentinel"
set "CONFIG_DIR=C:\ProgramData\Sentinel"
set "SERVICE_NAME=SentinelAgent"
set "SCRIPT_DIR=%~dp0"

echo.
echo   M.A.R.K. Sentinel Agent -- Windows Uninstaller
echo   =============================================
echo.

:: ── Admin check ──────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: This uninstaller must be run as Administrator.
    echo   Right-click uninstall.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: ── Try uninstall.ps1 first (works when ExecutionPolicy allows it) ────────────
where pwsh >nul 2>&1
if %errorlevel% == 0 set "PWSH_EXE=pwsh"
where powershell >nul 2>&1
if %errorlevel% == 0 if not defined PWSH_EXE set "PWSH_EXE=powershell"

if defined PWSH_EXE (
    if exist "%SCRIPT_DIR%uninstall.ps1" (
        echo   PowerShell detected -- delegating to uninstall.ps1 ^(full uninstall^)...
        echo.
        %PWSH_EXE% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%uninstall.ps1"
        exit /b %errorlevel%
    )
)

echo   [INFO] PowerShell unavailable -- running batch uninstall ^(no NSSM^).
echo.

:: ── Stop and delete service ──────────────────────────────────────────────────
echo   Removing Windows Service "%SERVICE_NAME%" if present...
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% == 0 (
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo   [OK] Service removed via sc.exe
) else (
    echo   Service "%SERVICE_NAME%" not found, skipping.
)

:: ── Remove directories ───────────────────────────────────────────────────────
echo   Removing install and config directories...
if exist "%INSTALL_DIR%" (
    rd /s /q "%INSTALL_DIR%" >nul 2>&1
    echo   [OK] Removed %INSTALL_DIR%
) else (
    echo   %INSTALL_DIR% not found, skipping.
)

if exist "%CONFIG_DIR%" (
    rd /s /q "%CONFIG_DIR%" >nul 2>&1
    echo   [OK] Removed %CONFIG_DIR%
) else (
    echo   %CONFIG_DIR% not found, skipping.
)

:: ── Remove desktop shortcut ──────────────────────────────────────────────────
if exist "%USERPROFILE%\Desktop\Sentinel Dashboard.url" (
    del /f /q "%USERPROFILE%\Desktop\Sentinel Dashboard.url" >nul 2>&1
    echo   [OK] Desktop shortcut removed
) else (
    echo   Desktop shortcut not found, skipping.
)

echo.
echo   M.A.R.K. Sentinel Agent has been uninstalled.
echo   Removed install dir : %INSTALL_DIR%
echo   Removed config      : %CONFIG_DIR%
echo.

endlocal
pause
