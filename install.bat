@echo off
:: M.A.R.K. Sentinel Agent -- Windows Installer (Batch)
:: Run as Administrator: install.bat [ServerURL] [Token]
:: Example: install.bat http://10.0.1.50:7331 mysecrettoken
:: For richer output and NSSM support, use install.ps1 instead.

setlocal EnableDelayedExpansion

set "INSTALL_DIR=C:\Program Files\Sentinel"
set "CONFIG_DIR=C:\ProgramData\Sentinel"
set "CONFIG_FILE=%CONFIG_DIR%\agent_config.json"
set "SERVICE_NAME=SentinelAgent"
set "SCRIPT_DIR=%~dp0"
set "SERVER_ARG=%~1"
set "TOKEN_ARG=%~2"

echo.
echo   M.A.R.K. Sentinel Agent -- Windows Installer
echo   =============================================
echo.

:: -- Admin check --------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: This installer must be run as Administrator.
    echo   Right-click install.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: -- Try install.ps1 first (works when ExecutionPolicy allows it) --------------
where pwsh >nul 2>&1
if %errorlevel% == 0 set "PWSH_EXE=pwsh"
where powershell >nul 2>&1
if %errorlevel% == 0 if not defined PWSH_EXE set "PWSH_EXE=powershell"

if defined PWSH_EXE (
    if exist "%SCRIPT_DIR%install.ps1" (
        echo   PowerShell detected -- delegating to install.ps1 ^(full install^)...
        echo.
        if "%SERVER_ARG%"=="" (
            %PWSH_EXE% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1"
        ) else if "%TOKEN_ARG%"=="" (
            %PWSH_EXE% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1" -Server "%SERVER_ARG%"
        ) else (
            %PWSH_EXE% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1" -Server "%SERVER_ARG%" -Token "%TOKEN_ARG%"
        )
        exit /b %errorlevel%
    )
)

echo   [INFO] PowerShell unavailable -- running batch install ^(no NSSM, no color^).
echo.

:: -- Python 3.11+ check -------------------------------------------------------
set "PYTHON_EXE="
for %%C in (python python3 py) do (
    if not defined PYTHON_EXE (
        where %%C >nul 2>&1
        if !errorlevel! == 0 (
            for /f "tokens=2 delims= " %%V in ('%%C --version 2^>^&1') do (
                for /f "tokens=1,2 delims=." %%A in ("%%V") do (
                    set /a "_maj=%%A" 2>nul
                    set /a "_min=%%B" 2>nul
                    if !_maj! gtr 3 set "PYTHON_EXE=%%C"
                    if !_maj! equ 3 if !_min! geq 11 set "PYTHON_EXE=%%C"
                )
            )
        )
    )
)

if not defined PYTHON_EXE (
    echo   ERROR: Python 3.11 or later is required but was not found in PATH.
    echo   Install from https://www.python.org/downloads/
    echo   Check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%V in ('%PYTHON_EXE% --version 2^>^&1') do echo   [OK] Found %%V

:: -- Install pip dependencies -------------------------------------------------
echo   Installing Python dependencies...
if exist "%SCRIPT_DIR%requirements.txt" (
    %PYTHON_EXE% -m pip install --quiet --upgrade pip
    %PYTHON_EXE% -m pip install --quiet -r "%SCRIPT_DIR%requirements.txt"
    if !errorlevel! neq 0 (
        echo   ERROR: pip install failed. Check requirements.txt and network.
        pause
        exit /b 1
    )
    echo   [OK] Dependencies installed
) else (
    echo   [WARN] requirements.txt not found, skipping.
)

:: -- Copy files ---------------------------------------------------------------
echo   Copying files to %INSTALL_DIR%...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

for %%F in (agent.py audit.py storage.py server.py requirements.txt) do (
    if exist "%SCRIPT_DIR%%%F" copy /y "%SCRIPT_DIR%%%F" "%INSTALL_DIR%\" >nul
)

for %%D in (checks connectors profiles) do (
    if exist "%SCRIPT_DIR%%%D" (
        if exist "%INSTALL_DIR%\%%D" rd /s /q "%INSTALL_DIR%\%%D"
        xcopy /e /i /q "%SCRIPT_DIR%%%D" "%INSTALL_DIR%\%%D" >nul
    )
)
echo   [OK] Files copied to %INSTALL_DIR%

:: -- Create config ------------------------------------------------------------
echo   Configuring %CONFIG_FILE%...
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"

if not exist "%CONFIG_FILE%" (
    if exist "%SCRIPT_DIR%agent_config.json.example" (
        copy /y "%SCRIPT_DIR%agent_config.json.example" "%CONFIG_FILE%" >nul
    ) else (
        set "_server=http://localhost:7331"
        set "_token=replace-with-your-secret-token"
        if not "%SERVER_ARG%"=="" set "_server=%SERVER_ARG%"
        if not "%TOKEN_ARG%"=="" set "_token=%TOKEN_ARG%"
        (
            echo {
            echo   "server": "!_server!",
            echo   "token": "!_token!",
            echo   "target": ".",
            echo   "profile": "default",
            echo   "interval": 3600
            echo }
        ) > "%CONFIG_FILE%"
        set "SERVER_ARG="
        set "TOKEN_ARG="
    )
    echo   [OK] Created default config
)

icacls "%CONFIG_FILE%" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" >nul

:: -- Windows Service ----------------------------------------------------------
echo   Registering Windows Service "%SERVICE_NAME%"...

sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% == 0 (
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

set "WRAPPER=%INSTALL_DIR%\run-agent.bat"
(
    echo @echo off
    echo cd /d "%INSTALL_DIR%"
    echo set PYTHONUNBUFFERED=1
    echo set PYTHONUTF8=1
    echo "%PYTHON_EXE%" "%INSTALL_DIR%\agent.py" --daemon --config "%CONFIG_FILE%" >> "%CONFIG_DIR%\sentinel-agent.log" 2>^&1
) > "%WRAPPER%"

sc create %SERVICE_NAME% binPath= "cmd.exe /c \"%WRAPPER%\"" start= auto DisplayName= "M.A.R.K. Sentinel Agent" >nul
sc description %SERVICE_NAME% "Distributed security audit agent (M.A.R.K. Sentinel)" >nul
sc failure %SERVICE_NAME% reset= 86400 actions= restart/30000/restart/30000/restart/30000 >nul
sc start %SERVICE_NAME% >nul

timeout /t 2 /nobreak >nul
sc query %SERVICE_NAME% | find "RUNNING" >nul
if %errorlevel% == 0 (
    echo   [OK] Service registered and running
) else (
    echo   [WARN] Service registered but may not have started.
    echo         Check: %CONFIG_DIR%\sentinel-agent.log
)

:: -- Desktop shortcut ---------------------------------------------------------
set "DASH_URL=http://localhost:7331/fleet"
if not "%SERVER_ARG%"=="" set "DASH_URL=%SERVER_ARG%/fleet"
(
    echo [InternetShortcut]
    echo URL=%DASH_URL%
    echo IconIndex=0
) > "%USERPROFILE%\Desktop\Sentinel Dashboard.url"
echo   [OK] Desktop shortcut created

echo.
echo   M.A.R.K. Sentinel Agent installed successfully.
echo   Install dir : %INSTALL_DIR%
echo   Config      : %CONFIG_FILE%
echo.
echo   Edit %CONFIG_FILE% to set your server URL and token, then restart the service.
echo   Or use Settings in the fleet dashboard to push config without a terminal.
echo.

endlocal
pause
