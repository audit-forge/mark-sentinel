@echo off
REM M.A.R.K. Sentinel -- Windows Installer (Batch)
REM Requires Python 3.9+ with python.exe in PATH.
REM Run from the repository root:  scripts\install.bat
REM
REM For a richer install experience with color output, use install.ps1 instead:
REM   powershell -ExecutionPolicy Bypass -File scripts\install.ps1

setlocal EnableDelayedExpansion

echo.
echo   M.A.R.K. Sentinel -- Windows Installer
echo   =======================================
echo.

REM ── Find Python ──────────────────────────────────────────────────────────────
set PYTHON_EXE=
for %%C in (python python3 py) do (
    if not defined PYTHON_EXE (
        where %%C >nul 2>&1
        if !ERRORLEVEL! == 0 (
            set PYTHON_EXE=%%C
        )
    )
)

if not defined PYTHON_EXE (
    echo   ERROR: Python not found in PATH.
    echo   Download Python 3.9+ from: https://www.python.org/downloads/
    echo   Make sure to check "Add Python to PATH" during installation.
    exit /b 1
)

for /f "tokens=*" %%V in ('!PYTHON_EXE! --version 2^>^&1') do (
    echo   Python found: %%V  ^(!PYTHON_EXE!^)
)

REM ── Create virtual environment ────────────────────────────────────────────────
echo   Creating virtual environment ^(.venv^)...
!PYTHON_EXE! -m venv .venv
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Failed to create virtual environment.
    exit /b 1
)

REM ── Upgrade pip ───────────────────────────────────────────────────────────────
echo   Upgrading pip...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet

REM ── Install dependencies ──────────────────────────────────────────────────────
echo   Installing dependencies...
.venv\Scripts\pip.exe install -r requirements.txt --quiet
if %ERRORLEVEL% neq 0 (
    echo   ERROR: pip install failed. Check requirements.txt and your network connection.
    exit /b 1
)

REM ── Done ──────────────────────────────────────────────────────────────────────
echo.
echo   Installation complete.
echo.
echo   Quick scan (plain-English report):
echo     .venv\Scripts\python.exe audit.py --mode config --profile smb --target test\fixtures\deploy-hardened --output plain
echo.
echo   Scan your own directory:
echo     .venv\Scripts\python.exe audit.py --mode config --target C:\path\to\your\project --profile smb --output plain
echo.

endlocal
