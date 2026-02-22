@echo off
setlocal EnableDelayedExpansion
:: NetWatchM Windows Installer

echo [NetWatchM] Windows Installer
echo ================================

:: 1. Check Python >= 3.12
echo [INFO] Checking Python...
python --version > nul 2>&1
if errorlevel 1 (
    echo [ERR ] Python not found. Install Python 3.12+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [INFO] Python !PY_VER! found

:: 2. Check tshark
echo [INFO] Checking tshark...
tshark --version > nul 2>&1
if errorlevel 1 (
    echo [WARN] tshark not found.
    echo [INFO] Download Wireshark from https://www.wireshark.org/download.html
    echo [INFO] Ensure "TShark" component is selected during installation.
    pause
    exit /b 1
)
echo [INFO] tshark found

:: 3. Install uv if missing
echo [INFO] Checking uv...
uv --version > nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing uv...
    pip install uv
)
echo [INFO] uv ready

:: 4. Sync dependencies (with windows extras)
echo [INFO] Installing Python dependencies...
uv sync --extra windows

:: 5. Copy config
set CONFIG_DIR=%PROGRAMDATA%\netwatchm
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
set CONFIG_FILE=%CONFIG_DIR%\netwatchm.yaml
if not exist "%CONFIG_FILE%" (
    echo [INFO] Creating %CONFIG_FILE%...
    copy /Y netwatchm.yaml.example "%CONFIG_FILE%"
) else (
    echo [INFO] Config already exists at %CONFIG_FILE%
)

:: 6. Prompt for Gmail App Password
echo.
set /p EMAIL_PASS=Enter Gmail App Password for alerts (leave empty to skip):
if defined EMAIL_PASS (
    setx NETWATCHM_EMAIL_PASSWORD "!EMAIL_PASS!" /M
    echo [INFO] App password saved to system environment.
)

:: 7. Install Windows Service
echo [INFO] Installing Windows Service...
uv run python -m netwatchm service install
if errorlevel 1 (
    echo [WARN] Service install failed. You can start NetWatchM manually:
    echo        uv run netwatchm --config "%CONFIG_FILE%"
) else (
    echo [INFO] Service installed. Start with: sc start netwatchm
)

echo.
echo [INFO] NetWatchM installed!
echo [INFO]   Config: %CONFIG_FILE%
echo [INFO]   Start:  sc start netwatchm
echo [INFO]   Manual: uv run netwatchm --config "%CONFIG_FILE%"
pause
