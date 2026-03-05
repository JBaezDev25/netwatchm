#Requires -Version 5.1
<#
.SYNOPSIS
    NetWatchM Windows installer.

.DESCRIPTION
    Installs NetWatchM on Windows 10/11. Requires an elevated PowerShell session
    (the script self-elevates if necessary).

.PARAMETER Yes
    Non-interactive mode: skip all prompts and use defaults.

.PARAMETER NoService
    Install the Python package only; skip Windows service registration.

.PARAMETER NoWeb
    Skip web server (netwatchm-server) setup.

.PARAMETER Uninstall
    Remove NetWatchM services and files.

.PARAMETER Config
    Path to the YAML config file. Default: $env:PROGRAMDATA\netwatchm\netwatchm.yaml

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
    powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1 -Yes
    powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$NoService,
    [switch]$NoWeb,
    [switch]$Uninstall,
    [string]$Config = "$env:PROGRAMDATA\netwatchm\netwatchm.yaml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Green  }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Step    { param($msg) Write-Host "[STEP]  $msg" -ForegroundColor Cyan   }
function Write-Err     { param($msg) Write-Host "[ERR ]  $msg" -ForegroundColor Red; exit 1 }

# ── Self-elevate if not admin ─────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warn "Not running as Administrator — re-launching elevated..."
    $argList  = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($Yes)       { $argList += " -Yes"       }
    if ($NoService) { $argList += " -NoService" }
    if ($NoWeb)     { $argList += " -NoWeb"     }
    if ($Uninstall) { $argList += " -Uninstall" }
    if ($Config -ne "$env:PROGRAMDATA\netwatchm\netwatchm.yaml") {
        $argList += " -Config `"$Config`""
    }
    Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    exit 0
}

$InstallerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot     = Split-Path -Parent $InstallerDir
$ConfigDir    = Split-Path -Parent $Config

# ── Helper: run a command and abort on failure ────────────────────────────────
function Invoke-Or-Fail {
    param([string]$Desc, [scriptblock]$Block)
    Write-Info "$Desc..."
    try {
        & $Block
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Err "$Desc failed (exit code $LASTEXITCODE)."
        }
    } catch {
        Write-Err "$Desc failed: $_"
    }
}

# ── Helper: winget install ────────────────────────────────────────────────────
function Install-WinGet {
    param([string]$PackageId, [string]$DisplayName)
    Write-Warn "$DisplayName not found — installing via winget..."
    winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Err "winget failed to install $DisplayName. Install it manually and re-run."
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
}

# ══════════════════════════════════════════════════════════════════════════════
#  UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
if ($Uninstall) {
    Write-Step "Uninstalling NetWatchM..."

    foreach ($svc in @('netwatchm', 'netwatchm-web')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Write-Info "Stopping and removing service: $svc"
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            sc.exe delete $svc | Out-Null
        }
    }

    foreach ($task in @('netwatchm-web')) {
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Write-Info "Removed scheduled task: $task"
        }
    }

    if (Get-Command uv -ErrorAction SilentlyContinue) {
        uv tool uninstall netwatchm 2>$null
    }

    Write-Info "NetWatchM removed."
    Write-Info "Config and data left in place:"
    Write-Info "  $ConfigDir  (config)"
    Write-Info "  $env:PROGRAMDATA\netwatchm  (data)"
    Write-Info "Delete manually if desired."
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Running preflight checks..."

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Install-WinGet 'Python.Python.3.12' 'Python 3.12'
}
$pyVer = (python --version 2>&1) -replace 'Python ', ''
$parts = $pyVer -split '\.'
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 12)) {
    Write-Warn "Python 3.12+ required (found $pyVer). Installing Python 3.12..."
    Install-WinGet 'Python.Python.3.12' 'Python 3.12'
}
Write-Info "Python $pyVer OK"

if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Install-WinGet 'Wireshark.Wireshark' 'Wireshark (tshark)'
}
if (Get-Command tshark -ErrorAction SilentlyContinue) {
    Write-Info "tshark found: $(Get-Command tshark | Select-Object -ExpandProperty Source)"
} else {
    Write-Warn "tshark still not in PATH after install. Ensure Wireshark's bin dir is on PATH."
}

$drive = Split-Path -Qualifier $env:PROGRAMDATA
$disk  = Get-PSDrive -Name ($drive -replace ':','') -ErrorAction SilentlyContinue
if ($disk -and $disk.Free -lt 200MB) {
    Write-Err "Less than 200 MB free on $drive. Free up space and retry."
}
Write-Info "Disk space OK"

try {
    $null = Invoke-WebRequest -Uri 'https://pypi.org/simple/' -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-Info "Network: pypi.org reachable — OK"
} catch {
    Write-Warn "Cannot reach pypi.org — check your network connection."
}

# ══════════════════════════════════════════════════════════════════════════════
#  uv
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Checking uv..."
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Info "Installing uv..."
    pip install uv
    if ($LASTEXITCODE -ne 0) { Write-Err "pip install uv failed." }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
}
Write-Info "uv ready"

# ══════════════════════════════════════════════════════════════════════════════
#  PYTHON PACKAGE
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Installing Python dependencies..."
Push-Location $RepoRoot
try {
    Invoke-Or-Fail 'uv sync --extra windows' { uv sync --extra windows }
    Invoke-Or-Fail 'uv tool install netwatchm' { uv tool install --no-cache . --force }
} finally {
    Pop-Location
}

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Setting up configuration..."
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}
if (-not (Test-Path $Config)) {
    Write-Info "Creating $Config..."
    Copy-Item "$RepoRoot\netwatchm.yaml.example" $Config -Force
    Write-Info "Edit $Config to customise settings."
} else {
    Write-Info "Config already exists at $Config — not overwriting."
}

# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL PASSWORD
# ══════════════════════════════════════════════════════════════════════════════
if (-not [System.Environment]::GetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD', 'Machine')) {
    if ($Yes) {
        Write-Info "Skipping email password prompt (-Yes mode)."
    } else {
        Write-Host ""
        $secPass = Read-Host "Enter Gmail App Password for alert emails (leave empty to skip)" -AsSecureString
        $bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $plain   = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if ($plain) {
            [System.Environment]::SetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD', $plain, 'Machine')
            Write-Info "App password saved to system environment (NETWATCHM_EMAIL_PASSWORD)."
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  MONITOR SERVICE
# ══════════════════════════════════════════════════════════════════════════════
if (-not $NoService) {
    Write-Step "Installing netwatchm monitor service..."
    Push-Location $RepoRoot
    try {
        uv run python -m netwatchm --config $Config --install-service
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Service install reported an error (may already be installed). Continuing..."
        } else {
            Write-Info "Monitor service installed. Start with: sc start netwatchm"
        }
    } catch {
        Write-Warn "Service install failed: $_"
    } finally {
        Pop-Location
    }
} else {
    Write-Info "Skipping monitor service setup (-NoService)."
}

# ══════════════════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════════════════
if (-not $NoWeb) {
    Write-Step "Installing web server..."
    $DataDir = "$env:PROGRAMDATA\netwatchm"

    $serverDst = "$DataDir\netwatchm-server.py"
    Copy-Item "$RepoRoot\netwatchm_server.py" $serverDst -Force
    Write-Info "Server script installed at $serverDst"

    Write-Step "Setting up HTTPS certificate..."
    $certFile = "$DataDir\server.crt"
    $keyFile  = "$DataDir\server.key"
    if (-not (Test-Path $certFile)) {
        if (Get-Command openssl -ErrorAction SilentlyContinue) {
            openssl req -x509 -newkey rsa:2048 `
                -keyout $keyFile -out $certFile `
                -days 3650 -nodes `
                -subj "/CN=localhost/O=NetWatchM" `
                2>$null
            Write-Info "  TLS: self-signed certificate generated (browser will warn)"
        } else {
            Write-Warn "openssl not found — skipping TLS certificate generation."
            Write-Warn "Install OpenSSL or copy server.crt/server.key to $DataDir manually."
        }
    } else {
        Write-Info "  TLS: certificate already exists — not regenerating."
    }

    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $nssm) {
        Write-Warn "NSSM not found — trying winget install..."
        winget install --id NSSM.NSSM --silent --accept-package-agreements --accept-source-agreements 2>$null
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                    [System.Environment]::GetEnvironmentVariable('Path', 'User')
        $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    }

    if ($nssm) {
        Write-Info "Registering netwatchm-web service via NSSM..."
        $pythonExe = (Get-Command python | Select-Object -ExpandProperty Source)
        nssm install netwatchm-web $pythonExe $serverDst | Out-Null
        nssm set netwatchm-web AppDirectory $DataDir | Out-Null
        nssm set netwatchm-web DisplayName "NetWatchM Web Server" | Out-Null
        nssm set netwatchm-web Description "NetWatchM HTTPS dashboard and Grafana bridge" | Out-Null
        nssm set netwatchm-web Start SERVICE_AUTO_START | Out-Null
        Start-Service netwatchm-web -ErrorAction SilentlyContinue
        Write-Info "  netwatchm-web service registered and started."
    } else {
        Write-Warn "NSSM unavailable — registering as a Startup scheduled task instead."
        $pythonExe = (Get-Command python | Select-Object -ExpandProperty Source)
        $action    = New-ScheduledTaskAction -Execute $pythonExe -Argument $serverDst -WorkingDirectory $DataDir
        $trigger   = New-ScheduledTaskTrigger -AtLogon
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "netwatchm-web" `
            -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal `
            -Description "NetWatchM web dashboard" -Force | Out-Null
        Start-ScheduledTask -TaskName "netwatchm-web" -ErrorAction SilentlyContinue
        Write-Info "  netwatchm-web registered as Scheduled Task (runs at system startup as SYSTEM)."
    }
} else {
    Write-Info "Skipping web server setup (-NoWeb)."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Info "NetWatchM installed successfully!"
Write-Info ""
Write-Info "  Monitor service:  sc query netwatchm"
Write-Info "  Web dashboard:    https://localhost:8765/events.html"
Write-Info "  Web service:      sc query netwatchm-web  (or Get-ScheduledTask netwatchm-web)"
Write-Info "  Config:           $Config"
Write-Info "  Start monitor:    sc start netwatchm"
Write-Info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
