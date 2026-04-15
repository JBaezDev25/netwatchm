#Requires -Version 5.1
<#
.SYNOPSIS
    NetWatchM Windows installer.

.DESCRIPTION
    Installs NetWatchM on Windows 10/11. Requires an elevated PowerShell session
    (the script self-elevates if necessary). Shows a GUI progress window unless
    running in non-interactive (-Yes) mode.

.PARAMETER Yes
    Non-interactive mode: skip GUI and all prompts, use defaults.

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

$AppVersion  = "0.2.31"
$DataDir     = "$env:PROGRAMDATA\netwatchm"
$VersionFile = "$DataDir\version.txt"
$ConfigDir   = Split-Path -Parent $Config

# ── Self-elevate if not admin ─────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
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

# ══════════════════════════════════════════════════════════════════════════════
#  GUI SETUP  (skipped in -Yes / non-interactive mode)
# ══════════════════════════════════════════════════════════════════════════════
$UseGui = -not $Yes

if ($UseGui) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form                  = New-Object System.Windows.Forms.Form
    $form.Text             = "NetWatchM Installer v$AppVersion"
    $form.Size             = New-Object System.Drawing.Size(520, 440)
    $form.StartPosition    = "CenterScreen"
    $form.FormBorderStyle  = "FixedDialog"
    $form.MaximizeBox      = $false
    $form.BackColor        = [System.Drawing.Color]::FromArgb(28, 28, 28)

    $lblTitle              = New-Object System.Windows.Forms.Label
    $lblTitle.Text         = "NetWatchM $AppVersion"
    $lblTitle.Font         = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor    = [System.Drawing.Color]::White
    $lblTitle.Location     = New-Object System.Drawing.Point(20, 14)
    $lblTitle.Size         = New-Object System.Drawing.Size(460, 30)

    $lblSub                = New-Object System.Windows.Forms.Label
    $lblSub.Text           = "Network Monitoring and Threat Detection"
    $lblSub.Font           = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblSub.ForeColor      = [System.Drawing.Color]::Silver
    $lblSub.Location       = New-Object System.Drawing.Point(22, 46)
    $lblSub.Size           = New-Object System.Drawing.Size(460, 18)

    $sep                   = New-Object System.Windows.Forms.Label
    $sep.BorderStyle       = "Fixed3D"
    $sep.Location          = New-Object System.Drawing.Point(20, 70)
    $sep.Size              = New-Object System.Drawing.Size(460, 2)

    $lblStep               = New-Object System.Windows.Forms.Label
    $lblStep.Text          = "Initializing..."
    $lblStep.Font          = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblStep.ForeColor     = [System.Drawing.Color]::LightSkyBlue
    $lblStep.Location      = New-Object System.Drawing.Point(20, 80)
    $lblStep.Size          = New-Object System.Drawing.Size(460, 20)

    $progressBar           = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location  = New-Object System.Drawing.Point(20, 104)
    $progressBar.Size      = New-Object System.Drawing.Size(460, 20)
    $progressBar.Minimum   = 0
    $progressBar.Maximum   = 100
    $progressBar.Style     = "Continuous"

    $logBox                = New-Object System.Windows.Forms.RichTextBox
    $logBox.Location       = New-Object System.Drawing.Point(20, 134)
    $logBox.Size           = New-Object System.Drawing.Size(460, 228)
    $logBox.ReadOnly       = $true
    $logBox.BackColor      = [System.Drawing.Color]::FromArgb(12, 12, 12)
    $logBox.ForeColor      = [System.Drawing.Color]::LightGreen
    $logBox.Font           = New-Object System.Drawing.Font("Consolas", 8.5)
    $logBox.ScrollBars     = "Vertical"
    $logBox.BorderStyle    = "None"

    $btnClose              = New-Object System.Windows.Forms.Button
    $btnClose.Text         = "Please wait..."
    $btnClose.Location     = New-Object System.Drawing.Point(390, 372)
    $btnClose.Size         = New-Object System.Drawing.Size(90, 28)
    $btnClose.Enabled      = $false
    $btnClose.FlatStyle    = "Flat"
    $btnClose.BackColor    = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $btnClose.ForeColor    = [System.Drawing.Color]::White
    $btnClose.Add_Click({ $form.Close() })

    $form.Controls.AddRange(@($lblTitle, $lblSub, $sep, $lblStep, $progressBar, $logBox, $btnClose))
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
}

# ── Logging helpers ───────────────────────────────────────────────────────────
function Log-Info {
    param($msg)
    Write-Host "[INFO]  $msg" -ForegroundColor Green
    if ($UseGui) {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionColor = [System.Drawing.Color]::LightGreen
        $logBox.AppendText("[OK]  $msg`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Log-Warn {
    param($msg)
    Write-Host "[WARN]  $msg" -ForegroundColor Yellow
    if ($UseGui) {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionColor = [System.Drawing.Color]::Yellow
        $logBox.AppendText("[WARN] $msg`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Log-Step {
    param($msg, [int]$Progress = -1)
    Write-Host "[STEP]  $msg" -ForegroundColor Cyan
    if ($UseGui) {
        $lblStep.Text = $msg
        if ($Progress -ge 0) { $progressBar.Value = [Math]::Min($Progress, 100) }
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionColor = [System.Drawing.Color]::LightSkyBlue
        $logBox.AppendText("`n--- $msg ---`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Log-Err {
    param($msg)
    Write-Host "[ERR ]  $msg" -ForegroundColor Red
    if ($UseGui) {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.SelectionColor = [System.Drawing.Color]::OrangeRed
        $logBox.AppendText("[ERR] $msg`n")
        $logBox.ScrollToCaret()
        $lblStep.Text      = "Installation failed"
        $lblStep.ForeColor = [System.Drawing.Color]::OrangeRed
        $progressBar.Value = 0
        $btnClose.Text     = "Close"
        $btnClose.Enabled  = $true
        [System.Windows.Forms.Application]::DoEvents()
        [System.Windows.Forms.MessageBox]::Show(
            $msg, "NetWatchM Installer — Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
    exit 1
}

# ── winget helper ─────────────────────────────────────────────────────────────
function Install-WinGet {
    param([string]$PackageId, [string]$DisplayName)
    Log-Warn "$DisplayName not found — installing via winget..."
    winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { Log-Err "winget failed to install $DisplayName. Install it manually and re-run." }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
}

# ══════════════════════════════════════════════════════════════════════════════
#  VERSION DETECTION — upgrade / reinstall / uninstall / cancel
# ══════════════════════════════════════════════════════════════════════════════
if ((Test-Path $VersionFile) -and -not $Uninstall) {
    $installedVer = (Get-Content $VersionFile -ErrorAction SilentlyContinue).Trim()

    if ($Yes) {
        Log-Info "Existing installation detected (v$installedVer) — upgrading to v$AppVersion."
    } elseif ($UseGui) {
        $msgText = if ($installedVer -eq $AppVersion) {
            "NetWatchM v$installedVer is already installed.`n`nWhat would you like to do?"
        } else {
            "NetWatchM v$installedVer is installed.`n`nUpgrade to version $AppVersion?"
        }
        $result = [System.Windows.Forms.MessageBox]::Show(
            "$msgText`n`n  [Yes]    Upgrade / Reinstall`n  [No]     Uninstall`n  [Cancel] Exit",
            "NetWatchM Already Installed",
            [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) { $form.Close(); exit 0 }
        if ($result -eq [System.Windows.Forms.DialogResult]::No)     { $Uninstall = $true }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
if ($Uninstall) {
    Log-Step "Uninstalling NetWatchM..." 10

    foreach ($svc in @('netwatchm', 'netwatchm-web')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Log-Info "Stopping and removing service: $svc"
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            sc.exe delete $svc | Out-Null
        }
    }

    foreach ($task in @('netwatchm-web')) {
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Log-Info "Removed scheduled task: $task"
        }
    }

    if (Get-Command uv -ErrorAction SilentlyContinue) {
        uv tool uninstall netwatchm 2>$null
    }

    Remove-Item "$env:PUBLIC\Desktop\NetWatchM Dashboard.url" -ErrorAction SilentlyContinue
    Remove-Item "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\NetWatchM" -Recurse -ErrorAction SilentlyContinue
    Remove-Item $VersionFile -ErrorAction SilentlyContinue

    Log-Info "NetWatchM removed. Config and data at $DataDir left in place — delete manually if desired."

    if ($UseGui) {
        $progressBar.Value = 100
        $lblStep.Text      = "Uninstall complete"
        $btnClose.Text     = "Close"
        $btnClose.Enabled  = $true
        [System.Windows.Forms.Application]::DoEvents()
        [System.Windows.Forms.MessageBox]::Show(
            "NetWatchM has been removed.`n`nConfig and data remain at:`n$DataDir`n`nDelete manually if desired.",
            "Uninstall Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        $form.ShowDialog() | Out-Null
    }
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Running preflight checks..." 5

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Install-WinGet 'Python.Python.3.12' 'Python 3.12'
}
$pyVer = (python --version 2>&1) -replace 'Python ', ''
$parts = $pyVer -split '\.'
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 12)) {
    Log-Warn "Python 3.12+ required (found $pyVer). Installing Python 3.12..."
    Install-WinGet 'Python.Python.3.12' 'Python 3.12'
}
Log-Info "Python $pyVer OK"

if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Install-WinGet 'Wireshark.Wireshark' 'Wireshark (tshark)'
}
if (Get-Command tshark -ErrorAction SilentlyContinue) {
    Log-Info "tshark found: $(Get-Command tshark | Select-Object -ExpandProperty Source)"
} else {
    Log-Warn "tshark still not in PATH after install. Ensure Wireshark bin dir is on PATH."
}

$drive = Split-Path -Qualifier $env:PROGRAMDATA
$disk  = Get-PSDrive -Name ($drive -replace ':','') -ErrorAction SilentlyContinue
if ($disk -and $disk.Free -lt 200MB) { Log-Err "Less than 200 MB free on $drive. Free up space and retry." }
Log-Info "Disk space OK"

try {
    $null = Invoke-WebRequest -Uri 'https://pypi.org/simple/' -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Log-Info "Network: pypi.org reachable — OK"
} catch {
    Log-Warn "Cannot reach pypi.org — check your network connection."
}

# ══════════════════════════════════════════════════════════════════════════════
#  uv
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Installing uv package manager..." 20

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Log-Info "Installing uv..."
    pip install uv
    if ($LASTEXITCODE -ne 0) { Log-Err "pip install uv failed." }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
}
Log-Info "uv ready"

# ══════════════════════════════════════════════════════════════════════════════
#  PYTHON PACKAGE
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Installing NetWatchM and dependencies (this may take a few minutes)..." 35
if ($UseGui) { Log-Info "Window may pause briefly during package download..." }

# Pre-add Defender exclusions for pip/uv cache dirs to prevent AV blocking package downloads
$pipCache = "$env:LOCALAPPDATA\pip\cache"
$uvCache  = "$env:LOCALAPPDATA\uv\cache"
foreach ($excl in @($pipCache, $uvCache, $env:TEMP)) {
    try { Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue } catch {}
}
Log-Info "Defender exclusions added for package cache dirs"

Push-Location $RepoRoot
try {
    uv sync --extra windows
    if ($LASTEXITCODE -ne 0) { Log-Err "uv sync failed." }
    Log-Info "Dependencies installed"

    uv tool install --no-cache . --force
    if ($LASTEXITCODE -ne 0) { Log-Err "uv tool install failed." }
    Log-Info "netwatchm CLI installed"
} finally {
    Pop-Location
}

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Setting up configuration..." 55

if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
if (-not (Test-Path $Config)) {
    Copy-Item "$RepoRoot\netwatchm.yaml.example" $Config -Force
    Log-Info "Config created at $Config — edit to customise."
} else {
    Log-Info "Config already exists at $Config — not overwriting."
}

# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL PASSWORD
# ══════════════════════════════════════════════════════════════════════════════
if (-not [System.Environment]::GetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD', 'Machine')) {
    if ($Yes) {
        Log-Info "Skipping email password prompt (-Yes mode)."
    } elseif ($UseGui) {
        $ask = [System.Windows.Forms.MessageBox]::Show(
            "Would you like to configure a Gmail App Password for email alerts?`n`n(You can skip this and configure it later in $Config)",
            "Email Alerts (Optional)",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($ask -eq [System.Windows.Forms.DialogResult]::Yes) {
            $passForm              = New-Object System.Windows.Forms.Form
            $passForm.Text         = "Gmail App Password"
            $passForm.Size         = New-Object System.Drawing.Size(360, 150)
            $passForm.StartPosition = "CenterScreen"
            $passForm.FormBorderStyle = "FixedDialog"
            $passForm.MaximizeBox  = $false

            $passLbl               = New-Object System.Windows.Forms.Label
            $passLbl.Text          = "Enter Gmail App Password:"
            $passLbl.Location      = New-Object System.Drawing.Point(10, 15)
            $passLbl.Size          = New-Object System.Drawing.Size(320, 20)

            $passTxt               = New-Object System.Windows.Forms.TextBox
            $passTxt.Location      = New-Object System.Drawing.Point(10, 40)
            $passTxt.Size          = New-Object System.Drawing.Size(320, 22)
            $passTxt.PasswordChar  = '*'

            $passOk                = New-Object System.Windows.Forms.Button
            $passOk.Text           = "Save"
            $passOk.Location       = New-Object System.Drawing.Point(250, 75)
            $passOk.Size           = New-Object System.Drawing.Size(80, 26)
            $passOk.DialogResult   = [System.Windows.Forms.DialogResult]::OK
            $passForm.AcceptButton = $passOk

            $passForm.Controls.AddRange(@($passLbl, $passTxt, $passOk))
            if ($passForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK -and $passTxt.Text) {
                [System.Environment]::SetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD', $passTxt.Text, 'Machine')
                Log-Info "Email app password saved to system environment."
            }
        } else {
            Log-Info "Email password skipped — set NETWATCHM_EMAIL_PASSWORD later."
        }
    } else {
        $secPass = Read-Host "Enter Gmail App Password for alert emails (leave empty to skip)" -AsSecureString
        $bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $plain   = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if ($plain) {
            [System.Environment]::SetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD', $plain, 'Machine')
            Log-Info "App password saved to system environment."
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  MONITOR SERVICE
# ══════════════════════════════════════════════════════════════════════════════
if (-not $NoService) {
    Log-Step "Installing netwatchm monitor service..." 65
    Push-Location $RepoRoot
    try {
        uv run python -m netwatchm --config $Config --install-service
        if ($LASTEXITCODE -ne 0) {
            Log-Warn "Service install reported an error (may already be installed). Continuing..."
        } else {
            Log-Info "Monitor service installed. Start with: sc start netwatchm"
        }
    } catch {
        Log-Warn "Service install failed: $_"
    } finally {
        Pop-Location
    }
} else {
    Log-Info "Skipping monitor service setup (-NoService)."
}

# ══════════════════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════════════════
if (-not $NoWeb) {
    Log-Step "Installing web server..." 75

    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    $serverDst = "$DataDir\netwatchm-server.py"
    Copy-Item "$RepoRoot\netwatchm_server.py" $serverDst -Force
    Log-Info "Server script installed at $serverDst"

    Log-Step "Setting up HTTPS certificate..." 80
    $certFile = "$DataDir\server.crt"
    $keyFile  = "$DataDir\server.key"
    if (-not (Test-Path $certFile)) {
        if (Get-Command openssl -ErrorAction SilentlyContinue) {
            openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile `
                -days 3650 -nodes -subj "/CN=localhost/O=NetWatchM" 2>$null
            Log-Info "TLS: self-signed certificate generated (browser will warn)"
        } else {
            Log-Warn "openssl not found — skipping TLS cert. Copy server.crt/server.key to $DataDir manually."
        }
    } else {
        Log-Info "TLS: certificate already exists — not regenerating."
    }

    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $nssm) {
        Log-Warn "NSSM not found — trying winget install..."
        winget install --id NSSM.NSSM --silent --accept-package-agreements --accept-source-agreements 2>$null
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                    [System.Environment]::GetEnvironmentVariable('Path', 'User')
        $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    }

    if ($nssm) {
        Log-Info "Registering netwatchm-web service via NSSM..."
        $pythonExe = (Get-Command python | Select-Object -ExpandProperty Source)
        nssm install netwatchm-web $pythonExe $serverDst | Out-Null
        nssm set netwatchm-web AppDirectory $DataDir | Out-Null
        nssm set netwatchm-web DisplayName "NetWatchM Web Server" | Out-Null
        nssm set netwatchm-web Description "NetWatchM HTTPS dashboard and Grafana bridge" | Out-Null
        nssm set netwatchm-web Start SERVICE_AUTO_START | Out-Null
        Start-Service netwatchm-web -ErrorAction SilentlyContinue
        Log-Info "netwatchm-web service registered and started."
    } else {
        Log-Warn "NSSM unavailable — registering as Startup scheduled task instead."
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
        Log-Info "netwatchm-web registered as Scheduled Task (runs at startup as SYSTEM)."
    }
} else {
    Log-Info "Skipping web server setup (-NoWeb)."
}

# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS DEFENDER EXCLUSION
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Adding Windows Defender exclusion..." 90
try {
    Add-MpPreference -ExclusionPath $DataDir -ErrorAction Stop
    Log-Info "Defender exclusion added: $DataDir"
} catch {
    Log-Warn "Could not add Defender exclusion (may already exist or Defender is disabled)."
}

# ══════════════════════════════════════════════════════════════════════════════
#  SHORTCUTS
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Creating shortcuts..." 94

$dashboardUrl    = "https://localhost:8765/events.html"
$shortcutContent = "[InternetShortcut]`r`nURL=$dashboardUrl`r`nIconIndex=0`r`n"

try {
    Set-Content -Path "$env:PUBLIC\Desktop\NetWatchM Dashboard.url" -Value $shortcutContent -Force
    Log-Info "Desktop shortcut created"
} catch {
    Log-Warn "Could not create desktop shortcut: $_"
}

$startMenuDir = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\NetWatchM"
if (-not (Test-Path $startMenuDir)) { New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null }
try {
    Set-Content -Path "$startMenuDir\NetWatchM Dashboard.url" -Value $shortcutContent -Force
    Log-Info "Start Menu shortcut created"
} catch {
    Log-Warn "Could not create Start Menu shortcut: $_"
}

# ══════════════════════════════════════════════════════════════════════════════
#  SAVE INSTALLED VERSION
# ══════════════════════════════════════════════════════════════════════════════
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
Set-Content -Path $VersionFile -Value $AppVersion -Force
Log-Info "Version recorded: $AppVersion"

# ══════════════════════════════════════════════════════════════════════════════
#  DONE
# ══════════════════════════════════════════════════════════════════════════════
Log-Step "Installation complete!" 100

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "NetWatchM $AppVersion installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Monitor:    sc start netwatchm"
Write-Host "  Dashboard:  https://localhost:8765/events.html"
Write-Host "  Config:     $Config"
Write-Host "  Shortcut:   Desktop > NetWatchM Dashboard"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

if ($UseGui) {
    $lblStep.Text      = "Installation complete!"
    $lblStep.ForeColor = [System.Drawing.Color]::LightGreen
    $btnClose.Text     = "Close"
    $btnClose.Enabled  = $true
    [System.Windows.Forms.Application]::DoEvents()
    [System.Windows.Forms.MessageBox]::Show(
        "NetWatchM $AppVersion installed successfully!`n`n" +
        "Dashboard:  https://localhost:8765/events.html`n" +
        "Config:     $Config`n`n" +
        "A shortcut has been placed on your Desktop.",
        "Installation Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    $form.ShowDialog() | Out-Null
}
