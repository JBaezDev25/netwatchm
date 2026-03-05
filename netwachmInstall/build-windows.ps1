#Requires -Version 5.1
<#
.SYNOPSIS
    Build NetWatchM Windows executables with PyInstaller.

.DESCRIPTION
    Run this script on a Windows machine from anywhere — it resolves the repo root
    automatically via $PSScriptRoot.
    Produces dist\netwatchm\ (inside repo root) containing:
      netwatchm.exe        — CLI monitor
      netwatchm-server.exe — HTTPS web server

.PARAMETER Zip
    Zip dist\netwatchm\ to dist\netwatchm-windows.zip after build.

.PARAMETER Clean
    Delete dist\ and build\ before building.

.EXAMPLE
    .\netwachmInstall\build-windows.ps1
    .\netwachmInstall\build-windows.ps1 -Zip -Clean
#>
param(
    [switch]$Zip,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green  }
function Write-Warn { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERR ]  $m" -ForegroundColor Red; exit 1 }
function Write-Step { param($m) Write-Host "[STEP]  $m" -ForegroundColor Cyan   }

$InstallerDir = $PSScriptRoot
$RepoRoot     = Split-Path -Parent $InstallerDir
$Spec         = Join-Path $InstallerDir 'netwatchm.spec'

Set-Location $RepoRoot
Write-Info "Repository root: $RepoRoot"

# ── Verify Python ─────────────────────────────────────────────────────────────
Write-Step "Checking Python..."
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Err "python not found. Install Python 3.12+ and add it to PATH."
}
$pyVer = (python --version 2>&1) -replace 'Python ', ''
Write-Info "Python $pyVer"

# ── Install / upgrade build tools ─────────────────────────────────────────────
Write-Step "Installing build dependencies..."
pip install --quiet --upgrade pip
pip install --quiet pyinstaller>=6.0

if (Get-Command uv -ErrorAction SilentlyContinue) {
    Write-Info "uv found — syncing extra windows deps..."
    uv sync --extra windows
} else {
    Write-Warn "uv not found — skipping uv sync (pywin32 may be missing)"
    Write-Warn "Install uv with: pip install uv"
}

# ── Clean (optional) ──────────────────────────────────────────────────────────
if ($Clean) {
    Write-Step "Cleaning previous build artifacts..."
    foreach ($dir in @('dist', 'build')) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force
            Write-Info "  Removed $dir\"
        }
    }
}

# ── Build ─────────────────────────────────────────────────────────────────────
Write-Step "Running PyInstaller..."
pyinstaller $Spec --clean --noconfirm

if ($LASTEXITCODE -ne 0) {
    Write-Err "PyInstaller failed (exit code $LASTEXITCODE). See output above."
}

# ── Verify outputs ────────────────────────────────────────────────────────────
Write-Step "Verifying outputs..."
$distDir = "dist\netwatchm"
foreach ($exe in @("$distDir\netwatchm.exe", "$distDir\netwatchm-server.exe")) {
    if (Test-Path $exe) {
        $size = (Get-Item $exe).Length / 1MB
        Write-Info "  $exe  ($([math]::Round($size, 1)) MB)"
    } else {
        Write-Warn "  MISSING: $exe"
    }
}

Write-Step "Smoke-testing netwatchm.exe --help..."
try {
    $null = & ".\$distDir\netwatchm.exe" --help 2>&1
    Write-Info "  --help OK"
} catch {
    Write-Warn "  netwatchm.exe --help failed: $_"
}

# ── Zip (optional) ────────────────────────────────────────────────────────────
if ($Zip) {
    Write-Step "Creating distribution zip..."
    $zipPath = "dist\netwatchm-windows.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "dist\netwatchm" -DestinationPath $zipPath
    $zipSize = (Get-Item $zipPath).Length / 1MB
    Write-Info "  Created $zipPath  ($([math]::Round($zipSize, 1)) MB)"
}

Write-Host ""
Write-Info "Build complete!"
Write-Info "  Output folder:   dist\netwatchm\"
Write-Info "  CLI executable:  dist\netwatchm\netwatchm.exe"
Write-Info "  Web executable:  dist\netwatchm\netwatchm-server.exe"
if ($Zip) { Write-Info "  Zip archive:     dist\netwatchm-windows.zip" }
Write-Info ""
Write-Info "Quick test:"
Write-Info "  .\dist\netwatchm\netwatchm.exe --help"
