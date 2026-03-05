# NetWatchM — Installation Guide

All installer and build scripts live in this folder (`netwachmInstall/`).

---

## Contents of this folder

| File | Purpose |
|---|---|
| `install.sh` | Linux / macOS installer |
| `install.ps1` | Windows 10/11 installer (PowerShell) |
| `install.bat` | Windows legacy installer (CMD fallback) |
| `netwatchm.spec` | PyInstaller spec — builds both `.exe` files |
| `build-linux.sh` | Build standalone Linux binaries |
| `build-windows.ps1` | Build standalone Windows `.exe` files |
| `INSTALL.md` | This guide |

---

## Prerequisites

### Linux
| Requirement | Min version | Notes |
|---|---|---|
| Python | 3.12+ | `python3 --version` |
| tshark | any | `sudo apt install tshark` / `dnf install wireshark-cli` |
| arp-scan | any | `sudo apt install arp-scan` |
| curl | any | used by uv installer |
| openssl | any | generates self-signed TLS cert |

> The installer auto-installs tshark, arp-scan, and uv if missing.

### Windows
| Requirement | Min version | Notes |
|---|---|---|
| Windows | 10 / 11 | |
| Python | 3.12+ | auto-installed via winget if missing |
| Wireshark (tshark) | any | auto-installed via winget if missing |
| winget | any | Ships with Windows 11; [install on Win 10](https://aka.ms/getwinget) |

---

## Option A — Linux install (recommended)

### 1. Clone or download the repo
```bash
git clone https://github.com/al4nbr3/netwatchm.git
cd netwatchm
```

### 2. Run the installer
```bash
bash netwachmInstall/install.sh
```
The installer will:
- Check Python 3.12+, free disk space, and network
- Install tshark and arp-scan if missing
- Install `uv` (Python package manager)
- Install NetWatchM and all dependencies
- Copy config to `/etc/netwatchm/netwatchm.yaml`
- Prompt for a Gmail App Password (for email alerts — skip if not needed)
- Generate a self-signed TLS certificate in `/var/lib/netwatchm/`
- Register and start `netwatchm` and `netwatchm-web` systemd services

### 3. Edit the config
```bash
sudo nano /etc/netwatchm/netwatchm.yaml
```
Key settings to review:
- `interface:` — network interface to monitor (e.g. `eth0`, `wlan0`)
- `alerts.email` — sender/recipient for email alerts
- `alerts.ntfy` — push notifications via ntfy.sh

After editing, restart the service:
```bash
sudo systemctl restart netwatchm
```

### 4. Verify the install
```bash
# Check monitor service
systemctl status netwatchm

# Check web server
systemctl status netwatchm-web

# Open the dashboard
xdg-open https://localhost:8765/events.html
# (browser will warn about self-signed cert — click "Advanced > Proceed")

# Follow live logs
journalctl -u netwatchm -f
```

### Non-interactive install (CI / scripted)
```bash
bash netwachmInstall/install.sh --yes
```
Skips all prompts. Useful for automated deployments.

### Partial installs
```bash
# Package only — no systemd services
bash netwachmInstall/install.sh --no-service

# No web server
bash netwachmInstall/install.sh --no-web

# Custom config path
bash netwachmInstall/install.sh --config /opt/netwatchm/config.yaml
```

### Uninstall
```bash
bash netwachmInstall/install.sh --uninstall
```
Stops and removes services, uninstalls the CLI tool. Config and data in
`/etc/netwatchm/` and `/var/lib/netwatchm/` are left in place — delete
them manually if desired.

---

## Option B — Windows install (PowerShell)

> Run from an **elevated** PowerShell — the script will self-elevate if needed.

### 1. Clone or download the repo
```powershell
git clone https://github.com/al4nbr3/netwatchm.git
cd netwatchm
```

### 2. Run the installer
```powershell
powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
```
The installer will:
- Check Python 3.12+ and install via winget if missing
- Check tshark / Wireshark and install via winget if missing
- Install `uv` via pip if missing
- Install NetWatchM and all dependencies (`pywin32` included)
- Copy config to `%PROGRAMDATA%\netwatchm\netwatchm.yaml`
- Prompt for a Gmail App Password (stored in system environment)
- Generate a self-signed TLS certificate
- Register `netwatchm` as a Windows service
- Register `netwatchm-web` as a Windows service (via NSSM) or Scheduled Task

### 3. Edit the config
```powershell
notepad "$env:PROGRAMDATA\netwatchm\netwatchm.yaml"
```
Same key settings as Linux: `interface`, `alerts.email`, `alerts.ntfy`.

### 4. Verify the install
```powershell
# Check monitor service
sc query netwatchm

# Start if not running
sc start netwatchm

# Open dashboard
Start-Process https://localhost:8765/events.html
```

### Flags
```powershell
# Skip all prompts
.\netwachmInstall\install.ps1 -Yes

# Package only (no services)
.\netwachmInstall\install.ps1 -NoService

# No web server
.\netwachmInstall\install.ps1 -NoWeb

# Remove everything
.\netwachmInstall\install.ps1 -Uninstall
```

### Windows legacy (CMD)
If you cannot use PowerShell:
```cmd
netwachmInstall\install.bat
```
Note: the `.bat` installer is basic — it does not auto-install Python or
Wireshark and does not set up the web server.

---

## Option C — Standalone executables (no Python required)

Pre-built `.exe` files require no Python installation on the target machine.

### Download
Grab the latest `netwatchm-windows.zip` from the Releases page, extract it,
and run:
```
netwatchm.exe --help
netwatchm-server.exe
```

### What's included
```
netwatchm\
├── netwatchm.exe        ← CLI monitor
├── netwatchm-server.exe ← HTTPS web server
└── (DLLs and support files)
```

---

## Building your own executables

### Build on Linux
```bash
# From repo root
bash netwachmInstall/build-linux.sh --clean

# Output: dist/netwatchm/netwatchm + dist/netwatchm/netwatchm-server
# With archive:
bash netwachmInstall/build-linux.sh --clean --zip
# Output: dist/netwatchm-linux.tar.gz
```

### Build on Windows
```powershell
# From repo root (PowerShell)
.\netwachmInstall\build-windows.ps1 -Clean

# With zip:
.\netwachmInstall\build-windows.ps1 -Clean -Zip
# Output: dist\netwatchm-windows.zip
```

Both scripts:
1. Install `pyinstaller` via pip
2. Run `uv sync` to ensure all deps are present
3. Run `pyinstaller netwachmInstall/netwatchm.spec`
4. Smoke-test `netwatchm --help`
5. Optionally produce a zip / tar.gz

---

## Post-install configuration

### GeoIP (optional — enables country lookups)
1. Create a free account at https://dev.maxmind.com/
2. Download `GeoLite2-City.mmdb`
3. Place it in `/var/lib/netwatchm/GeoLite2-City.mmdb` (Linux) or
   `%PROGRAMDATA%\netwatchm\GeoLite2-City.mmdb` (Windows)
4. Restart the web server service

### Email alerts
Set `NETWATCHM_EMAIL_PASSWORD` in the environment:
- Linux: add to `/etc/netwatchm/env`, restart service
- Windows: already set by installer; update with:
  ```powershell
  [System.Environment]::SetEnvironmentVariable('NETWATCHM_EMAIL_PASSWORD','your-app-password','Machine')
  ```

### ntfy.sh push notifications
In `netwatchm.yaml`:
```yaml
alerts:
  ntfy:
    enabled: true
    server: https://ntfy.sh
    topic: your-unique-topic
```
Test: `curl -d "test" https://ntfy.sh/your-unique-topic`

### Trusted HTTPS (Linux)
Install `mkcert` before running the installer for a browser-trusted certificate:
```bash
sudo apt install mkcert   # or: brew install mkcert
bash netwachmInstall/install.sh
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `tshark: permission denied` | `sudo setcap cap_net_raw+ep $(which tshark)` |
| `uv: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| Browser shows TLS warning | Expected for self-signed cert — click Advanced > Proceed. Install mkcert to fix. |
| `systemctl status netwatchm` shows failed | Check `journalctl -u netwatchm -n 50` for errors |
| Web dashboard blank | Check `systemctl status netwatchm-web`; ensure port 8765 is not blocked by firewall |
| Windows: service won't start | Check Event Viewer > Windows Logs > Application for Python errors |
| No email alerts | Confirm `NETWATCHM_EMAIL_PASSWORD` is set; use a Gmail App Password, not your account password |
| Windows Defender flags the installer or files | See note below |

### Windows Defender / SmartScreen

NetWatchM is not code-signed (certificates cost ~$300–500/year). This means Windows
SmartScreen and Defender may warn or block the installer. **This is a false positive** —
NetWatchM is open-source and you can review every line at
[github.com/al4nbr3/netwatchm](https://github.com/al4nbr3/netwatchm).

**To run the PowerShell installer despite the SmartScreen warning:**
1. Right-click `install.ps1` → **Properties**
2. At the bottom, check **Unblock** → **OK**
3. Then run normally:
   ```powershell
   powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
   ```

**If SmartScreen blocks a `.exe` from Releases:**
1. Click **More info** on the SmartScreen dialog
2. Click **Run anyway**

**If Defender quarantines files after install:**
The installer automatically adds `%PROGRAMDATA%\netwatchm` to Defender exclusions.
If you ran the installer before this fix, add the exclusion manually:
```powershell
Add-MpPreference -ExclusionPath "$env:PROGRAMDATA\netwatchm"
```
