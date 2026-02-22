# NetWatchM

> Real-time network threat monitor for Linux — port scan, brute force,
> data exfiltration, and new-device detection with a Rich terminal dashboard,
> browser-based web UI, and email alerts.

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-57%20passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## What It Does

NetWatchM watches every packet on your network interface and alerts you in real time when it detects:

| Threat | How it works |
|--------|-------------|
| **Port Scan** | A single IP hits 15+ distinct ports within 10 seconds |
| **Brute Force** | 10+ login attempts to SSH / RDP / FTP / MySQL / VNC in 30 seconds |
| **Exfiltration** | A device sends more than 10 MB in 60 seconds |
| **New Device** | An IP not seen during the 5-minute baseline period appears |

Alerts are delivered via terminal, rotating log file, sound (beep), and Gmail email.

---

## Quick Start

```bash
git clone https://github.com/al4nbr3/netwatchm.git
cd netwatchm
sudo bash install.sh
```

The installer handles everything: Python deps, config, log directories, and three systemd services (`netwatchm`, `netwatchm-web`, `netwatchm-notify@`).

---

## Architecture

```
Network Interface
      │
      ▼
  tshark subprocess  ──►  capture.py  ──►  packet queue
                                                │
                          ┌─────────────────────┤
                          │   4 Detectors        │
                          │   PortScan           │
                          │   BruteForce    ──►  alert queue
                          │   Exfiltration       │
                          │   NewIP              │
                          └─────────────────────┘
                                                │
                          ┌─────────────────────┤
                          │   Alert Handlers     │
                          │   Terminal           │
                          │   Log file      ◄────┘
                          │   Sound
                          │   Email
                          └─────────────────────┘
                                                │
                          inventory.json  ◄──────┘
                                │
                          report.html  (browser dashboard)
```

---

## Project Structure

```
netwatchm/
├── src/netwatchm/
│   ├── __main__.py          # CLI entry point
│   ├── models.py            # Packet, Alert, DeviceRecord, ThreatLevel
│   ├── config.py            # YAML config loader
│   ├── capture.py           # tshark subprocess + NDJSON parser
│   ├── scorer.py            # Aggregate threat level from active alerts
│   ├── detector/            # port_scan, brute_force, exfiltration, new_ip
│   ├── alerts/              # terminal, logfile, sound, email_alert
│   ├── inventory/           # store, resolver, exporter
│   ├── ui/                  # dashboard, inventory_view, input_handler
│   └── service/             # linux.py (systemd), windows.py (pywin32)
├── scripts/
│   ├── notify-down.py       # Service-down email notifier
│   └── Watch-NetWatchMLogs.ps1  # PowerShell HIGH-alert log watcher
├── tests/                   # 57 pytest tests (all passing)
├── netwatchm-web.service    # Permanent web dashboard service
├── netwatchm-notify@.service # Service-down alert template
├── netwatchm-journald.conf  # Journal disk limits (200 MB cap)
├── netwatchm-logrotate      # Daily logrotate safety net
├── report.html              # Browser inventory dashboard
├── NetWatchM-guide.pdf      # 17-phase beginner build guide
├── install.sh               # Linux one-shot installer (10 steps)
├── deploy-services.sh       # Re-deploy service units without full reinstall
└── netwatchm.yaml.example   # Annotated config template
```

---

## Installation

### Automated (recommended)

```bash
sudo bash install.sh
```

Installs and enables two services:

| Service | Description | URL |
|---------|-------------|-----|
| `netwatchm` | Packet capture + threat detection | — |
| `netwatchm-web` | Browser dashboard HTTP server | http://localhost:8765/report.html |

### Re-deploy services only

If the Python package is already installed and you only need to (re-)deploy the
systemd units, notify script, and journald limits:

```bash
sudo bash deploy-services.sh
```

### Manual (development)

```bash
uv sync
sudo uv run netwatchm --config netwatchm.yaml.example --interface eth0
```

---

## Configuration

Config lives at `/etc/netwatchm/netwatchm.yaml` after install.

```yaml
interface: auto          # or e.g. enp6s0, wlan0
baseline_period: 300     # seconds to learn the network before alerting

thresholds:
  port_scan:
    ports_per_window: 15
    window_seconds: 10
  brute_force:
    attempts_per_window: 10
    window_seconds: 30
    ports: [22, 3389, 21, 3306, 5900]
  exfiltration:
    bytes_per_window: 10485760   # 10 MB
    window_seconds: 60

alerts:
  terminal: true
  log:
    enabled: true
    path: /var/log/netwatchm/netwatchm.log
  sound:
    enabled: true
  email:
    enabled: false           # set to true + configure below
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: you@gmail.com
    recipient: you@gmail.com
    min_level: HIGH
```

> **Email password:** never put it in the YAML. Use the environment variable:
> ```bash
> echo "NETWATCHM_EMAIL_PASSWORD=your-app-password" | sudo tee /etc/netwatchm/env
> sudo chmod 600 /etc/netwatchm/env
> ```

---

## Running

```bash
# Service management
sudo systemctl start netwatchm
sudo systemctl stop netwatchm
sudo systemctl restart netwatchm
systemctl status netwatchm

# Interactive mode (with Rich dashboard)
sudo uv run netwatchm --config /etc/netwatchm/netwatchm.yaml

# Headless / log-only
sudo uv run netwatchm --config /etc/netwatchm/netwatchm.yaml --no-ui

# Live logs
journalctl -u netwatchm -f
```

### Dashboard keyboard shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit |
| `I` | Switch to inventory view |
| `M` | Switch back to main dashboard |
| `E` | Export inventory to CSV |
| `/` | Filter devices by IP / hostname |
| `Esc` | Clear filter |

---

## Web Dashboard

```bash
# Open in browser (service is started by the installer)
http://localhost:8765/report.html

# Service management
systemctl status netwatchm-web
sudo systemctl restart netwatchm-web
```

Features: summary cards, sortable table, threat filter, port badges, auto-refresh every 30 s, dark/light theme, CSV export.

---

## Device Inventory

```bash
# Terminal table
uv run netwatchm inventory

# Filter + sort
uv run netwatchm inventory --filter 192.168 --sort-by threat

# Export to CSV
uv run netwatchm inventory --export /tmp/devices.csv
```

Inventory is saved automatically to `/var/lib/netwatchm/inventory.json` every 60 seconds.

---

## Service-Down Alerts

When `netwatchm` or `netwatchm-web` crashes, an email is sent automatically with:
- The failure reason in plain English (mapped from systemd exit code)
- The last 25 journal log lines
- Exact commands to restart

Uses `netwatchm-notify@.service` triggered by `OnFailure=` in each service unit.

---

## Log Management

| Layer | Cap | Mechanism |
|-------|-----|-----------|
| Alert log | 60 MB (10 MB × 6 files) | Python `RotatingFileHandler` |
| systemd journal | 200 MB, 30-day retention | `netwatchm-journald.conf` drop-in |
| Alert log (backup) | 7 days compressed | `netwatchm-logrotate` |

Journal limits are applied automatically by `deploy-services.sh` (and by `install.sh`). To apply them manually:

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
sudo cp netwatchm-journald.conf /etc/systemd/journald.conf.d/netwatchm.conf
sudo systemctl restart systemd-journald
sudo journalctl --vacuum-size=200M
```

---

## PowerShell Log Watcher

Read-only, non-destructive watcher that raises a coloured console alert the instant `HIGH` appears in a journal line.

```powershell
# Load and run
. ./scripts/Watch-NetWatchMLogs.ps1
Watch-NetWatchMLogs

# Export HIGH alerts to CSV
Watch-NetWatchMLogs -EmitObjects |
    Export-Csv ~/high-alerts.csv -Append -NoTypeInformation
```

---

## Tests

```bash
uv run pytest tests/ -v
# 57 passed
```

---

## Requirements

| Requirement | Version |
|------------|---------|
| Python | 3.12+ |
| tshark | any recent |
| uv | any |
| Linux | systemd-based |

Python dependencies: `rich`, `pyyaml`, `pygame`

---

## Documentation

A complete 17-phase beginner build guide is included:

📄 **[NetWatchM-guide.pdf](NetWatchM-guide.pdf)** — covers installation, configuration, dashboard usage, all four detectors, alert channels, log management, service-down alerts, and the PowerShell watcher.

---

## License

MIT
