# NetWatchM — Novice Build Guide

> A complete walkthrough of the NetWatchM project: what it is, how it works,
> how to install it, configure it, run it, and extend it.

---

## Table of Contents

1. [What Is NetWatchM?](#1-what-is-netwatchm)
2. [How It Works — Big Picture](#2-how-it-works--big-picture)
3. [Project Structure](#3-project-structure)
4. [Prerequisites](#4-prerequisites)
5. [Installation](#5-installation)
6. [Configuration Reference](#6-configuration-reference)
7. [Running NetWatchM](#7-running-netwatchm)
8. [Understanding the Dashboard](#8-understanding-the-dashboard)
9. [Threat Detectors Deep Dive](#9-threat-detectors-deep-dive)
10. [Alert System](#10-alert-system)
11. [Device Inventory](#11-device-inventory)
12. [The HTML Report Dashboard](#12-the-html-report-dashboard)
13. [Running as a System Service](#13-running-as-a-system-service)
14. [Testing](#14-testing)
15. [Troubleshooting](#15-troubleshooting)
16. [Glossary](#16-glossary)

---

## 1. What Is NetWatchM?

NetWatchM (**Net**work **Watch** **M**onitor) is a real-time network security
monitor that runs on Linux (and Windows). It watches all traffic passing through
a network interface and raises alerts when it sees suspicious behaviour such as:

- **Port scans** — someone probing many ports in a short time
- **Brute-force attempts** — repeated login failures on SSH, RDP, FTP, etc.
- **Data exfiltration** — a device sending an unusually large amount of data
- **New unknown devices** — a device that was never seen before joins the network

It is written entirely in **Python 3.12** and has no heavyweight dependencies —
just `tshark` (the command-line Wireshark capture engine), `rich` for the
terminal UI, `pyyaml` for config, and `pygame` for sound alerts.

---

## 2. How It Works — Big Picture

```
Network Interface (enp6s0 / eth0 / etc.)
         │
         ▼
   ┌──────────────┐
   │   tshark     │  subprocess — captures raw packets, outputs NDJSON
   └──────┬───────┘
          │ stdout (line by line)
          ▼
   ┌──────────────┐
   │  capture.py  │  parses each JSON line → Packet dataclass
   └──────┬───────┘
          │ asyncio.Queue
          ▼
   ┌──────────────────────────────────────────────────────┐
   │                   detector_loop                      │
   │                                                      │
   │  PortScanDetector  ──┐                               │
   │  BruteForceDetector ─┼──► Alert ──► alert_queue     │
   │  ExfiltrationDetector┘                               │
   │  NewIPDetector ──────┘                               │
   │                                                      │
   │  DeviceStore.update(packet)  ◄── inventory tracking  │
   └──────┬───────────────────────────────────────────────┘
          │
          ▼
   ┌──────────────────────────────────────────────────────┐
   │              alert_dispatch_loop                     │
   │                                                      │
   │  ThreatScorer ──► current threat level               │
   │                                                      │
   │  TerminalAlert  ──┐                                  │
   │  LogFileAlert   ──┼──► notify user                   │
   │  SoundAlert     ──┤                                  │
   │  EmailAlert     ──┘                                  │
   └──────────────────────────────────────────────────────┘
          │
          ▼
   ┌──────────────┐
   │  Rich UI     │  terminal dashboard — updated every 0.5 s
   └──────────────┘
          │
          ▼
   ┌──────────────────────────┐
   │  inventory.json          │  persisted to disk every 60 s
   │  /var/lib/netwatchm/     │
   └──────────────────────────┘
          │
          ▼
   ┌──────────────────────────┐
   │  report.html             │  human-readable browser dashboard
   │  (auto-refreshes 30 s)   │
   └──────────────────────────┘
```

Everything runs inside a **single Python process** using `asyncio` coroutines.
There are no threads (except the keyboard input handler). Each major piece of
work is its own `asyncio.Task`:

| Task name  | What it does |
|------------|--------------|
| `capture`  | Spawns tshark, reads NDJSON lines, puts `Packet` objects on a queue |
| `detector` | Reads packets, runs 4 detectors, updates inventory, feeds alert queue |
| `alerts`   | Reads alert queue, scores threat level, dispatches to all handlers |
| `scorer`   | Every second, expires old alerts and updates the displayed threat level |
| `ui`       | Every 0.5 s, polls keyboard and redraws the Rich dashboard |
| `resolver` | Background DNS reverse-lookup for every device IP |
| `persist`  | Every 60 s, writes `inventory.json` to disk |

---

## 3. Project Structure

```
netwatchm/
│
├── src/netwatchm/              ← main Python package
│   ├── __main__.py             ← CLI entry point (argparse + asyncio.run)
│   ├── models.py               ← core dataclasses: Packet, Alert, DeviceRecord, ThreatLevel
│   ├── config.py               ← load_config() reads netwatchm.yaml → Config dataclass
│   ├── interface.py            ← detect_interface() auto-picks active NIC
│   ├── capture.py              ← spawns tshark, parses NDJSON → Packet
│   ├── scorer.py               ← ThreatScorer: tracks active alerts, returns max level
│   │
│   ├── detector/               ← one file per detection type
│   │   ├── base.py             ← abstract Detector base class
│   │   ├── port_scan.py        ← PortScanDetector
│   │   ├── brute_force.py      ← BruteForceDetector
│   │   ├── exfiltration.py     ← ExfiltrationDetector
│   │   └── new_ip.py           ← NewIPDetector
│   │
│   ├── alerts/                 ← one file per output channel
│   │   ├── terminal.py         ← prints coloured alert to console (Rich)
│   │   ├── logfile.py          ← rotating log file
│   │   ├── sound.py            ← plays alert.wav via pygame
│   │   └── email_alert.py      ← sends Gmail via SMTP
│   │
│   ├── inventory/
│   │   ├── store.py            ← DeviceStore: in-memory device tracking + JSON persist
│   │   ├── resolver.py         ← async DNS reverse lookups
│   │   └── exporter.py         ← exports DeviceStore to CSV
│   │
│   ├── ui/
│   │   ├── dashboard.py        ← Rich Live dashboard
│   │   ├── inventory_view.py   ← Rich table of tracked devices
│   │   └── input_handler.py    ← non-blocking keyboard reader (thread)
│   │
│   └── service/
│       ├── linux.py            ← writes /etc/systemd/system/netwatchm.service
│       └── windows.py          ← Windows service via pywin32
│
├── tests/                      ← 57 pytest tests (all passing)
├── assets/
│   └── alert.wav               ← 880 Hz beep generated at install time
├── netwatchm.yaml.example      ← annotated config template
├── report.html                 ← browser dashboard (reads inventory.json)
├── install.sh                  ← Linux one-shot installer
├── install.bat                 ← Windows installer
└── pyproject.toml              ← project metadata & dependencies
```

---

## 4. Prerequisites

### Linux

| Requirement | Minimum version | Check |
|-------------|----------------|-------|
| Python      | 3.12+          | `python3 --version` |
| tshark      | any recent     | `tshark --version` |
| uv (package manager) | any  | `uv --version` |

**Install tshark on Ubuntu/Debian:**
```bash
sudo apt install tshark
# During install, choose "Yes" to allow non-superusers to capture packets
# (or always run netwatchm as root / via sudo)
```

**Install uv** (Python package manager, replaces pip+venv):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc for permanence
```

### Windows

- Python 3.12+ from python.org
- Wireshark (includes tshark) from wireshark.org
- `pip install uv` or download from astral.sh

---

## 5. Installation

### Option A — Automated (Linux, recommended)

```bash
git clone https://github.com/yourrepo/netwatchm.git
cd netwatchm
sudo bash install.sh
```

The installer does all of this for you:

1. Verifies Python 3.12+ and tshark
2. Installs `uv` to `/root/.local/bin` if missing
3. Runs `uv sync` to install Python dependencies into `.venv/`
4. Copies `netwatchm.yaml.example` → `/etc/netwatchm/netwatchm.yaml`
5. Creates log directory `/var/log/netwatchm/` and data directory `/var/lib/netwatchm/`
6. Prompts for a Gmail App Password (optional, for email alerts)
7. Installs and enables the systemd service

### Option B — Manual (development mode)

```bash
# 1. Clone the repo
git clone https://github.com/yourrepo/netwatchm.git
cd netwatchm

# 2. Install dependencies
uv sync

# 3. Run directly (no service, no install)
sudo uv run netwatchm --config netwatchm.yaml.example --interface eth0
```

> **Why sudo?** tshark needs root (or `CAP_NET_RAW` capability) to open a
> network interface in promiscuous mode. Without it you'll get a permission error.

### Verify the install

```bash
systemctl status netwatchm       # should show active (running)
journalctl -u netwatchm -f       # live log stream
```

---

## 6. Configuration Reference

Config file: `/etc/netwatchm/netwatchm.yaml`

```yaml
# Which network interface to monitor.
# "auto" picks the first non-loopback interface with an IP address.
interface: auto          # or e.g.  enp6s0 / eth0 / wlan0

# How long (seconds) to silently learn the network before alerting on new IPs.
# During this window, NewIPDetector collects IPs without firing alerts.
baseline_period: 300     # 5 minutes

thresholds:

  port_scan:
    # Alert fires when one source IP hits this many DISTINCT destination ports
    # within the time window below.
    ports_per_window: 15
    window_seconds: 10

  brute_force:
    # Alert fires when one source IP makes this many connection attempts
    # to any of the watched ports within the time window.
    attempts_per_window: 10
    window_seconds: 30
    ports: [22, 3389, 21, 3306, 5900]
    #        SSH  RDP  FTP MySQL VNC

  exfiltration:
    # Alert fires when a single source IP sends this many bytes in the window.
    bytes_per_window: 10485760   # 10 MB (10 * 1024 * 1024)
    window_seconds: 60

  new_ip:
    # Whether to alert when an IP not seen during baseline_period appears.
    enabled: true

alerts:
  terminal: true           # print coloured alerts to the console

  log:
    enabled: true
    path: /var/log/netwatchm/netwatchm.log
    max_bytes: 10485760    # rotate at 10 MB
    backup_count: 5        # keep 5 rotated files

  sound:
    enabled: true
    file: assets/alert.wav
    min_level: HIGH        # LOW / MEDIUM / HIGH / CRITICAL

  email:
    enabled: false         # set to true and fill in fields below
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: you@gmail.com
    password: ""           # NEVER put password here — use env var instead:
                           #   export NETWATCHM_EMAIL_PASSWORD="your-app-password"
    recipient: you@gmail.com
    min_level: HIGH
    cooldown_seconds: 300  # don't send another email for the same type for 5 min

inventory:
  enabled: true
  persist_interval: 60    # save inventory.json to disk every N seconds
  dns_timeout: 2          # seconds to wait for reverse DNS reply
  dns_cache_ttl: 300      # cache failed DNS lookups for N seconds
  export_dir: .           # directory for CSV exports ("." = current directory)
```

### Email password — the secure way

Never put the password in the YAML file. Instead:

```bash
# One-time setup
echo "NETWATCHM_EMAIL_PASSWORD=your-app-password" | sudo tee /etc/netwatchm/env
sudo chmod 600 /etc/netwatchm/env

# The installer adds this to the service file automatically.
# For manual runs, export it first:
export NETWATCHM_EMAIL_PASSWORD="your-app-password"
sudo -E uv run netwatchm --config /etc/netwatchm/netwatchm.yaml
```

> **Gmail App Password:** Go to Google Account → Security → 2-Step Verification
> → App passwords. Generate one for "Mail" on "Other device". Use that 16-char
> code as the password — NOT your regular Gmail password.

---

## 7. Running NetWatchM

### As a service (after install)

```bash
sudo systemctl start netwatchm     # start
sudo systemctl stop netwatchm      # stop
sudo systemctl restart netwatchm   # restart (e.g. after config change)
sudo systemctl status netwatchm    # is it running?
journalctl -u netwatchm -f         # watch live logs
```

### Manually in the terminal (interactive dashboard)

```bash
sudo uv run netwatchm \
  --config /etc/netwatchm/netwatchm.yaml \
  --interface enp6s0
```

### Headless / log-only mode

```bash
sudo uv run netwatchm \
  --config /etc/netwatchm/netwatchm.yaml \
  --no-ui
```

Use `--no-ui` when running over SSH or in a service — it disables the Rich
dashboard so only log output is produced.

### Override the interface at launch

```bash
sudo uv run netwatchm --interface wlan0
```

### Subcommand: query inventory offline

```bash
# Show all devices in a Rich table
uv run netwatchm inventory

# Filter by IP or hostname substring
uv run netwatchm inventory --filter 192.168

# Sort by threat level (highest first)
uv run netwatchm inventory --sort-by threat

# Export to CSV
uv run netwatchm inventory --export /tmp/devices.csv

# Print CSV to stdout
uv run netwatchm inventory --export - --format CSV
```

### CLI flags summary

| Flag | Default | Description |
|------|---------|-------------|
| `--config PATH` | `/etc/netwatchm/netwatchm.yaml` | Path to YAML config |
| `--interface NAME` | from config | Override NIC |
| `--no-ui` | off | Disable Rich dashboard |
| `--install-service` | off | Install systemd/Windows service and exit |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## 8. Understanding the Dashboard

When you run without `--no-ui`, a Rich terminal dashboard is shown.

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit NetWatchM |
| `I` | Switch to Inventory view (list of all seen devices) |
| `M` | Switch back to Main dashboard |
| `E` | (in Inventory view) Export current list to CSV |
| `/` | (in Inventory view) Start typing to filter by IP/hostname |
| `Esc` | (in Inventory view) Clear the filter |
| `Backspace` | (in Inventory view) Delete last filter character |

### Dashboard panels

- **Threat level** — LOW (green) / MEDIUM (yellow) / HIGH (red) / CRITICAL (bold red)
  aggregated from all currently active alerts
- **Active alerts** — scrolling list of recent alerts with type, source IP, and description
- **Traffic stats** — packets per second and bytes seen on the interface
- **Interface** — which NIC is being monitored

### Inventory view

Shows every device that has sent or received a packet:

| Column | Description |
|--------|-------------|
| IP | Source or destination IP address |
| Hostname | Resolved via reverse DNS (fills in after a few seconds) |
| MAC | Layer-2 hardware address (from ARP frames if available) |
| Threat | Highest threat level this device has triggered |
| Last Seen | Timestamp of the most recent packet |
| Bytes | Total traffic (sent + received) |

---

## 9. Threat Detectors Deep Dive

All detectors live in `src/netwatchm/detector/` and implement the same interface:

```python
class Detector:
    def process(self, packet: Packet) -> Alert | None: ...
    def flush_expired(self) -> None: ...
```

Every packet flows through all four detectors in sequence. If a detector decides
the packet is suspicious it returns an `Alert`; otherwise it returns `None`.

### PortScanDetector (`port_scan.py`)

**What it detects:** A single source IP contacting many different destination
ports in a short time — the classic sign of a network port scanner like nmap.

**How it works:**
- Keeps a sliding time window (default: 10 seconds) per source IP
- Counts *distinct* destination ports hit within that window
- When the count reaches `ports_per_window` (default: 15), raises a `HIGH` alert
- The alert is deduplicated: only one alert fires per IP per window (no flooding)
- When the port count drops back below the threshold (old entries expire), the
  IP is removed from the "already alerted" set so future scans are caught

**Example:** If `10.0.0.5` hits ports 22, 23, 80, 443, 8080, 3306, 3389...
(15+ ports) within 10 seconds → `PORT_SCAN` HIGH alert.

### BruteForceDetector (`brute_force.py`)

**What it detects:** Repeated connection attempts to authentication services —
the hallmark of automated password-guessing tools.

**Watched ports by default:** 22 (SSH), 3389 (RDP), 21 (FTP), 3306 (MySQL),
5900 (VNC)

**How it works:**
- Keeps a sliding window per `(src_ip, dst_port)` pair
- Counts packets (each packet = one connection attempt) within the window
- When attempts reach `attempts_per_window` (default: 10) within
  `window_seconds` (default: 30 s) → raises a `HIGH` alert

**Example:** A bot hammering SSH from `203.0.113.42` — 10+ packets to port 22
in 30 seconds → `BRUTE_FORCE` HIGH alert.

### ExfiltrationDetector (`exfiltration.py`)

**What it detects:** A device sending an abnormally large volume of data in a
short time — could indicate data theft, a compromised host uploading files, or
a misconfigured backup running at the wrong time.

**How it works:**
- Tracks bytes sent per source IP in a sliding window
- Default threshold: 10 MB in 60 seconds
- Raises a `HIGH` alert when exceeded

**Example:** A workstation suddenly uploading 15 MB in 60 seconds to an unknown
external IP → `EXFILTRATION` HIGH alert.

### NewIPDetector (`new_ip.py`)

**What it detects:** A device that was never seen before appearing on the
network — could be a rogue device, an attacker who gained LAN access, or
simply a new legitimate device.

**How it works:**
- During the `baseline_period` (default: 300 s after startup), it silently
  collects all IPs it sees and adds them to a "known IPs" set
- After the baseline period ends, any new IP not in the known set triggers
  a `MEDIUM` alert
- Once an IP is added to `known_ips` it never alerts again for that IP

**Example:** After 5 minutes of learning the network, a Raspberry Pi with
`192.168.1.250` that was never seen before connects → `NEW_IP` MEDIUM alert.

### ThreatScorer (`scorer.py`)

The scorer doesn't detect anything itself. It aggregates all active alerts
and returns the *maximum* current threat level:

- `LOW` — no active alerts
- `MEDIUM` — at least one MEDIUM alert, nothing higher
- `HIGH` — at least one HIGH alert, nothing higher
- `CRITICAL` — at least one CRITICAL alert

Alerts automatically expire after their `expires_at` timestamp. The scorer
calls `flush_expired()` every second to remove stale alerts and recalculate.

---

## 10. Alert System

An alert is represented by the `Alert` dataclass:

```python
@dataclass
class Alert:
    alert_type:  str          # "PORT_SCAN", "BRUTE_FORCE", etc.
    level:       ThreatLevel  # LOW / MEDIUM / HIGH / CRITICAL
    src_ip:      str | None   # attacker's IP
    dst_ip:      str | None   # target IP
    description: str          # human-readable message
    timestamp:   datetime     # when it fired
    expires_at:  float        # epoch seconds; 0 = never
```

Each alert passes through all enabled handlers in `alerts/`:

### TerminalAlert

Prints a coloured line to the Rich console in the dashboard.
Disabled automatically when `--no-ui` is used.

### LogFileAlert

Writes to a rotating log file (default: `/var/log/netwatchm/netwatchm.log`).
Uses Python's `RotatingFileHandler` — rolls over at 10 MB, keeps 5 backups.

**View the log:**
```bash
tail -f /var/log/netwatchm/netwatchm.log
```

### SoundAlert

Plays `assets/alert.wav` (an 880 Hz beep) via `pygame.mixer`.
Only fires for alerts at or above `min_level` (default: HIGH).
Silently skipped if no audio device is available (e.g. headless servers).

### EmailAlert

Sends an email via SMTP (default: Gmail on port 587 with STARTTLS).
Has a per-alert-type cooldown (default: 5 minutes) to avoid flooding your inbox.
The password is **always** read from the `NETWATCHM_EMAIL_PASSWORD` environment
variable — never from the YAML file.

---

## 11. Device Inventory

### What is tracked

Every IP address that appears as a source or destination in a captured packet
gets a `DeviceRecord`:

```python
@dataclass
class DeviceRecord:
    ip:             str
    mac:            str | None      # from ARP; may be None for routed traffic
    hostname:       str | None      # from reverse DNS; filled in asynchronously
    vendor:         str | None      # from MAC OUI lookup
    first_seen:     datetime
    last_seen:      datetime
    bytes_sent:     int
    bytes_received: int
    ports_observed: set[int]
    threat_level:   ThreatLevel
```

### Where it lives

- **In memory:** `DeviceStore` holds a dict of `{ip: DeviceRecord}`
- **On disk:** `/var/lib/netwatchm/inventory.json` — auto-saved every 60 s
  and on clean shutdown

### DNS resolution

`DNSResolver` runs as a background asyncio task. It picks IPs from the store
that don't yet have a hostname, performs a `socket.getfqdn()` reverse lookup,
and writes the result back to the store. Lookups have a 2-second timeout and
failed results are cached for 5 minutes so the same dead lookup isn't retried
constantly.

### Exporting

**From the terminal UI:** press `I` (inventory view) then `E` → writes a CSV
to the configured `export_dir`.

**From the CLI:**
```bash
uv run netwatchm inventory --export /tmp/devices.csv
```

**Manually:**
```bash
cat /var/lib/netwatchm/inventory.json | python3 -m json.tool
```

---

## 12. The HTML Report Dashboard

`report.html` is a self-contained single-file web dashboard that reads
`inventory.json` and presents it visually.

### Starting it

```bash
# One-time: copy the HTML next to inventory.json
sudo cp /home/jbaez120/ai-projects/netwatchm/report.html /var/lib/netwatchm/

# Start a local server (needed so fetch() can read the JSON)
cd /var/lib/netwatchm && python3 -m http.server 8765

# Open in browser
brave http://localhost:8765/report.html
```

### Features

| Feature | Details |
|---------|---------|
| Summary cards | Total devices, HIGH / MEDIUM / LOW counts, total traffic |
| Live indicator | Pulsing dot + spinning ring shows it's active |
| Auto-refresh | Fetches fresh `inventory.json` every 30 s without a page reload |
| Countdown | Header shows "refresh in 18 s" |
| Search | Filters by IP, hostname, MAC, or port number as you type |
| Threat filter | Click HIGH / MEDIUM / LOW to isolate devices by risk tier |
| Sortable columns | Click any column header to sort ascending / descending |
| Port badges | Known service ports (SSH, HTTP, DNS…) shown in blue with name |
| Human-readable bytes | Sent ↑ / Received ↓ shown as KB / MB / GB |
| Relative timestamps | "5m ago" with full date visible on the row |
| Row flash | Rows briefly highlight when data refreshes |
| Dark / Light theme | Toggle button top-right |
| CSV export | Download filtered table as `.csv` |
| Avalonia WebView ready | Supports data injection via `window.__INVENTORY_DATA__` |

### Keeping it running automatically

Add a simple systemd service or cron job to keep the Python server alive:

```bash
# Quick one-liner — keeps server alive in background
nohup python3 -m http.server 8765 --directory /var/lib/netwatchm &
```

Or add this to `/etc/rc.local` for a permanent solution.

---

## 13. Running as a System Service

### Linux (systemd)

The installer creates `/etc/systemd/system/netwatchm.service` automatically.
To do it manually:

```bash
sudo uv run netwatchm --config /etc/netwatchm/netwatchm.yaml --install-service
```

This generates a service file that:
- Runs netwatchm with `--no-ui` (no dashboard needed in a service)
- Loads the email password from `/etc/netwatchm/env`
- Restarts automatically if it crashes (`Restart=on-failure`)
- Starts after the network is up (`After=network.target`)

**Useful commands:**
```bash
sudo systemctl start netwatchm      # start now
sudo systemctl stop netwatchm       # stop
sudo systemctl enable netwatchm     # start on boot
sudo systemctl disable netwatchm    # don't start on boot
sudo systemctl restart netwatchm    # apply config changes
journalctl -u netwatchm -n 50       # last 50 log lines
journalctl -u netwatchm -f          # follow live logs
```

### Windows

```powershell
# Run as Administrator
python -m netwatchm --install-service
```

Requires `pywin32` (`pip install pywin32`). Creates a Windows Service visible
in `services.msc`.

---

## 14. Testing

NetWatchM has 57 automated tests covering all detectors, the config loader,
the inventory store, exporters, and alert handlers.

### Run all tests

```bash
export PATH="$HOME/.local/bin:$PATH"
uv run pytest tests/ -v
```

### Run a specific file

```bash
uv run pytest tests/test_port_scan.py -v
```

### Run a specific test

```bash
uv run pytest tests/test_port_scan.py::test_port_scan_fires -v
```

### What the tests cover

| Test file | What it tests |
|-----------|--------------|
| `test_models.py` | Packet, Alert, DeviceRecord dataclasses |
| `test_config.py` | YAML loading, defaults, env var password injection |
| `test_port_scan.py` | PortScanDetector fires and deduplicates correctly |
| `test_brute_force.py` | BruteForceDetector fires on correct ports |
| `test_exfiltration.py` | ExfiltrationDetector fires at byte threshold |
| `test_new_ip.py` | NewIPDetector respects baseline period |
| `test_scorer.py` | ThreatScorer aggregates and expires alerts |
| `test_inventory_store.py` | DeviceStore updates, persists, loads |
| `test_exporter.py` | CSV export format |
| `test_capture.py` | NDJSON parsing edge cases |
| `test_alerts.py` | Terminal, log, sound, email handlers |

---

## 15. Troubleshooting

### `uv: command not found` after install

```bash
export PATH="$HOME/.local/bin:$PATH"
# Make it permanent:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### `tshark: command not found`

```bash
sudo apt install tshark          # Ubuntu/Debian
sudo dnf install wireshark-cli   # Fedora/RHEL
sudo pacman -S wireshark-cli     # Arch
```

### `Permission denied` on the network interface

NetWatchM (via tshark) needs root or `CAP_NET_RAW`:

```bash
# Option 1: run with sudo
sudo uv run netwatchm ...

# Option 2: give tshark the capability (no sudo needed after this)
sudo setcap cap_net_raw,cap_net_admin+eip $(which tshark)
sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)
```

### `env: 'uv': No such file or directory` in systemd

The systemd service uses an absolute path to uv. Re-run the installer to
regenerate the service file with the correct path:

```bash
sudo bash install.sh
```

### HTML report shows "Could not load inventory.json"

Brave (and Chrome) block `fetch()` on `file://` URLs. Use the Python server:

```bash
cd /var/lib/netwatchm && python3 -m http.server 8765
# then open: http://localhost:8765/report.html
```

### No alerts firing — is it working?

Check that tshark is seeing traffic:

```bash
sudo tshark -i enp6s0 -c 10
```

If no packets appear, check your interface name:

```bash
ip link show          # list all interfaces
ip addr               # show IPs (pick the one with your LAN IP)
```

Then update `interface:` in `/etc/netwatchm/netwatchm.yaml` and restart:

```bash
sudo systemctl restart netwatchm
```

### Sound not playing

The sound alert silently skips if pygame can't find an audio device. This is
expected on headless servers. To test locally:

```bash
python3 -c "import pygame; pygame.mixer.init(); print('Audio OK')"
```

### Email not being sent

1. Make sure `enabled: true` in the email section of your config
2. Verify the env var is set: `echo $NETWATCHM_EMAIL_PASSWORD`
3. Use a Gmail **App Password** (not your regular password)
4. Make sure 2FA is enabled on the Gmail account (required for App Passwords)
5. Check logs: `journalctl -u netwatchm | grep -i email`

---

## 16. Phase 3 Threat Detectors

Three additional detectors were added after the core four:

### TorExitDetector (`detector/tor_exit.py`)
Downloads the Tor Project's daily exit node list and checks every source IP against it.
- Alert type: `TOR_EXIT` — level: **HIGH**
- List refreshed every 24 hours automatically
- Config: `tor_exit.enabled`, `tor_exit.refresh_interval_hours`

### AdultDomainDetector (`detector/adult_domain.py`)
Checks DNS queries and TLS SNI fields against the Steven Black porn domain list (153k domains).
- Alert type: `ADULT_DOMAIN` — level: **MEDIUM**
- Fired once per device/domain pair per session (deduplication)
- Config: `adult_domain.enabled`, `adult_domain.extra_domains`, `adult_domain.refresh_hours`

### DataHogDetector (`detector/data_hog.py`)
Tracks total bytes sent and received per local device over a 24-hour rolling window.
- Alert type: `DATA_HOG` — level: **HIGH**
- Default threshold: 10 GiB in 24 hours
- Config: `data_hog.enabled`, `data_hog.threshold_gb`, `data_hog.window_hours`
- Avoids double-counting: only adds destination bytes when the source is external

---

## 17. Events Portal (`/events.html`)

The Events Portal is a built-in web SPA at `https://localhost:8765/events.html`.
It shows a searchable, filterable live view of all security alerts from the last 72 hours.

### Features

| Feature | Details |
|---------|---------|
| Auto-refresh | Every 15 seconds with countdown timer |
| Text search | Filters by IP, type, or description as you type |
| Level filter | ALL / LOW / MEDIUM / HIGH / CRITICAL |
| Type filter | Populated dynamically from events in DB |
| Expandable rows | Click any row to see full description |
| Deep Inspect link | Launches `/inspect/{ip}` for the source IP |
| CSV export | Downloads filtered table as `.csv` |
| Test Notify | Fires a live ntfy push notification |
| **Clear Alerts** | Deletes all events (admin token required) |

### Clear Alerts

1. Click **🗑 Clear Alerts** in the toolbar
2. A modal prompts for the **admin token**
3. Default token: `netwatchm-admin`
4. Change via env var: `NETWATCHM_ADMIN_TOKEN=your-token` in the service file
5. On success all events are deleted and the table reloads empty

### Event Store

- Database: `/var/lib/netwatchm/events.db` (SQLite)
- Retention: 72 hours (auto-purged)
- All alert types are stored regardless of level

---

## 18. Push Notifications (ntfy.sh)

NetWatchM can send push notifications to your phone via [ntfy.sh](https://ntfy.sh) —
a free, open-source push notification service.

### How it works

Every alert that passes the `min_level` threshold is sent as an HTTP POST to:
```
https://ntfy.sh/{your-topic}
```
The priority maps to threat level: LOW=2, MEDIUM=3, HIGH=4, CRITICAL=5.

### Config (`netwatchm.yaml`)

```yaml
alerts:
  ntfy:
    enabled: true
    server: https://ntfy.sh       # or self-hosted ntfy instance
    topic: your-topic-name        # unique topic name (keep it private)
    min_level: HIGH               # LOW / MEDIUM / HIGH / CRITICAL
    cooldown_seconds: 300         # silence same alert type for 5 min
    # token: ""                   # optional Bearer token for private topics
```

### Token authentication

For private topics, set the token via environment variable — never in YAML:
```bash
# Add to /etc/systemd/system/netwatchm.service [Service] section:
Environment=NETWATCHM_NTFY_TOKEN=tk_your_token_here
```

### Subscribe on your phone

1. Install the ntfy app (Android / iOS)
2. Add subscription → enter your topic name
3. Push notifications arrive whenever an alert fires

### Test Notify button

The **🔔 Test Notify** button in the Events Portal fires a test notification
immediately by calling `POST /api/test-ntfy` on the web server.

---

## 19. Grafana → ntfy Webhook Bridge

Grafana can forward its own alert notifications to ntfy via the NetWatchM bridge.

### Setup

```bash
bash scripts/setup-grafana-ntfy.sh
```

This creates a Grafana contact point (`NetWatchM ntfy`) pointing to:
```
http://127.0.0.1:8766/api/grafana-ntfy
```

Grafana's notification policy routes all `source=netwatchm` alerts through this bridge.

### How it works

1. Grafana fires an alert (e.g. HIGH device count > 0)
2. Grafana POSTs a JSON webhook to `/api/grafana-ntfy`
3. NetWatchM reads the payload, extracts title + summary
4. Forwards to ntfy.sh as a push notification

### Manual test

```bash
curl -s -X POST http://localhost:8766/api/grafana-ntfy \
  -H "Content-Type: application/json" \
  -d '{"status":"firing","title":"Test","alerts":[]}'
```

---

## 20. Grafana Dashboard Guide

The Grafana dashboard is at `http://localhost:3000`.
Credentials: `admin` / `BioIluvleeloo@5858`

### Top Row — Inventory Stats (y=0)

| Panel | Source | Description |
|-------|--------|-------------|
| Total Devices | `/api/inventory/total` | All devices seen in inventory |
| HIGH Threat | `/api/inventory/high` | Devices with HIGH threat level |
| MEDIUM Threat | `/api/inventory/medium` | Devices with MEDIUM threat level |
| LOW Threat | `/api/inventory/low` | Devices with LOW threat level |
| Threat Distribution | `/api/inventory/stats` | Donut chart: HIGH/MEDIUM/LOW device counts |

### Second Row — Alert Count Stats (y=4)

These pull from the **events database** (not inventory) and show live alert counts:

| Panel | Source | Color |
|-------|--------|-------|
| CRITICAL Alerts | `/api/events/count/critical` | Red `#f85149` |
| HIGH Alerts | `/api/events/count/high` | Orange `#ff9900` |
| MEDIUM Alerts | `/api/events/count/medium` | Amber `#cc8800` |

### Device Inventory Table (y=8)

Full device table: IP, Hostname, MAC, Vendor, Threat (colour-coded), Bytes Sent, Bytes Received, Last Seen.

### Top Traffic Devices (y=16)

Live enriched traffic table from `/api/flows/devices/enriched`:
- Columns: IP, Device, Sent, Received, Total
- Each IP has **View Events** link → events portal filtered by IP
- Each IP has **Deep Inspect** link → `/inspect/{ip}` launcher

### Application Activity + Hourly Activity (y=24)

- **Application Activity** — donut showing top applications by traffic (port-based)
- **Hourly Activity** — bar chart of traffic volume per hour over the last 24 hours

### Connection Report Row (y=33, collapsed)

Click the row header to expand. Contains historical connection data panels.
Collapse keeps the dashboard clean.

### Intelligence Row (y=34)

| Panel | Source | Description |
|-------|--------|-------------|
| Trigger Sites | `/api/events/adult-domains` | ADULT_DOMAIN events grouped by device + domain |
| Browsing Activity | `/api/flows/browsing` | Local device → external site traffic |

Browsing Activity links: Deep Inspect → `/inspect/{src_ip}`

### Alert History (y=46)

Table of last 72h MEDIUM/HIGH/CRITICAL alerts from the events database.
Columns: Time, Type, Level (colour-coded), Source IP, Dest IP, Description, Country (GeoIP).
Source IP links → events portal filtered by IP.

### Dashboard maintenance

```bash
bash scripts/import-dashboard.sh    # re-import after grafana-dashboard.json changes
bash scripts/deploy-server.sh       # deploy server changes + restart service
bash scripts/test-all-alerts.sh     # smoke test: seeds events + fires ntfy + Grafana bridge
```

### Parser rules (hard-won lessons)

- **Always use `backend` parser** with explicit columns — `jsonata` dumps all JSON fields
- All Infinity targets require `"url_options": {"method": "GET", "data": ""}` or panels fail silently
- Specific routes must be checked BEFORE generic `startswith` handlers in `GrafanaHandler.do_GET()`
- Use `timestamp_epoch_ms` column type for time fields in stat panels

---

## 21. Deep Inspect

Deep Inspect runs a security analysis on any IP address on your network.

### What it checks

| Check | Details |
|-------|---------|
| Port scan | Probes 15 common ports (21, 22, 80, 443, 3306, 3389, etc.) |
| GeoIP | Country, city, ISP, ASN (external IPs only) |
| HTTP/HTTPS | Attempts connection, checks for web server banner |
| SSH fingerprint | Reads host key type (via paramiko) |
| SMB/CIFS | Detects Windows file sharing |
| RDP | Detects Remote Desktop Protocol |
| Risk score | low / medium / high based on open ports + findings |

### How to launch

1. **Events Portal** — click **Deep Inspect** on any event row
2. **Grafana** — click the Deep Inspect link in the Traffic or Browsing table
3. **Direct URL** — `https://localhost:8765/inspect/{ip}`

### Launcher page

`/inspect/{ip}` shows a spinner while the job runs in the background.
It polls `/api/deep-inspect/status?target={ip}` every 2 seconds.
When complete, it auto-redirects to the report at `/deep-inspect-{ip}.html`.

### CLI

```bash
uv run netwatchm deep-inspect --target 192.168.1.100 --output /tmp/report.html
```

---

## 22. Web Server API Reference

The NetWatchM web server runs on two ports:

| Port | Protocol | Used by |
|------|----------|---------|
| 8765 | HTTPS | Browser (Events Portal, reports, launcher pages) |
| 8766 | HTTP | Grafana Infinity datasource |

### HTTPS API (port 8765)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events.html` | Events Portal SPA |
| GET | `/api/events` | Query events (params: `limit`, `type`, `level`, `ip`) |
| GET | `/api/events/types` | List distinct alert types in DB |
| GET | `/api/aliases` | Get all device aliases `{ip: label}` |
| POST | `/api/aliases` | Set alias `{ip, label}` (empty label = delete) |
| POST | `/api/deep-inspect` | Start deep inspect job `{target, ports}` |
| GET | `/api/deep-inspect/status` | Poll job status `?target=ip` |
| POST | `/api/test-ntfy` | Fire test push notification |
| POST | `/api/analytics` | Generate analytics report |
| DELETE | `/api/events` | Clear all events (requires `X-Admin-Token` header) |
| GET | `/inspect/{ip}` | Deep Inspect launcher page |

### HTTP API (port 8766, Grafana only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/inventory/{total\|high\|medium\|low\|stats}` | Device counts |
| GET | `/api/events/history` | MEDIUM+ alert history (with GeoIP country) |
| GET | `/api/events/adult-domains` | ADULT_DOMAIN events grouped by device+domain |
| GET | `/api/events/count/{critical\|high\|medium}` | Count of alerts by level |
| GET | `/api/alerts/data-hog` | DATA_HOG event count last 24h |
| GET | `/api/flows/browsing` | Local device → site browsing activity |
| GET | `/api/flows/devices/enriched` | Top devices with sent/received/total |
| GET | `/api/flows/top-apps` | Top applications by traffic (port-based) |
| GET | `/api/flows/hourly` | Hourly traffic for last 24h |
| POST | `/api/grafana-ntfy` | Grafana webhook → ntfy bridge |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWATCHM_PORT` | `8765` | HTTPS port |
| `NETWATCHM_GEOIP_DB` | `/var/lib/netwatchm/GeoLite2-City.mmdb` | GeoIP database |
| `NETWATCHM_FLOW_DB` | `/var/lib/netwatchm/flows.db` | Flow store database |
| `NETWATCHM_EVENT_DB` | `/var/lib/netwatchm/events.db` | Events database |
| `NETWATCHM_ADMIN_TOKEN` | `netwatchm-admin` | Admin token for DELETE /api/events |
| `NETWATCHM_CMD` | `netwatchm` | CLI binary path |
| `NETWATCHM_CONFIG` | `/etc/netwatchm/netwatchm.yaml` | Config file path |
| `NETWATCHM_NTFY_TOKEN` | _(none)_ | ntfy Bearer token for private topics |

---

## 16. Glossary

| Term | Meaning |
|------|---------|
| **asyncio** | Python's built-in library for writing concurrent code using `async`/`await` without threads |
| **tshark** | Command-line version of Wireshark; captures live network packets |
| **NDJSON** | Newline-Delimited JSON — one JSON object per line; tshark outputs this with `-T ek` |
| **NIC** | Network Interface Card — the hardware (or virtual) device that connects to a network (e.g. `enp6s0`, `eth0`, `wlan0`) |
| **promiscuous mode** | A mode where a NIC captures ALL packets on the network, not just those addressed to it |
| **port scan** | Systematically probing many ports on a host to find open services |
| **brute force** | Trying many passwords rapidly against an authentication service |
| **exfiltration** | Unauthorized transfer of data out of a system or network |
| **sliding window** | A time-based counter that tracks events within the last N seconds, discarding older ones as they expire |
| **ThreatLevel** | An enum: LOW(1) < MEDIUM(2) < HIGH(3) < CRITICAL(4) |
| **DeviceRecord** | All known information about one device (IP, MAC, hostname, traffic, threat level) |
| **inventory.json** | The on-disk database of all seen devices — updated every 60 s |
| **systemd** | Linux's init system and service manager; used to run netwatchm as a background service |
| **App Password** | A 16-character Google-generated password for third-party apps; safer than your real password |
| **Rich** | A Python library for beautiful terminal output — tables, colours, live displays |
| **uv** | A fast Python package manager from Astral that replaces pip + venv |

---

*Guide written for NetWatchM v0.1.0 — February 2026*
