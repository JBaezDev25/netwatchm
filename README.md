# NetWatchM

> Real-time network threat monitor for Linux — port scan detection, brute force, data exfiltration, adult/tracker domain alerts, and new-device notifications with a Rich terminal dashboard, full browser-based web UI, Grafana integration, and push notifications.

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-174%20passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## What It Does

NetWatchM watches every packet on your network interface and alerts you in real time:

| Threat | How it works |
|--------|-------------|
| **Port Scan** | A single IP hits 15+ distinct ports within 10 seconds |
| **Brute Force** | 10+ login attempts to SSH / RDP / FTP / MySQL / VNC in 30 seconds |
| **Exfiltration** | A device sends more than 10 MB in 60 seconds |
| **Data Hog** | A device transfers more than 10 GiB in 24 hours |
| **New Device** | An IP not seen during baseline period appears |
| **Adult Domain** | DNS/TLS SNI matches Steven Black adult domain list (153k domains) |
| **Tracker Domain** | DNS/TLS SNI matches ads/tracking/analytics domain list |
| **Tor Exit Node** | Outbound connection to a known Tor exit node |

Alerts are delivered via: terminal, rotating log file, sound (beep), Gmail email, and **ntfy push notifications** (Android/iOS).  
All alert notifications use **plain-English descriptions** — no raw alert codes.

---

## Quick Start

```bash
git clone https://github.com/al4nbr3/netwatchm.git
cd netwatchm
sudo bash install.sh
```

The installer handles Python deps, config, log directories, TLS cert, GeoIP database, and systemd services.

After install, open the portal in your browser:

```
https://localhost:8765/events.html        # Security events SPA
https://localhost:8765/inventory.html     # Device inventory
https://localhost:8765/ai.html            # AI network assistant
```

From any machine on the LAN (after running `scripts/setup-hostname.sh`):

```
https://netwatch.local:8765/events.html
```

---

## Web Portal Pages

| Page | URL | Description |
|------|-----|-------------|
| Events | `/events.html` | Live security alert feed — search, filter, export CSV |
| Inventory | `/inventory.html` | All discovered devices — friendly names, nmap scan, verify |
| Analytics | `/analytics.html` | Flow data charts — device traffic, destinations, protocols, hourly |
| Connection Report | `/connection-report.html` | Per-flow breakdown with GeoIP, risk scoring, deep inspect |
| History | `/history.html` | Historical inactive connections (30-day rolling) |
| Pcap Analyzer | `/pcap.html` | Upload .pcap/.pcapng — device list, DNS/TLS latency analysis |
| AI Assistant | `/ai.html` | Natural-language device analysis powered by OpenAI |
| Reports Index | `/reports` | Archive of past connection reports (last 50 kept) |

---

## AI Assistant

The built-in AI Chat (`/ai.html`) uses OpenAI `gpt-4o-mini` to answer natural-language questions about your network:

- "What is 192.168.1.50 doing on the network?"
- "Which devices contacted port 443 in the last 72 hours?"
- "Summarize all devices and flag anything suspicious"
- "Are there any unidentified devices I should investigate?"
- "Which alert types are currently suppressed?"

The AI receives live context from multiple sources every time you ask a question:

| Context | Source |
|---------|--------|
| Device identity (IP, MAC, hostname, vendor) | `inventory.json` |
| Friendly name / verified status | `aliases.json`, `verified.json` |
| Security alert history (last 20) | `events.db` |
| Port usage + byte counts (72h) | `flows.db` |
| MAC vendor lookup (OUI database) | `oui.json` |
| Suppressed alert types | `suppressed.json` |
| Global IP whitelist + per-type whitelist | `netwatchm.yaml` |
| Unidentified devices (no hostname + no vendor) | Cross-referenced at query time |

The AI flags **unidentified devices** (no resolved hostname and no vendor in the OUI database) as the highest-priority unknowns, and warns if high-risk alert types like `BRUTE_FORCE` are suppressed.

**Setup:**
```bash
bash scripts/setup-ai-key.sh   # prompts for OPENAI_API_KEY, writes to systemd drop-in
bash scripts/hotdeploy.sh      # deploy server + ai.html
```

---

## MAC Vendor Database

NetWatchM includes a built-in MAC OUI → vendor lookup backed by the official IEEE registry (38,000+ entries). This fills in vendor names for devices that `arp-scan` cannot identify.

```bash
# Build or refresh the database (~3 MB, takes ~10 seconds)
bash scripts/update-oui-db.sh
```

The database is stored at `/var/lib/netwatchm/oui.json` and is consulted automatically by:
- The ARP scanner (fallback when arp-scan returns no vendor)
- The AI chat context builder (vendor enrichment per device)
- The unidentified-device policy report

Run `update-oui-db.sh` once after install, then monthly to pick up new OUI assignments.

---

## Service Hardening

The `netwatchm-web` service (browser portal) runs as a dedicated low-privilege system user (`netwatchm`) rather than root. The packet capture service still runs as root because tshark requires `CAP_NET_RAW`.

```bash
# Switch netwatchm-web from root → dedicated system user
bash scripts/harden-service-user.sh

# After hardening, re-deploy the server (rebuilds system venv accessible to netwatchm user)
bash scripts/deploy-server.sh
```

`harden-service-user.sh` is idempotent — safe to run multiple times. It:
1. Creates the `netwatchm` system user (no login shell, no home directory)
2. Transfers ownership of `/var/lib/netwatchm`, `/var/log/netwatchm`, `/etc/netwatchm`
3. Secures the OpenAI API key drop-in to `chmod 600` (root-only read)
4. Updates the service `User=` directive
5. Reloads systemd and restarts the web service

`deploy-server.sh` installs a system-wide Python venv at `/usr/local/lib/netwatchm/venv`, independent of the developer's home directory.

---

## Architecture

```
Network Interface
      │
      ▼
  tshark subprocess ──► capture.py ──► packet queue
                                            │
                    ┌───────────────────────┤
                    │   Detectors            │
                    │   PortScan             │
                    │   BruteForce      ──► alert queue
                    │   Exfiltration         │
                    │   NewIP                │
                    │   DataHog              │
                    │   AdultDomain          │
                    │   TrackerDomain        │
                    │   TorExitNode          │
                    └───────────────────────┘
                                            │
                    ┌───────────────────────┤
                    │   Alert Handlers       │
                    │   Terminal             │
                    │   Log file        ◄───┘
                    │   Sound
                    │   Email (Gmail SMTP)
                    │   ntfy push (Android/iOS)
                    └───────────────────────┘

netwatchm_server.py (port 8765, TLS)
  ├── /events.html       — live SPA (SQLite events.db)
  ├── /inventory.html    — device SPA (inventory.json + aliases.json)
  ├── /history.html      — flow history SPA (flow-history.db)
  ├── /pcap.html         — pcap upload analyzer
  ├── /ai.html           — AI chat UI (OpenAI gpt-4o-mini)
  ├── /api/ai            — AI query endpoint
  ├── /api/deep-inspect  — async GeoIP + nmap + SSH/SMB/HTTP inspection
  ├── /api/analytics     — async Chart.js analytics page generator
  ├── /api/aliases       — friendly device names CRUD
  ├── /api/verified      — device verified status toggle
  ├── /api/nmap          — per-device nmap scan
  └── /api/diagnostics/* — conntrack, tcpstates, iperf3

Grafana (port 3000)
  └── netwatchm_server.py (port 8766, no TLS) — Grafana-only API
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
│   ├── detector/            # port_scan, brute_force, exfiltration, new_ip,
│   │                        # data_hog, adult_domain, tracker_domain, tor_exit
│   ├── alerts/              # terminal, logfile, sound, email_alert, ntfy_alert,
│   │                        # alert_labels (plain-English titles + summaries)
│   ├── inventory/           # store, resolver, exporter, arp_scanner,
│   │                        # oui_lookup (IEEE MAC vendor database)
│   ├── reports/             # connection_report, analytics_report, deep_inspect,
│   │                        # flow_store, flow_history
│   ├── ui/                  # dashboard, inventory_view, input_handler
│   └── service/             # linux.py (systemd), windows.py (pywin32)
├── scripts/
│   ├── hotdeploy.sh             # Fast deploy: copy server + ai.html + restart
│   ├── deploy-server.sh         # Full deploy: system venv + server + restart
│   ├── harden-service-user.sh   # Switch netwatchm-web to dedicated non-root user
│   ├── update-oui-db.sh         # Download IEEE OUI registry → oui.json
│   ├── setup-hostname.sh        # Enable netwatch.local mDNS via Avahi
│   ├── setup-ai-key.sh          # Write OPENAI_API_KEY to systemd drop-in
│   ├── enable-remote-access.sh  # Open port 8765 + regenerate TLS cert with LAN SAN
│   ├── setup-grafana-alerts.sh  # Configure Grafana email alerting
│   ├── install-cert-linux.sh    # Trust NetWatchM cert on Linux client
│   ├── install-cert-windows.ps1 # Trust NetWatchM cert on Windows client
│   └── ...                      # 15+ additional setup and deploy scripts
├── netwachmInstall/
│   └── install.ps1          # Windows installer (GUI progress, upgrade/uninstall)
├── tests/                   # 174 pytest tests (all passing)
├── ai.html                  # AI Chat web UI
├── netwatchm_server.py      # Combined HTTPS server (8765) + Grafana API (8766)
├── netwatchm.yaml.example   # Annotated config template
└── install.sh               # Linux one-shot installer
```

---

## Installation

### Linux (recommended)

```bash
git clone https://github.com/al4nbr3/netwatchm.git
cd netwatchm
sudo bash install.sh
```

Installs and enables:

| Service | Description |
|---------|-------------|
| `netwatchm` | Packet capture + threat detection |
| `netwatchm-web` | Browser portal (HTTPS, port 8765) |

After install, build the MAC vendor database:

```bash
bash scripts/update-oui-db.sh
```

### Windows

```
1. git clone https://github.com/al4nbr3/netwatchm.git
2. cd netwatchm
3. Right-click netwachmInstall\install.ps1 → Properties → Unblock → OK
4. powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
```

The Windows installer shows a GUI progress window and creates Desktop + Start Menu shortcuts.

### Enable mDNS hostname (optional)

Access the portal from any LAN device by name instead of IP:

```bash
bash scripts/setup-hostname.sh
# Portal available at https://netwatch.local:8765
```

### Trust the TLS certificate

```bash
# Linux client
bash scripts/install-cert-linux.sh 192.168.1.180

# Windows client (run as Administrator)
powershell -ExecutionPolicy Bypass -File scripts/install-cert-windows.ps1

# Quick bypass (Chrome/Edge): type "thisisunsafe" on the cert warning page
```

---

## Configuration

Config lives at `/etc/netwatchm/netwatchm.yaml` after install.

```yaml
interface: enp6s0        # or auto

thresholds:
  port_scan:
    ports_per_window: 15
    window_seconds: 10
  brute_force:
    attempts_per_window: 10
    window_seconds: 30
  exfiltration:
    bytes_per_window: 10485760   # 10 MB
    window_seconds: 60
  data_hog:
    bytes_24h: 10737418240       # 10 GiB

alerts:
  terminal: true
  log:
    enabled: true
    path: /var/log/netwatchm/netwatchm.log
  email:
    enabled: false
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: you@gmail.com
    recipient: you@gmail.com
    min_level: HIGH
  ntfy:
    enabled: false
    server: https://ntfy.sh
    topic: your-topic
    min_level: MEDIUM

whitelist:
  - 192.168.1.1          # router
  - 10.0.0.0/8           # CIDR blocks supported

detector_whitelist:
  PORT_SCAN:
    - 192.168.1.50       # suppress port scan alerts from this IP only
```

> **Email/ntfy credentials:** never put passwords in YAML. Use env vars or systemd drop-ins.

---

## Grafana Dashboard

NetWatchM ships a full Grafana dashboard with live data panels:

- Device inventory table (threat level color-coded, links to events + deep inspect)
- Top traffic devices and destinations
- Alert history table (MEDIUM+, with GeoIP country)
- Protocol / application doughnut charts
- Hourly activity bar chart
- Adult domain trigger sites panel
- CRITICAL / HIGH / MEDIUM alert count stat panels

```bash
# One-time setup
bash scripts/configure-grafana-remote.sh
bash scripts/import-dashboard.sh

# Wire Grafana → ntfy push notifications
bash scripts/setup-grafana-ntfy.sh
```

Grafana runs on port 3000. Default credentials are set during install — change them immediately.

---

## Running

```bash
# Service control
sudo systemctl start netwatchm
sudo systemctl restart netwatchm-web
journalctl -u netwatchm -f

# Interactive terminal dashboard
sudo uv run netwatchm --config /etc/netwatchm/netwatchm.yaml

# Generate connection report manually
sudo bash scripts/gen-report.sh

# Deploy server changes
bash scripts/hotdeploy.sh
```

### Terminal dashboard keyboard shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit |
| `I` | Inventory view |
| `M` | Main dashboard |
| `E` | Export inventory CSV |
| `/` | Filter by IP / hostname |
| `Esc` | Clear filter |

---

## Tests

```bash
uv run pytest tests/ -v
# 174 passed
```

---

## Requirements

| Requirement | Version |
|------------|---------|
| Python | 3.12+ |
| tshark | any recent |
| uv | any |
| Linux | systemd-based |
| nmap | for deep inspect / per-device scan |
| avahi-daemon | for `netwatch.local` mDNS (optional) |

Python dependencies: `rich`, `pyyaml`, `pygame`, `geoip2`, `paramiko`, `openai`

---

## License

MIT
