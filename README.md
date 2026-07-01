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
| **Malware Domain** | DNS/TLS SNI matches abuse.ch URLhaus active malware/C2 host list |
| **DNS Tunneling** | Burst of long or high-entropy DNS queries from one device (data smuggling over DNS) |
| **Beaconing (C2)** | Periodic outbound contacts to a single external host with low jitter |

Alerts are delivered via: terminal, rotating log file, sound (beep), Gmail email, and **ntfy push notifications** (Android/iOS).  
All alert notifications use **plain-English descriptions** — no raw alert codes.

### Incident Response (forensics + threat-intel enrichment)

When `alerts.forensics.enabled: true`, an alert at/above the configured level
(default `HIGH`) automatically opens an **incident case**:

- a **short-burst pcap** of the offending IP is captured for evidence (bounded by
  duration and packet count) — downloadable from the portal,
- the external IP is **enriched against GreyNoise, AbuseIPDB, VirusTotal** and the
  local GeoLite2 DB, folded into a single verdict (`malicious` / `suspicious` /
  `benign`) + score,
- the case lands in **`/incidents.html`** with a status workflow
  (open → reviewed / false positive).

Capture + lookups run off the alert path (per-IP cooldown), so detection is never
blocked. Threat-intel API keys come from env vars only —
`NETWATCHM_ABUSEIPDB_KEY`, `NETWATCHM_VT_KEY`, `NETWATCHM_GREYNOISE_KEY`
(GreyNoise community works with no key).

**Alert triage:** incidents carry a **priority** (auto-derived from severity,
editable), an **assignee**, and a **hits** counter — repeat alerts of the same
type from the same IP within an hour correlate into one case instead of
flooding the queue. Filter the queue by status, priority, or assignee.

### SIEM forwarding (CEF over syslog)

With `alerts.siem.enabled: true`, every alert at/above `min_level` is forwarded
to your SIEM as **ArcSight CEF wrapped in syslog** (UDP or TCP) — ingested
natively by Splunk, IBM QRadar, Elastic, Wazuh, Graylog, and Microsoft
Sentinel. Severity maps from ThreatLevel; no credentials (plain syslog to a
collector `host:port`).

### GRC — Risk & Compliance (`/grc.html`)

A governance/risk/compliance view over the whole fleet:

- a **per-device risk score** (0–100) folding network exposure (risky open
  ports + attack surface), recent alert activity, and threat-intel verdict for
  public peers — with concrete remediation recommendations,
- a **CIS Controls v8-aligned assessment** (asset inventory, cleartext-service
  exposure, remote-admin hardening, audit logging, high-risk devices) scored
  pass / warn / fail with an overall **compliance %**,
- an exportable **risk register** (CSV).

---

## Quick Start

```bash
git clone https://github.com/JBaezDev25/netwatchm.git
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
| Incidents | `/incidents.html` | Auto incident cases — pcap evidence + threat-intel verdict, triage (priority/assignee/hits), status workflow |
| GRC | `/grc.html` | Per-device risk scores + CIS-aligned compliance assessment + exportable risk register |
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

- "What is 10.0.0.50 doing on the network?"
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

## Autonomous Agent

NetWatchM ships an opt-in autonomous agent that observes recent events every few
minutes, asks a **local** LLM (default: `mistral:latest` via Ollama, free / no
API keys) what to do, and either logs the decision (dry-run) or acts on it
(live). Every decision and every action — proposed, executed, blocked, or rolled
back — is written to `/var/lib/netwatchm/agent_actions.db`.

### Two modes

| Mode | What it does | Recommended use |
|---|---|---|
| **dry-run** (Phase 1) | Reads context, asks the LLM, records rationale. Action tools are blocked at dispatch even if the model fabricates one. | First few days after enabling. Watch the audit log to verify the LLM's judgment is sound on *your* traffic. |
| **live** (Phase 2) | Same as dry-run, plus the agent can add/remove TTL-bounded whitelist entries, suppress alert types, run nmap / deep-inspect scans, and send ntfy notifications with one-tap rollback action buttons. | Flip `agent.dry_run: false` once you trust what dry-run shows. |

### Notification mode (reactive vs digest)

A separate axis from dry-run/live, set by `agent.mode`:

| Mode | Notifications |
|---|---|
| **reactive** (default) | The agent decides every `interval_seconds` and may push per tick. |
| **digest** | The agent stays quiet, then pushes **one categorized summary every `digest_interval_days`** (default 5) — each threat category with its count, top source, and a recommended mitigation. Real-time push is still sent for genuine threats via the ntfy handler (`alerts.ntfy.min_level: CRITICAL`). |

Beacon patterns (`BEACONING`) are **never pushed** in either mode — they're still
detected and stored in `events.db`, and rolled into the digest only if you remove
them from `digest_exclude_types`. Configure the live host with
`bash scripts/configure-digest-mode.sh` (prompts for your ntfy topic, backs up the
config, validates, and restarts).

### Read-only tools (always available)

`query_recent_events`, `query_threat_history`, `query_device_inventory`,
`query_whitelist_state`, `query_suppression_state`.

### Action tools (live mode only)

`add_whitelist_entry`, `remove_whitelist_entry`, `suppress_alert_type`,
`unsuppress_alert_type`, `run_active_scan`, `send_ntfy_alert`.

### Hard guardrails

Server-side Python — the LLM cannot override these:

- Cannot whitelist `0.0.0.0`, multicast, reserved, or any IP that fired CRITICAL
  in the last 24h
- Cannot suppress CRITICAL alert types (`EXFILTRATION`, `MALWARE_DOMAIN`)
- Whitelist entries are TTL-bounded (default 24h, hard cap 72h) and auto-expire
- Rate caps: 5 whitelist changes/hr, 3 suppress changes/hr, 10 scans/hr, 20
  notifications/day — enforced from the audit DB so they survive a runaway loop
- All packet-derived text wrapped in `<untrusted>` tags in the LLM prompt; tool
  args (IPs, integers, scan types) validated before any subprocess fires

### Enable

```yaml
# /etc/netwatchm/netwatchm.yaml
agent:
  enabled: true             # default false
  dry_run: true             # flip to false ONLY after audit review
  model: mistral:latest     # fastest tool-capable CPU model
  interval_seconds: 300     # 5 min between ticks (reactive mode)
  mode: digest              # reactive | digest
  digest_interval_days: 5   # one categorized summary every 5 days
```

Then `bash scripts/deploy-server.sh && sudo systemctl restart netwatchm`.

### Verify wiring without enabling

```bash
bash scripts/agent-doctor.sh
```

Runs **one** tick against your live `events.db`, prints the decision the agent
records to a scratch audit DB. No service restart, no config touch.

### Inspect live decisions

```bash
sqlite3 /var/lib/netwatchm/agent_actions.db \
  'SELECT ts, mode, max_severity, rationale FROM agent_decisions ORDER BY ts DESC LIMIT 10'

# tool calls (executed / blocked / rolled_back)
sqlite3 /var/lib/netwatchm/agent_actions.db \
  'SELECT tool_name, status, blocked_reason FROM agent_tool_calls ORDER BY ts DESC LIMIT 20'

# active agent-managed whitelist entries (skipped at alert dispatch)
curl -s https://localhost:8765/api/agent/whitelist -k -H "X-Read-Token: ..." | jq
```

### Rollback

When the agent whitelists an IP, the ntfy notification arrives with an inline
**Rollback** button (HTTP POST action — one tap, no browser round-trip).
Equivalent CLI:

```bash
curl -X POST https://localhost:8765/api/agent/rollback/<entry_id> -k
```

Phases 3-4 (DNS history + firewall rules + OS fingerprints + bandwidth
aggregator context tools, plus a web UI for the audit log) are planned but not
yet shipped.

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
                    │   MalwareDomain        │
                    │   DnsTunneling         │
                    │   Beaconing (C2)       │
                    └───────────────────────┘
                                            │
                    ┌───────────────────────┤
                    │   Alert Handlers       │
                    │   Terminal             │
                    │   Log file        ◄───┘
                    │   Sound
                    │   Email (Gmail SMTP)
                    │   ntfy push (Android/iOS)
                    │   SIEM forward (CEF/syslog)
                    │   Incident case (forensics)
                    └───────────────────────┘

netwatchm_server.py (port 8765, TLS)
  ├── /events.html       — live SPA (SQLite events.db)
  ├── /incidents.html    — incident cases SPA (SQLite forensics.db) + triage
  ├── /grc.html          — risk & compliance SPA (inventory + events + forensics)
  ├── /inventory.html    — device SPA (inventory.json + aliases.json)
  ├── /history.html      — flow history SPA (flow-history.db)
  ├── /pcap.html         — pcap upload analyzer
  ├── /ai.html           — AI chat UI (OpenAI gpt-4o-mini)
  ├── /api/ai            — AI query endpoint
  ├── /api/incidents     — incident cases list / detail / pcap download / status / triage
  ├── /api/grc           — fleet risk scores + CIS control assessment
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
│   │                        # data_hog, adult_domain, tracker_domain, tor_exit,
│   │                        # malware_domain, dns_tunneling, beaconing
│   ├── alerts/              # terminal, logfile, sound, email_alert, ntfy_alert,
│   │                        # siem_alert (CEF/syslog forwarding),
│   │                        # forensic_handler (incident cases),
│   │                        # alert_labels (plain-English titles + summaries)
│   ├── enrich/             # reputation (GreyNoise/AbuseIPDB/VirusTotal + GeoIP)
│   ├── forensics/          # store (incidents.db, triage), capture (short-burst pcap)
│   ├── grc/                # risk scoring + CIS-aligned control assessment
│   ├── inventory/           # store, resolver, exporter, arp_scanner,
│   │                        # oui_lookup (IEEE MAC vendor database)
│   ├── reports/             # connection_report, analytics_report, deep_inspect,
│   │                        # flow_store, flow_history
│   ├── ui/                  # dashboard, inventory_view, input_handler
│   ├── util.py              # shared helpers (format_bytes)
│   └── service/             # linux.py (systemd), windows.py (pywin32)
├── scripts/
│   ├── hotdeploy.sh             # Fast deploy: copy server + web/ + ai.html + restart
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
├── tests/                   # 356 pytest tests (all passing)
├── ai.html                  # AI Chat web UI
├── web/                      # static portal SPAs (events, inventory, history, pcap)
├── netwatchm_server.py      # Combined HTTPS server (8765) + Grafana API (8766)
├── netwatchm.yaml.example   # Annotated config template
└── install.sh               # Linux one-shot installer
```

---

## Installation

### Full rebuild — one command (Linux)

Rebuilding a box from scratch? One script installs the whole stack — NetWatchM, the local AI
(Ollama + `mistral` / `nomic-embed-text`), and the `nic-asst-ai` Claude/OpenRouter assistant:

```bash
git clone https://github.com/JBaezDev25/netwatchm.git
cd netwatchm
bash netwachmInstall/reinstall-all.sh           # --no-ai / --no-nic / --yes
```

Prefer a window? A **Linux GUI installer** wraps the same steps (checkboxes + live log):

```bash
python3 netwachmInstall/installer_gui_linux.py
bash netwachmInstall/install-launcher.sh        # add it to the app menu (Frenchie icon)
```

See `netwachmInstall/INSTALL.md` for details.

### Linux (recommended)

```bash
git clone https://github.com/JBaezDev25/netwatchm.git
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
1. git clone https://github.com/JBaezDev25/netwatchm.git
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
bash scripts/install-cert-linux.sh 10.0.0.180

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
  - 10.0.0.1          # router
  - 10.0.0.0/8           # CIDR blocks supported

detector_whitelist:
  PORT_SCAN:
    - 10.0.0.50       # suppress port scan alerts from this IP only
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

## Data Storage & Migration

### Runtime paths (current — after 2026-06-23 migration)

| Resource | Path |
|---|---|
| Config | `/etc/netwatchm/netwatchm.yaml` |
| Databases (`flows`, `events`, `flow-history`, `agent_actions`) | `/mnt/jbaez_data/netwatchm/` |
| GeoIP DB | `/mnt/jbaez_data/netwatchm/GeoLite2-City.mmdb` |
| JSON state (`inventory`, `aliases`, `verified`, `suppressed`, `oui`) | `/mnt/jbaez_data/netwatchm/` |
| Reports | `/mnt/jbaez_data/netwatchm/reports/` |
| Logs | `/mnt/jbaez_data/netwatchm/logs/netwatchm.log` |
| SSL certs + `agent_actions.db` | `/var/lib/netwatchm/` (unchanged — hardcoded paths) |
| Service drop-in | `/etc/systemd/system/netwatchm-web.service.d/nas-migration.conf` |

All configurable paths are set via environment variables in the systemd drop-in — the app code is unchanged.

### Migration history

**2026-06-23 — Data disk migration**

Moved all growing data off the main system drive (`/dev/sda2`, 61% full) onto the secondary data disk (`/dev/sdb1`, 432 GB free) to prevent the main drive from filling up over time.

Steps performed:
1. **Backup** — full snapshot of `/var/lib/netwatchm/` to `/mnt/jbaez_data/netwatchm-backup-<timestamp>/` with WAL checkpoint before copy
2. **NAS directories** — created `/volume1/AI-Programming/netwatchm/{reports,logs}` on the UGREEN NAS (`10.0.0.245`) for future archival
3. **Local data directory** — created `/mnt/jbaez_data/netwatchm/` owned by the `netwatchm` system user
4. **Data copy** — copied all databases, GeoIP, JSON state files, and reports to new location; archived existing log to NAS
5. **Service config** — wrote systemd drop-in (`nas-migration.conf`) overriding `WorkingDirectory` and all path env vars; updated `netwatchm.yaml` log path
6. **Cutover** — restarted both `netwatchm` and `netwatchm-web` services; brief downtime ~10 seconds
7. **Verification** — all 7 checks passed: services active, databases readable, API responding

**What stayed in place:** SSL certs and `agent_actions.db` remain at `/var/lib/netwatchm/` — their paths are hardcoded in the server and moving them would require a code change.

**NAS live mount (not implemented):** SSHFS and rsync were attempted for live report/log archival to the NAS but are blocked by UGOS SSH limitations. A scheduled sync job via SSH pipe is planned as a follow-up.

### Migration scripts (in `scripts/`)

| Script | Purpose |
|---|---|
| `backup-before-nas-migration.sh` | Point-in-time backup before any changes |
| `setup-local-data-dir.sh` | Create `/mnt/jbaez_data/netwatchm/` with correct ownership |
| `setup-nas-mount.sh` | SSHFS mount setup (reference only — blocked by UGOS) |
| `copy-data-to-new-locations.sh` | Copy databases and files to new paths |
| `update-config-for-nas.sh` | Write systemd drop-in + update yaml log path |
| `nas-cutover.sh` | Restart services against new paths |
| `verify-nas-migration.sh` | Verify all services, paths, and API are healthy |
| `rollback-nas-migration.sh` | Revert to original `/var/lib/netwatchm/` paths |

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
