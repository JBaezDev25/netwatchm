# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
uv run pytest tests/ -v

# Run a single test file
uv run pytest tests/test_detectors.py -v

# Run a single test by name
uv run pytest tests/test_detectors.py::test_port_scan_detected -v

# Run the monitor (dev mode on loopback)
uv run netwatchm --config netwatchm.yaml.example --interface lo

# Run without Rich dashboard (service mode)
uv run netwatchm --config netwatchm.yaml.example --interface lo --no-ui

# Subcommands (--interface is a top-level flag, before the subcommand)
uv run netwatchm --interface lo report --duration 5
uv run netwatchm inventory --filter 10.0.0.0/24
uv run netwatchm deep-inspect --target 10.0.0.50 --output /tmp/report.html
uv run netwatchm analytics --output /tmp/analytics.html
```

### Deployment scripts (never run sudo manually — use these scripts)
```bash
bash scripts/hotdeploy.sh            # fast deploy: copy netwatchm_server.py + restart netwatchm-web
bash scripts/deploy-server.sh        # full deploy: copy server + sync CLI from venv
bash scripts/import-dashboard.sh     # re-import Grafana dashboard JSON
bash scripts/seed-events.sh          # seed events.db with synthetic alerts for testing
bash scripts/enable-ntfy.sh          # deploy ntfy config + restart
bash scripts/apply-config-fix.sh     # safe config update with backup
bash scripts/capture-targetip.sh     # interactive tshark capture (prompts for IP, duration, interface)
```

## Architecture

NetWatchM is a real-time network threat monitor built on asyncio. Packets flow through a pipeline:

```
tshark (capture.py) → packet_queue → detector_loop → alert_queue → alert_dispatch_loop → handlers[]
                                                   ↘ inventory store (DeviceStore)
```

All async tasks run concurrently inside `run_monitor()` in `__main__.py`:
- **capture_loop** — wraps async tshark subprocess in `capture.py`
- **detector_loop** — feeds packets to each detector, pushes alerts to `alert_queue`
- **alert_dispatch_loop** — applies global whitelist, per-detector whitelist, and suppression file before scoring and dispatching to handlers
- **scorer_loop** — ThreatScorer decays old alerts to update the overall threat level
- **ui_refresh_loop** — updates Rich dashboard or inventory view at 2 Hz
- **resolver / persist / arp_scanner** — background inventory management

### Key modules

| Module | Role |
|---|---|
| `models.py` | `Packet`, `Alert`, `ThreatLevel`, `DeviceRecord` dataclasses |
| `config.py` | `load_config()` + all config dataclasses; env vars override YAML for secrets |
| `capture.py` | async tshark subprocess; emits `Packet` objects with dns_query + TLS SNI |
| `scorer.py` | `ThreatScorer` — sliding-window overall threat level (LOW/MEDIUM/HIGH/CRITICAL) |
| `whitelist.py` | `WhitelistChecker` — plain IPs + CIDR blocks, applied before scoring |

### Detectors (`src/netwatchm/detector/`)

Each detector implements `process(packet) -> Alert | None` and `flush_expired()`. The base pattern: a sliding deque per `src_ip` keyed on timestamp; when the window count exceeds threshold, fire an alert.

| Detector | Alert type | Level |
|---|---|---|
| `PortScanDetector` | `PORT_SCAN` | HIGH |
| `BruteForceDetector` | `BRUTE_FORCE` | HIGH |
| `ExfiltrationDetector` | `EXFILTRATION` | CRITICAL |
| `NewIPDetector` | `NEW_IP` | LOW |
| `TorExitDetector` | `TOR_EXIT` | HIGH |
| `AdultDomainDetector` | `ADULT_DOMAIN` | MEDIUM |
| `DataHogDetector` | `DATA_HOG` | HIGH |

For `TorExitDetector` and `AdultDomainDetector`: pass a `domain_set`/`exit_nodes` param in tests to bypass HTTP list downloads.

### Alert handlers (`src/netwatchm/alerts/`)

All handlers implement `async send(alert)`. `EventStoreHandler` (SQLite `events.db`) is always registered. Others are gated by config.

### Web server (`netwatchm_server.py`)

Standalone HTTPS server (port 8765) + HTTP Grafana bridge (port 8766). Not part of the main `netwatchm` package — deployed separately via `scripts/deploy-server.sh`. Reads the same YAML config. Key env vars: `NETWATCHM_GEOIP_DB`, `NETWATCHM_FLOW_DB`, `NETWATCHM_EVENT_DB`, `NETWATCHM_ADMIN_TOKEN` (default: `netwatchm-admin`).

**Route ordering matters in `GrafanaHandler.do_GET()`**: specific paths must be checked before generic `startswith` handlers.

### Inventory (`src/netwatchm/inventory/`)

`DeviceStore` tracks `DeviceRecord` objects keyed by IP. Persists to `/var/lib/netwatchm/inventory.json` (Linux). `DNSResolver` runs reverse lookups in a background loop. `ARPScanner` uses tshark ARP.

### Config system

`load_config(path)` builds a `Config` dataclass from YAML; missing keys use defaults. Secrets (email password, ntfy token) are always loaded from env vars in `Config.__post_init__()`, overriding any YAML value.

Two whitelist mechanisms:
1. **`whitelist`** — global IP/CIDR list; suppresses all alert types from those IPs
2. **`detector_whitelist`** — per-alert-type suppression for specific IPs only

### Testing conventions

- `pytest-asyncio` with `asyncio_mode = "auto"` — async tests work without decorators
- `conftest.py` provides `make_packet()` helper and fixture shortcuts for threshold configs
- Detectors using remote lists accept `domain_set`/`exit_nodes` constructor params to inject test data directly
- Tests import from `netwatchm.*` (package is in `src/`, installed via `uv sync`)

## Runtime paths (Linux)

Paths were migrated to the data disk on 2026-06-23. The service drop-in at
`/etc/systemd/system/netwatchm-web.service.d/nas-migration.conf` sets all env vars.

| Resource | Path |
|---|---|
| Config | `/etc/netwatchm/netwatchm.yaml` |
| Inventory | `/mnt/jbaez_data/netwatchm/inventory.json` |
| Events DB | `/mnt/jbaez_data/netwatchm/events.db` |
| Flow DB | `/mnt/jbaez_data/netwatchm/flows.db` |
| GeoIP DB | `/mnt/jbaez_data/netwatchm/GeoLite2-City.mmdb` |
| Logs | `/mnt/jbaez_data/netwatchm/logs/netwatchm.log` |
| Reports | `/mnt/jbaez_data/netwatchm/reports/` |
| SSL certs + agent_actions.db | `/var/lib/netwatchm/` (hardcoded, unchanged) |
| Service | `/etc/systemd/system/netwatchm-web.service` |
| Service drop-in | `/etc/systemd/system/netwatchm-web.service.d/nas-migration.conf` |

## Web portals (served by `netwatchm_server.py`)

| URL | Purpose |
|---|---|
| `/events.html` | Alert event history — search, filter, expandable rows, CSV export, Clear Alerts |
| `/inventory.html` | Device inventory — sortable, click-to-edit labels, verified toggle, per-device nmap scan |
| `/connection-report.html` | Live connection report (generated on demand via API) |
| `/history.html` | Inactive flow history — pin-to-keep, search, delete |
| `/pcap.html` | Drag-and-drop pcap/pcapng analyzer (devices, DNS latency, TLS latency) |
| `/deep-inspect-{ip}.html` | Per-device deep inspection report (GeoIP, ports, SSH, HTTP, RDP, SMB) |

Side-car JSON stores in `/var/lib/netwatchm/`:
- `aliases.json` — `{ip: label}` friendly names (GET/POST `/api/aliases`)
- `verified.json` — `{ip: bool}` verified device flag (GET `/api/verified`, POST `/api/verify`)
- `flow-history.db` — inactive flow history with pin support

## Coding style

- **Comments**: use sparingly. Only comment logic that is genuinely non-obvious. Do not comment what the code already says.
- **Credentials**: never hardcode passwords, tokens, or secrets in scripts or source files. Scripts that need credentials must prompt interactively (`read -rsp`) or read from an env var.

## Workflow preferences

- **sudo commands**: NEVER ask the user to run sudo manually. Write a `scripts/` bash script instead and describe what it does. Do not ask "run this now?" — the user decides when to run it.
- Live config edits: write to `/tmp/netwatchm.yaml` first, then use a script with `sudo cp`. Restart the service after config changes.
- Before proposing a new feature or change, check `CHECKLIST.md` to understand what already exists and what is pending.
- **CHECKLIST.md auto-update**: After EVERY change made to the project (code, scripts, config, fixes), immediately update `CHECKLIST.md` to record it under the current session section. Do not wait until the end of the session — update it after each individual task.
- **CHECKLIST.md reminder**: Remind the user to update CHECKLIST.md every 30 minutes with a countdown. Reset the countdown if the user asks to do it manually.
- **README.md auto-update**: After any session that adds a new feature, new script, new module, or changes user-facing behavior, update `README.md` to reflect it. Update the relevant section (What It Does, AI Assistant, Architecture, Project Structure, Scripts, etc.). Commit README.md together with the code changes. Also mark the README update in CHECKLIST.md under the session's Documentation entry.
- **Change confirmation**: After any file(s) in the project are modified, always end the response with a summary block listing every file that was updated, created, or deleted — with a ✅ confirmation that changes are complete.

## Session History
[Both Claude desktop and opencode update this section after each session.]
- 2026-06-30 — Built Claude ↔ opencode bridge (registry.json + .project-meta.json)
