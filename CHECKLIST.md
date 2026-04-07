# NetWatchM — Project Checklist

Last updated: 2026-04-06 (session 15)

## Session 15 — 2026-04-06

### AI Chat Integration (Web UI)
- [x] `netwatchm_server.py` — `_AI_SYSTEM_PROMPT` explains ports_observed semantics (destination ports contacted, not local listeners); ephemeral port range 32768–60999 explicitly excluded from analysis
- [x] `netwatchm_server.py` — `_PORT_NAMES` dict (40+ named services), `_EPHEMERAL_PORT_MIN = 32768`, `_fmt_bytes()` helper
- [x] `netwatchm_server.py` — `_build_device_context(ip)` reads inventory.json + events.db + flows.db; filters to known named ports only (eliminates misleading "56k open ports" reports)
- [x] `netwatchm_server.py` — `_build_network_context()` builds network-wide summary (device count, named service distribution)
- [x] `netwatchm_server.py` — `_ai_sessions: dict[str, list[dict]]` + `_ai_lock` for multi-turn conversation state; trimmed to last 20 messages per session
- [x] `netwatchm_server.py` — `_ai_ask(query, focus_ip, session_id)` calls OpenAI `gpt-4o-mini` with session history
- [x] `netwatchm_server.py` — `POST /api/ai` + `POST /api/ai/reset` routes in `do_POST`; `GET /ai.html` file serve in `do_GET`
- [x] `ai.html` — dark-theme chat UI (matching NetWatchM color scheme); device dropdown via `/api/aliases` + inventory; multi-turn session; simple markdown rendering (bold, code, lists); suggestion buttons that change by context
- [x] `openai>=1.0` added to `pyproject.toml` dependencies; `uv.lock` updated
- [x] `scripts/setup-ai-key.sh` — writes `OPENAI_API_KEY` to systemd drop-in `/etc/systemd/system/netwatchm-web.service.d/ai-env.conf`; uses `uv add openai` in project dir
- [x] `scripts/deploy-ai.sh` — copies `ai.html` to `/var/lib/netwatchm/ai.html` and restarts `netwatchm-web`
- [x] `scripts/hotdeploy.sh` — updated to also copy `ai.html` to `/var/lib/netwatchm/ai.html` (3-step deploy)

### mDNS Hostname (`netwatch.local`)
- [x] `scripts/setup-hostname.sh` — creates Avahi service XML + `netwatch-mdns.service` systemd unit; publishes `netwatch.local` → LAN IP via `avahi-publish -a -R`
- [x] Verified: `avahi-resolve -n netwatch.local` → `192.168.1.180`; all pages accessible from any LAN device by hostname

### AI Chat Nav Link — All Pages
- [x] `netwatchm_server.py` — AI Chat link added to dynamically rendered nav bars: events.html topbar, inventory.html nav, history.html nav, pcap.html nav
- [x] `src/netwatchm/reports/analytics_report.py` — full nav bar added: Connection Report, Inventory, Events, History, 🤖 AI Chat
- [x] `src/netwatchm/reports/connection_report.py` — AI Chat button added to toolbar
- [x] `netwatchm_server.py` — reports index (`/reports`) updated with AI Chat link
- [x] `netwatchm_server.py` — startup log updated to show `netwatch.local:8765` and AI Assistant URL
- [x] `scripts/patch-static-nav.sh` — Python-based patch injects AI Chat nav link into existing on-disk `analytics.html` (for pages already generated before this session)

### Bug Fixes
- [x] Fixed routing bug: `/api/ai` and `/api/ai/reset` routes were accidentally placed inside `do_DELETE` instead of `do_POST`; moved to correct location
- [x] Port analysis: AI no longer reports ephemeral outbound ports as "open ports"; context limited to named services only

### Deploy commands (session 15)
```bash
bash scripts/setup-ai-key.sh             # one-time: write OPENAI_API_KEY to systemd drop-in
bash scripts/setup-hostname.sh           # one-time: enable netwatch.local mDNS hostname
bash scripts/hotdeploy.sh               # deploy server + ai.html
bash scripts/patch-static-nav.sh        # patch existing static analytics.html with AI nav link
```

---

## Session 14 — 2026-03-29

### LAN IP / FQDN — remote access fixes
- [x] `netwatchm_server.py` — added `_get_local_ip()` helper; startup log now prints `Access via IP: https://<LAN-IP>:8765` and `Access via hostname: https://<fqdn>:8765`
- [x] `socket` added to top-level imports
- [x] `src/netwatchm/reports/connection_report.py` — Dashboard/Inventory Dashboard links now use `location.hostname` dynamically; NetWatchM Home uses relative `/`
- [x] `src/netwatchm/reports/deep_inspect.py` — Grafana Dashboard link now uses `location.hostname` dynamically
- [x] `scripts/import-dashboard.sh` — auto-detects server LAN IP and substitutes `localhost:8765` → `<LAN-IP>:8765` in Grafana panel links at import time (uses `NETWATCHM_SERVER_IP` override or UDP probe)

---

## Session 13 — 2026-03-22

### Hostname (mDNS) Access
- [x] TLS cert SAN extended to include `DNS:ai-rnd-01.local` + `DNS:ai-rnd-01` — portal now accessible via `https://ai-rnd-01.local:8765` from any LAN device
- [x] `scripts/enable-remote-access.sh` — auto-detects hostname via `hostname` and adds it to SAN
- [x] `netwatchm_server.py` `_ensure_cert()` — also includes hostname SANs on first-run cert generation
- [x] `apply-config-fix.sh` applied — adult domain alerts fixed (user machine removed from whitelist)

---

## Session 12 — 2026-03-20

- [x] Added `TrackerDomainDetector` — new `TRACKER_DOMAIN` (LOW) alert type for ads/tracking/analytics domains
  - Uses Steven Black unified adware+malware hosts list (separate from porn-only list)
  - Keeps `ADULT_DOMAIN` (MEDIUM) purely for adult content — no more false positives like `api.segment.io`
  - `TrackerDomainConfig` added to `config.py` + `load_config()`
  - `detector/tracker_domain.py`, wired into `detector/__init__.py` and `__main__.py`
  - `netwatchm.yaml.example` updated with `tracker_domain` thresholds + `TRACKER_DOMAIN` in detector_whitelist comment
  - 10 new tests — 174 total, all passing

### Deploy
```bash
bash scripts/hotdeploy.sh
```

---

## Completed
- [x] Core capture engine (tshark + async)
- [x] Threat scorer + detectors (port scan, brute force, exfiltration, new IP)
- [x] Whitelist checker (plain IPs + CIDR)
- [x] Alert handlers (terminal, logfile, sound, email)
- [x] Device inventory (store, resolver, exporter)
- [x] Terminal UI dashboard + inventory view
- [x] Systemd service (Linux) + Windows service stub
- [x] Connection report (HTML, CSV, table) — flows, protocols, domain/SNI
- [x] Investigate button in HTML report (modal + CLI command builder + context panel)
- [x] HTTPS on web server (mkcert for trusted cert; openssl self-signed fallback)
- [x] Metasploit investigate subcommand (`netwatchm investigate --target <ip>`)
- [x] arp-scan integration (cap_net_raw, no sudo needed)
- [x] Grafana Infinity dashboard
- [x] install.sh + install.bat (HTTPS cert setup via mkcert or openssl fallback)
- [x] 163 tests, all passing

## Phase 1 — Deep Inspection + GeoIP  ✅ COMPLETE (2026-02-24)
- [x] `src/netwatchm/reports/deep_inspect.py` — inspection engine (GeoIP, port scan, SSH, SMB, HTTP, RDP)
- [x] `src/netwatchm/reports/investigate_report.py` — Metasploit/nmap investigation engine
- [x] `netwatchm deep-inspect` CLI subcommand wired in `__main__.py`
- [x] `--db-path` argument added to `deep-inspect` subcommand (no hardcoded path required)
- [x] `NETWATCHM_GEOIP_DB` env var added to `netwatchm_server.py`; server passes `--db-path` to subprocess
- [x] `netwatchm-web.service` updated: sets `NETWATCHM_GEOIP_DB=/var/lib/netwatchm/GeoLite2-City.mmdb`
- [x] `install.sh` updated: auto-copies `.mmdb` from `geolite2-city-gzip/` to `/var/lib/netwatchm/` on install
- [x] GeoIP `registered_country` fallback added (fixes IPs like 1.1.1.1 returning "Unknown")
- [x] GeoLite2-City.mmdb downloaded and extracted → `geolite2-city-gzip/GeoLite2-City.mmdb` (61 MB)
- [x] `geoip2`, `paramiko`, `impacket` confirmed installed and working (via `uv sync`)
- [x] Deep Inspect buttons wired in connection report portal (Source + Destination)
- [x] `/api/deep-inspect` POST endpoint + `/api/deep-inspect/status` polling in server
- [x] End-to-end test passed: 8.8.8.8 → United States, 1.1.1.1 → Australia, risk badge, ports table, findings

### Production deploy command (run once after session)
```bash
sudo cp geolite2-city-gzip/GeoLite2-City.mmdb /var/lib/netwatchm/GeoLite2-City.mmdb
bash scripts/hotdeploy.sh   # copies netwatchm_server.py to /usr/local/lib/netwatchm/ + restart
```

---

## Phase 2 — Flow Data Store + Analytics  ✅ COMPLETE (2026-02-26)
- [x] `src/netwatchm/reports/flow_store.py` — SQLite store, 72h rolling purge, indexes on captured_at/src_ip/dst_ip
- [x] `src/netwatchm/reports/analytics_report.py` — dark-theme HTML with Chart.js (device bar, destination bar, protocol doughnut, hourly activity, per-device drill-down)
- [x] `netwatchm analytics` CLI subcommand (`--output`, `--db-path`) wired in `__main__.py`
- [x] `_report_subcommand` persists flows to SQLite after every capture (best-effort, never blocks rendering)
- [x] `netwatchm_server.py` — `FLOW_DB` env var, `_run_analytics()` runner, `/api/analytics` POST, `/api/analytics/status` GET
- [x] `netwatchm-web.service` updated: sets `NETWATCHM_FLOW_DB=/var/lib/netwatchm/flows.db`
- [x] `connection_report.py` — "📊 Analytics" button in toolbar; polls `/api/analytics`, opens result in new tab
- [x] End-to-end test passed: synthetic flows inserted → analytics HTML generated (53 MB total, 4 devices, 7 destinations, 3 protocols)

### Production deploy command (run once after session)
```bash
bash scripts/hotdeploy.sh   # copies netwatchm_server.py to /usr/local/lib/netwatchm/ + restart
```

## Phase 3 — Behavioral Threat Detectors  ✅ COMPLETE (2026-03-02)
- [x] Tor exit node detector (daily list download + real-time flow check)
- [x] Adult content domain detector — DNS query + TLS SNI, Steven Black porn list (153k domains), 24h refresh, per-device dedup, `extra_domains` config, 12 tests
- [x] Data hog alert — 24h rolling byte counter per local device (sent + received), configurable threshold (default 10 GiB), HIGH alert, per-device dedup, 12 tests
- [x] `/events.html` portal — SQLite event store (72h retention), live SPA: text search + level/type filters, expandable rows, deep-inspect link, auto-refresh, CSV export, 13 tests

---

## Stack 4 — Grafana Alerting  ✅ COMPLETE (2026-03-02)
- [x] `GET /api/alerts/data-hog` (port 8766) — returns 24h DATA_HOG event count as `[{value, time}]`
- [x] `GET /api/inventory/high` already returns `[{value, time}]` — reused for High Threat rule
- [x] `scripts/setup-grafana-alerts.sh` — interactive setup: SMTP drop-in, contact point, two alert rules
- [x] SMTP via systemd drop-in `/etc/systemd/system/grafana-server.service.d/netwatchm-smtp.conf` (no grafana.ini edits needed)
- [x] Grafana email contact point → jbaez120@gmail.com
- [x] Alert rule: **High Threat Detected** — HIGH device count > 0, fires after 1 min
- [x] Alert rule: **Data Hog Alert** — DATA_HOG events last 24h > 0, fires after 1 min
- [x] Notification policy updated: NetWatchM Email as default receiver, 4h repeat interval

### Deploy commands (run once)
```bash
bash scripts/deploy-server.sh          # deploy server with new /api/alerts/data-hog endpoint
bash scripts/setup-grafana-alerts.sh   # interactive: enter Gmail app password → wires everything
```

---

## Stack 5 — Device Friendly Names  ✅ COMPLETE (2026-03-02)
- [x] `/var/lib/netwatchm/aliases.json` — `{ip: label}` store, separate from inventory.json
- [x] `GET /api/aliases` — returns full alias dict (HTTPS server)
- [x] `POST /api/aliases` — `{ip, label}` — set or clear label (empty = delete)
- [x] `/inventory.html` — dark-theme SPA: sortable table, inline click-to-edit labels, search filter (includes label), CSV export with Label column
- [x] Grafana `/inventory.json` enriched with `label` field per device
- [x] `src/netwatchm/inventory/exporter.py` — Label as first CSV column, aliases loaded from disk
- [x] `src/netwatchm/ui/inventory_view.py` — Label column in terminal table, filter searches labels

### Access
```
https://localhost:8765/inventory.html
```

---

## Completed — Misc (pre-session 4)
- [x] Demo report script with synthetic high/medium/low risk flows (`sudo bash scripts/run-demo.sh`)
- [x] gen-report.sh uses PYTHONPATH to guarantee local source (fixes modal disappearing)
- [x] Auto-refresh the HTML report (↻ Refresh button + Auto interval + countdown, localStorage persist)
- [x] Persist connection report history (📁 History → `/reports`, last 50 kept, dark-theme index)
- [x] Alert on new/unknown devices detected by arp-scan (NEW_DEVICE MEDIUM alert → all handlers)
- [x] Grafana dashboard panels for connection report data (flows, devices, destinations, protocols, hourly)

---

## Session 4 — Windows Installer + GitHub Release  ✅ COMPLETE (2026-03-04)

### GitHub
- [x] All session 3/4 changes pushed to `al4nbr3/netwatchm` (master)
- [x] `netwachmInstall/` folder tracked in repo (was untracked)
- [x] `geolite2-city-gzip/` added to `.gitignore` (61 MB binary, not for repo)
- [x] `INSTALL.md` clone URLs fixed → `https://github.com/al4nbr3/netwatchm.git`

### Windows Installer (`netwachmInstall/install.ps1`)
- [x] **GUI progress window** — WinForms dark-theme dialog: step label, progress bar 0→100%, color-coded scrolling log
- [x] **Version detection** — reads `%PROGRAMDATA%\netwatchm\version.txt` on startup
- [x] **Upgrade / Reinstall / Uninstall / Cancel dialog** — shown when existing install detected
- [x] **Desktop shortcut** — `NetWatchM Dashboard.url` on Desktop (all users) → `https://localhost:8765/events.html`
- [x] **Start Menu shortcut** — `Start Menu\Programs\NetWatchM\NetWatchM Dashboard.url`
- [x] **Windows Defender exclusion** — auto-adds `%PROGRAMDATA%\netwatchm` on install
- [x] **Uninstall** cleans shortcuts and removes version file
- [x] **Saves version** to `version.txt` after successful install
- [x] **Error dialog** pops up if any step fails; Close button enables
- [x] **Success dialog** at end with dashboard URL confirmation
- [x] **`-Yes` flag** skips GUI entirely for CI/scripted deploys

### Documentation
- [x] `netwachmInstall/INSTALL.md` — Windows Defender/SmartScreen section added
  - Explains why popups happen (no code signing — cost not justified at this stage)
  - Step-by-step: unblock `.ps1` via Properties, bypass SmartScreen on `.exe`
  - Manual Defender exclusion command

### Deploy command (Windows — from fresh clone)
```
1. git clone https://github.com/al4nbr3/netwatchm.git
2. cd netwatchm
3. Right-click netwachmInstall\install.ps1 → Properties → Unblock → OK
4. powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
```

### GitHub Actions Release (v0.1.0 tag pushed)
- [x] `.github/workflows/release.yml` — builds `netwatchm-setup.exe` on Windows runner and publishes to GitHub Releases
- [x] `al4nbr3` added as publisher in exe Properties → Details tab and installer window subtitle
- [x] `installer_version.txt` — PyInstaller version metadata (CompanyName, LegalCopyright, ProductName)

### Session 5 — Windows Installer Fix + Auto Release  ✅ COMPLETE (2026-03-06)
- [x] **Root cause found**: `impacket` flagged by Windows Defender during pip install — blocked download and caused `pip install failed` error
- [x] `impacket` moved from base deps to optional `[forensics]` extra in `pyproject.toml` — Windows installer no longer installs it
- [x] SMB check in `deep_inspect.py` already catches `ImportError` gracefully — no code change needed
- [x] Pre-install Defender exclusions added for pip/uv cache + TEMP dirs in both `installer_gui.py` and `install.ps1`
- [x] **Auto version bump on every push to master** — `release.yml` now auto-increments patch version, builds exe, commits version bump, tags, and publishes GitHub Release automatically
- [x] Version bumped to `v0.2.0` across all files (`pyproject.toml`, `installer_gui.py`, `install.ps1`, `installer_version.txt`)

### Pending — Windows Installer
- [ ] Verify end-to-end install on a clean Windows machine (Desktop shortcut, services, dashboard)

---

## Session 6 — UI Polish + Network Tools  ✅ COMPLETE (2026-03-07)

---

### Session 6a — Inventory Tools + Flow History + Alert Fixes

#### Verified Devices
- [x] `/var/lib/netwatchm/verified.json` — `{ip: bool}` store, same pattern as aliases.json
- [x] `GET /api/verified` — returns full verified dict
- [x] `POST /api/verify` — `{ip, verified}` toggle
- [x] `inventory.html` — checkmark column (✓/○ toggle per device, persists immediately)

#### Per-Device nmap Scan (from inventory.html)
- [x] Scan button per row in `inventory.html` — triggers `nmap -sV --open -T4 -p 1-1024` per device
- [x] `POST /api/nmap`, `GET /api/nmap/status` — async background thread, results in modal overlay
- [x] Modal shows open ports + services on completion; no sudo required

#### Pcap Analyzer (`/pcap.html`)
- [x] Drag-and-drop pcap/pcapng upload + async background analysis via tshark
- [x] Reports: device list (MAC + OUI vendor from `/usr/share/wireshark/manuf`), DNS resolution latency (matched by client_ip + dns.id pair), TLS handshake latency (matched by tcp.stream)
- [x] `GET /api/pcap/status`, `POST /api/pcap/upload` endpoints
- [x] "📊 Pcap" nav link added to `inventory.html`
- [x] `scripts/capture-targetip.sh` — interactive: prompts for target IP, save path, duration (seconds), interface; pre-creates output file with `touch + chmod 644` to avoid tshark permission denied error
  - Renamed from `capture-switch.sh`
- [x] Nintendo Switch investigation: `scannIp.pcapng` identified `192.168.1.217` as Nintendo Co.,Ltd (MAC `98:e2:55:d4:be:85`); port scan showed all RST (no open ports), no DNS/TLS because Switch was passive during scan

#### Flow History (`/history.html`)
- [x] `flow-history.db` (SQLite) — `active_snapshot` + `flow_history` tables
- [x] `_update_flow_history()` — on each report generate: compares current flows.db snapshot vs previous active_snapshot; inactive flows written to `flow_history`; 30-day rolling purge (unpinned only)
- [x] Pin-to-keep: `pinned=1` excludes entry from automatic purge
- [x] `GET /api/flow-history`, `POST /api/flow-history/pin`, `DELETE /api/flow-history/{id}`
- [x] SPA: search bar, pin/unpin toggle, delete, date shown for each inactive connection
- [x] When Generate button is clicked: only active connections shown in report; inactive ones logged to history

#### Connection Report Toolbar Updates (`connection_report.py`)
- [x] "📱 Inventory" button → `/inventory.html`
- [x] "⏱ History" button → `/history.html`
- [x] External links group (purple): Dashboard → `http://localhost:3000`, Inventory Dashboard → `/d/netwatchm-inventory/`, NetWatchM Home → `https://localhost:8765/`
- [x] Shared new-tab toggle checkbox for the three external links, `localStorage` persists preference
- [x] `scripts/patch-report-dashboard-btn.sh` — one-time script to apply buttons to existing live `connection-report.html` (writes to `/tmp/`, then `sudo cp`)

#### Adult Domain Alert Fix
- [x] **Root cause 1:** `192.168.1.180` (user's own machine) was in the whitelist — whitelist suppresses ALL alerts from that src_ip, including ADULT_DOMAIN when browsing from that machine
- [x] **Root cause 2:** `interface: auto` in config (though enp6s0 was being selected anyway)
- [x] Fix: remove `192.168.1.180` from whitelist; set `interface: enp6s0` explicitly; add explicit `adult_domain` config block
- [x] `scripts/apply-config-fix.sh` — backs up `/etc/netwatchm/netwatchm.yaml`, applies `/tmp/netwatchm-fixed.yaml`, restarts `netwatchm` service
- [x] `/tmp/netwatchm-fixed.yaml` — corrected config (Twingate relays whitelisted, user's own IP removed)

#### Scripts Added
- [x] `scripts/hotdeploy.sh` — fast deploy: `sudo cp netwatchm_server.py /usr/local/lib/netwatchm/` + `sudo systemctl restart netwatchm-web` (two commands, no interactive prompts)
- [x] `scripts/apply-config-fix.sh` — safe config update with backup
- [x] `scripts/capture-targetip.sh` — interactive tshark capture with all params prompted

---

### Session 6b — Nav Buttons + Grafana Panel Debug

#### Navigation Buttons Added
- [x] `events.html` topbar: added "Inventory" → `/inventory.html` and "📊 Dashboard" → `http://localhost:3000/d/netwatchm-inventory/` (new tab)
- [x] `deep-inspect-{ip}.html`: navbar injected at top of every generated report — "← Inventory" → `/inventory.html`, "⚠ Events" → `/events.html?q={ip}` (pre-filtered to that device), "📊 Dashboard" → Grafana (new tab)
- [x] Changes in `netwatchm_server.py` (events.html) and `src/netwatchm/reports/deep_inspect.py`

#### Grafana Panel Investigation + Fix
- [x] Confirmed all flow endpoints return valid data via direct curl tests:
  - `/api/flows/devices/enriched` → Top Traffic Devices — Live ✅
  - `/api/flows/devices` → Top Devices by Data Sent ✅
  - `/api/flows/destinations` → Top Destinations ✅
  - `/api/flows/top-apps` → Application Activity ✅
  - `/api/flows/browsing` → Browsing Activity ✅
- [x] Root cause for "Top Devices by Data Sent" + "Top Destinations" not visible: both panels are **inside the collapsed "Connection Report" row** — click the row header in Grafana to expand

### Deploy
```bash
bash scripts/hotdeploy.sh              # deploy netwatchm_server.py → live server (port 8765/8766)
bash scripts/apply-config-fix.sh       # fix adult domain alerts (remove 192.168.1.180 from whitelist)
```

---

## Session 7 — IP Lookup Modal + Per-Detector Whitelist  ✅ COMPLETE (2026-03-07)

### Per-Detector IP Whitelist (`detector_whitelist` config)
- [x] `config.py` — `DetectorWhitelistConfig` dataclass with `is_suppressed(alert_type, ip)` method
- [x] `__main__.py` — check in `alert_dispatch_loop()` after global whitelist, before scorer/handlers
- [x] `netwatchm.yaml.example` — documented with all 7 alert types
- [x] Allows suppressing e.g. `PORT_SCAN` from one IP without silencing all alerts from that device

### IP Lookup Modal in `events.html`
- [x] Globe button on each expanded event row opens a 4-tab modal
- [x] **GeoIP tab** — country, city, region, coords, timezone, org/ISP (via GeoLite2)
- [x] **DNS tab** — reverse PTR + forward A record (`dig +short`)
- [x] **Security tab** — Tor exit check, threat level, alert history breakdown from `events.db`
- [x] **WHOIS tab** — parsed key fields + raw output
- [x] Backend: `_ip_lookup()` in `netwatchm_server.py` aggregates GeoLite2 + ipinfo.io + whois + local DB
- [x] 163 tests still passing

### Workflow Preference Added
- [x] Read `CHECKLIST.md` at the start of every session and update it with all tasks requested

---

## Session 8 — Remote Access + URL Fix  ✅ COMPLETE (2026-03-08)

### Grafana Remote Access
- [x] `scripts/configure-grafana-remote.sh` — patches `/etc/grafana/grafana.ini`: sets `domain = 192.168.1.180` + `root_url = http://192.168.1.180:3000/`; opens ufw port 3000; restarts grafana-server
- [x] Verified: Grafana accessible from remote machine at `http://192.168.1.180:3000`

### NetWatchM Portal Remote Access (`https://192.168.1.180:8765`)
- [x] TLS cert regenerated with `subjectAltName` (DNS:localhost, IP:127.0.0.1, IP:\<LAN IP\>) — old cert had `CN=localhost` only, breaking remote browser connections
- [x] `_ensure_cert()` in `netwatchm_server.py` now auto-detects LAN IP and embeds it in SAN; override with `NETWATCHM_SERVER_IP` env var
- [x] `scripts/enable-remote-access.sh` — opens ufw port 8765, regenerates cert with LAN IP SAN, restarts `netwatchm-web`
- [x] Grafana nav link (`📊 Dashboard`) changed from hardcoded `http://localhost:3000/...` to `javascript: window.open('http://'+location.hostname+':3000/...')` — works from any host
- [x] Verified: portal accessible from remote machine at `https://192.168.1.180:8765`

### Events Portal URL Fix
- [x] `events.html` pre-fill now handles `?q=` param (alongside `?ip=` and `?search=`) — deep-inspect "View Events" links use `?q={ip}`
- [x] Deployed via `bash scripts/hotdeploy.sh`

### Windows Cert Trust (remote machine)
- [x] `GET /cert` endpoint — serves `server.crt` as a downloadable file (`application/x-x509-ca-cert`)
- [x] `scripts/install-cert-windows.ps1` — clean single-command-per-line script; downloads cert from `/cert` and installs into Windows Trusted Root; run as Administrator on Windows machine
- [x] Quick bypass alternative: type `thisisunsafe` on Chrome/Edge cert error page

### Connection Report Toolbar Layout
- [x] Purple external buttons (Dashboard, Inventory Dashboard, NetWatchM) moved to second row below blue buttons
- [x] Toolbar restructured into two `.toolbar-row` divs; CSS changed to `flex-direction: column`
- [x] Purple row centered-right under Analytics using `.ext-row` class (`justify-content:center; padding-left:200px`)

### Whitelist Update
- [x] `192.168.1.248` added to global whitelist in `/etc/netwatchm/netwatchm.yaml`; service restarted

### Deploy commands (session 8)
```bash
bash scripts/hotdeploy.sh               # deploy events.html ?q= fix + cert SAN change + /cert endpoint
bash scripts/enable-remote-access.sh    # open port 8765, regen TLS cert, restart web
bash scripts/configure-grafana-remote.sh  # patch grafana.ini, open port 3000, restart grafana
```

**Windows cert install (run on Windows machine as Administrator):**
```powershell
powershell -ExecutionPolicy Bypass -File \\192.168.1.180\...\install-cert-windows.ps1
# or download the script and run it locally
```

---

## Session 9 — Linux Cert Trust (2026-03-09)

### Linux Certificate Install Script
- [x] `scripts/install-cert-linux.sh` — downloads cert from `/cert` endpoint, installs into system trusted roots (`update-ca-certificates`) and Chrome NSS store (`certutil`); accepts optional `SERVER_IP` and `PORT` args

---

## Session 10 — Security Hardening (2026-03-10)

### Hardcoded Credential Removal
- [x] `scripts/reset-grafana-password.sh` — removed hardcoded plaintext password; now prompts interactively at runtime (`read -rsp`, silent input)

---

## Session 11 — Network Diagnostics Tools (2026-03-12)

### Network Diagnostic Tools Added
- [x] Installed `conntrack` and `iperf3` packages
- [x] API endpoints added to `netwatchm_server.py`:
  - `/api/diagnostics/conntrack` — show active TCP connections
  - `/api/diagnostics/tcpstates` — show TCP connection states via `ss`
  - `/api/diagnostics/iperf` — run iperf3 bandwidth test to target IP
  - `/api/diagnostics/bandwidth/{ip}` — get bandwidth stats per device from flow DB
- [x] `deep-inspect-web.html` updated with new tabs:
  - **Network Diagnostics** — buttons for conntrack, tcpstates, iperf
  - **Bandwidth** — check per-device bandwidth from flow data

### Conntrack IP Filter Update (2026-03-12)
- [x] `/api/diagnostics/conntrack` now accepts optional `target` query param to filter by IP
- [x] `deep-inspect-web.html`: conntrack now requires target IP input; shows blank when idle

### IP Investigation Guide (2026-03-12)
- [x] Created `docs/ip-investigation-qrcards.md` — comprehensive reference for investigating suspicious IPs
- [x] Updated Quick Reference Card with tcpdump port 80/443 command
- [x] Created `docs/ip-investigation-log.md` — real investigation example with step-by-step log

### Deploy commands
```bash
bash scripts/hotdeploy.sh              # deploy netwatchm_server.py
bash scripts/copy-deep-inspect-web.sh  # copy updated HTML UI
```

---

## Pending — Next Session

### Must Do (sudo required — run manually)
- [x] **`bash scripts/apply-config-fix.sh`** — fixes adult domain alerts (removes user machine from whitelist) — applied 2026-03-22
- [ ] **Windows install test** — verify end-to-end on a clean Windows machine (overdue since session 4)

### Completed This Session (session 7)
- [x] GitHub repo moved from **public → private** (`al4nbr3/netwatchm`)
- [x] Grafana credentials removed from CHECKLIST.md (were exposed in public repo)
- [x] Test count corrected: 143 → 163
- [x] Duplicate Session 6c removed from CHECKLIST
- [x] Deploy path corrected (Phase 1/2 commands pointed to wrong binary location)
- [x] Orphaned "In Progress" section given proper label
- [x] `netwatchm.yaml.production` saved to repo root (no longer lost on reboot)
- [x] `apply-config-fix.sh` updated to read from repo file instead of `/tmp/`
- [x] `netwatchm.yaml.production` added to `.gitignore` (contains private IPs)

### Improvements / Nice to Have
- [x] **README.md** — rewritten session 15 (2026-04-06): current feature set, all portal pages, AI assistant, architecture, scripts, 174 tests
- [ ] **Events retention setting** — 72h is hardcoded in `event_store.py`; expose as config option
- [ ] **Grafana alert rules** — currently only HIGH threat + DATA_HOG; add CRITICAL Exfiltration rule
- [ ] **Events portal paging** — currently loads up to 500 events; add pagination for large datasets
- [ ] **Dark/Light theme** — events portal dark-only; connection report has toggle but events portal doesn't
- [ ] **Alert suppression** — no way to silence a recurring low-value alert type (e.g. NEW_IP flood)
- [ ] **Role-based access** — single admin token; no read-only vs admin distinction
- [ ] **Mobile-friendly** — events portal not tested on phone browser (ntfy app covers this partially)
- [ ] **Code signing** — skipped (cert costs ~$300-500/yr); revisit if project grows
- [ ] **SQLite schema migrations** — 3 databases (events, flows, flow-history) have no migration system

## Grafana Setup — ✅ COMPLETE (2026-03-02)

### What works:
- Grafana 12.4.0 + Infinity v3.7.2 installed and running
- NetWatchM HTTP server on port 8766 (Grafana-only, no TLS)
- Infinity datasource "NetWatchM" configured — allowed hosts: `http://127.0.0.1:8766` AND `http://localhost:8766`
- All API endpoints confirmed working:
  - `/api/inventory/{total|high|medium|low|stats}` — device counts
  - `/api/flows/{stats|devices|destinations|protocols|hourly}` — flow data
  - `/api/flows/browsing` — local device → site activity
  - `/api/events/adult-domains` — ADULT_DOMAIN events grouped by src_ip + domain
- Dashboard imported via `scripts/import-dashboard.sh`
- Grafana credentials: stored locally — do NOT commit to repo
- `scripts/seed-events.sh` — seed live events.db with 6 synthetic test alerts

### Dashboard panels (v5):
- Stat panels: Total Devices, HIGH/MEDIUM/LOW Threat counts
- Threat Distribution donut: HIGH/MEDIUM/LOW device counts (from `/api/inventory/stats`)
- Device Inventory table: IP, Hostname, MAC, Vendor, Threat (colour-coded), Sent, Received, Last Seen
- Flow stats: Total Flows, Total Data, Active Devices (72h)
- Top Devices table: IP + host + bytes, clickable IP links → events portal + deep inspect
- Top Destinations table: IP + domain + port + bytes, clickable IP links
- Protocol Doughnut + Hourly Activity bar
- **Intelligence row:**
  - Trigger Sites: ADULT_DOMAIN events (src_ip, domain, count, last_seen)
  - Browsing Activity: local device → website (src_ip, device, site, port, bytes)

### Key lessons (jsonata vs backend parser):
- `jsonata` parser ignores column definitions — dumps all JSON fields; causes byte fields to inflate pie/bar charts
- `backend` parser respects explicit column list — use this for all panels
- All Infinity targets require `url_options: {"method": "GET", "data": ""}` or JS crashes silently
- Stat panels need `timestamp_epoch_ms` column + `filterFieldsByName` transformation to hide time field
- Specific routes (`/api/flows/browsing`) must be checked BEFORE generic `startswith` routes

### Deploy commands:
```bash
bash scripts/deploy-server.sh     # copy server + restart service
bash scripts/import-dashboard.sh  # re-import dashboard after JSON changes
```

---

---

## Session 3 — Push Notifications + Dashboard Overhaul  ✅ COMPLETE (2026-03-03)

### Stack 6 — ntfy.sh Push Notifications
- [x] `src/netwatchm/alerts/ntfy_alert.py` — NtfyAlert handler (urllib, priority map, cooldown, Bearer token)
- [x] `src/netwatchm/config.py` — NtfyAlertConfig dataclass; wired into AlertsConfig + load_config()
- [x] `src/netwatchm/__main__.py` — NtfyAlert registered when `config.alerts.ntfy.enabled`
- [x] `netwatchm.yaml.example` — ntfy section (server, topic, min_level, cooldown_seconds)
- [x] Live config `/etc/netwatchm/netwatchm.yaml` — enabled with topic `netwatchm-abc123`
- [x] `tests/test_ntfy_alert.py` — 20 tests (priority, min_level, cooldown, headers, token, URLError)
- [x] Events portal — **Test Notify** button fires live ntfy push via `POST /api/test-ntfy`

### Stack 6b — Grafana → ntfy Webhook Bridge
- [x] `POST /api/grafana-ntfy` (port 8766) — receives Grafana unified alerting webhook, forwards to ntfy
- [x] ASCII-safe header encoding (em-dash fix for latin-1 codec error)
- [x] `scripts/setup-grafana-ntfy.sh` — creates Grafana contact point + notification policy route
- [x] End-to-end tested: Grafana alert → webhook → ntfy push on phone

### GeoIP + Deploy Fix
- [x] `scripts/deploy-geoip.sh` — copies GeoLite2-City.mmdb to `/var/lib/netwatchm/`
- [x] `scripts/deploy-server.sh` — fixed to use venv Python (system python3 was missing geoip2)
  - Server now runs via bash wrapper at `/usr/local/bin/netwatchm-server` → venv Python
  - Also syncs `~/.local/bin/netwatchm` CLI from venv on deploy
- [x] GeoIP country column working in Alert History (Grafana) and deep inspect reports

### Grafana Dashboard v17 Overhaul
- [x] Color standard: HIGH=#ff9900 (orange), MEDIUM=#cc8800 (amber), LOW=#3fb950, CRITICAL=#f85149
- [x] Device Inventory panel height 14 → 8
- [x] Top Devices barchart replaced with enriched live traffic table (IP, device, sent, received, total)
  - Endpoint: `/api/flows/devices/enriched`
  - Columns have View Events + Deep Inspect data links
- [x] "Why" breakdown merged into traffic table (consolidated panel 23)
- [x] Alert History table (panel 20) — MEDIUM+ only, GeoIP country column, src_ip links to events portal
- [x] Alert History endpoint: `GET /api/events/history` (port 8766)
- [x] Application Activity donut (panel 14) replacing Protocol Mix — `/api/flows/top-apps`
- [x] Hourly Activity fixed to last 24h rolling window
- [x] Connection Report row collapsed (click to expand)
- [x] Browsing Activity deep-inspect link → `/inspect/{ip}` launcher
- [x] **Alert count stat panels** (panels 24/25/26) at y=4 filling empty space:
  - CRITICAL Alerts (red) — `/api/events/count/critical`
  - HIGH Alerts (orange) — `/api/events/count/high`
  - MEDIUM Alerts (amber) — `/api/events/count/medium`
- [x] Dashboard v17, revert tag: `dashboard-pre-cleanup`

### Deep Inspect 404 Fix
- [x] `/inspect/{ip}` launcher page — triggers POST, shows spinner, polls status, auto-redirects
- [x] Hostname injected into deep inspect report title
- [x] Events + Deep Inspect data links added to Browsing Activity and Traffic tables
- [x] `--db-path` removed from deep-inspect subprocess call (uses DEFAULT_GEOIP_DB)

### Clear Alerts + Admin Token
- [x] `DELETE /api/events` endpoint — requires `X-Admin-Token` header (env: `NETWATCHM_ADMIN_TOKEN`, default: `netwatchm-admin`)
- [x] Events portal — **🗑 Clear Alerts** button + password modal (admin token required)
- [x] `do_OPTIONS` updated: allows DELETE method + `X-Admin-Token` header

### Test Scripts
- [x] `scripts/test-all-alerts.sh` — fires all 3 channels simultaneously:
  1. Seeds events.db with MEDIUM/HIGH/CRITICAL alerts
  2. Direct ntfy pushes for all 3 levels (bypasses cooldown)
  3. POST to `/api/grafana-ntfy` to test bridge

### Deploy commands (session 3)
```bash
bash scripts/deploy-server.sh       # deploy latest server + sync CLI
bash scripts/import-dashboard.sh    # import dashboard v17 (alert count panels)
bash scripts/test-all-alerts.sh     # smoke test all alert channels
```

---

## Known Issues / Notes
- `sudo uv` fails — always use full path: `sudo /home/jbaez120/.local/bin/uv`
- Regenerate report: `sudo bash scripts/gen-report.sh` (optional duration arg, default 30s)
- Demo report (synthetic high/medium/low risk flows): `sudo bash scripts/run-demo.sh`
- Report served at https://localhost:8765/connection-report.html from /var/lib/netwatchm/
- TLS cert generated via mkcert at /var/lib/netwatchm/server.crt (browser-trusted)
- Web server service: netwatchm-web (not netwatchm-server)
- Deploy server changes: `bash scripts/deploy-server.sh`
- Live config: /etc/netwatchm/netwatchm.yaml — restart service after edits
- Email password: never in YAML, use NETWATCHM_EMAIL_PASSWORD env var
- GeoLite2-City DB: `geolite2-city-gzip/GeoLite2-City.mmdb` (local) / `/var/lib/netwatchm/GeoLite2-City.mmdb` (production)
