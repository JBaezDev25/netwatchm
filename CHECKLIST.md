# NetWatchM — Project Checklist

Last updated: 2026-03-02 (session 2)

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
- [x] 143 tests, all passing

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
sudo cp netwatchm_server.py /usr/local/bin/netwatchm-server
sudo systemctl daemon-reload && sudo systemctl restart netwatchm-web
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
sudo cp netwatchm_server.py /usr/local/bin/netwatchm-server
sudo systemctl daemon-reload && sudo systemctl restart netwatchm-web
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

## In Progress / Next Up
- [x] Demo report script with synthetic high/medium/low risk flows (`sudo bash scripts/run-demo.sh`)
- [x] gen-report.sh uses PYTHONPATH to guarantee local source (fixes modal disappearing)
- [x] Auto-refresh the HTML report (↻ Refresh button + Auto interval + countdown, localStorage persist)
- [x] Persist connection report history (📁 History → `/reports`, last 50 kept, dark-theme index)
- [x] Alert on new/unknown devices detected by arp-scan (NEW_DEVICE MEDIUM alert → all handlers)
- [x] Grafana dashboard panels for connection report data (flows, devices, destinations, protocols, hourly)

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
- Grafana credentials: `admin` / `BioIluvleeloo@5858`
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
