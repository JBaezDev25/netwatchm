# NetWatchM — Project Checklist

Last updated: 2026-03-02 (end of session)

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
- All API endpoints confirmed working via curl:
  - `http://127.0.0.1:8766/api/inventory/total`    → `[{"time": <epoch_ms>, "value": 452}]`
  - `http://127.0.0.1:8766/api/inventory/high`     → `[{"time": <epoch_ms>, "value": N}]`
  - `http://127.0.0.1:8766/api/inventory/medium`   → `[{"time": <epoch_ms>, "value": N}]`
  - `http://127.0.0.1:8766/api/inventory/low`      → `[{"time": <epoch_ms>, "value": N}]`
  - `http://127.0.0.1:8766/api/flows/stats`        — total flows/bytes/packets
  - `http://127.0.0.1:8766/api/flows/devices`      — top devices by bytes
  - `http://127.0.0.1:8766/api/flows/destinations` — top destinations
  - `http://127.0.0.1:8766/api/flows/protocols`    — protocol breakdown
  - `http://127.0.0.1:8766/api/flows/hourly`       — hourly activity
- Dashboard imported via `scripts/import-dashboard.sh`
- Grafana credentials: `admin` / `BioIluvleeloo@5858`
- JSONata parser works in **Explore** (browser-side) — shows data correctly

### Root causes found and fixed:
- [x] `proxy_type: "url"` in datasource config was routing through nonexistent proxy → removed
- [x] Allowed hosts had `localhost:8766` but panels used `127.0.0.1:8766` → fixed (both added)
- [x] Dashboard import was not resolving `${DS_NETWATCHM}` template → fixed (using `/api/dashboards/import` with `inputs`)
- [x] `/api/inventory/stats` returning all 452 raw device records instead of counts → fixed with dedicated `/api/inventory/{metric}` endpoints
- [x] Added `"time": int(time.time() * 1000)` to inventory metric responses (for Grafana time-range filter)

### Current blocker — stat panels still show "No data":
- `backend` parser: returns data confirmed via `/api/ds/query` (`fields: ['value'], values: [[452]]`) but stat panels show "No data"
- `jsonata` parser: works in Explore (browser executes it) but routes through backend API in dashboard panels → returns empty
- `uql` parser: tried, returned empty
- Adding explicit `timestamp_epoch_ms` + `number` column definitions → panels now show **warning triangle** (error) instead of silent "No data"
- The warning triangle error message was NOT captured before end of session

### What fixed it (root cause summary):
1. `url_options: {"method": "GET", "data": ""}` was missing from all Infinity query targets → caused JS error "cannot read properties of undefined (reading 'method')" → panels showed warning triangle + no data
2. Adding `"time": int(time.time() * 1000)` to API responses + `timestamp_epoch_ms` column definition → created proper time-series frames that pass Grafana 12 Scenes time-range filtering
3. `filterFieldsByName` transformation with `include.names: ["Value"]` → hides the raw timestamp from stat panel display, shows only the count

### Final working config for stat panels:
- `parser: "backend"`, explicit columns: `[{timestamp_epoch_ms: "Time"}, {number: "Value"}]`
- `url_options: {"method": "GET", "data": ""}`
- `filterFieldsByName` transformation: include only "Value"
- `reduceOptions.calcs: ["lastNotNull"]`, `fields: ""`

### Deploy command:
```bash
bash scripts/import-dashboard.sh
```

---

## Known Issues / Notes
- `sudo uv` fails — always use full path: `sudo /home/jbaez120/.local/bin/uv`
- Regenerate report: `sudo bash scripts/gen-report.sh` (optional duration arg, default 30s)
- Demo report (synthetic high/medium/low risk flows): `sudo bash scripts/run-demo.sh`
- Report served at https://localhost:8765/connection-report.html from /var/lib/netwatchm/
- TLS cert generated via mkcert at /var/lib/netwatchm/server.crt (browser-trusted)
- Web server service: netwatchm-web (not netwatchm-server)
- Deploy server changes: `sudo cp netwatchm_server.py /usr/local/bin/netwatchm-server && sudo systemctl restart netwatchm-web`
- Live config: /etc/netwatchm/netwatchm.yaml — restart service after edits
- Email password: never in YAML, use NETWATCHM_EMAIL_PASSWORD env var
- GeoLite2-City DB: `geolite2-city-gzip/GeoLite2-City.mmdb` (local) / `/var/lib/netwatchm/GeoLite2-City.mmdb` (production)
