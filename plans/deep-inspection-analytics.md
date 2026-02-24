# Plan: Deep Inspection, GeoIP & Flow Analytics

**Status:** Draft
**Date:** 2026-02-23
**Priority:** High

---

## Overview

Extend the connection report portal with three major capabilities:
1. Deep security inspection of suspicious hosts (weak auth, misconfigs, GeoIP)
2. Local flow data store with 3-day rolling retention and analytics
3. Behavioral threat detectors (Tor, adult content, data hogs)

All built in Python, no Metasploit required.

---

## Phase 1 — Deep Inspection + GeoIP

### Goal
When a suspicious connection appears in the report, clicking Investigate
opens a new page with a full security profile of the target IP.

### What it checks
| Check | Method | Library |
|---|---|---|
| Country / City / ISP / ASN | Local MaxMind GeoLite2 DB | `geoip2` |
| SSH banner + password auth enabled | Banner grab + auth probe | `paramiko` |
| SMB null session + signing disabled | SMB handshake | `impacket` |
| HTTP default credentials / headers | HTTP probe | `requests` |
| RDP exposed + NLA check | Port probe | stdlib `socket` |
| Open ports | TCP connect scan | stdlib `socket` |

### Output
New portal page: `https://localhost:8765/investigate-<ip>.html`
- GeoIP card: flag, country, city, ISP, ASN, abuse contact
- Risk summary badge (Low / Medium / High)
- Open ports table with service versions
- Security findings list (e.g. "SMB signing disabled — relay attack possible")
- Raw output collapsible section

### New files
- `src/netwatchm/reports/deep_inspect.py` — inspection engine
- Updated `netwatchm_server.py` — `/api/investigate` POST endpoint
- Updated `connection_report.py` — modal triggers API, opens result in new tab

### Dependencies to add
```
geoip2
paramiko
impacket
```

### GeoIP database
- Download free MaxMind GeoLite2-City.mmdb (requires free account)
- Store at `/var/lib/netwatchm/GeoLite2-City.mmdb`
- Auto-update weekly via cron or systemd timer

---

## Phase 2 — Flow Data Store + Analytics Portal

### Goal
Every captured flow is persisted to a local SQLite database with a
3-day rolling retention window. A new analytics portal page shows
historical trends, top talkers, and data usage per device.

### Database schema
```sql
CREATE TABLE flows (
    id          INTEGER PRIMARY KEY,
    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip      TEXT,
    src_host    TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    domain      TEXT,
    app_name    TEXT,
    username    TEXT,
    packets     INTEGER,
    bytes       INTEGER,
    first_seen  REAL,
    last_seen   REAL
);
```
- Auto-purge rows older than 72 hours on each insert batch
- Index on `captured_at`, `src_ip`, `dst_ip`

### Analytics portal (`/analytics.html`)
- Total data per device (bar chart, last 3 days)
- Top 10 destinations by bytes
- Protocol breakdown (pie/donut)
- Hourly activity heatmap
- Per-device drill-down table

### New files
- `src/netwatchm/reports/flow_store.py` — SQLite store + purge
- `src/netwatchm/reports/analytics_report.py` — render analytics HTML
- Updated `netwatchm_server.py` — serve `/analytics.html`, `/api/analytics`

---

## Phase 3 — Behavioral Threat Detectors

### Goal
Automatically detect and alert on high-risk behaviors observed in
captured traffic. Alert appears in the portal and triggers the
existing alert pipeline (terminal, log, email, sound).

### Detectors

#### Tor Exit Node Detection
- Daily download of Tor exit node list from `https://check.torproject.org/torbulkexitlist`
- Cache at `/var/lib/netwatchm/tor-exits.txt`
- Check every dst_ip in captured flows against the list
- Alert: "Tor usage detected — device <src_ip> (<hostname>) connected to Tor exit node <dst_ip>"
- Log to flow_store with `threat=tor` tag

#### Adult Content Detection
- Maintain local domain category list (DNS-based)
- Check `domain` field in flows against known adult content domains
- Alert: "Adult content access — <src_ip> visited <domain>"
- Configurable: enable/disable in netwatchm.yaml

#### Data Hog Alert
- Per-device 24h rolling byte counter from flow_store
- Configurable threshold (default: 1 GB/24h)
- Alert: "<src_ip> has transferred 1.2 GB in the last 24 hours"

### Threat Events Portal (`/events.html`)
- Table of all detected threat events (last 3 days)
- Columns: Time, Device, Type, Detail, Bytes
- Filter by type (Tor / Adult / Data hog)
- Click row → opens investigation page for that device

---

## Open Questions
- [ ] MaxMind GeoLite2 license key — user needs to register (free)
- [ ] Adult domain list source — decide on blocklist provider
- [ ] Data hog threshold — make configurable per-device?
- [ ] Should Tor detection alert in real-time (capture loop) or post-capture (report)?

---

## Estimated Scope
| Phase | New Files | Complexity |
|---|---|---|
| 1 — Deep Inspection + GeoIP | 2 | Medium |
| 2 — Flow Store + Analytics | 3 | Medium |
| 3 — Behavioral Detectors | 2 | Medium-High |
