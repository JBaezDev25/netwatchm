#!/usr/bin/env python3
"""NetWatchM web server — serves dashboard and triggers connection reports via API."""
from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import shutil
import sqlite3
import ssl
import subprocess
import threading
import time as _time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _send_test_ntfy() -> tuple[bool, str]:
    """Read ntfy config from YAML and fire a test notification. Returns (ok, message)."""
    import urllib.request
    from urllib.error import URLError
    import yaml

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", "/etc/netwatchm/netwatchm.yaml"))
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {} if cfg_path.exists() else {}
    except Exception as exc:
        return False, f"Could not read config: {exc}"

    ntfy = raw.get("alerts", {}).get("ntfy", {})
    if not ntfy.get("enabled", False):
        return False, "ntfy is not enabled in config"
    server = ntfy.get("server", "https://ntfy.sh").rstrip("/")
    topic  = ntfy.get("topic", "")
    token  = os.environ.get("NETWATCHM_NTFY_TOKEN", ntfy.get("token", ""))

    if not topic:
        return False, "ntfy topic is not configured"

    url  = f"{server}/{topic}"
    body = b"This is a test notification from NetWatchM. If you see this, push alerts are working!"
    headers = {
        "X-Title":    "[TEST] NetWatchM Alert",
        "X-Priority": "3",
        "X-Tags":     "white_check_mark",
        "Content-Type": "text/plain",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True, f"Test notification sent to topic '{topic}'"
    except URLError as exc:
        return False, f"ntfy request failed: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Unexpected error: {exc}"


def _forward_grafana_ntfy(payload: dict) -> tuple[bool, str]:
    """Receive a Grafana unified-alerting webhook payload and send an ntfy notification."""
    import urllib.request
    from urllib.error import URLError
    import yaml

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", "/etc/netwatchm/netwatchm.yaml"))
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {} if cfg_path.exists() else {}
    except Exception as exc:
        return False, f"Could not read config: {exc}"

    ntfy = raw.get("alerts", {}).get("ntfy", {})
    if not ntfy.get("enabled", False):
        return False, "ntfy not enabled"
    server = ntfy.get("server", "https://ntfy.sh").rstrip("/")
    topic  = ntfy.get("topic", "")
    token  = os.environ.get("NETWATCHM_NTFY_TOKEN", ntfy.get("token", ""))
    if not topic:
        return False, "ntfy topic not configured"

    status  = payload.get("status", "firing")
    alerts  = payload.get("alerts", [])
    title   = payload.get("title", "") or f"[{status.upper()}] Grafana Alert"

    # Build message body from alert annotations
    lines: list[str] = []
    for a in alerts:
        ann = a.get("annotations", {})
        summary = ann.get("summary") or ann.get("description") or a.get("labels", {}).get("alertname", "")
        if summary:
            lines.append(summary)
    body_text = "\n".join(lines) if lines else title

    priority = "4" if status == "firing" else "2"
    tag      = "warning" if status == "firing" else "white_check_mark"

    # HTTP headers must be ASCII — strip/replace non-ASCII chars
    safe_title = title.encode("ascii", errors="replace").decode("ascii")

    url = f"{server}/{topic}"
    headers = {
        "X-Title":    safe_title,
        "X-Priority": priority,
        "X-Tags":     tag,
        "Content-Type": "text/plain",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body_text.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True, f"Grafana alert forwarded to ntfy (status={status})"
    except URLError as exc:
        return False, f"ntfy request failed: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Unexpected error: {exc}"


def _load_aliases() -> dict[str, str]:
    """Return {ip: label} from aliases.json; empty dict if missing or corrupt."""
    if not ALIASES_FILE.exists():
        return {}
    try:
        return json.loads(ALIASES_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_aliases(aliases: dict[str, str]) -> None:
    """Persist aliases dict atomically to aliases.json."""
    ALIASES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ALIASES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(aliases, indent=2))
    tmp.replace(ALIASES_FILE)


def _classify_ip(ip_str: str) -> str:
    """Return 'Local(IP)' for RFC-1918/loopback/multicast, 'External(IP)' otherwise."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return "Local(IP)"
        return "External(IP)"
    except ValueError:
        return "External(IP)"

SERVE_DIR = Path(os.environ.get("NETWATCHM_SERVE_DIR", "/var/lib/netwatchm"))
PORT = int(os.environ.get("NETWATCHM_PORT", "8765"))
NETWATCHM_CMD = os.environ.get("NETWATCHM_CMD", "netwatchm")
NETWATCHM_CONFIG = os.environ.get("NETWATCHM_CONFIG", "/etc/netwatchm/netwatchm.yaml")
DEFAULT_NETWORK = os.environ.get("NETWATCHM_NETWORK", "192.168.1.0/24")
GEOIP_DB    = os.environ.get("NETWATCHM_GEOIP_DB", "/var/lib/netwatchm/GeoLite2-City.mmdb")
FLOW_DB     = os.environ.get("NETWATCHM_FLOW_DB",    "/var/lib/netwatchm/flows.db")
EVENT_DB    = os.environ.get("NETWATCHM_EVENT_DB",   "/var/lib/netwatchm/events.db")
ADMIN_TOKEN = os.environ.get("NETWATCHM_ADMIN_TOKEN", "netwatchm-admin")
ALIASES_FILE = Path(os.environ.get("NETWATCHM_ALIASES_FILE", "/var/lib/netwatchm/aliases.json"))
REPORTS_DIR = SERVE_DIR / "reports"
REPORTS_MAX = 50  # keep this many archived reports

_lock = threading.Lock()
_state: dict = {
    "status": "idle",       # idle | running | ready | error
    "generated_at": None,
    "duration": None,
    "network": None,
    "error": None,
}

# Investigation state keyed by target IP
_inv_lock = threading.Lock()
_inv_state: dict[str, dict] = {}   # {ip: {status, error}}

# Deep inspect state keyed by target IP
_deep_lock = threading.Lock()
_deep_state: dict[str, dict] = {}  # {ip: {status, error}}

# Analytics state
_anal_lock = threading.Lock()
_anal_state: dict = {"status": "idle", "error": None, "generated_at": None}


def _run_deep_inspect(target_ip: str, ports: str) -> None:
    """Run netwatchm deep-inspect in a background thread, write HTML to SERVE_DIR."""
    with _deep_lock:
        _deep_state[target_ip] = {"status": "running", "error": None}
    try:
        out_path = SERVE_DIR / f"deep-inspect-{target_ip}.html"
        cmd = [NETWATCHM_CMD, "--config", NETWATCHM_CONFIG,
               "deep-inspect", "--target", target_ip, "--output", str(out_path)]
        if ports:
            cmd += ["--ports", ports]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "deep-inspect failed")
        # Inject hostname into generated report
        try:
            inv_file = SERVE_DIR / "inventory.json"
            if inv_file.exists():
                inv = json.loads(inv_file.read_text())
                hostname = next((d.get("hostname", "") for d in inv
                                 if d.get("ip") == target_ip and d.get("hostname")), "")
                if hostname:
                    html = out_path.read_text()
                    html = html.replace(
                        f"Deep Inspect: {target_ip}",
                        f"Deep Inspect: {hostname} ({target_ip})"
                    ).replace(
                        f"Deep Inspect — {target_ip}",
                        f"Deep Inspect — {hostname} ({target_ip})"
                    )
                    out_path.write_text(html)
        except Exception:  # noqa: BLE001
            pass  # hostname injection is best-effort
        with _deep_lock:
            _deep_state[target_ip] = {"status": "ready", "error": None}
    except Exception as exc:
        with _deep_lock:
            _deep_state[target_ip] = {"status": "error", "error": str(exc)}


def _run_analytics() -> None:
    """Regenerate analytics.html from the flow store in a background thread."""
    from datetime import datetime, timezone
    with _anal_lock:
        _anal_state.update({"status": "running", "error": None})
    try:
        out_path = SERVE_DIR / "analytics.html"
        cmd = [NETWATCHM_CMD, "--config", NETWATCHM_CONFIG,
               "analytics", "--output", str(out_path), "--db-path", FLOW_DB]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "analytics failed")
        with _anal_lock:
            _anal_state.update({
                "status": "ready",
                "error": None,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            })
    except Exception as exc:
        with _anal_lock:
            _anal_state.update({"status": "error", "error": str(exc)})


def _run_investigate(target_ip: str, ports: str) -> None:
    """Run netwatchm investigate in a background thread, write HTML to SERVE_DIR."""
    out_path = SERVE_DIR / f"investigate-{target_ip}.html"
    try:
        cmd = [NETWATCHM_CMD, "--config", NETWATCHM_CONFIG,
               "investigate", "--target", target_ip, "--output", str(out_path)]
        if ports:
            cmd += ["--ports", ports]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "investigate failed")
        with _inv_lock:
            _inv_state[target_ip] = {"status": "ready", "error": None}
    except Exception as exc:
        with _inv_lock:
            _inv_state[target_ip] = {"status": "error", "error": str(exc)}


def _run_report(duration: int, network: str) -> None:
    """Run netwatchm report in background thread, write HTML to SERVE_DIR."""
    html_path = SERVE_DIR / "connection-report.html"
    try:
        result = subprocess.run(
            [
                NETWATCHM_CMD,
                "--config", NETWATCHM_CONFIG,
                "report",
                "--duration", str(duration),
                "--network", network,
                "--output", str(html_path),
            ],
            capture_output=True,
            text=True,
            timeout=duration + 60,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "netwatchm report failed")
        now = datetime.now(timezone.utc)
        _archive_report(html_path, now)
        with _lock:
            _state.update({
                "status": "ready",
                "generated_at": now.isoformat(),
                "error": None,
            })
    except Exception as exc:
        with _lock:
            _state.update({
                "status": "error",
                "generated_at": None,
                "error": str(exc),
            })


def _archive_report(src: Path, ts: datetime) -> None:
    """Copy src to REPORTS_DIR with a timestamp name; prune oldest if over REPORTS_MAX."""
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = ts.strftime("%Y-%m-%dT%H-%M-%SZ")
        dest = REPORTS_DIR / f"connection-report-{stamp}.html"
        shutil.copy2(src, dest)
        # Prune oldest archives beyond REPORTS_MAX
        archives = sorted(REPORTS_DIR.glob("connection-report-*.html"))
        for old in archives[:-REPORTS_MAX]:
            old.unlink(missing_ok=True)
    except Exception:
        pass  # archiving is best-effort


def _render_reports_index() -> bytes:
    """Return a dark-theme HTML index of all archived reports."""
    archives = sorted(
        REPORTS_DIR.glob("connection-report-*.html"),
        reverse=True,
    )
    rows = []
    for p in archives:
        # Parse timestamp from filename: connection-report-2026-02-28T14-30-00Z.html
        name = p.stem  # connection-report-2026-02-28T14-30-00Z
        ts_part = name.removeprefix("connection-report-")
        try:
            dt = datetime.strptime(ts_part, "%Y-%m-%dT%H-%M-%SZ")
            display = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            display = ts_part
        size_kb = round(p.stat().st_size / 1024)
        rows.append(
            f"<tr>"
            f"<td><a href='/reports/{p.name}'>{display}</a></td>"
            f"<td class='num'>{size_kb} KB</td>"
            f"<td><a href='/reports/{p.name}' target='_blank'>Open</a>"
            f" &nbsp; <a href='/reports/{p.name}' download>Download</a></td>"
            f"</tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='3' style='color:var(--muted)'>No archived reports yet.</td></tr>"
    page = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>NetWatchM — Report History</title>
<style>
  :root {{ --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#c9d1d9; --accent:#58a6ff; --muted:#8b949e; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:monospace; font-size:13px; padding:24px; }}
  h1 {{ color:var(--accent); font-size:20px; margin-bottom:8px; }}
  .meta {{ color:var(--muted); margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:var(--surface); color:var(--muted); text-transform:uppercase; font-size:11px;
        padding:8px 10px; text-align:left; border-bottom:2px solid var(--border); }}
  td {{ padding:8px 10px; border-bottom:1px solid var(--border); }}
  tr:hover td {{ background:var(--surface); }}
  .num {{ text-align:right; }}
  a {{ color:var(--accent); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .back {{ display:inline-block; margin-bottom:16px; color:var(--muted); font-size:12px; }}
</style>
</head><body>
<a class="back" href="/connection-report.html">← Back to Live Report</a>
<h1>NetWatchM — Report History</h1>
<div class="meta">{len(archives)} saved report(s) &nbsp;|&nbsp; Max {REPORTS_MAX} kept</div>
<table>
<thead><tr><th>Generated (UTC)</th><th class="num">Size</th><th>Actions</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</body></html>"""
    return page.encode()


def _query_flows_endpoint(sub: str) -> object:
    """Query flows.db directly and return JSON-serialisable data for Grafana."""
    db = Path(FLOW_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        if sub == "stats":
            cur.execute(
                "SELECT COUNT(*) AS flows,"
                " COALESCE(SUM(bytes),0) AS bytes,"
                " COALESCE(SUM(packets),0) AS packets FROM flows"
            )
            r = cur.fetchone()
            # Return as single-element list so Infinity backend parser works
            return [{"flows": r["flows"], "bytes": r["bytes"], "packets": r["packets"]}]
        if sub == "devices":
            cur.execute("""
                SELECT src_ip AS ip, MAX(src_host) AS host,
                       COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY src_ip ORDER BY bytes DESC LIMIT 20
            """)
            return [{"ip": r["ip"], "host": r["host"] or r["ip"], "bytes": r["bytes"]}
                    for r in cur.fetchall()]
        if sub == "devices/top":
            cur.execute("""
                SELECT src_ip AS ip, MAX(src_host) AS host,
                       COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY src_ip ORDER BY bytes DESC LIMIT 1
            """)
            row = cur.fetchone()
            if not row:
                return [{"value": 0, "label": "—", "time": int(_time.time() * 1000)}]
            label = f"{row['host'] or row['ip']} ({row['ip']})"
            return [{"value": row["bytes"], "label": label,
                     "time": int(_time.time() * 1000)}]
        if sub == "devices/top/why":
            _PORT_SERVICES = {
                80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt",
                22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet",
                25: "SMTP", 587: "SMTP", 465: "SMTPS",
                53: "DNS", 123: "NTP", 161: "SNMP",
                445: "SMB/File Share", 139: "NetBIOS", 3306: "MySQL",
                5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                1194: "OpenVPN", 51820: "WireGuard",
            }
            # Find top sender
            top = cur.execute("""
                SELECT src_ip, MAX(src_host) AS host, COALESCE(SUM(bytes),0) AS total
                FROM flows GROUP BY src_ip ORDER BY total DESC LIMIT 1
            """).fetchone()
            if not top:
                return []
            top_ip = top["src_ip"]
            rows = cur.execute("""
                SELECT dst_ip, MAX(domain) AS domain, dst_port,
                       COALESCE(SUM(bytes),0) AS bytes, COUNT(*) AS conns
                FROM flows WHERE src_ip=?
                GROUP BY dst_ip ORDER BY bytes DESC LIMIT 8
            """, (top_ip,)).fetchall()
            result = []
            for r in rows:
                svc = _PORT_SERVICES.get(r["dst_port"], f"port {r['dst_port']}")
                dest = r["domain"] or r["dst_ip"]
                result.append({
                    "destination": dest,
                    "service": svc,
                    "bytes": r["bytes"],
                    "connections": r["conns"],
                })
            return result
        if sub == "destinations":
            cur.execute("""
                SELECT dst_ip AS ip, MAX(domain) AS domain,
                       dst_port AS port, COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY dst_ip ORDER BY bytes DESC LIMIT 10
            """)
            return [{"ip": r["ip"], "domain": r["domain"] or r["ip"],
                     "port": r["port"], "bytes": r["bytes"]}
                    for r in cur.fetchall()]
        if sub == "protocols":
            cur.execute("""
                SELECT COALESCE(protocol,'Other') AS name,
                       COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY name ORDER BY bytes DESC
            """)
            return [{"name": r["name"], "bytes": r["bytes"]} for r in cur.fetchall()]
        if sub == "hourly":
            # Rolling last 24h, grouped by hour-of-day
            cur.execute("""
                SELECT strftime('%H:00', captured_at) AS hour,
                       COALESCE(SUM(bytes),0) AS bytes
                FROM flows
                WHERE captured_at >= datetime('now', '-24 hours')
                GROUP BY hour ORDER BY hour
            """)
            return [{"hour": r["hour"], "bytes": r["bytes"]} for r in cur.fetchall()]
        if sub == "top-apps":
            _SVC = {
                80:"HTTP", 443:"HTTPS", 8080:"HTTP-alt", 8443:"HTTPS-alt",
                22:"SSH", 3389:"RDP", 21:"FTP", 25:"SMTP", 587:"SMTP",
                53:"DNS", 123:"NTP", 445:"SMB", 3306:"MySQL",
                5432:"PostgreSQL", 6379:"Redis", 1194:"OpenVPN", 51820:"WireGuard",
            }
            cur.execute("""
                SELECT dst_port, COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY dst_port ORDER BY bytes DESC LIMIT 12
            """)
            result: dict[str, int] = {}
            for r in cur.fetchall():
                name = _SVC.get(r["dst_port"], f"port {r['dst_port']}")
                result[name] = result.get(name, 0) + r["bytes"]
            return [{"app": k, "bytes": v} for k, v in
                    sorted(result.items(), key=lambda x: -x[1])]
        if sub == "devices/enriched":
            cur.execute("""
                SELECT src_ip AS ip, MAX(src_host) AS host,
                       COALESCE(SUM(bytes),0) AS total
                FROM flows GROUP BY src_ip ORDER BY total DESC LIMIT 10
            """)
            devices = [dict(r) for r in cur.fetchall()]
            _SVC2 = {
                80:"HTTP", 443:"HTTPS", 8080:"HTTP-alt", 8443:"HTTPS-alt",
                22:"SSH", 3389:"RDP", 21:"FTP", 25:"SMTP", 587:"SMTP",
                53:"DNS", 123:"NTP", 445:"SMB", 3306:"MySQL",
                5432:"PostgreSQL", 6379:"Redis", 1194:"OpenVPN", 51820:"WireGuard",
            }
            result2 = []
            for dev in devices:
                top = cur.execute("""
                    SELECT dst_ip, MAX(domain) AS domain, dst_port,
                           COALESCE(SUM(bytes),0) AS bytes
                    FROM flows WHERE src_ip=?
                    GROUP BY dst_ip ORDER BY bytes DESC LIMIT 1
                """, (dev["ip"],)).fetchone()
                dest = ""
                svc = ""
                if top:
                    dest = top["domain"] or top["dst_ip"]
                    svc = _SVC2.get(top["dst_port"], f"port {top['dst_port']}")
                result2.append({
                    "ip": dev["ip"],
                    "device": dev["host"] or dev["ip"],
                    "traffic": dev["total"],
                    "top_destination": dest,
                    "service": svc,
                })
            return result2
        return {"error": "unknown endpoint"}
    finally:
        con.close()


def _query_events(
    limit: int = 200,
    alert_type: str | None = None,
    level: str | None = None,
    ip: str | None = None,
) -> list[dict]:
    """Query events.db and return JSON-serialisable list, newest first."""
    db = Path(EVENT_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        clauses: list[str] = []
        params: list = []
        if alert_type:
            clauses.append("alert_type = ?")
            params.append(alert_type)
        if level:
            clauses.append("level = ?")
            params.append(level.upper())
        if ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cur = con.execute(
            f"SELECT id, timestamp, alert_type, level, src_ip, dst_ip, description "
            f"FROM events {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()


def _query_event_types() -> list[str]:
    db = Path(EVENT_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    try:
        cur = con.execute("SELECT DISTINCT alert_type FROM events ORDER BY alert_type")
        return [r[0] for r in cur.fetchall()]
    finally:
        con.close()


def _render_inspect_launcher(ip: str) -> str:
    """Launcher page: triggers deep-inspect job, shows progress, redirects when done."""
    # Look up hostname from inventory
    hostname = ""
    try:
        inv_file = SERVE_DIR / "inventory.json"
        if inv_file.exists():
            inv = json.loads(inv_file.read_text())
            hostname = next((d.get("hostname", "") for d in inv
                             if d.get("ip") == ip and d.get("hostname")), "")
    except Exception:  # noqa: BLE001
        pass
    display = f"{hostname} ({ip})" if hostname else ip
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Deep Inspect — {display}</title>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:monospace;display:flex;
       align-items:center;justify-content:center;min-height:100vh;margin:0;flex-direction:column;gap:20px}}
  h2{{color:#58a6ff;font-size:18px;margin:0}}
  .sub{{color:#8b949e;font-size:13px}}
  .spinner{{width:40px;height:40px;border:3px solid #30363d;border-top-color:#58a6ff;
            border-radius:50%;animation:spin 0.8s linear infinite}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
  .status{{color:#8b949e;font-size:12px;min-height:18px}}
  .err{{color:#f85149}}
  .links{{display:flex;gap:12px;margin-top:8px}}
  a.btn{{background:#21262d;color:#58a6ff;border:1px solid #30363d;padding:6px 16px;
         border-radius:4px;text-decoration:none;font-size:13px}}
  a.btn:hover{{border-color:#58a6ff}}
</style>
</head>
<body>
<h2>&#128269; Deep Inspect: {display}</h2>
<div class="spinner" id="spin"></div>
<div class="status" id="status">Starting inspection…</div>
<div class="links">
  <a class="btn" href="/events.html?q={ip}" target="_blank">&#9888; View Events</a>
  <a class="btn" href="/connection-report.html">&#8592; Connection Report</a>
</div>
<script>
const ip = {json.dumps(ip)};
const resultUrl = '/deep-inspect-' + ip + '.html';

async function trigger() {{
  // Check if already done
  const s = await fetch('/api/deep-inspect/status?target=' + ip).then(r=>r.json()).catch(()=>({{}}));
  if (s.status === 'ready') {{ window.location.href = resultUrl; return; }}
  if (s.status !== 'running') {{
    // Trigger new job
    await fetch('/api/deep-inspect?target=' + ip, {{method:'POST'}}).catch(()=>{{}});
  }}
  poll();
}}

function poll() {{
  const t = setInterval(async () => {{
    try {{
      const d = await fetch('/api/deep-inspect/status?target=' + ip).then(r=>r.json());
      if (d.status === 'ready') {{
        clearInterval(t);
        document.getElementById('status').textContent = 'Done! Loading report…';
        window.location.href = resultUrl;
      }} else if (d.status === 'error') {{
        clearInterval(t);
        document.getElementById('spin').style.display = 'none';
        document.getElementById('status').innerHTML =
          '<span class="err">Error: ' + (d.error||'unknown') + '</span>';
      }} else {{
        document.getElementById('status').textContent = 'Scanning… ' + new Date().toLocaleTimeString();
      }}
    }} catch(e) {{
      document.getElementById('status').textContent = 'Waiting for server…';
    }}
  }}, 2000);
}}

trigger();
</script>
</body>
</html>"""


def _render_events_html() -> bytes:
    """Return the self-contained events portal SPA."""
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetWatchM — Threat Events</title>
<style>
  :root {
    --bg:#0d1117; --surface:#161b22; --surface2:#21262d; --border:#30363d;
    --text:#c9d1d9; --muted:#8b949e; --accent:#58a6ff;
    --low:#3fb950; --medium:#d29922; --high:#f85149; --critical:#ff7b72;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:monospace; font-size:13px; }
  /* ── Top bar ── */
  .topbar {
    display:flex; align-items:center; gap:12px; padding:12px 20px;
    background:var(--surface); border-bottom:1px solid var(--border);
    flex-wrap:wrap;
  }
  .topbar h1 { color:var(--accent); font-size:16px; white-space:nowrap; margin-right:8px; }
  .topbar a { color:var(--muted); font-size:12px; text-decoration:none; }
  .topbar a:hover { color:var(--accent); }
  .spacer { flex:1; }
  .refresh-btn {
    background:var(--surface2); color:var(--text); border:1px solid var(--border);
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .refresh-btn:hover { border-color:var(--accent); color:var(--accent); }
  .countdown { color:var(--muted); font-size:11px; white-space:nowrap; }
  /* ── Filter bar ── */
  .filterbar {
    display:flex; align-items:center; gap:8px; padding:10px 20px;
    background:var(--surface); border-bottom:1px solid var(--border); flex-wrap:wrap;
  }
  .filterbar input, .filterbar select {
    background:var(--bg); color:var(--text); border:1px solid var(--border);
    padding:5px 10px; border-radius:4px; font-family:monospace; font-size:12px;
  }
  .filterbar input { width:220px; }
  .filterbar input:focus, .filterbar select:focus {
    outline:none; border-color:var(--accent);
  }
  .filterbar label { color:var(--muted); font-size:12px; }
  .result-count { color:var(--muted); font-size:12px; margin-left:auto; }
  /* ── Table ── */
  .table-wrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; }
  thead th {
    background:var(--surface); color:var(--muted); text-transform:uppercase;
    font-size:11px; padding:8px 12px; text-align:left;
    border-bottom:2px solid var(--border); white-space:nowrap; position:sticky; top:0;
  }
  tbody tr { border-bottom:1px solid var(--border); cursor:pointer; }
  tbody tr:hover td { background:var(--surface2); }
  tbody tr.expanded td { background:var(--surface2); }
  td { padding:8px 12px; vertical-align:top; white-space:nowrap; max-width:280px; overflow:hidden; text-overflow:ellipsis; }
  td.desc { white-space:normal; color:var(--muted); font-size:12px; }
  /* ── Detail row ── */
  .detail-row td {
    background:var(--surface); border-bottom:2px solid var(--accent);
    padding:14px 20px; cursor:default; white-space:normal;
  }
  .detail-grid { display:flex; gap:24px; flex-wrap:wrap; }
  .detail-field { display:flex; flex-direction:column; gap:3px; }
  .detail-label { color:var(--muted); font-size:11px; text-transform:uppercase; }
  .detail-value { color:var(--text); font-size:13px; }
  .detail-desc { margin-top:10px; color:var(--text); font-size:13px; line-height:1.5; word-break:break-word; }
  .deep-btn {
    display:inline-block; margin-top:10px; background:var(--accent); color:#0d1117;
    padding:5px 14px; border-radius:4px; font-family:monospace; font-size:12px;
    text-decoration:none; font-weight:bold;
  }
  .deep-btn:hover { opacity:0.85; }
  /* ── Level badges ── */
  .badge {
    display:inline-block; padding:2px 8px; border-radius:3px;
    font-size:11px; font-weight:bold; text-transform:uppercase;
  }
  .badge-LOW      { background:#1a3a22; color:var(--low); }
  .badge-MEDIUM   { background:#3a2f0e; color:var(--medium); }
  .badge-HIGH     { background:#3a1214; color:var(--high); }
  .badge-CRITICAL { background:#3a0f0f; color:var(--critical); }
  /* ── Empty state ── */
  .empty { text-align:center; padding:60px 20px; color:var(--muted); }
  .empty .big { font-size:32px; margin-bottom:12px; }
  /* ── Export btn ── */
  .export-btn {
    background:var(--surface2); color:var(--muted); border:1px solid var(--border);
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .export-btn:hover { color:var(--accent); border-color:var(--accent); }
  /* ── Test notify btn ── */
  .notify-btn {
    background:var(--surface2); color:var(--muted); border:1px solid var(--border);
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .notify-btn:hover { color:#3fb950; border-color:#3fb950; }
  .notify-btn:disabled { opacity:0.5; cursor:default; }
  .clear-btn {
    background:var(--surface2); color:#f85149; border:1px solid #f85149;
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .clear-btn:hover { background:#f85149; color:#fff; }
  /* ── Clear modal ── */
  #clearModal {
    display:none; position:fixed; top:0; left:0; width:100%; height:100%;
    background:rgba(0,0,0,.75); z-index:999; align-items:center; justify-content:center;
  }
  .modal-box {
    background:#1e1e2e; border:1px solid #444; border-radius:8px;
    padding:28px 32px; min-width:320px; text-align:center;
  }
  .modal-box h3 { color:#f85149; margin:0 0 8px; }
  .modal-box p  { color:#888; font-size:13px; margin:0 0 16px; }
  .modal-box input {
    width:100%; padding:8px 10px; background:#2a2a3e; border:1px solid #555;
    border-radius:4px; color:#e6e6e6; font-size:14px; box-sizing:border-box; margin-bottom:14px;
  }
  .modal-actions { display:flex; gap:10px; justify-content:center; }
  .modal-actions button { padding:8px 22px; border:none; border-radius:4px; cursor:pointer; font-size:14px; }
  .modal-confirm { background:#f85149; color:#fff; }
  .modal-cancel  { background:#333; color:#e6e6e6; }
  /* ── Toast ── */
  #toast {
    position:fixed; bottom:24px; left:50%; transform:translateX(-50%);
    background:var(--surface2); border:1px solid var(--border); border-radius:6px;
    padding:10px 20px; font-size:13px; z-index:999; display:none;
    box-shadow:0 4px 16px rgba(0,0,0,0.5);
  }
  #toast.ok  { border-color:#3fb950; color:#3fb950; }
  #toast.err { border-color:#f85149; color:#f85149; }
  /* ── Auto-refresh toggle ── */
  .auto-toggle {
    display:flex; align-items:center; gap:6px; cursor:pointer;
    color:var(--muted); font-size:12px; user-select:none;
  }
  .auto-toggle input { accent-color:var(--accent); }
</style>
</head>
<body>

<div class="topbar">
  <h1>&#9888; NetWatchM &mdash; Threat Events</h1>
  <a href="/connection-report.html">&#8592; Report</a>
  <a href="/analytics.html">Analytics</a>
  <div class="spacer"></div>
  <label class="auto-toggle">
    <input type="checkbox" id="autoRefresh" checked> Auto-refresh
  </label>
  <span class="countdown" id="countdown"></span>
  <button class="refresh-btn" onclick="loadEvents()">&#8635; Refresh</button>
  <button class="export-btn" onclick="exportCSV()">&#11123; CSV</button>
  <button class="notify-btn" id="testNtfyBtn" onclick="testNtfy()">&#128276; Test Notify</button>
  <button class="clear-btn" onclick="clearAlerts()">&#128465; Clear Alerts</button>
</div>
<div id="toast"></div>
<div id="clearModal">
  <div class="modal-box">
    <h3>&#9888; Clear All Alerts?</h3>
    <p>This permanently deletes all events from the database.<br>Enter your admin token to confirm.</p>
    <input type="password" id="adminToken" placeholder="Admin token" onkeydown="if(event.key==='Enter')confirmClear()">
    <div class="modal-actions">
      <button class="modal-confirm" onclick="confirmClear()">Clear</button>
      <button class="modal-cancel" onclick="closeClearModal()">Cancel</button>
    </div>
  </div>
</div>

<div class="filterbar">
  <label>Search:</label>
  <input type="text" id="search" placeholder="IP, type, description…" oninput="applyFilters()">
  <label>Level:</label>
  <select id="levelFilter" onchange="applyFilters()">
    <option value="">All</option>
    <option value="LOW">LOW</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="HIGH">HIGH</option>
    <option value="CRITICAL">CRITICAL</option>
  </select>
  <label>Type:</label>
  <select id="typeFilter" onchange="applyFilters()">
    <option value="">All</option>
  </select>
  <span class="result-count" id="resultCount"></span>
</div>

<div class="table-wrap">
<table id="eventsTable">
  <thead>
    <tr>
      <th>Time</th>
      <th>Type</th>
      <th>Level</th>
      <th>Source IP</th>
      <th>Dest IP</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>
</div>

<script>
let _allEvents = [];
let _expandedId = null;
let _autoTimer = null;
let _countdown = 15;

function showToast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = ok ? 'ok' : 'err';
  t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.display = 'none'; }, 4000);
}

async function testNtfy() {
  const btn = document.getElementById('testNtfyBtn');
  btn.disabled = true;
  btn.textContent = '… Sending';
  try {
    const r = await fetch('/api/test-ntfy', {method:'POST'});
    const d = await r.json();
    showToast(d.message, d.ok);
  } catch(e) {
    showToast('Request failed: ' + e, false);
  } finally {
    btn.disabled = false;
    btn.textContent = '\\u{1F514} Test Notify';
  }
}

function clearAlerts() {
  document.getElementById('adminToken').value = '';
  const m = document.getElementById('clearModal');
  m.style.display = 'flex';
  setTimeout(() => document.getElementById('adminToken').focus(), 80);
}
function closeClearModal() {
  document.getElementById('clearModal').style.display = 'none';
}
async function confirmClear() {
  const token = document.getElementById('adminToken').value.trim();
  if (!token) { showToast('Admin token required', false); return; }
  try {
    const r = await fetch('/api/events', {
      method: 'DELETE',
      headers: {'X-Admin-Token': token}
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      closeClearModal();
      showToast('All alerts cleared', true);
      loadEvents();
    } else {
      showToast(d.error || 'Failed — check token', false);
    }
  } catch(e) {
    showToast('Request failed: ' + e, false);
  }
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const pad = n => String(n).padStart(2,'0');
  return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())
    +' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
}

function badge(level) {
  return `<span class="badge badge-${level}">${level}</span>`;
}

function esc(s) {
  if (!s) return '—';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function loadEvents() {
  resetCountdown();
  try {
    const [evts, types] = await Promise.all([
      fetch('/api/events?limit=500').then(r => r.json()),
      fetch('/api/events/types').then(r => r.json()),
    ]);
    _allEvents = evts;
    _expandedId = null;
    populateTypeFilter(types);
    applyFilters();
  } catch(e) {
    document.getElementById('tbody').innerHTML =
      '<tr><td colspan="6" style="color:var(--high);padding:20px">Failed to load events: '+esc(String(e))+'</td></tr>';
  }
}

function populateTypeFilter(types) {
  const sel = document.getElementById('typeFilter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All</option>';
  types.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t; opt.textContent = t;
    if (t === cur) opt.selected = true;
    sel.appendChild(opt);
  });
}

function applyFilters() {
  const search = document.getElementById('search').value.toLowerCase();
  const level  = document.getElementById('levelFilter').value;
  const type   = document.getElementById('typeFilter').value;

  const filtered = _allEvents.filter(e => {
    if (level && e.level !== level) return false;
    if (type  && e.alert_type !== type) return false;
    if (search) {
      const hay = [e.alert_type, e.level, e.src_ip, e.dst_ip, e.description]
                    .join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  document.getElementById('resultCount').textContent =
    filtered.length + ' of ' + _allEvents.length + ' events';

  renderTable(filtered);
}

function renderTable(events) {
  const tbody = document.getElementById('tbody');
  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty">'
      + '<div class="big">&#128268;</div>No events match your filters.</div></td></tr>';
    return;
  }
  const rows = [];
  events.forEach(e => {
    const expanded = e.id === _expandedId;
    rows.push(
      `<tr class="${expanded?'expanded':''}" onclick="toggleDetail(${e.id})" data-id="${e.id}">
        <td>${fmtTime(e.timestamp)}</td>
        <td>${esc(e.alert_type)}</td>
        <td>${badge(e.level)}</td>
        <td>${esc(e.src_ip)}</td>
        <td>${esc(e.dst_ip)}</td>
        <td class="desc" title="${esc(e.description)}">${esc(e.description)}</td>
      </tr>`
    );
    if (expanded) {
      rows.push(buildDetailRow(e));
    }
  });
  tbody.innerHTML = rows.join('');
}

function buildDetailRow(e) {
  const deepLink = e.src_ip && !e.src_ip.startsWith('192.168') && !e.src_ip.startsWith('10.')
    ? `<a class="deep-btn" href="/inspect/${esc(e.src_ip)}" target="_blank">&#128269; Deep Inspect ${esc(e.src_ip)}</a>`
    : '';
  return `<tr class="detail-row" onclick="event.stopPropagation()">
    <td colspan="6">
      <div class="detail-grid">
        <div class="detail-field"><span class="detail-label">ID</span><span class="detail-value">${e.id}</span></div>
        <div class="detail-field"><span class="detail-label">Time</span><span class="detail-value">${fmtTime(e.timestamp)}</span></div>
        <div class="detail-field"><span class="detail-label">Type</span><span class="detail-value">${esc(e.alert_type)}</span></div>
        <div class="detail-field"><span class="detail-label">Level</span><span class="detail-value">${badge(e.level)}</span></div>
        <div class="detail-field"><span class="detail-label">Source IP</span><span class="detail-value">${esc(e.src_ip)}</span></div>
        <div class="detail-field"><span class="detail-label">Dest IP</span><span class="detail-value">${esc(e.dst_ip)}</span></div>
      </div>
      <div class="detail-desc">${esc(e.description)}</div>
      ${deepLink}
    </td>
  </tr>`;
}

function toggleDetail(id) {
  _expandedId = (_expandedId === id) ? null : id;
  applyFilters();
}

function exportCSV() {
  const search = document.getElementById('search').value.toLowerCase();
  const level  = document.getElementById('levelFilter').value;
  const type   = document.getElementById('typeFilter').value;
  const filtered = _allEvents.filter(e => {
    if (level && e.level !== level) return false;
    if (type  && e.alert_type !== type) return false;
    if (search) {
      const hay = [e.alert_type, e.level, e.src_ip, e.dst_ip, e.description].join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });
  const cols = ['id','timestamp','alert_type','level','src_ip','dst_ip','description'];
  const csv  = [cols.join(',')].concat(
    filtered.map(e => cols.map(c => {
      const v = c === 'timestamp' ? fmtTime(e[c]) : (e[c] ?? '');
      return '"' + String(v).replace(/"/g,'""') + '"';
    }).join(','))
  ).join('\\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'netwatchm-events.csv';
  a.click();
}

function resetCountdown() {
  _countdown = 15;
  document.getElementById('countdown').textContent = '';
}

function tickCountdown() {
  if (!document.getElementById('autoRefresh').checked) {
    document.getElementById('countdown').textContent = '';
    return;
  }
  _countdown--;
  if (_countdown <= 0) {
    loadEvents();
  } else {
    document.getElementById('countdown').textContent = 'Next refresh in ' + _countdown + 's';
  }
}

document.getElementById('autoRefresh').addEventListener('change', function() {
  if (this.checked) { resetCountdown(); }
  else { document.getElementById('countdown').textContent = ''; }
});

// Pre-fill search from ?ip= or ?search= URL param (e.g. from Grafana data links)
(function() {
  const p = new URLSearchParams(window.location.search);
  const ip = p.get('ip') || p.get('search');
  if (ip) document.getElementById('search').value = ip;
})();

setInterval(tickCountdown, 1000);
loadEvents();
</script>
</body>
</html>"""
    return page.encode()


def _render_inventory_html() -> bytes:
    """Return the self-contained device inventory + label editor SPA."""
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatchM — Device Inventory</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--accent:#1f6feb}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  header h1{font-size:15px;font-weight:600;color:var(--blue)}
  .toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-left:auto}
  input[type=search]{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:6px;font-size:12px;width:220px}
  input[type=search]:focus{outline:none;border-color:var(--blue)}
  button{background:var(--accent);color:#fff;border:none;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px}
  button:hover{opacity:.85}
  button.secondary{background:var(--surface);border:1px solid var(--border);color:var(--text)}
  .count{color:var(--muted);font-size:12px}
  table{width:100%;border-collapse:collapse}
  thead th{background:var(--surface);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1;cursor:pointer;user-select:none}
  thead th:hover{color:var(--text)}
  thead th.sorted{color:var(--blue)}
  tbody tr{border-bottom:1px solid var(--border)}
  tbody tr:hover{background:rgba(255,255,255,.03)}
  td{padding:7px 10px;vertical-align:middle}
  .label-cell{min-width:140px;max-width:200px}
  .label-display{cursor:pointer;color:var(--blue);padding:2px 6px;border-radius:4px;display:inline-block;min-width:80px}
  .label-display:hover{background:rgba(88,166,255,.12)}
  .label-display.empty{color:var(--muted);font-style:italic}
  .label-input{background:var(--bg);border:1px solid var(--blue);color:var(--text);padding:2px 6px;border-radius:4px;font-size:13px;width:140px;outline:none}
  .threat{font-weight:600;font-size:11px;padding:2px 7px;border-radius:10px;display:inline-block}
  .HIGH{background:rgba(248,81,73,.15);color:var(--red)}
  .MEDIUM{background:rgba(210,153,34,.15);color:var(--yellow)}
  .LOW{background:rgba(63,185,80,.15);color:var(--green)}
  .CRITICAL{background:rgba(248,81,73,.3);color:var(--red)}
  .ip{font-family:monospace;font-size:12px}
  .scroll{overflow-x:auto}
  .empty-state{text-align:center;padding:60px;color:var(--muted)}
  .toast{position:fixed;bottom:20px;right:20px;background:var(--green);color:#000;padding:8px 16px;border-radius:6px;font-size:12px;opacity:0;transition:opacity .3s;pointer-events:none;z-index:99}
  .toast.show{opacity:1}
  a{color:var(--blue);text-decoration:none}
  a:hover{text-decoration:underline}
  nav{display:flex;gap:16px;align-items:center}
  nav a{color:var(--muted);font-size:13px}
  nav a:hover{color:var(--text)}
</style>
</head>
<body>
<header>
  <h1>&#128241; Device Inventory</h1>
  <nav>
    <a href="/connection-report.html">&#8592; Report</a>
    <a href="/events.html">Events</a>
    <a href="/analytics.html">Analytics</a>
  </nav>
  <div class="toolbar">
    <input type="search" id="searchBox" placeholder="Search IP, label, hostname, vendor…">
    <span class="count" id="countLabel">— devices</span>
    <button class="secondary" id="exportBtn">&#11123; Export CSV</button>
  </div>
</header>
<div class="scroll">
<table id="devTable">
  <thead>
    <tr>
      <th data-col="label" class="sorted">Label &#9660;</th>
      <th data-col="ip">IP</th>
      <th data-col="hostname">Hostname</th>
      <th data-col="mac">MAC</th>
      <th data-col="vendor">Vendor</th>
      <th data-col="threat_level">Threat</th>
      <th data-col="bytes_sent">&#8593; Sent</th>
      <th data-col="bytes_received">&#8595; Recv</th>
      <th data-col="last_seen">Last Seen</th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div class="empty-state" id="emptyState" style="display:none">No devices match your search.</div>
<div class="toast" id="toast"></div>
<script>
let _devices = [], _aliases = {}, _sortCol = 'label', _sortAsc = true;

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function fmtBytes(n){
  n = parseInt(n)||0;
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(1)+' MB';
  return (n/1073741824).toFixed(1)+' GB';
}

function fmtTime(s){
  if(!s) return '—';
  const d=new Date(s); if(isNaN(d)) return s;
  return d.toLocaleString();
}

function toast(msg, ok=true){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.style.background=ok?'#3fb950':'#f85149';
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2000);
}

async function loadData(){
  const [devResp, aliasResp] = await Promise.all([
    fetch('/inventory.json'),
    fetch('/api/aliases')
  ]);
  _devices = await devResp.json();
  _aliases  = await aliasResp.json();
  render();
}

function getLabel(ip){ return _aliases[ip] || ''; }

function sortDevices(devices){
  return [...devices].sort((a,b)=>{
    let av='', bv='';
    if(_sortCol==='label'){
      av=getLabel(a.ip).toLowerCase();
      bv=getLabel(b.ip).toLowerCase();
      // unlabelled items always last
      if(!av && bv) return 1;
      if(av && !bv) return -1;
    } else if(_sortCol==='bytes_sent'||_sortCol==='bytes_received'){
      av=parseInt(a[_sortCol])||0;
      bv=parseInt(b[_sortCol])||0;
    } else {
      av=String(a[_sortCol]||'').toLowerCase();
      bv=String(b[_sortCol]||'').toLowerCase();
    }
    if(av<bv) return _sortAsc?-1:1;
    if(av>bv) return _sortAsc?1:-1;
    return 0;
  });
}

function render(){
  const q = document.getElementById('searchBox').value.toLowerCase();
  let rows = _devices.filter(d=>{
    if(!q) return true;
    const label = getLabel(d.ip).toLowerCase();
    return (d.ip||'').includes(q) || label.includes(q) ||
           (d.hostname||'').toLowerCase().includes(q) ||
           (d.vendor||'').toLowerCase().includes(q) ||
           (d.mac||'').toLowerCase().includes(q);
  });
  rows = sortDevices(rows);
  document.getElementById('countLabel').textContent = rows.length+' device'+(rows.length!==1?'s':'');
  document.getElementById('emptyState').style.display = rows.length?'none':'block';
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = rows.map(d=>{
    const label = getLabel(d.ip);
    const lvl = d.threat_level||'LOW';
    return `<tr>
      <td class="label-cell"><span class="label-display ${label?'':'empty'}" data-ip="${esc(d.ip)}">${label?esc(label):'Add label…'}</span></td>
      <td class="ip">${esc(d.ip)}</td>
      <td>${esc(d.hostname)||'—'}</td>
      <td class="ip">${esc(d.mac)||'—'}</td>
      <td>${esc(d.vendor)||'—'}</td>
      <td><span class="threat ${lvl}">${lvl}</span></td>
      <td>${fmtBytes(d.bytes_sent)}</td>
      <td>${fmtBytes(d.bytes_received)}</td>
      <td>${fmtTime(d.last_seen)}</td>
    </tr>`;
  }).join('');
  attachLabelEditors();
}

function attachLabelEditors(){
  document.querySelectorAll('.label-display').forEach(el=>{
    el.addEventListener('click', startEdit);
  });
}

function startEdit(e){
  const el = e.currentTarget;
  const ip = el.dataset.ip;
  const current = _aliases[ip]||'';
  const input = document.createElement('input');
  input.type='text';
  input.className='label-input';
  input.value=current;
  input.placeholder='Device label…';
  el.replaceWith(input);
  input.focus();
  input.select();

  const commit = async ()=>{
    const val = input.value.trim();
    try{
      const r = await fetch('/api/aliases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,label:val})});
      const j = await r.json();
      _aliases = j.aliases;
      toast(val ? `Saved: ${val}` : 'Label cleared');
    } catch(_){ toast('Save failed',false); }
    render();
  };
  input.addEventListener('blur', commit);
  input.addEventListener('keydown', ev=>{
    if(ev.key==='Enter'){ ev.preventDefault(); input.blur(); }
    if(ev.key==='Escape'){ input.removeEventListener('blur',commit); render(); }
  });
}

// Column sort
document.querySelectorAll('thead th[data-col]').forEach(th=>{
  th.addEventListener('click',()=>{
    const col=th.dataset.col;
    if(_sortCol===col) _sortAsc=!_sortAsc;
    else{ _sortCol=col; _sortAsc=true; }
    document.querySelectorAll('thead th').forEach(t=>t.classList.remove('sorted'));
    th.classList.add('sorted');
    th.textContent=th.textContent.replace(/[▲▼]/g,'').trim()+(_sortAsc?' ▲':' ▼');
    render();
  });
});

// Search
document.getElementById('searchBox').addEventListener('input', render);

// CSV export (with labels)
document.getElementById('exportBtn').addEventListener('click', ()=>{
  const q = document.getElementById('searchBox').value.toLowerCase();
  let rows = _devices.filter(d=>{
    if(!q) return true;
    const label = getLabel(d.ip).toLowerCase();
    return (d.ip||'').includes(q)||label.includes(q)||(d.hostname||'').toLowerCase().includes(q)||(d.vendor||'').toLowerCase().includes(q)||(d.mac||'').toLowerCase().includes(q);
  });
  const header = 'Label,IP,Hostname,MAC,Vendor,Threat Level,Bytes Sent,Bytes Received,Last Seen\\n';
  const body = rows.map(d=>[
    `"${(getLabel(d.ip)||'').replace(/"/g,'""')}"`,
    `"${(d.ip||'').replace(/"/g,'""')}"`,
    `"${(d.hostname||'').replace(/"/g,'""')}"`,
    `"${(d.mac||'').replace(/"/g,'""')}"`,
    `"${(d.vendor||'').replace(/"/g,'""')}"`,
    d.threat_level||'LOW',
    d.bytes_sent||0,
    d.bytes_received||0,
    `"${(d.last_seen||'').replace(/"/g,'""')}"`
  ].join(',')).join('\\n');
  const blob=new Blob([header+body],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='netwatchm-inventory-'+new Date().toISOString().slice(0,19).replace(/:/g,'-')+'.csv';
  a.click();
});

loadData();
</script>
</body>
</html>"""
    return page.encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        pass

    def _send_json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists():
            self.send_error(404, "Not Found")
            return
        mime, _ = mimetypes.guess_type(str(path))
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        if mime and "html" in mime:
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/report/status":
            with _lock:
                self._send_json(dict(_state))
            return

        if path == "/api/investigate/status":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0]
            with _inv_lock:
                state = _inv_state.get(target, {"status": "unknown", "error": None})
            self._send_json({"target": target, **state})
            return

        if path == "/api/deep-inspect/status":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0]
            with _deep_lock:
                st = _deep_state.get(target, {"status": "unknown", "error": None})
            self._send_json({"target": target, **st})
            return

        if path == "/api/analytics/status":
            with _anal_lock:
                self._send_json(dict(_anal_state))
            return

        if path.startswith("/api/flows/"):
            sub = path.removeprefix("/api/flows/")
            try:
                result = _query_flows_endpoint(sub)
                self._send_json(result if isinstance(result, (list, dict)) else [])
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/events":
            qs = parse_qs(parsed.query)
            try:
                events = _query_events(
                    limit=min(int(qs.get("limit", ["500"])[0]), 1000),
                    alert_type=qs.get("type", [None])[0] or None,
                    level=qs.get("level", [None])[0] or None,
                    ip=qs.get("ip", [None])[0] or None,
                )
                self._send_json(events)
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/events/types":
            try:
                self._send_json(_query_event_types())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/aliases":
            self._send_json(_load_aliases())
            return

        if path.startswith("/inspect/"):
            ip = path.removeprefix("/inspect/").strip("/")
            body = _render_inspect_launcher(ip).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/events.html":
            body = _render_events_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/inventory.html":
            body = _render_inventory_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return

        if path in ("/reports", "/reports/"):
            body = _render_reports_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return

        # Static file serving — prevent path traversal
        if path in ("/", "/index.html"):
            self._send_file(SERVE_DIR / "report.html")
            return

        rel = path.lstrip("/")
        if ".." in rel:
            self.send_error(403, "Forbidden")
            return
        self._send_file(SERVE_DIR / rel)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/aliases":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            ip = (body.get("ip") or "").strip()
            label = (body.get("label") or "").strip()
            if not ip:
                self._send_json({"error": "ip required"}, 400)
                return
            aliases = _load_aliases()
            if label:
                aliases[ip] = label
            else:
                aliases.pop(ip, None)
            _save_aliases(aliases)
            self._send_json({"ok": True, "aliases": aliases})
            return

        if parsed.path == "/api/report":
            qs = parse_qs(parsed.query)
            duration = int(qs.get("duration", ["30"])[0])
            network = qs.get("network", [DEFAULT_NETWORK])[0]
            duration = max(5, min(300, duration))

            with _lock:
                if _state["status"] == "running":
                    self._send_json({"error": "Report already running"}, 409)
                    return
                _state.update({
                    "status": "running",
                    "duration": duration,
                    "network": network,
                    "error": None,
                    "generated_at": None,
                })

            thread = threading.Thread(
                target=_run_report, args=(duration, network), daemon=True
            )
            thread.start()
            self._send_json({"status": "running", "duration": duration, "network": network})
            return

        if parsed.path == "/api/investigate":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            ports  = qs.get("ports",  [""])[0].strip()
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            with _inv_lock:
                if _inv_state.get(target, {}).get("status") == "running":
                    self._send_json({"status": "running", "target": target})
                    return
                _inv_state[target] = {"status": "running", "error": None}
            thread = threading.Thread(
                target=_run_investigate, args=(target, ports), daemon=True
            )
            thread.start()
            self._send_json({
                "status": "running",
                "target": target,
                "result_url": f"/investigate-{target}.html",
            })
            return

        if parsed.path == "/api/deep-inspect":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            ports  = qs.get("ports",  [""])[0].strip()
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            with _deep_lock:
                if _deep_state.get(target, {}).get("status") == "running":
                    self._send_json({"error": "Deep inspect already running"}, 409)
                    return
            threading.Thread(
                target=_run_deep_inspect, args=(target, ports), daemon=True
            ).start()
            self._send_json({
                "status": "running",
                "target": target,
                "result_url": f"/deep-inspect-{target}.html",
            })
            return

        if parsed.path == "/api/analytics":
            with _anal_lock:
                if _anal_state.get("status") == "running":
                    self._send_json({"status": "running"}, 409)
                    return
            threading.Thread(target=_run_analytics, daemon=True).start()
            self._send_json({"status": "running", "result_url": "/analytics.html"})
            return

        if parsed.path == "/api/test-ntfy":
            ok, msg = _send_test_ntfy()
            self._send_json({"ok": ok, "message": msg}, 200 if ok else 400)
            return

        self.send_error(404, "Not Found")

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/events":
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                self._send_json({"error": "unauthorized"}, 401)
                return
            try:
                con = sqlite3.connect(str(Path(EVENT_DB)))
                con.execute("DELETE FROM events")
                con.commit()
                con.close()
                self._send_json({"ok": True, "message": "All alerts cleared"})
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return
        self.send_error(404, "Not Found")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
        self.end_headers()


CERT_DIR = Path(os.environ.get("NETWATCHM_CERT_DIR", "/var/lib/netwatchm"))
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE  = CERT_DIR / "server.key"


def _ensure_cert() -> None:
    """Generate a self-signed TLS certificate if one doesn't already exist."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    print("Generating self-signed TLS certificate…", flush=True)
    subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", str(KEY_FILE),
            "-out", str(CERT_FILE),
            "-days", "3650",
            "-nodes",
            "-subj", "/CN=localhost/O=NetWatchM",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(KEY_FILE, 0o600)
    print(f"Certificate written to {CERT_FILE}", flush=True)


HTTP_PORT = int(os.environ.get("NETWATCHM_HTTP_PORT", "8766"))


def _query_adult_domains() -> list[dict]:
    """Return ADULT_DOMAIN events grouped by src_ip + domain, newest first."""
    db = Path(EVENT_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute("""
            SELECT src_ip,
                   description,
                   COUNT(*) AS count,
                   MAX(timestamp) AS last_seen
            FROM events
            WHERE alert_type = 'ADULT_DOMAIN'
            GROUP BY src_ip, description
            ORDER BY last_seen DESC
            LIMIT 200
        """)
        rows = []
        for r in cur.fetchall():
            desc = r["description"] or ""
            # "Adult domain accessed (DNS): xvideos.com" → "xvideos.com"
            domain = desc.split(": ", 1)[-1] if ": " in desc else desc
            rows.append({
                "src_ip": r["src_ip"] or "—",
                "domain": domain,
                "count": r["count"],
                "last_seen": r["last_seen"],
            })
        return rows
    finally:
        con.close()


def _query_data_hog_count() -> list[dict]:
    """Return count of DATA_HOG events in the last 24 h as a single-row metric list."""
    db = Path(EVENT_DB)
    now_ms = int(_time.time() * 1000)
    if not db.exists():
        return [{"value": 0}]
    con = sqlite3.connect(str(db))
    try:
        cutoff = _time.time() - 86400
        row = con.execute(
            "SELECT COUNT(*) FROM events WHERE alert_type='DATA_HOG' AND timestamp >= ?",
            (cutoff,),
        ).fetchone()
        return [{"value": row[0] if row else 0}]
    finally:
        con.close()


def _geoip_country(ip: str) -> str:
    """Return ISO country code for ip, or '' if unavailable."""
    db = Path(GEOIP_DB)
    if not db.exists():
        return ""
    try:
        import geoip2.database  # type: ignore
        with geoip2.database.Reader(str(db)) as reader:
            rec = reader.city(ip)
            return rec.country.iso_code or ""
    except Exception:  # noqa: BLE001
        return ""


def _query_events_for_grafana(limit: int = 200) -> list[dict]:
    """Return MEDIUM+ alerts enriched with GeoIP country for Grafana history panel."""
    db = Path(EVENT_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(
            """SELECT id, timestamp, alert_type, level, src_ip, dst_ip, description
               FROM events
               WHERE level IN ('MEDIUM','HIGH','CRITICAL')
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        con.close()

    for row in rows:
        row["time"] = int(row["timestamp"] * 1000)  # epoch_ms for Grafana
        ip = row.get("src_ip") or ""
        row["country"] = _geoip_country(ip) if ip else ""
    return rows


def _count_events_by_level(level: str) -> list[dict]:
    """Return count of events at the given threat level as a single Grafana row."""
    db = Path(EVENT_DB)
    if not db.exists():
        return [{"time": int(_time.time() * 1000), "value": 0}]
    con = sqlite3.connect(str(db))
    try:
        cur = con.execute("SELECT COUNT(*) FROM events WHERE level = ?", (level.upper(),))
        count = cur.fetchone()[0]
    finally:
        con.close()
    return [{"time": int(_time.time() * 1000), "value": count}]


def _query_browsing() -> list[dict]:
    """Return local-device browsing activity: src → site, grouped by device + site."""
    db = Path(FLOW_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute("""
            SELECT src_ip,
                   MAX(src_host) AS src_host,
                   COALESCE(domain, dst_ip) AS site,
                   dst_port,
                   COALESCE(SUM(bytes), 0) AS bytes
            FROM flows
            WHERE (   src_ip LIKE '192.168.%'
                   OR src_ip LIKE '10.%'
                   OR src_ip LIKE '172.1_.%'
                   OR src_ip LIKE '172.2_.%'
                   OR src_ip LIKE '172.30.%'
                   OR src_ip LIKE '172.31.%')
              AND dst_ip NOT LIKE '192.168.%'
              AND dst_ip NOT LIKE '10.%'
              AND dst_ip NOT LIKE '172.1_.%'
              AND dst_ip NOT LIKE '172.2_.%'
              AND dst_ip NOT LIKE '172.30.%'
              AND dst_ip NOT LIKE '172.31.%'
              AND dst_ip NOT LIKE '127.%'
              AND dst_ip NOT LIKE '224.%'
              AND dst_ip NOT LIKE '239.%'
              AND dst_ip NOT LIKE '255.%'
            GROUP BY src_ip, COALESCE(domain, dst_ip), dst_port
            ORDER BY bytes DESC
            LIMIT 200
        """)
        return [
            {
                "src_ip": r["src_ip"],
                "device": r["src_host"] or r["src_ip"],
                "site": r["site"] or "—",
                "port": r["dst_port"],
                "bytes": r["bytes"],
            }
            for r in cur.fetchall()
        ]
    finally:
        con.close()


class GrafanaHandler(BaseHTTPRequestHandler):
    """Minimal plain-HTTP handler for Grafana Infinity datasource (localhost only)."""

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data: object, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/inventory.json":
            inv = SERVE_DIR / "inventory.json"
            if inv.exists():
                devices = json.loads(inv.read_text())
                aliases = _load_aliases()
                for d in devices:
                    d["ip_category"] = _classify_ip(d.get("ip", ""))
                    d["label"] = aliases.get(d.get("ip", ""), "")
                self._send_json(devices)
            else:
                self._send_json([])
            return

        if path.startswith("/api/inventory/"):
            inv = SERVE_DIR / "inventory.json"
            devices = json.loads(inv.read_text()) if inv.exists() else []
            counts = {"total": len(devices), "high": 0, "medium": 0, "low": 0}
            for d in devices:
                lvl = (d.get("threat_level") or "").lower()
                if lvl in counts:
                    counts[lvl] += 1
            metric = path.removeprefix("/api/inventory/")
            now_ms = int(_time.time() * 1000)
            if metric == "stats":
                self._send_json([{**counts, "time": now_ms}])
            elif metric in counts:
                self._send_json([{"value": counts[metric]}])
            else:
                self._send_json({"error": "unknown metric"}, 404)
            return

        if path == "/api/flows/browsing":
            try:
                self._send_json(_query_browsing())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/events/history":
            try:
                self._send_json(_query_events_for_grafana())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/events/adult-domains":
            try:
                self._send_json(_query_adult_domains())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path in ("/api/events/count/critical",
                    "/api/events/count/high",
                    "/api/events/count/medium"):
            level = path.split("/")[-1]
            try:
                self._send_json(_count_events_by_level(level))
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/alerts/data-hog":
            try:
                self._send_json(_query_data_hog_count())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path.startswith("/api/flows/"):
            sub = path.removeprefix("/api/flows/")
            try:
                self._send_json(_query_flows_endpoint(sub))
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/grafana-ntfy":
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                payload = {}

            ok, msg = _forward_grafana_ntfy(payload)
            body = json.dumps({"ok": ok, "message": msg}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404, "Not Found")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()


if __name__ == "__main__":
    SERVE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    # Plain HTTP server for Grafana Infinity (localhost only, no TLS)
    grafana_server = HTTPServer(("127.0.0.1", HTTP_PORT), GrafanaHandler)
    threading.Thread(target=grafana_server.serve_forever, daemon=True).start()
    print(f"Grafana HTTP endpoint listening on http://127.0.0.1:{HTTP_PORT}", flush=True)

    print(f"NetWatchM web server listening on https://0.0.0.0:{PORT}", flush=True)
    print("Note: browser will show a self-signed cert warning — click 'Advanced > Proceed'.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
