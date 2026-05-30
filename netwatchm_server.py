#!/usr/bin/env python3
"""NetWatchM web server — serves dashboard and triggers connection reports via API."""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import shutil
import socket
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

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", _config_file()))
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {} if cfg_path.exists() else {}
    except Exception as exc:
        return False, f"Could not read config: {exc}"

    ntfy = raw.get("alerts", {}).get("ntfy", {})
    if not ntfy.get("enabled", False):
        return False, "ntfy is not enabled in config"
    server = ntfy.get("server", "https://ntfy.sh").rstrip("/")
    topic = ntfy.get("topic", "")
    token = os.environ.get("NETWATCHM_NTFY_TOKEN", ntfy.get("token", ""))

    if not topic:
        return False, "ntfy topic is not configured"

    url = f"{server}/{topic}"
    body = b"This is a test notification from NetWatchM. If you see this, push alerts are working!"
    headers = {
        "X-Title": "[TEST] NetWatchM Alert",
        "X-Priority": "3",
        "X-Tags": "white_check_mark",
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

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", _config_file()))
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {} if cfg_path.exists() else {}
    except Exception as exc:
        return False, f"Could not read config: {exc}"

    ntfy = raw.get("alerts", {}).get("ntfy", {})
    if not ntfy.get("enabled", False):
        return False, "ntfy not enabled"
    server = ntfy.get("server", "https://ntfy.sh").rstrip("/")
    topic = ntfy.get("topic", "")
    token = os.environ.get("NETWATCHM_NTFY_TOKEN", ntfy.get("token", ""))
    if not topic:
        return False, "ntfy topic not configured"

    status = payload.get("status", "firing")
    alerts = payload.get("alerts", [])
    title = payload.get("title", "") or f"[{status.upper()}] Grafana Alert"

    # Build message body from alert annotations
    lines: list[str] = []
    for a in alerts:
        ann = a.get("annotations", {})
        summary = (
            ann.get("summary")
            or ann.get("description")
            or a.get("labels", {}).get("alertname", "")
        )
        if summary:
            lines.append(summary)
    body_text = "\n".join(lines) if lines else title

    priority = "4" if status == "firing" else "2"
    tag = "warning" if status == "firing" else "white_check_mark"

    # HTTP headers must be ASCII — strip/replace non-ASCII chars
    safe_title = title.encode("ascii", errors="replace").decode("ascii")

    url = f"{server}/{topic}"
    headers = {
        "X-Title": safe_title,
        "X-Priority": priority,
        "X-Tags": tag,
        "Content-Type": "text/plain",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(
        url, data=body_text.encode(), headers=headers, method="POST"
    )
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


def _load_verified() -> dict[str, bool]:
    """Return {ip: True} for verified devices; empty dict if missing or corrupt."""
    if not VERIFIED_FILE.exists():
        return {}
    try:
        return json.loads(VERIFIED_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_verified(verified: dict[str, bool]) -> None:
    """Persist verified dict atomically to verified.json."""
    VERIFIED_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = VERIFIED_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(verified, indent=2))
    tmp.replace(VERIFIED_FILE)


_FLOW_HISTORY_SQL = """
CREATE TABLE IF NOT EXISTS active_snapshot (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    dst_ip     TEXT NOT NULL,
    dns        TEXT NOT NULL DEFAULT '',
    port       INTEGER,
    protocol   TEXT,
    report_time TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flow_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    dst_ip       TEXT NOT NULL,
    dns          TEXT NOT NULL DEFAULT '',
    port         INTEGER,
    protocol     TEXT,
    last_active  TEXT NOT NULL,
    went_inactive TEXT NOT NULL,
    expires_at   TEXT,
    pinned       INTEGER NOT NULL DEFAULT 0,
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_fh_expires ON flow_history (expires_at);
CREATE INDEX IF NOT EXISTS idx_fh_dst     ON flow_history (dst_ip);
"""
_RETENTION_DAYS = 15  # Session 29 uniform retention (was 30; pinned entries kept forever)


def _fh_conn() -> sqlite3.Connection:
    """Open (and initialise) the flow-history DB."""
    Path(FLOW_HISTORY_DB).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(FLOW_HISTORY_DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(_FLOW_HISTORY_SQL)
    conn.commit()
    return conn


def _update_flow_history(duration_s: int) -> None:
    """Compare latest flows.db snapshot against previous active set.

    Flows that disappeared → inserted into flow_history with a 30-day expiry.
    Flows that reappeared  → removed from flow_history (back to active).
    Unpinned entries older than RETENTION_DAYS are purged automatically.
    """
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    expires = (now + timedelta(days=_RETENTION_DAYS)).isoformat()

    # ── 1. Query flows.db for current active (dst_ip, dns) pairs ─────────────
    current: set[tuple[str, str]] = set()
    current_meta: dict[tuple, dict] = {}
    try:
        cutoff = (now - timedelta(seconds=duration_s + 120)).isoformat()
        with sqlite3.connect(FLOW_DB) as fc:
            for row in fc.execute(
                "SELECT dst_ip, domain, dst_port, protocol FROM flows "
                "WHERE captured_at >= ? AND dst_ip IS NOT NULL",
                (cutoff,),
            ):
                key = (row[0] or "", row[1] or "")
                current.add(key)
                current_meta[key] = {"port": row[2], "protocol": row[3]}
    except Exception:
        return  # flows.db may not exist yet

    with _fh_conn() as hc:
        # ── 2. Previous active snapshot ───────────────────────────────────────
        prev: set[tuple[str, str]] = {
            (r["dst_ip"], r["dns"])
            for r in hc.execute("SELECT dst_ip, dns FROM active_snapshot")
        }

        # ── 3. Went inactive (in prev but not in current) ─────────────────────
        for key in prev - current:
            dst_ip, dns = key
            exists = hc.execute(
                "SELECT id FROM flow_history WHERE dst_ip=? AND dns=?",
                (dst_ip, dns),
            ).fetchone()
            if not exists:
                meta = current_meta.get(key, {})
                hc.execute(
                    "INSERT INTO flow_history "
                    "(dst_ip, dns, port, protocol, last_active, went_inactive, expires_at, pinned) "
                    "VALUES (?,?,?,?,?,?,?,0)",
                    (
                        dst_ip,
                        dns,
                        meta.get("port"),
                        meta.get("protocol"),
                        now.isoformat(),
                        now.isoformat(),
                        expires,
                    ),
                )

        # ── 4. Reactivated (back in current) — remove unpinned history entry ──
        for key in current & prev:
            dst_ip, dns = key
            hc.execute(
                "DELETE FROM flow_history WHERE dst_ip=? AND dns=? AND pinned=0",
                (dst_ip, dns),
            )

        # ── 5. Replace active snapshot ────────────────────────────────────────
        hc.execute("DELETE FROM active_snapshot")
        hc.executemany(
            "INSERT INTO active_snapshot (dst_ip, dns, port, protocol, report_time) "
            "VALUES (?,?,?,?,?)",
            [
                (
                    k[0],
                    k[1],
                    current_meta[k].get("port"),
                    current_meta[k].get("protocol"),
                    now.isoformat(),
                )
                for k in current
            ],
        )

        # ── 6. Purge expired unpinned entries ─────────────────────────────────
        hc.execute(
            "DELETE FROM flow_history WHERE pinned=0 AND expires_at < ?",
            (now.isoformat(),),
        )
        hc.commit()


def _load_suppressed() -> dict:
    """Return {types: [...], updated_at: str|None}."""
    if not SUPPRESSED_FILE.exists():
        return {"types": [], "updated_at": None}
    try:
        return json.loads(SUPPRESSED_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {"types": [], "updated_at": None}


def _save_suppressed(data: dict) -> None:
    SUPPRESSED_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SUPPRESSED_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(SUPPRESSED_FILE)


def _check_read_auth(headers: object) -> bool:
    """Return True if the request may read events. Public if READ_TOKEN not set."""
    if not READ_TOKEN:
        return True
    provided = getattr(headers, "get", lambda *a: "")(  # type: ignore[call-arg]
        "X-Read-Token", ""
    )
    return provided in (READ_TOKEN, ADMIN_TOKEN)


def _classify_ip(ip_str: str) -> str:
    """Return 'Local(IP)' for RFC-1918/loopback/multicast, 'External(IP)' otherwise."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return "Local(IP)"
        return "External(IP)"
    except ValueError:
        return "External(IP)"


import sys as _sys


def _data_dir() -> str:
    if _sys.platform == "win32":
        return os.path.join(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "netwatchm"
        )
    return "/var/lib/netwatchm"


def _config_file() -> str:
    if _sys.platform == "win32":
        return os.path.join(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
            "netwatchm",
            "netwatchm.yaml",
        )
    return "/etc/netwatchm/netwatchm.yaml"


_DD = _data_dir()

SERVE_DIR = Path(os.environ.get("NETWATCHM_SERVE_DIR", _DD))
# Static portal HTML shipped alongside this file (resolved via __file__ so it
# works both in dev — repo root — and deployed at /usr/local/lib/netwatchm/web).
WEB_DIR = Path(
    os.environ.get("NETWATCHM_WEB_DIR", str(Path(__file__).resolve().parent / "web"))
)
PORT = int(os.environ.get("NETWATCHM_PORT", "8765"))
NETWATCHM_CMD = os.environ.get("NETWATCHM_CMD", "netwatchm")
NETWATCHM_CONFIG = os.environ.get("NETWATCHM_CONFIG", _config_file())
DEFAULT_NETWORK = os.environ.get("NETWATCHM_NETWORK", "192.168.1.0/24")
GEOIP_DB = os.environ.get("NETWATCHM_GEOIP_DB", str(Path(_DD) / "GeoLite2-City.mmdb"))
FLOW_DB = os.environ.get("NETWATCHM_FLOW_DB", str(Path(_DD) / "flows.db"))
FLOW_HISTORY_DB = os.environ.get(
    "NETWATCHM_FLOW_HISTORY_DB", str(Path(_DD) / "flow-history.db")
)
EVENT_DB = os.environ.get("NETWATCHM_EVENT_DB", str(Path(_DD) / "events.db"))
FORENSICS_DB = os.environ.get("NETWATCHM_FORENSICS_DB", str(Path(_DD) / "forensics.db"))
ADMIN_TOKEN = os.environ.get("NETWATCHM_ADMIN_TOKEN", "netwatchm-admin")
READ_TOKEN = os.environ.get("NETWATCHM_READ_TOKEN", "")  # empty = public reads allowed
ALIASES_FILE = Path(
    os.environ.get("NETWATCHM_ALIASES_FILE", str(Path(_DD) / "aliases.json"))
)
VERIFIED_FILE = Path(
    os.environ.get("NETWATCHM_VERIFIED_FILE", str(Path(_DD) / "verified.json"))
)
SUPPRESSED_FILE = Path(
    os.environ.get("NETWATCHM_SUPPRESSED_FILE", str(Path(_DD) / "suppressed.json"))
)
REPORTS_DIR = SERVE_DIR / "reports"
REPORTS_MAX = 50  # keep this many archived reports

_lock = threading.Lock()
_state: dict = {
    "status": "idle",  # idle | running | ready | error
    "generated_at": None,
    "duration": None,
    "network": None,
    "error": None,
}

# Investigation state keyed by target IP
_inv_lock = threading.Lock()
_inv_state: dict[str, dict] = {}  # {ip: {status, error}}

# Deep inspect state keyed by target IP
_deep_lock = threading.Lock()
_deep_state: dict[str, dict] = {}  # {ip: {status, error}}

# nmap scan state keyed by target IP
_nmap_lock = threading.Lock()
_nmap_state: dict[str, dict] = {}  # {ip: {status, output, error}}

# pcap analysis state keyed by job_id
_pcap_lock = threading.Lock()
_pcap_state: dict[str, dict] = {}  # {job_id: {status, result, error}}

# Analytics state
_anal_lock = threading.Lock()
_anal_state: dict = {"status": "idle", "error": None, "generated_at": None}


def _run_deep_inspect(target_ip: str, ports: str) -> None:
    """Run netwatchm deep-inspect in a background thread, write HTML to SERVE_DIR."""
    with _deep_lock:
        _deep_state[target_ip] = {"status": "running", "error": None}
    try:
        out_path = SERVE_DIR / f"deep-inspect-{target_ip}.html"
        cmd = [
            NETWATCHM_CMD,
            "--config",
            NETWATCHM_CONFIG,
            "deep-inspect",
            "--target",
            target_ip,
            "--output",
            str(out_path),
        ]
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
                hostname = next(
                    (
                        d.get("hostname", "")
                        for d in inv
                        if d.get("ip") == target_ip and d.get("hostname")
                    ),
                    "",
                )
                if hostname:
                    html = out_path.read_text()
                    html = html.replace(
                        f"Deep Inspect: {target_ip}",
                        f"Deep Inspect: {hostname} ({target_ip})",
                    ).replace(
                        f"Deep Inspect — {target_ip}",
                        f"Deep Inspect — {hostname} ({target_ip})",
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
        cmd = [
            NETWATCHM_CMD,
            "--config",
            NETWATCHM_CONFIG,
            "analytics",
            "--output",
            str(out_path),
            "--db-path",
            FLOW_DB,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "analytics failed")
        with _anal_lock:
            _anal_state.update(
                {
                    "status": "ready",
                    "error": None,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as exc:
        with _anal_lock:
            _anal_state.update({"status": "error", "error": str(exc)})


def _run_investigate(target_ip: str, ports: str) -> None:
    """Run netwatchm investigate in a background thread, write HTML to SERVE_DIR."""
    out_path = SERVE_DIR / f"investigate-{target_ip}.html"
    try:
        cmd = [
            NETWATCHM_CMD,
            "--config",
            NETWATCHM_CONFIG,
            "investigate",
            "--target",
            target_ip,
            "--output",
            str(out_path),
        ]
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


def _run_nmap_scan(target_ip: str, ports: str) -> None:
    """Run nmap against target_ip in a background thread; store output in _nmap_state."""
    import shutil

    with _nmap_lock:
        _nmap_state[target_ip] = {"status": "running", "output": "", "error": None}
    try:
        if not shutil.which("nmap"):
            with _nmap_lock:
                _nmap_state[target_ip] = {
                    "status": "error",
                    "output": "",
                    "error": "nmap not found — install it with: sudo apt install nmap",
                }
            return
        port_arg = ports or "1-1024"
        cmd = ["nmap", "-sV", "--open", "-T4", "-p", port_arg, target_ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + (result.stderr if result.returncode != 0 else "")
        with _nmap_lock:
            _nmap_state[target_ip] = {
                "status": "ready",
                "output": output.strip(),
                "error": None,
            }
    except subprocess.TimeoutExpired:
        with _nmap_lock:
            _nmap_state[target_ip] = {
                "status": "error",
                "output": "",
                "error": "nmap timed out after 120 s",
            }
    except Exception as exc:
        with _nmap_lock:
            _nmap_state[target_ip] = {
                "status": "error",
                "output": "",
                "error": str(exc),
            }


# ---------------------------------------------------------------------------
# Network diagnostics (conntrack, ss, iperf)
# ---------------------------------------------------------------------------


def _run_conntrack(target: str | None = None) -> dict:
    """Get active TCP connections via conntrack, optionally filtered by target IP."""
    try:
        result = subprocess.run(
            ["conntrack", "-L", "-p", "tcp", "--state", "ESTABLISHED"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "conntrack failed"}
        connections = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            src = dst = sport = dport = None
            for p in parts:
                if p.startswith("src="):
                    src = p[4:]
                elif p.startswith("dst="):
                    dst = p[4:]
                elif p.startswith("sport="):
                    sport = p[6:]
                elif p.startswith("dport="):
                    dport = p[6:]
            if src and dst:
                if target and src != target and dst != target:
                    continue
                connections.append(
                    {"src": src, "dst": dst, "sport": sport, "dport": dport}
                )
        return {"connections": connections, "count": len(connections)}
    except FileNotFoundError:
        return {"error": "conntrack not installed"}
    except Exception as exc:
        return {"error": str(exc)}


def _run_tcpstates() -> dict:
    """Get TCP connection states via ss."""
    try:
        result = subprocess.run(
            ["ss", "-tan", "state", "established"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "ss failed"}
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return {"connections": [], "count": 0}
        headers = lines[0].split()
        connections = []
        for line in lines[1:]:
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                connections.append(
                    {
                        "state": parts[0],
                        "local": parts[4],
                        "peer": parts[5] if len(parts) > 5 else "",
                    }
                )
        return {"connections": connections, "count": len(connections)}
    except Exception as exc:
        return {"error": str(exc)}


def _run_iperf_client(target: str, duration: int = 10) -> dict:
    """Run iperf3 client test to target."""
    try:
        result = subprocess.run(
            ["iperf3", "-c", target, "-t", str(duration), "-f", "m", "-P", "4"],
            capture_output=True,
            text=True,
            timeout=duration + 20,
        )
        if result.returncode != 0:
            err = result.stderr.strip()
            if "connect" in err.lower() or "no route" in err.lower():
                return {
                    "error": f"Cannot connect to {target}. Try a public server.",
                    "target": target,
                }
            return {"error": err or "iperf failed", "target": target}
        output = result.stdout
        sender = receiver = None
        for line in output.split("\n"):
            if "sender" in line and "Mbits/sec" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "Mbits/sec" and i > 0:
                        try:
                            sender = float(parts[i - 1])
                        except (ValueError, IndexError):
                            pass
            elif "receiver" in line and "Mbits/sec" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "Mbits/sec" and i > 0:
                        try:
                            receiver = float(parts[i - 1])
                        except (ValueError, IndexError):
                            pass
        return {
            "target": target,
            "sender_mbps": sender,
            "receiver_mbps": receiver,
            "duration": duration,
            "raw": output,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": "Test timed out - target may not be reachable",
            "target": target,
        }
    except FileNotFoundError:
        return {"error": "iperf3 not installed"}
    except Exception as exc:
        return {"error": str(exc)}


def _run_simple_speedtest() -> dict:
    """Simple HTTP-based speed test using public test files."""
    import urllib.request

    test_urls = [
        ("http://speedtest.tele2.net/1MB.zip", 1),
        ("http://speedtest.tele2.net/10MB.zip", 10),
    ]
    results = {"servers": []}
    for url, size_mb in test_urls:
        try:
            import time

            start = time.time()
            req = urllib.request.Request(url, headers={"User-Agent": "NetWatchM/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            elapsed = time.time() - start
            mbps = (len(data) * 8) / (elapsed * 1_000_000)
            results["servers"].append(
                {
                    "url": url,
                    "size_mb": size_mb,
                    "duration_s": round(elapsed, 2),
                    "mbps": round(mbps, 2),
                }
            )
        except Exception as e:
            results["servers"].append({"url": url, "error": str(e)})
    if results["servers"]:
        results["avg_mbps"] = round(
            sum(s.get("mbps", 0) for s in results["servers"]) / len(results["servers"]),
            2,
        )
    return results


def _get_bandwidth_for_ip(ip: str) -> dict:
    """Get bandwidth stats for a specific IP from flow data."""
    import sqlite3

    try:
        conn = sqlite3.connect(str(FLOW_DB))
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 
                SUM(CASE WHEN src_ip = ? THEN bytes ELSE 0 END) as sent,
                SUM(CASE WHEN dst_ip = ? THEN bytes ELSE 0 END) as received,
                COUNT(*) as flow_count
            FROM flows
            WHERE src_ip = ? OR dst_ip = ?
        """,
            (ip, ip, ip, ip),
        )
        row = cur.fetchone()
        conn.close()
        return {
            "ip": ip,
            "sent_bytes": row[0] or 0,
            "received_bytes": row[1] or 0,
            "flow_count": row[2] or 0,
            "sent_mb": round((row[0] or 0) / 1024 / 1024, 2),
            "received_mb": round((row[1] or 0) / 1024 / 1024, 2),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# pcap analysis
# ---------------------------------------------------------------------------

_NINTENDO_KEYWORDS = ("nintendo", "nintend", "wup-", "lp1.", "nasc.", "ctest.")

_PORT_SERVICE = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    1720: "H.323",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


def _oui_lookup(mac: str) -> str:
    """Return vendor string for a MAC address using the Wireshark manuf file."""
    if not mac:
        return ""
    prefix6 = mac[:8].upper()  # e.g. "98:E2:55"
    prefix8 = mac[:11].upper()  # e.g. "98:E2:55:D4"
    manuf_paths = [
        "/usr/share/wireshark/manuf",
        "/usr/share/wireshark/manuf.gz",
    ]
    for mp in manuf_paths:
        p = Path(mp)
        if not p.exists():
            continue
        try:
            if mp.endswith(".gz"):
                import gzip

                text = gzip.open(mp, "rt", errors="ignore").read()
            else:
                text = p.read_text(errors="ignore")
            for line in text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("\t", 2)
                if len(parts) < 2:
                    continue
                if parts[0].upper() in (prefix8, prefix6):
                    return parts[-1].strip()
        except Exception:
            continue
    return ""


def _tshark(pcap_path: str, *args: str, timeout: int = 90) -> str:
    """Run tshark on pcap_path with extra args; return stdout."""
    try:
        r = subprocess.run(
            ["tshark", "-r", pcap_path] + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        raise RuntimeError("tshark not found — install wireshark-cli")


def _analyze_pcap(pcap_path: str) -> dict:
    """Full tshark-based pcap analysis. Returns structured result dict."""
    import collections

    # ── 1. Frame timestamps (summary) ────────────────────────────────────────
    ts_out = _tshark(pcap_path, "-T", "fields", "-e", "frame.time_epoch")
    times = []
    for line in ts_out.splitlines():
        try:
            times.append(float(line.strip()))
        except ValueError:
            pass
    total_packets = len(times)
    duration_s = round(max(times) - min(times), 2) if len(times) > 1 else 0.0

    # ── 2. IP → MAC mapping + packet counts ──────────────────────────────────
    ipmac_out = _tshark(
        pcap_path,
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "eth.src",
        "-E",
        "separator=\t",
    )
    ip_to_mac: dict[str, str] = {}
    ip_pkt_count: dict[str, int] = collections.Counter()
    for line in ipmac_out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0]:
            ip_pkt_count[parts[0]] += 1
            if parts[0] not in ip_to_mac and parts[1]:
                ip_to_mac[parts[0]] = parts[1]

    # ── 3. Open ports (SYN-ACK responses) ────────────────────────────────────
    synack_out = _tshark(
        pcap_path,
        "-Y",
        "tcp.flags.syn==1 and tcp.flags.ack==1",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-E",
        "separator=\t",
    )
    open_ports_by_ip: dict[str, list[int]] = collections.defaultdict(list)
    for line in synack_out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1]:
            try:
                open_ports_by_ip[parts[0]].append(int(parts[1]))
            except ValueError:
                pass

    # ── 4. DNS latency ────────────────────────────────────────────────────────
    dns_out = _tshark(
        pcap_path,
        "-Y",
        "dns",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "dns.id",
        "-e",
        "dns.flags.response",
        "-e",
        "dns.qry.name",
        "-e",
        "dns.a",
        "-E",
        "separator=\t",
    )
    # key: (src_ip, dst_ip, dns_id) → query record
    dns_pending: dict[tuple, dict] = {}
    dns_results: list[dict] = []
    for line in dns_out.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            ts = float(parts[0])
            src, dst = parts[1], parts[2]
            dns_id = parts[3].strip()
            is_resp = parts[4].strip() == "1"
            qname = parts[5].strip()
            a_records = parts[6].strip() if len(parts) > 6 else ""
        except (ValueError, IndexError):
            continue

        if not is_resp:
            # query: key by (client, server, id)
            dns_pending[(src, dst, dns_id)] = {
                "ts": ts,
                "src": src,
                "server": dst,
                "qname": qname,
            }
        else:
            # response: client was dst of query, server was src
            key = (dst, src, dns_id)
            q = dns_pending.pop(key, None)
            if q:
                latency_ms = round((ts - q["ts"]) * 1000, 2)
                nintendo = any(k in q["qname"].lower() for k in _NINTENDO_KEYWORDS)
                resolved = a_records.split(",")[0].strip() if a_records else ""
                dns_results.append(
                    {
                        "query": q["qname"],
                        "src_ip": q["src"],
                        "server_ip": q["server"],
                        "resolved_ip": resolved,
                        "latency_ms": latency_ms,
                        "nintendo": nintendo,
                    }
                )

    dns_results.sort(key=lambda x: x["latency_ms"])

    # ── 5. TLS handshake latency ──────────────────────────────────────────────
    tls_out = _tshark(
        pcap_path,
        "-Y",
        "tls.handshake.type == 1 or tls.handshake.type == 2",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.stream",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.extensions_server_name",
        "-E",
        "separator=\t",
    )
    tls_pending: dict[str, dict] = {}  # tcp.stream → ClientHello info
    tls_results: list[dict] = []
    for line in tls_out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            ts = float(parts[0])
            src, dst = parts[1], parts[2]
            stream = parts[3].strip()
            htype = int(parts[4].strip())
            sni = parts[5].strip() if len(parts) > 5 else ""
        except (ValueError, IndexError):
            continue

        if htype == 1:  # ClientHello
            tls_pending[stream] = {"ts": ts, "src": src, "dst": dst, "sni": sni}
        elif htype == 2:  # ServerHello
            ch = tls_pending.pop(stream, None)
            if ch:
                latency_ms = round((ts - ch["ts"]) * 1000, 2)
                name = ch["sni"] or ch["dst"]
                nintendo = any(k in name.lower() for k in _NINTENDO_KEYWORDS)
                tls_results.append(
                    {
                        "server_name": name,
                        "src_ip": ch["src"],
                        "dst_ip": ch["dst"],
                        "latency_ms": latency_ms,
                        "nintendo": nintendo,
                    }
                )

    tls_results.sort(key=lambda x: x["latency_ms"])

    # ── 6. Build device list ──────────────────────────────────────────────────
    all_ips = set(ip_to_mac) | set(ip_pkt_count)
    devices = []
    for ip in all_ips:
        mac = ip_to_mac.get(ip, "")
        vendor = _oui_lookup(mac)
        ports = sorted(set(open_ports_by_ip.get(ip, [])))
        port_labels = [f"{p}/{_PORT_SERVICE.get(p, 'unknown')}" for p in ports]
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "packet_count": ip_pkt_count.get(ip, 0),
                "open_ports": port_labels,
                "nintendo": "nintendo" in vendor.lower(),
            }
        )
    devices.sort(key=lambda d: d["packet_count"], reverse=True)

    return {
        "summary": {
            "filename": Path(pcap_path).name,
            "total_packets": total_packets,
            "duration_s": duration_s,
        },
        "devices": devices,
        "dns": dns_results,
        "tls": tls_results,
    }


def _run_pcap_job(job_id: str, pcap_path: str) -> None:
    """Background thread: run pcap analysis and store result."""
    try:
        result = _analyze_pcap(pcap_path)
        with _pcap_lock:
            _pcap_state[job_id] = {"status": "ready", "result": result, "error": None}
    except Exception as exc:
        with _pcap_lock:
            _pcap_state[job_id] = {"status": "error", "result": None, "error": str(exc)}
    finally:
        try:
            Path(pcap_path).unlink(missing_ok=True)
        except Exception:
            pass


def _run_report(duration: int, network: str) -> None:
    """Run netwatchm report in background thread, write HTML to SERVE_DIR."""
    html_path = SERVE_DIR / "connection-report.html"
    try:
        result = subprocess.run(
            [
                NETWATCHM_CMD,
                "--config",
                NETWATCHM_CONFIG,
                "report",
                "--duration",
                str(duration),
                "--network",
                network,
                "--output",
                str(html_path),
            ],
            capture_output=True,
            text=True,
            timeout=duration + 60,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "netwatchm report failed")
        now = datetime.now(timezone.utc)
        _archive_report(html_path, now)
        try:
            _update_flow_history(duration)
        except Exception:
            pass  # history update is best-effort
        with _lock:
            _state.update(
                {
                    "status": "ready",
                    "generated_at": now.isoformat(),
                    "error": None,
                }
            )
    except Exception as exc:
        with _lock:
            _state.update(
                {
                    "status": "error",
                    "generated_at": None,
                    "error": str(exc),
                }
            )


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
    rows_html = (
        "\n".join(rows)
        if rows
        else "<tr><td colspan='3' style='color:var(--muted)'>No archived reports yet.</td></tr>"
    )
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
<div style="display:flex;gap:14px;align-items:center;margin-bottom:16px;flex-wrap:wrap">
  <a class="back" href="/connection-report.html" style="margin:0">← Back to Live Report</a>
  <a class="back" href="/inventory.html" style="margin:0">Inventory</a>
  <a class="back" href="/events.html" style="margin:0">Events</a>
  <a class="back" href="/firewall.html" style="margin:0">&#128737; Firewall</a>
  <a href="/ai.html" style="color:#58a6ff;font-size:12px;font-weight:bold;text-decoration:none">&#129302; AI Chat</a>
</div>
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
            return [
                {"ip": r["ip"], "host": r["host"] or r["ip"], "bytes": r["bytes"]}
                for r in cur.fetchall()
            ]
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
            return [
                {
                    "value": row["bytes"],
                    "label": label,
                    "time": int(_time.time() * 1000),
                }
            ]
        if sub == "devices/top/why":
            _PORT_SERVICES = {
                80: "HTTP",
                443: "HTTPS",
                8080: "HTTP-alt",
                8443: "HTTPS-alt",
                22: "SSH",
                3389: "RDP",
                21: "FTP",
                23: "Telnet",
                25: "SMTP",
                587: "SMTP",
                465: "SMTPS",
                53: "DNS",
                123: "NTP",
                161: "SNMP",
                445: "SMB/File Share",
                139: "NetBIOS",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                1194: "OpenVPN",
                51820: "WireGuard",
            }
            # Find top sender
            top = cur.execute("""
                SELECT src_ip, MAX(src_host) AS host, COALESCE(SUM(bytes),0) AS total
                FROM flows GROUP BY src_ip ORDER BY total DESC LIMIT 1
            """).fetchone()
            if not top:
                return []
            top_ip = top["src_ip"]
            rows = cur.execute(
                """
                SELECT dst_ip, MAX(domain) AS domain, dst_port,
                       COALESCE(SUM(bytes),0) AS bytes, COUNT(*) AS conns
                FROM flows WHERE src_ip=?
                GROUP BY dst_ip ORDER BY bytes DESC LIMIT 8
            """,
                (top_ip,),
            ).fetchall()
            result = []
            for r in rows:
                svc = _PORT_SERVICES.get(r["dst_port"], f"port {r['dst_port']}")
                dest = r["domain"] or r["dst_ip"]
                result.append(
                    {
                        "destination": dest,
                        "service": svc,
                        "bytes": r["bytes"],
                        "connections": r["conns"],
                    }
                )
            return result
        if sub == "destinations":
            cur.execute("""
                SELECT dst_ip AS ip, MAX(domain) AS domain,
                       dst_port AS port, COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY dst_ip ORDER BY bytes DESC LIMIT 10
            """)
            return [
                {
                    "ip": r["ip"],
                    "domain": r["domain"] or r["ip"],
                    "port": r["port"],
                    "bytes": r["bytes"],
                }
                for r in cur.fetchall()
            ]
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
                80: "HTTP",
                443: "HTTPS",
                8080: "HTTP-alt",
                8443: "HTTPS-alt",
                22: "SSH",
                3389: "RDP",
                21: "FTP",
                25: "SMTP",
                587: "SMTP",
                53: "DNS",
                123: "NTP",
                445: "SMB",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                1194: "OpenVPN",
                51820: "WireGuard",
            }
            cur.execute("""
                SELECT dst_port, COALESCE(SUM(bytes),0) AS bytes
                FROM flows GROUP BY dst_port ORDER BY bytes DESC LIMIT 12
            """)
            result: dict[str, int] = {}
            for r in cur.fetchall():
                name = _SVC.get(r["dst_port"], f"port {r['dst_port']}")
                result[name] = result.get(name, 0) + r["bytes"]
            return [
                {"app": k, "bytes": v}
                for k, v in sorted(result.items(), key=lambda x: -x[1])
            ]
        if sub == "devices/enriched":
            cur.execute("""
                SELECT src_ip AS ip, MAX(src_host) AS host,
                       COALESCE(SUM(bytes),0) AS total
                FROM flows GROUP BY src_ip ORDER BY total DESC LIMIT 10
            """)
            devices = [dict(r) for r in cur.fetchall()]
            _SVC2 = {
                80: "HTTP",
                443: "HTTPS",
                8080: "HTTP-alt",
                8443: "HTTPS-alt",
                22: "SSH",
                3389: "RDP",
                21: "FTP",
                25: "SMTP",
                587: "SMTP",
                53: "DNS",
                123: "NTP",
                445: "SMB",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                1194: "OpenVPN",
                51820: "WireGuard",
            }
            result2 = []
            for dev in devices:
                top = cur.execute(
                    """
                    SELECT dst_ip, MAX(domain) AS domain, dst_port,
                           COALESCE(SUM(bytes),0) AS bytes
                    FROM flows WHERE src_ip=?
                    GROUP BY dst_ip ORDER BY bytes DESC LIMIT 1
                """,
                    (dev["ip"],),
                ).fetchone()
                dest = ""
                svc = ""
                if top:
                    dest = top["domain"] or top["dst_ip"]
                    svc = _SVC2.get(top["dst_port"], f"port {top['dst_port']}")
                result2.append(
                    {
                        "ip": dev["ip"],
                        "device": dev["host"] or dev["ip"],
                        "traffic": dev["total"],
                        "top_destination": dest,
                        "service": svc,
                    }
                )
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


def _forensics_row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["intel"] = json.loads(d.get("intel_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        d["intel"] = {}
    d.pop("intel_json", None)
    return d


def _query_incidents(
    limit: int = 200, status: str | None = None, ip: str | None = None,
    priority: str | None = None, assignee: str | None = None
) -> list[dict]:
    """Query forensics.db incidents, newest first. Empty list if DB absent."""
    db = Path(FORENSICS_DB)
    if not db.exists():
        return []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if priority:
            clauses.append("priority = ?")
            params.append(priority)
        if assignee:
            clauses.append("assignee = ?")
            params.append(assignee)
        if ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cur = con.execute(
            f"SELECT * FROM incidents {where} ORDER BY created_at DESC LIMIT ?", params
        )
        return [_forensics_row_to_dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()


def _get_incident(incident_id: int) -> dict | None:
    db = Path(FORENSICS_DB)
    if not db.exists():
        return None
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return _forensics_row_to_dict(row) if row else None
    except sqlite3.OperationalError:
        return None
    finally:
        con.close()


def _set_incident_status(incident_id: int, status: str) -> bool:
    if status not in ("open", "reviewed", "false_positive"):
        return False
    return _update_incident_field(incident_id, "status", status)


def _set_incident_priority(incident_id: int, priority: str) -> bool:
    if priority not in ("low", "medium", "high", "critical"):
        return False
    return _update_incident_field(incident_id, "priority", priority)


def _set_incident_assignee(incident_id: int, assignee: str) -> bool:
    return _update_incident_field(incident_id, "assignee", assignee.strip())


def _update_incident_field(incident_id: int, column: str, value: str) -> bool:
    # column is never user-controlled — only the three setters above pass it.
    db = Path(FORENSICS_DB)
    if not db.exists():
        return False
    con = sqlite3.connect(str(db))
    try:
        cur = con.execute(
            f"UPDATE incidents SET {column}=? WHERE id=?", (value, incident_id)
        )
        con.commit()
        return cur.rowcount > 0
    except sqlite3.OperationalError:
        return False
    finally:
        con.close()


_ALERT_LEVEL_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _event_stats_by_ip() -> dict[str, dict]:
    """Per-IP {count, max_level} folded from events.db (best-effort).

    Severity is attributed to the OFFENDER (src_ip) — the scanner, brute-forcer
    or exfiltrating host. The target (dst_ip) accrues an activity count only and
    does NOT inherit the alert's severity band, so a host that was merely
    scanned is not scored as if it were the attacker.
    """
    db = Path(EVENT_DB)
    if not db.exists():
        return {}
    con = sqlite3.connect(str(db))
    out: dict[str, dict] = {}

    def _rec(ip: str) -> dict:
        return out.setdefault(ip, {"count": 0, "max_rank": 0, "max_level": ""})

    try:
        cur = con.execute("SELECT level, src_ip, dst_ip FROM events")
        for level, src, dst in cur.fetchall():
            rank = _ALERT_LEVEL_RANK.get((level or "").upper(), 0)
            if src:
                rec = _rec(src)
                rec["count"] += 1
                if rank > rec["max_rank"]:
                    rec["max_rank"] = rank
                    rec["max_level"] = (level or "").upper()
            if dst and dst != src:
                _rec(dst)["count"] += 1
    except sqlite3.OperationalError:
        return {}
    finally:
        con.close()
    return out


def _intel_verdict_by_ip() -> dict[str, str]:
    """Worst threat-intel verdict per IP from forensics.db incidents."""
    db = Path(FORENSICS_DB)
    if not db.exists():
        return {}
    order = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}
    con = sqlite3.connect(str(db))
    out: dict[str, str] = {}
    try:
        cur = con.execute("SELECT src_ip, dst_ip, verdict FROM incidents")
        for src, dst, verdict in cur.fetchall():
            v = (verdict or "unknown").lower()
            for ip in (src, dst):
                if not ip:
                    continue
                if order.get(v, 0) > order.get(out.get(ip, "unknown"), 0):
                    out[ip] = v
    except sqlite3.OperationalError:
        return {}
    finally:
        con.close()
    return out


def _is_assessable_ip(ip_str: str) -> bool:
    """True for real hosts (private or public). Excludes multicast, broadcast,
    loopback, link-local, and unspecified pseudo-addresses — these are not
    assets and would pollute the risk register with ephemeral ports."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (ip.is_multicast or ip.is_loopback or ip.is_link_local
            or ip.is_unspecified or ip.is_reserved):
        return False
    if ip.version == 4 and str(ip).endswith(".255"):
        return False
    return True


def _drop_scan_runs(ports: list[int], run_threshold: int = 4) -> list[int]:
    """Drop maximal runs of >= run_threshold consecutive ports.

    A sequential block like 1,2,3,4,5,6,7,8 is a port-scan signature recorded
    in ports_observed, not real listening services. Short adjacent groups
    (e.g. NetBIOS 137-139, DHCP 67-68) are well under the threshold and kept.
    """
    s = sorted(set(ports))
    keep: list[int] = []
    i, n = 0, len(s)
    while i < n:
        j = i
        while j + 1 < n and s[j + 1] == s[j] + 1:
            j += 1
        run = s[i:j + 1]
        if len(run) < run_threshold:
            keep.extend(run)
        i = j + 1
    return keep


def _build_grc_assessment() -> dict:
    """Score every inventoried device and run the CIS control assessment."""
    from netwatchm.grc import assess_controls, assess_device

    inv_path = Path(EVENT_DB).parent / "inventory.json"
    records: list[dict] = []
    if inv_path.exists():
        try:
            records = json.loads(inv_path.read_text())
        except (json.JSONDecodeError, OSError):
            records = []

    aliases = _load_aliases()
    verified = _load_verified()
    ev_stats = _event_stats_by_ip()
    intel = _intel_verdict_by_ip()

    # The sensor host monitors others; its own ports_observed is polluted by the
    # outbound probes/nmap it runs, so it would be risk-scored for services it
    # does not actually expose. Exclude it from the register (it is the camera,
    # not a room being inspected). Override the detected IP with NETWATCHM_SERVER_IP.
    monitor_ip = _get_local_ip()

    devices: list[dict] = []
    for r in records:
        ip = r.get("ip", "")
        if not ip or not _is_assessable_ip(ip):
            continue
        if ip == monitor_ip:
            continue
        # ports_observed tracks ALL destination ports ever seen, including
        # ephemeral source ports from this device's outbound flows. Those are
        # not exposed services — keep only well-known (<1024) + recognized
        # named-service ports so the exposure score reflects real surface.
        ports = _drop_scan_runs([
            p for p in (r.get("ports_observed", []) or [])
            if p < 1024 or p in _PORT_NAMES
        ])
        is_ext = _classify_ip(ip).startswith("External")
        stats = ev_stats.get(ip, {})
        risk = assess_device(
            ip=ip,
            ports=ports,
            alert_count=stats.get("count", 0),
            max_alert_level=stats.get("max_level"),
            intel_verdict=intel.get(ip, "unknown"),
            verified=bool(verified.get(ip)),
            is_external=is_ext,
            label=aliases.get(ip, ""),
        )
        devices.append({
            "ip": ip,
            "label": aliases.get(ip, ""),
            "verified": bool(verified.get(ip)),
            "owned": not is_ext,
            "ports": list(ports),
            "risk": risk.to_dict(),
        })

    devices.sort(key=lambda d: d["risk"]["score"], reverse=True)
    controls = assess_controls(
        devices,
        events_present=bool(ev_stats),
        monitor_active=True,
    )
    return {"devices": devices, **controls}


def _query_events_paged(
    limit: int = 50,
    offset: int = 0,
    alert_type: str | None = None,
    level: str | None = None,
    ip: str | None = None,
    search: str | None = None,
) -> dict:
    """Paginated query — returns {events, total, offset, limit}."""
    db = Path(EVENT_DB)
    if not db.exists():
        return {"events": [], "total": 0, "offset": offset, "limit": limit}
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
        if search:
            term = f"%{search}%"
            clauses.append(
                "(alert_type LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR description LIKE ?)"
            )
            params.extend([term, term, term, term])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        total = con.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[
            0
        ]
        cur = con.execute(
            f"SELECT id, timestamp, alert_type, level, src_ip, dst_ip, description "
            f"FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return {
            "events": [dict(r) for r in cur.fetchall()],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
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
            hostname = next(
                (
                    d.get("hostname", "")
                    for d in inv
                    if d.get("ip") == ip and d.get("hostname")
                ),
                "",
            )
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


_AI_SYSTEM_PROMPT = """\
You are a network security analyst assistant integrated with NetWatchM, \
a real-time network monitoring system. You have access to live data from \
the local network: device inventory (IP, MAC, hostname, vendor), \
first/last seen timestamps, service ports, security alert history, \
and flow statistics.

IMPORTANT — understand the data model before analyzing:
- "Service ports" = destination ports (< 32768) this device has sent traffic TO. \
  These represent services the device actively uses or hosts. \
  Ephemeral/dynamic ports (32768–60999) are EXCLUDED — they are normal outbound \
  connection ports, not services.
- A high service-port count is NOT automatically a threat — a monitoring server \
  or gateway naturally contacts many services.
- "Flow history" shows actual destination ports used in the last 72 h with byte \
  counts — use this as the primary indicator of active service usage.
- Threat level is set by NetWatchM detectors (port scan, brute force, etc.), \
  NOT by port count alone.
- "Alert policy" shows which alert types are currently suppressed (silenced) and \
  which IPs are globally whitelisted. A whitelisted IP will NEVER generate alerts — \
  this is intentional. A suppressed alert type is silenced across all devices — \
  flag this if it seems risky (e.g. BRUTE_FORCE suppressed).
- "Unidentified devices" = devices with no resolved hostname AND no vendor in the \
  OUI database. These are the highest-priority unknowns — treat them as suspicious \
  until the user can physically verify what they are.

Your role:
- Describe devices clearly: identity, likely role, activity patterns
- Analyze active service ports: name the service, explain what it does, flag concerns
- Use flow history as the strongest signal for what a device is actually doing
- Highlight real anomalies: known-malicious ports, unexpected services, alert patterns
- Infer likely device type from port profile and vendor info
- Be concise but thorough; use bullet points for structured data
- Ground your analysis in the provided data — do not speculate beyond it
- Do NOT raise alarms based on port count alone

When asked about a specific device lead with: identity summary, threat posture, \
active service analysis (from flow history first, then service ports), \
risk assessment, and recommended actions.
Tone: professional, clear, security-focused.\
"""

# Ephemeral port range on Linux (from /proc/sys/net/ipv4/ip_local_port_range)
_EPHEMERAL_PORT_MIN = 32768

_PORT_NAMES: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH/SFTP", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD-Print", 587: "SMTP-Submit", 631: "IPP-Print", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL", 1883: "MQTT",
    2049: "NFS", 2375: "Docker-HTTP", 2376: "Docker-TLS", 3000: "HTTP-Node",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8765: "NetWatchM",
    8766: "NetWatchM-Graf", 9090: "Prometheus", 9100: "Node-Exporter",
    27017: "MongoDB", 51820: "WireGuard",
}


def _fmt_bytes(n: int) -> str:
    from netwatchm.util import format_bytes

    return format_bytes(
        n, units=("B", "KB", "MB", "GB", "TB"), overflow="PB", float_div=True
    )


def _build_device_context(ip: str) -> str:
    """Build a structured text block describing a device for the AI."""
    lines: list[str] = []

    # --- Inventory ---
    inv_path = Path(EVENT_DB).parent / "inventory.json"
    device: dict = {}
    if inv_path.exists():
        try:
            records = json.loads(inv_path.read_text())
            for rec in records:
                if rec.get("ip") == ip:
                    device = rec
                    break
        except (json.JSONDecodeError, OSError):
            pass

    aliases: dict = {}
    alias_path = ALIASES_FILE
    if alias_path.exists():
        try:
            aliases = json.loads(alias_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    verified: dict = {}
    ver_path = VERIFIED_FILE
    if ver_path.exists():
        try:
            verified = json.loads(ver_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    alias = aliases.get(ip, "")
    display_name = alias or device.get("hostname") or ip

    lines.append("=== DEVICE IDENTITY ===")
    lines.append(f"IP Address  : {ip}")
    lines.append(f"Display Name: {display_name}")
    lines.append(f"Hostname    : {device.get('hostname') or 'not resolved'}")
    lines.append(f"Alias       : {alias or 'none'}")
    mac = device.get("mac") or ""
    lines.append(f"MAC Address : {mac or 'unknown'}")
    vendor = device.get("vendor") or ""
    if not vendor and mac:
        try:
            from netwatchm.inventory import oui_lookup as _oui
            vendor = _oui.lookup(mac) or ""
        except Exception:
            pass
    lines.append(f"Vendor      : {vendor or 'unknown (not in OUI database)'}")
    lines.append(f"Verified    : {'yes' if verified.get(ip) else 'no'}")
    lines.append(f"Threat Level: {device.get('threat_level', 'unknown')}")
    lines.append(f"First Seen  : {device.get('first_seen', 'unknown')}")
    lines.append(f"Last Seen   : {device.get('last_seen', 'unknown')}")
    lines.append(f"Bytes Sent  : {_fmt_bytes(device.get('bytes_sent', 0))}")
    lines.append(f"Bytes Recv  : {_fmt_bytes(device.get('bytes_received', 0))}")

    all_ports = sorted(device.get("ports_observed", []))
    # Only show ports that are recognized named services (in _PORT_NAMES).
    # ports_observed tracks ALL destination ports ever seen — including ports this
    # device contacted on other devices while monitoring. Filtering to named services
    # removes the noise and shows only meaningful service interactions.
    known_ports = [p for p in all_ports if p in _PORT_NAMES]
    ephemeral_count = len([p for p in all_ports if p >= _EPHEMERAL_PORT_MIN])
    unknown_count = len(all_ports) - len(known_ports) - ephemeral_count
    lines.append(
        f"\n=== RECOGNIZED SERVICE PORTS ({len(known_ports)} named services "
        f"| {ephemeral_count} ephemeral excluded | {unknown_count} unrecognized excluded) ==="
    )
    lines.append("  Note: these are ports this device communicated with — not necessarily local listeners.")
    for p in known_ports:
        name = _PORT_NAMES[p]
        lines.append(f"  {p:>6}  {name}")

    # --- Events ---
    try:
        con = sqlite3.connect(EVENT_DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT timestamp, alert_type, level, src_ip, dst_ip, description "
            "FROM events WHERE src_ip=? OR dst_ip=? ORDER BY timestamp DESC LIMIT 20",
            (ip, ip),
        ).fetchall()
        con.close()
        lines.append(f"\n=== SECURITY ALERTS ({len(rows)}) ===")
        for r in rows:
            ts = datetime.fromtimestamp(r["timestamp"]).strftime("%m-%d %H:%M")
            direction = "→" if r["src_ip"] == ip else "←"
            peer = r["dst_ip"] if r["src_ip"] == ip else r["src_ip"]
            lines.append(
                f"  [{ts}] [{r['level']:<8}] {r['alert_type']:<20} {direction} {peer or '?'}"
            )
            lines.append(f"    {r['description']}")
        if not rows:
            lines.append("  No alerts recorded")
    except Exception:
        lines.append("\n=== SECURITY ALERTS ===\n  (unavailable)")

    # --- Flows ---
    try:
        fc = sqlite3.connect(FLOW_DB)
        fc.row_factory = sqlite3.Row
        flow_rows = fc.execute(
            """SELECT dst_port, protocol, MAX(domain) AS domain,
                      COUNT(*) AS flows, COALESCE(SUM(bytes),0) AS bytes
               FROM flows WHERE src_ip=? AND dst_port IS NOT NULL
               GROUP BY dst_port ORDER BY bytes DESC LIMIT 15""",
            (ip,),
        ).fetchall()
        fc.close()
        if flow_rows:
            lines.append("\n=== PORT USAGE (flow history, 72h) ===")
            lines.append(f"{'Port':<7} {'Service':<18} {'Proto':<8} {'Flows':<7} {'Bytes':<12} Domain")
            for r in flow_rows:
                name = _PORT_NAMES.get(r["dst_port"], f"port-{r['dst_port']}")
                lines.append(
                    f"  {r['dst_port']:<7} {name:<18} {r['protocol'] or '?':<8} "
                    f"{r['flows']:<7} {_fmt_bytes(r['bytes']):<12} {r['domain'] or ''}"
                )
    except Exception:
        pass

    lines.append(_build_policy_context())

    return "\n".join(lines)


def _build_policy_context() -> str:
    """Build a text block describing active alert suppression and IP whitelist."""
    lines: list[str] = []

    # --- Suppressed alert types ---
    suppressed = _load_suppressed().get("types", [])
    lines.append("\n=== ALERT POLICY ===")
    if suppressed:
        lines.append(f"Suppressed alert types ({len(suppressed)}) — these alerts are silenced and will NOT appear in events:")
        for t in suppressed:
            lines.append(f"  - {t}")
    else:
        lines.append("Suppressed alert types: none (all alert types are active)")

    # --- IP whitelist from config YAML ---
    try:
        import yaml  # type: ignore
        cfg_path = Path(NETWATCHM_CONFIG)
        if cfg_path.exists():
            raw = yaml.safe_load(cfg_path.read_text()) or {}
            wl = raw.get("whitelist", {})
            wl_enabled = wl.get("enabled", False)
            wl_ips = wl.get("ips", [])
            det_wl = raw.get("detector_whitelist", {})
            if wl_enabled and wl_ips:
                lines.append(f"\nGlobal IP whitelist (enabled) — {len(wl_ips)} IPs exempt from ALL alerts:")
                for ip_entry in wl_ips:
                    lines.append(f"  - {ip_entry}")
            elif wl_ips:
                lines.append(f"\nGlobal IP whitelist (disabled) — {len(wl_ips)} IPs defined but whitelist is off")
            else:
                lines.append("\nGlobal IP whitelist: not configured")
            if det_wl:
                lines.append(f"\nPer-type detector whitelist — IPs exempt from specific alert types:")
                for alert_type, ips in det_wl.items():
                    if ips:
                        lines.append(f"  {alert_type}: {', '.join(str(i) for i in ips)}")
    except Exception:
        lines.append("\nWhitelist: (could not read config)")

    # --- Unknown device report ---
    try:
        inv_path = Path(EVENT_DB).parent / "inventory.json"
        if inv_path.exists():
            records = json.loads(inv_path.read_text())
            try:
                from netwatchm.inventory import oui_lookup as _oui
                _oui_available = True
            except Exception:
                _oui_available = False

            unidentified = []
            for r in records:
                mac = r.get("mac") or ""
                vendor = r.get("vendor") or ""
                if not vendor and mac and _oui_available:
                    try:
                        from netwatchm.inventory import oui_lookup as _oui2
                        vendor = _oui2.lookup(mac) or ""
                    except Exception:
                        pass
                hostname = r.get("hostname") or ""
                no_vendor = not vendor
                no_hostname = not hostname
                if no_vendor and no_hostname:
                    unidentified.append((r.get("ip", "?"), mac or "no MAC", r.get("last_seen", "?")))

            if unidentified:
                lines.append(f"\nUnidentified devices (no hostname + no vendor) — {len(unidentified)} device(s) need investigation:")
                for dev_ip, dev_mac, last in unidentified:
                    lines.append(f"  {dev_ip:<18} MAC: {dev_mac:<20} Last seen: {str(last)[:19]}")
            else:
                lines.append("\nUnidentified devices: none — all devices have hostname or vendor info")
    except Exception:
        pass

    return "\n".join(lines)


def _build_network_context() -> str:
    """Build a summary of all devices for network-wide AI queries."""
    inv_path = Path(EVENT_DB).parent / "inventory.json"
    if not inv_path.exists():
        return "No inventory data available."
    try:
        records = json.loads(inv_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "Could not read inventory."
    lines = [f"=== NETWORK INVENTORY ({len(records)} devices) ===",
             f"{'IP':<18} {'Hostname':<25} {'MAC':<19} {'Vendor':<20} {'Threat':<10} {'Svcs':<6} Last Seen",
             "-" * 110]
    for r in sorted(records, key=lambda x: x.get("ip", "")):
        # Count only recognized named-service ports (not ephemeral or unknown)
        svc_count = sum(1 for p in r.get("ports_observed", []) if p in _PORT_NAMES)
        lines.append(
            f"{r.get('ip',''):<18} {(r.get('hostname') or '?')[:24]:<25} "
            f"{(r.get('mac') or '?'):<19} {(r.get('vendor') or 'unknown')[:19]:<20} "
            f"{r.get('threat_level','LOW'):<10} {svc_count:<6} "
            f"{(r.get('last_seen') or '')[:19]}"
        )
    lines.append(_build_policy_context())
    return "\n".join(lines)


# AI conversation sessions keyed by session_id
_ai_sessions: dict[str, list[dict]] = {}
_ai_lock = threading.Lock()


def _ai_ask(query: str, focus_ip: str | None = None, session_id: str | None = None) -> str:
    """Call OpenAI with network context and return the reply text."""
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return "OpenAI package not installed. Run: pip install openai"

    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return "OPENAI_API_KEY not set. Add it to the server environment."

    client = OpenAI(api_key=api_key)

    # Build context
    if focus_ip:
        context = _build_device_context(focus_ip)
    else:
        context = _build_network_context()

    # Manage session history
    with _ai_lock:
        if session_id not in _ai_sessions:
            _ai_sessions[session_id or "default"] = []
        history = _ai_sessions.get(session_id or "default", [])

    if not history or focus_ip:
        user_content = f"Network context:\n\n{context}\n\n---\n\n{query}"
    else:
        user_content = query

    history.append({"role": "user", "content": user_content})

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=2048,
            messages=[{"role": "system", "content": _AI_SYSTEM_PROMPT}] + history,
        )
        reply = response.choices[0].message.content
    except Exception as exc:
        reply = f"AI error: {exc}"

    history.append({"role": "assistant", "content": reply})

    # Trim history to last 20 messages to prevent runaway context
    with _ai_lock:
        _ai_sessions[session_id or "default"] = history[-20:]

    return reply


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

    def _send_static_page(self, filename: str) -> None:
        """Serve a static portal HTML file from WEB_DIR with no-cache headers."""
        path = WEB_DIR / filename
        if not path.exists():
            self.send_error(404, "Not Found")
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

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

        if path == "/api/auth/whoami":
            admin_tok = self.headers.get("X-Admin-Token", "")
            read_tok  = self.headers.get("X-Read-Token", "")
            if admin_tok and admin_tok == ADMIN_TOKEN:
                self._send_json({"role": "admin"})
            elif not READ_TOKEN or read_tok in (READ_TOKEN, ADMIN_TOKEN):
                self._send_json({"role": "reader"})
            else:
                self._send_json({"role": "guest"}, 403)
            return

        if path == "/api/events":
            if not _check_read_auth(self.headers):
                self._send_json(
                    {"error": "unauthorized — set X-Read-Token header"}, 401
                )
                return
            qs = parse_qs(parsed.query)
            try:
                if "offset" in qs:
                    result = _query_events_paged(
                        limit=min(int(qs.get("limit", ["50"])[0]), 500),
                        offset=max(int(qs.get("offset", ["0"])[0]), 0),
                        alert_type=qs.get("type", [None])[0] or None,
                        level=qs.get("level", [None])[0] or None,
                        ip=qs.get("ip", [None])[0] or None,
                        search=qs.get("q", [None])[0] or None,
                    )
                    self._send_json(result)
                else:
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
            if not _check_read_auth(self.headers):
                self._send_json(
                    {"error": "unauthorized — set X-Read-Token header"}, 401
                )
                return
            try:
                self._send_json(_query_event_types())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/aliases":
            self._send_json(_load_aliases())
            return

        if path == "/api/verified":
            self._send_json(_load_verified())
            return

        if path == "/api/ip-lookup":
            ip = parse_qs(parsed.query).get("ip", [""])[0].strip()
            if not ip:
                self._send_json({"error": "ip required"}, 400)
                return
            try:
                self._send_json(_ip_lookup(ip))
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/nmap/status":
            target = parse_qs(parsed.query).get("target", [""])[0].strip()
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            with _nmap_lock:
                state = _nmap_state.get(
                    target, {"status": "unknown", "output": "", "error": None}
                )
            self._send_json(state)
            return

        if path == "/api/connections/status":
            # Return all inventory devices with live ping status
            inv_file = SERVE_DIR / "inventory.json"
            devices = json.loads(inv_file.read_text()) if inv_file.exists() else []

            def _ping(ip: str) -> tuple[bool, float | None]:
                try:
                    r = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )
                    if r.returncode != 0:
                        return False, None
                    for line in r.stdout.splitlines():
                        if "time=" in line:
                            try:
                                ms = float(line.split("time=")[1].split()[0])
                                return True, ms
                            except (ValueError, IndexError):
                                pass
                    return True, None
                except Exception:
                    return False, None

            import concurrent.futures

            result = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(_ping, d.get("ip", "")): d for d in devices}
                for fut, dev in futures.items():
                    connected, latency_ms = fut.result()
                    result.append(
                        {
                            "ip": dev.get("ip", ""),
                            "hostname": dev.get("hostname") or dev.get("ip", ""),
                            "connected": connected,
                            "latency_ms": latency_ms,
                            "last_seen": dev.get("last_seen", ""),
                        }
                    )
            result.sort(key=lambda x: (not x["connected"], x["ip"]))
            self._send_json(result)
            return

        if path.startswith("/api/connections/status/"):
            target = path.removeprefix("/api/connections/status/").strip()
            try:
                r = subprocess.run(
                    ["ping", "-c", "3", "-W", "2", target],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                connected = r.returncode == 0
                latency_ms = None
                avg_latency_ms = None
                if connected:
                    for line in r.stdout.splitlines():
                        if "rtt" in line and "/" in line:
                            parts = line.split("=")[-1].strip().split("/")
                            try:
                                latency_ms = float(parts[0])
                                avg_latency_ms = float(parts[1])
                            except (ValueError, IndexError):
                                pass
                self._send_json(
                    {
                        "connected": connected,
                        "target": target,
                        "latency_ms": latency_ms,
                        "avg_latency_ms": avg_latency_ms,
                    }
                )
            except Exception as exc:
                self._send_json(
                    {"connected": False, "target": target, "error": str(exc)}
                )
            return

        # Network diagnostics endpoints
        if path == "/api/diagnostics/conntrack":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            result = _run_conntrack(target if target else None)
            self._send_json(result)
            return

        if path == "/api/diagnostics/tcpstates":
            result = _run_tcpstates()
            self._send_json(result)
            return

        if path == "/api/diagnostics/iperf":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            duration = int(qs.get("duration", ["10"])[0])
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            result = _run_iperf_client(target, duration)
            self._send_json(result)
            return

        if path.startswith("/api/diagnostics/bandwidth/"):
            ip = path.removeprefix("/api/diagnostics/bandwidth/").strip()
            if not ip:
                self._send_json({"error": "ip required"}, 400)
                return
            result = _get_bandwidth_for_ip(ip)
            self._send_json(result)
            return

        if path == "/api/diagnostics/speedtest":
            result = _run_simple_speedtest()
            self._send_json(result)
            return

        if path == "/api/deep-inspect/history":
            files = sorted(
                SERVE_DIR.glob("deep-inspect-*.html"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            result = []
            for f in files[:20]:
                ip = f.name.removeprefix("deep-inspect-").removesuffix(".html")
                result.append(
                    {
                        "capture_id": ip,
                        "target_ip": ip,
                        "timestamp": int(f.stat().st_mtime * 1000),
                        "report_url": f"/{f.name}",
                    }
                )
            self._send_json(result)
            return

        if path.startswith("/api/deep-inspect/analyze/"):
            target = path.removeprefix("/api/deep-inspect/analyze/").strip()
            try:
                # Flow stats from flows.db
                packet_count = 0
                byte_count = 0
                bandwidth_mbps = 0.0
                protocols: list[dict] = []
                db = Path(FLOW_DB)
                if db.exists():
                    con = sqlite3.connect(str(db))
                    con.row_factory = sqlite3.Row
                    try:
                        cur = con.cursor()
                        row = cur.execute(
                            "SELECT COALESCE(SUM(packets),0) AS p, COALESCE(SUM(bytes),0) AS b "
                            "FROM flows WHERE src_ip=? OR dst_ip=?",
                            (target, target),
                        ).fetchone()
                        packet_count = row["p"]
                        byte_count = row["b"]
                        if byte_count > 0:
                            bandwidth_mbps = round(byte_count * 8 / 1_000_000, 2)
                        proto_rows = cur.execute(
                            "SELECT COALESCE(protocol,'Other') AS protocol, "
                            "COUNT(*) AS cnt FROM flows "
                            "WHERE src_ip=? OR dst_ip=? GROUP BY protocol ORDER BY cnt DESC",
                            (target, target),
                        ).fetchall()
                        total_flows = sum(r["cnt"] for r in proto_rows) or 1
                        protocols = [
                            {
                                "protocol": r["protocol"],
                                "count": r["cnt"],
                                "percentage": round(r["cnt"] * 100 / total_flows, 1),
                            }
                            for r in proto_rows
                        ]
                    finally:
                        con.close()

                # Recent alerts from events.db
                alerts: list[str] = []
                findings: list[str] = []
                edb = Path(EVENT_DB)
                if edb.exists():
                    econ = sqlite3.connect(str(edb))
                    econ.row_factory = sqlite3.Row
                    try:
                        for er in econ.execute(
                            "SELECT alert_type, level, description FROM events "
                            "WHERE src_ip=? ORDER BY timestamp DESC LIMIT 10",
                            (target,),
                        ).fetchall():
                            alerts.append(f"[{er['level']}] {er['alert_type']}")
                            if er["description"]:
                                findings.append(er["description"])
                    finally:
                        econ.close()

                # Latency via ping
                latency_ms = None
                hop_count = None
                pr = subprocess.run(
                    ["ping", "-c", "3", "-W", "2", target],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if pr.returncode == 0:
                    for line in pr.stdout.splitlines():
                        if "rtt" in line and "/" in line:
                            parts = line.split("=")[-1].strip().split("/")
                            try:
                                latency_ms = float(parts[1])
                            except (ValueError, IndexError):
                                pass

                if not findings:
                    findings = ["No threat events recorded for this device"]

                self._send_json(
                    {
                        "target": target,
                        "packet_count": packet_count,
                        "byte_count": byte_count,
                        "bandwidth_mbps": bandwidth_mbps,
                        "hop_count": hop_count,
                        "latency_ms": latency_ms,
                        "alerts": alerts or ["No alerts for this device"],
                        "findings": findings,
                        "protocols": protocols,
                        "report_url": f"/deep-inspect-{target}.html"
                        if (SERVE_DIR / f"deep-inspect-{target}.html").exists()
                        else None,
                    }
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/flow-history":
            try:
                with _fh_conn() as hc:
                    rows = hc.execute(
                        "SELECT id, dst_ip, dns, port, protocol, "
                        "last_active, went_inactive, expires_at, pinned, note "
                        "FROM flow_history ORDER BY went_inactive DESC"
                    ).fetchall()
                self._send_json([dict(r) for r in rows])
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/history.html":
            self._send_static_page("history.html")
            return

        if path == "/api/pcap/status":
            job_id = parse_qs(parsed.query).get("id", [""])[0].strip()
            if not job_id:
                self._send_json({"error": "id required"}, 400)
                return
            with _pcap_lock:
                state = _pcap_state.get(
                    job_id, {"status": "unknown", "result": None, "error": None}
                )
            self._send_json(state)
            return

        if path == "/pcap.html":
            self._send_static_page("pcap.html")
            return

        if path == "/api/suppressed":
            self._send_json(_load_suppressed())
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
            self._send_static_page("events.html")
            return

        if path == "/incidents.html":
            self._send_static_page("incidents.html")
            return

        if path == "/grc.html":
            self._send_static_page("grc.html")
            return

        if path == "/api/grc":
            try:
                self._send_json(_build_grc_assessment())
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/incidents":
            qs = parse_qs(parsed.query)
            try:
                self._send_json({"incidents": _query_incidents(
                    limit=int(qs.get("limit", ["200"])[0]),
                    status=(qs.get("status", [""])[0] or None),
                    ip=(qs.get("ip", [""])[0] or None),
                    priority=(qs.get("priority", [""])[0] or None),
                    assignee=(qs.get("assignee", [""])[0] or None),
                )})
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
            return

        if path.startswith("/api/incidents/") and path.endswith("/pcap"):
            try:
                inc_id = int(path.removeprefix("/api/incidents/").removesuffix("/pcap"))
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
                return
            incident = _get_incident(inc_id)
            pcap_path = (incident or {}).get("pcap_path", "")
            # Only serve a path that the DB recorded — never a client-supplied path.
            if not incident or not pcap_path or not Path(pcap_path).is_file():
                self.send_error(404, "No pcap for this incident")
                return
            data = Path(pcap_path).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header(
                "Content-Disposition",
                f"attachment; filename=incident-{inc_id}.pcap",
            )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path.startswith("/api/incidents/"):
            try:
                inc_id = int(path.removeprefix("/api/incidents/"))
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
                return
            incident = _get_incident(inc_id)
            if incident is None:
                self._send_json({"error": "not found"}, 404)
                return
            self._send_json(incident)
            return

        if path == "/cert":
            try:
                cert_bytes = CERT_FILE.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header(
                    "Content-Disposition", "attachment; filename=netwatchm.crt"
                )
                self.send_header("Content-Length", str(len(cert_bytes)))
                self.end_headers()
                self.wfile.write(cert_bytes)
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/ai.html":
            self._send_file(SERVE_DIR / "ai.html")
            return

        if path == "/inventory.html":
            self._send_static_page("inventory.html")
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

        # Agent (Phase 2) — read-only visibility into recent decisions/whitelist
        if path == "/api/agent/decisions":
            try:
                from netwatchm.agent.audit import AuditLog, DEFAULT_AUDIT_DB
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                with AuditLog(DEFAULT_AUDIT_DB) as audit:
                    self._send_json({"decisions": audit.recent_decisions(limit=limit)})
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
            return

        if path.startswith("/api/agent/decisions/") and path.endswith("/calls"):
            try:
                d_id = int(path.removeprefix("/api/agent/decisions/").removesuffix("/calls"))
                from netwatchm.agent.audit import AuditLog, DEFAULT_AUDIT_DB
                with AuditLog(DEFAULT_AUDIT_DB) as audit:
                    self._send_json({"calls": audit.calls_for_decision(d_id)})
            except ValueError:
                self._send_json({"error": "invalid decision id"}, 400)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/agent/whitelist":
            try:
                from netwatchm.agent.state import AgentWhitelistStore
                self._send_json({"entries": AgentWhitelistStore().active_entries()})
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
            return

        # Agent (Phase 5) — active firewall blocks
        if path == "/api/agent/blocks":
            try:
                from netwatchm.agent.firewall import FirewallStore
                self._send_json({"entries": FirewallStore().active_entries()})
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
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

        if parsed.path.startswith("/api/incidents/") and parsed.path.endswith("/status"):
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                self._send_json({"error": "unauthorized"}, 401)
                return
            try:
                inc_id = int(
                    parsed.path.removeprefix("/api/incidents/").removesuffix("/status")
                )
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            status = (body.get("status") or "").strip()
            if not _set_incident_status(inc_id, status):
                self._send_json({"error": "invalid status or id"}, 400)
                return
            self._send_json({"ok": True, "id": inc_id, "status": status})
            return

        if parsed.path.startswith("/api/incidents/") and parsed.path.endswith("/triage"):
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                self._send_json({"error": "unauthorized"}, 401)
                return
            try:
                inc_id = int(
                    parsed.path.removeprefix("/api/incidents/").removesuffix("/triage")
                )
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            applied = {}
            if "priority" in body:
                pr = (body.get("priority") or "").strip()
                if not _set_incident_priority(inc_id, pr):
                    self._send_json({"error": "invalid priority or id"}, 400)
                    return
                applied["priority"] = pr
            if "assignee" in body:
                asg = (body.get("assignee") or "").strip()
                if not _set_incident_assignee(inc_id, asg):
                    self._send_json({"error": "invalid id"}, 400)
                    return
                applied["assignee"] = asg
            if not applied:
                self._send_json({"error": "nothing to update"}, 400)
                return
            self._send_json({"ok": True, "id": inc_id, **applied})
            return

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

        if parsed.path == "/api/verify":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            ip = (body.get("ip") or "").strip()
            if not ip:
                self._send_json({"error": "ip required"}, 400)
                return
            verified_val = bool(body.get("verified", True))
            verified = _load_verified()
            if verified_val:
                verified[ip] = True
            else:
                verified.pop(ip, None)
            _save_verified(verified)
            self._send_json({"ok": True, "ip": ip, "verified": verified_val})
            return

        if parsed.path == "/api/nmap":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            ports = qs.get("ports", [""])[0].strip()
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            with _nmap_lock:
                if _nmap_state.get(target, {}).get("status") == "running":
                    self._send_json({"status": "running", "target": target})
                    return
            threading.Thread(
                target=_run_nmap_scan, args=(target, ports), daemon=True
            ).start()
            self._send_json({"status": "running", "target": target})
            return

        if parsed.path == "/api/nmap/scan":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            target = body.get("target_ip", "").strip()
            ports = body.get("ports", "").strip()
            if not target:
                self._send_json({"error": "target_ip required"}, 400)
                return
            with _nmap_lock:
                if _nmap_state.get(target, {}).get("status") == "running":
                    self._send_json({"scan_id": target, "status": "running"})
                    return
            threading.Thread(
                target=_run_nmap_scan, args=(target, ports), daemon=True
            ).start()
            self._send_json({"scan_id": target, "status": "running"})
            return

        if parsed.path == "/api/deep-inspect/start":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            target = body.get("target_ip", "").strip()
            if not target:
                self._send_json({"error": "target_ip required"}, 400)
                return
            with _deep_lock:
                if _deep_state.get(target, {}).get("status") == "running":
                    self._send_json({"capture_id": target, "status": "running"})
                    return
            threading.Thread(
                target=_run_deep_inspect, args=(target, ""), daemon=True
            ).start()
            self._send_json({"capture_id": target, "status": "running"})
            return

        if parsed.path == "/api/flow-history/pin":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            row_id = body.get("id")
            pinned = int(bool(body.get("pinned", 1)))
            if row_id is None:
                self._send_json({"error": "id required"}, 400)
                return
            try:
                from datetime import timedelta

                with _fh_conn() as hc:
                    if pinned:
                        hc.execute(
                            "UPDATE flow_history SET pinned=1, expires_at=NULL WHERE id=?",
                            (row_id,),
                        )
                    else:
                        new_exp = (
                            datetime.now(timezone.utc) + timedelta(days=_RETENTION_DAYS)
                        ).isoformat()
                        hc.execute(
                            "UPDATE flow_history SET pinned=0, expires_at=? WHERE id=?",
                            (new_exp, row_id),
                        )
                    hc.commit()
                    row = hc.execute(
                        "SELECT expires_at FROM flow_history WHERE id=?", (row_id,)
                    ).fetchone()
                    expires_at = row["expires_at"] if row else None
                self._send_json(
                    {"ok": True, "pinned": pinned, "expires_at": expires_at}
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if parsed.path == "/api/pcap/upload":
            import tempfile, uuid as _uuid

            qs = parse_qs(parsed.query)
            filename = qs.get("filename", ["upload.pcap"])[0]
            # sanitise filename
            safe_name = Path(filename).name.replace("..", "_")
            length = int(self.headers.get("Content-Length", 0))
            if length > 200 * 1024 * 1024:
                self._send_json({"error": "File too large (max 200 MB)"}, 413)
                return
            if length == 0:
                self._send_json({"error": "Empty upload"}, 400)
                return
            tmp_dir = Path(tempfile.gettempdir()) / "netwatchm-pcap"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            job_id = str(_uuid.uuid4())
            tmp_path = tmp_dir / f"{job_id}_{safe_name}"
            try:
                data = self.rfile.read(length)
                tmp_path.write_bytes(data)
            except Exception as exc:
                self._send_json({"error": f"Write failed: {exc}"}, 500)
                return
            with _pcap_lock:
                _pcap_state[job_id] = {
                    "status": "running",
                    "result": None,
                    "error": None,
                }
            threading.Thread(
                target=_run_pcap_job, args=(job_id, str(tmp_path)), daemon=True
            ).start()
            self._send_json({"job_id": job_id, "status": "running"})
            return

        if parsed.path == "/api/suppressed":
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                self._send_json({"error": "unauthorized"}, 401)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            alert_type = (body.get("type") or "").strip().upper()
            if not alert_type:
                self._send_json({"error": "type required"}, 400)
                return
            data = _load_suppressed()
            if alert_type not in data["types"]:
                data["types"].append(alert_type)
            data["updated_at"] = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
            _save_suppressed(data)
            self._send_json({"ok": True, "suppressed": data})
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
                _state.update(
                    {
                        "status": "running",
                        "duration": duration,
                        "network": network,
                        "error": None,
                        "generated_at": None,
                    }
                )

            thread = threading.Thread(
                target=_run_report, args=(duration, network), daemon=True
            )
            thread.start()
            self._send_json(
                {"status": "running", "duration": duration, "network": network}
            )
            return

        if parsed.path == "/api/investigate":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            ports = qs.get("ports", [""])[0].strip()
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
            self._send_json(
                {
                    "status": "running",
                    "target": target,
                    "result_url": f"/investigate-{target}.html",
                }
            )
            return

        if parsed.path == "/api/deep-inspect":
            qs = parse_qs(parsed.query)
            target = qs.get("target", [""])[0].strip()
            ports = qs.get("ports", [""])[0].strip()
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
            self._send_json(
                {
                    "status": "running",
                    "target": target,
                    "result_url": f"/deep-inspect-{target}.html",
                }
            )
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

        if parsed.path == "/api/ai":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            query = (body.get("query") or "").strip()
            focus_ip = (body.get("focus_ip") or "").strip() or None
            session_id = (body.get("session_id") or "default").strip()
            if not query:
                self._send_json({"error": "query required"}, 400)
                return
            reply = _ai_ask(query, focus_ip=focus_ip, session_id=session_id)
            self._send_json({"reply": reply})
            return

        if parsed.path == "/api/ai/transcribe":
            content_length = int(self.headers.get("Content-Length", 0))
            if not content_length:
                self._send_json({"error": "no audio data"}, 400)
                return
            audio_bytes = self.rfile.read(content_length)
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                self._send_json({"error": "OPENAI_API_KEY not set"}, 500)
                return
            try:
                from openai import OpenAI  # type: ignore
                import io
                client = OpenAI(api_key=api_key)
                # Whisper accepts webm, ogg, wav, mp4, m4a, mp3, mpeg
                content_type = self.headers.get("Content-Type", "audio/webm")
                ext = "webm"
                if "ogg" in content_type:   ext = "ogg"
                elif "wav" in content_type:  ext = "wav"
                elif "mp4" in content_type:  ext = "mp4"
                buf = io.BytesIO(audio_bytes)
                buf.name = f"voice.{ext}"
                result = client.audio.transcriptions.create(model="whisper-1", file=buf)
                self._send_json({"text": result.text})
            except Exception as exc:
                logger.warning("Whisper transcription failed: %s", exc)
                self._send_json({"error": str(exc)}, 500)
            return

        if parsed.path == "/api/ai/reset":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                body = {}
            session_id = (body.get("session_id") or "default").strip()
            with _ai_lock:
                _ai_sessions.pop(session_id, None)
            self._send_json({"ok": True})
            return

        # Agent (Phase 2) — rollback a whitelist entry by id.
        # ntfy notification action buttons POST here; no admin token required
        # for rollback because (a) the entry was created autonomously and
        # the user is just reversing it, and (b) the ntfy URL is the only
        # way the entry_id ever surfaces — it's effectively a one-shot
        # capability bearer token. Reads of /api/agent/* are gated by the
        # existing read/admin token middleware.
        if parsed.path.startswith("/api/agent/rollback/"):
            entry_id = parsed.path.removeprefix("/api/agent/rollback/").strip()
            if not entry_id or "/" in entry_id:
                self._send_json({"error": "invalid entry id"}, 400)
                return
            try:
                from netwatchm.agent.state import AgentWhitelistStore
                store = AgentWhitelistStore()
                ok = store.rollback_by_id(entry_id)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
                return
            if ok:
                self._send_json({"ok": True, "entry_id": entry_id})
            else:
                self._send_json(
                    {"ok": False, "reason": "entry not found or already rolled back"},
                    404,
                )
            return

        # Agent (Phase 5) — unblock a firewall entry by id. Same capability-bearer
        # rationale as /api/agent/rollback/: the entry_id is only surfaced via
        # ntfy notifications the user controls, so possessing it = authorized.
        if parsed.path.startswith("/api/agent/unblock/"):
            entry_id = parsed.path.removeprefix("/api/agent/unblock/").strip()
            if not entry_id or "/" in entry_id:
                self._send_json({"error": "invalid entry id"}, 400)
                return
            try:
                from netwatchm.agent.firewall import (
                    FirewallController,
                    FirewallStore,
                )
                store = FirewallStore()
                entry = store.mark_rolled_back(entry_id)
                if entry is None:
                    self._send_json(
                        {"ok": False, "reason": "entry not found or already rolled back"},
                        404,
                    )
                    return
                ip = str(entry.get("ip") or "")
                port_raw = entry.get("port")
                port = int(port_raw) if port_raw is not None else None
                ufw_result = FirewallController().remove_block(ip=ip, port=port)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)
                return
            self._send_json({"ok": True, "entry_id": entry_id, "ufw": ufw_result})
            return

        self.send_error(404, "Not Found")

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path.startswith("/api/flow-history/"):
            try:
                row_id = int(parsed.path.removeprefix("/api/flow-history/"))
            except ValueError:
                self._send_json({"error": "invalid id"}, 400)
                return
            try:
                with _fh_conn() as hc:
                    hc.execute("DELETE FROM flow_history WHERE id=?", (row_id,))
                    hc.commit()
                self._send_json({"ok": True})
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

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

        if parsed.path == "/api/suppressed":
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                self._send_json({"error": "unauthorized"}, 401)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json({"error": "invalid JSON"}, 400)
                return
            alert_type = (body.get("type") or "").strip().upper()
            if not alert_type:
                self._send_json({"error": "type required"}, 400)
                return
            data = _load_suppressed()
            data["types"] = [t for t in data["types"] if t != alert_type]
            data["updated_at"] = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
            _save_suppressed(data)
            self._send_json({"ok": True, "suppressed": data})
            return

        self.send_error(404, "Not Found")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
        self.end_headers()


CERT_DIR = Path(os.environ.get("NETWATCHM_CERT_DIR", _DD))
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"


def _get_local_ip() -> str:
    """Return the LAN IP of this host (or env override), never localhost."""
    ip = os.environ.get("NETWATCHM_SERVER_IP", "")
    if ip:
        return ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip


def _ensure_cert() -> None:
    """Generate a self-signed TLS certificate if one doesn't already exist."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    print("Generating self-signed TLS certificate…", flush=True)
    local_ip = _get_local_ip()
    hostname = socket.gethostname()
    san = f"subjectAltName=DNS:localhost,DNS:{hostname}.local,DNS:{hostname},IP:127.0.0.1,IP:{local_ip}"
    ext_file = CERT_DIR / "san.ext"
    ext_file.write_text(san)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(KEY_FILE),
            "-out",
            str(CERT_FILE),
            "-days",
            "3650",
            "-nodes",
            "-subj",
            f"/CN={local_ip}/O=NetWatchM",
            "-addext",
            san,
        ],
        check=True,
        capture_output=True,
    )
    ext_file.unlink(missing_ok=True)
    os.chmod(KEY_FILE, 0o600)
    print(
        f"Certificate written to {CERT_FILE} (SAN: localhost, {hostname}.local, {hostname}, 127.0.0.1, {local_ip})",
        flush=True,
    )


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
            rows.append(
                {
                    "src_ip": r["src_ip"] or "—",
                    "domain": domain,
                    "count": r["count"],
                    "last_seen": r["last_seen"],
                }
            )
        return rows
    finally:
        con.close()


def _query_data_hog_count() -> list[dict]:
    """Return count of DATA_HOG events in the last 24 h as a single-row metric list."""
    db = Path(EVENT_DB)
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


def _query_exfiltration_count() -> list[dict]:
    """Return count of EXFILTRATION (CRITICAL) events in the last 24 h."""
    db = Path(EVENT_DB)
    if not db.exists():
        return [{"value": 0}]
    con = sqlite3.connect(str(db))
    try:
        cutoff = _time.time() - 86400
        row = con.execute(
            "SELECT COUNT(*) FROM events WHERE alert_type='EXFILTRATION' AND timestamp >= ?",
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
        cur = con.execute(
            "SELECT COUNT(*) FROM events WHERE level = ?", (level.upper(),)
        )
        count = cur.fetchone()[0]
    finally:
        con.close()
    return [{"time": int(_time.time() * 1000), "value": count}]


def _ip_lookup(ip: str) -> dict:
    """Aggregate WHOIS, GeoIP, DNS, and security info for a given IP."""
    result: dict = {"ip": ip, "whois": {}, "geo": {}, "dns": {}, "security": {}}

    # ── DNS (reverse + forward) ──────────────────────────────────────────────
    try:
        ptr_r = subprocess.run(
            ["dig", "+short", "-x", ip], capture_output=True, text=True, timeout=5
        )
        ptr = ptr_r.stdout.strip().rstrip(".")
        fwd = ""
        if ptr:
            fwd_r = subprocess.run(
                ["dig", "+short", ptr], capture_output=True, text=True, timeout=5
            )
            fwd = fwd_r.stdout.strip()
        result["dns"] = {"ptr": ptr or "(none)", "forward": fwd or "(none)"}
    except Exception as exc:
        result["dns"] = {"ptr": "(error)", "error": str(exc)}

    # ── GeoIP (GeoLite2 + ipinfo.io enrichment) ──────────────────────────────
    geo: dict = {}
    try:
        import geoip2.database

        db_path = os.environ.get(
            "NETWATCHM_GEOIP_DB", "/var/lib/netwatchm/GeoLite2-City.mmdb"
        )
        if Path(db_path).exists():
            with geoip2.database.Reader(db_path) as reader:
                r = reader.city(ip)
                geo = {
                    "country": r.country.name or r.registered_country.name or "",
                    "country_code": r.country.iso_code or "",
                    "city": r.city.name or "",
                    "lat": r.location.latitude,
                    "lon": r.location.longitude,
                    "timezone": r.location.time_zone or "",
                }
    except Exception:
        pass
    # ipinfo.io for org/ISP (free, no key)
    try:
        import urllib.request as _ur

        req = _ur.Request(
            f"https://ipinfo.io/{ip}/json", headers={"User-Agent": "netwatchm/1.0"}
        )
        with _ur.urlopen(req, timeout=5) as resp:
            ipinfo = json.loads(resp.read())
        geo["org"] = ipinfo.get("org", "")
        if not geo.get("country"):
            geo["country"] = ipinfo.get("country", "")
        if not geo.get("city"):
            geo["city"] = ipinfo.get("city", "")
        geo["region"] = ipinfo.get("region", "")
    except Exception:
        pass
    result["geo"] = geo

    # ── WHOIS ────────────────────────────────────────────────────────────────
    try:
        wo = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=12)
        raw = wo.stdout
        parsed: dict[str, str] = {}
        want = {
            "netname",
            "org-name",
            "orgname",
            "organization",
            "descr",
            "country",
            "cidr",
            "inetnum",
            "netrange",
            "abuse-mailbox",
            "aut-num",
            "registrant",
        }
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k2 = k.strip().lower()
                v2 = v.strip()
                if k2 in want and k2 not in parsed and v2 and not v2.startswith("%"):
                    parsed[k2] = v2
        result["whois"] = {"parsed": parsed, "raw": raw[:4000]}
    except Exception as exc:
        result["whois"] = {"parsed": {}, "raw": f"Error: {exc}"}

    # ── Security ─────────────────────────────────────────────────────────────
    sec: dict = {
        "is_tor_exit": False,
        "is_private": False,
        "alert_count": 0,
        "alert_types": [],
        "threat_level": "UNKNOWN",
    }
    try:
        import ipaddress

        sec["is_private"] = ipaddress.ip_address(ip).is_private
    except Exception:
        pass
    # Tor exit check
    for tor_path in (
        "/var/lib/netwatchm/tor-exit-nodes.txt",
        "/tmp/tor-exit-nodes.txt",
    ):
        if Path(tor_path).exists():
            sec["is_tor_exit"] = ip in Path(tor_path).read_text()
            break
    # Local alert history
    edb = Path(EVENT_DB)
    if edb.exists():
        try:
            econ = sqlite3.connect(str(edb))
            econ.row_factory = sqlite3.Row
            rows = econ.execute(
                "SELECT alert_type, level, COUNT(*) AS cnt FROM events "
                "WHERE src_ip=? OR dst_ip=? GROUP BY alert_type ORDER BY cnt DESC",
                (ip, ip),
            ).fetchall()
            econ.close()
            sec["alert_count"] = sum(r["cnt"] for r in rows)
            sec["alert_types"] = [
                {"type": r["alert_type"], "level": r["level"], "count": r["cnt"]}
                for r in rows
            ]
            levels = [r["level"] for r in rows]
            if "CRITICAL" in levels:
                sec["threat_level"] = "CRITICAL"
            elif "HIGH" in levels:
                sec["threat_level"] = "HIGH"
            elif "MEDIUM" in levels:
                sec["threat_level"] = "MEDIUM"
            elif levels:
                sec["threat_level"] = "LOW"
            else:
                sec["threat_level"] = "CLEAN"
        except Exception:
            pass
    result["security"] = sec
    return result


def _query_events_stats() -> list[dict]:
    """Return CRITICAL/HIGH/MEDIUM alert counts as a single row for the donut chart."""
    db = Path(EVENT_DB)
    now_ms = int(_time.time() * 1000)
    if not db.exists():
        return [{"time": now_ms, "critical": 0, "high": 0, "medium": 0}]
    con = sqlite3.connect(str(db))
    try:
        counts = {"critical": 0, "high": 0, "medium": 0}
        for row in con.execute(
            "SELECT level, COUNT(*) FROM events WHERE level IN ('CRITICAL','HIGH','MEDIUM') GROUP BY level"
        ):
            counts[row[0].lower()] = row[1]
    finally:
        con.close()
    return [{"time": now_ms, **counts}]


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
                verified = _load_verified()
                for d in devices:
                    d["ip_category"] = _classify_ip(d.get("ip", ""))
                    d["label"] = aliases.get(d.get("ip", ""), "")
                    d["verified"] = verified.get(d.get("ip", ""), False)
                self._send_json(devices)
            else:
                self._send_json([])
            return

        if path.startswith("/api/inventory/"):
            inv = SERVE_DIR / "inventory.json"
            all_devices = json.loads(inv.read_text()) if inv.exists() else []
            # Only count devices seen in the last 24 hours (active devices)
            cutoff = _time.time() - 86400
            devices = []
            for d in all_devices:
                ls = d.get("last_seen") or ""
                try:
                    import datetime as _dt

                    ts = _dt.datetime.fromisoformat(ls).timestamp()
                    if ts >= cutoff:
                        devices.append(d)
                except (ValueError, TypeError):
                    pass
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

        if path in (
            "/api/events/count/critical",
            "/api/events/count/high",
            "/api/events/count/medium",
        ):
            level = path.split("/")[-1]
            try:
                self._send_json(_count_events_by_level(level))
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/events/stats":
            try:
                self._send_json(_query_events_stats())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/alerts/data-hog":
            try:
                self._send_json(_query_data_hog_count())
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
            return

        if path == "/api/alerts/exfiltration":
            try:
                self._send_json(_query_exfiltration_count())
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
    print(
        f"Grafana HTTP endpoint listening on http://127.0.0.1:{HTTP_PORT}", flush=True
    )

    _lan_ip = _get_local_ip()
    _fqdn = socket.getfqdn()
    print(f"NetWatchM web server listening on https://0.0.0.0:{PORT}", flush=True)
    print(f"  Access via IP       : https://{_lan_ip}:{PORT}", flush=True)
    print(f"  Access via hostname : https://{_fqdn}:{PORT}", flush=True)
    print(f"  Access via mDNS     : https://netwatch.local:{PORT}", flush=True)
    print(f"  AI Assistant        : https://netwatch.local:{PORT}/ai.html", flush=True)
    print(
        "Note: browser will show a self-signed cert warning — click 'Advanced > Proceed'.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
