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

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", _config_file()))
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

    cfg_path = Path(os.environ.get("NETWATCHM_CONFIG", _config_file()))
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
_RETENTION_DAYS = 30


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
                    (dst_ip, dns, meta.get("port"), meta.get("protocol"),
                     now.isoformat(), now.isoformat(), expires),
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
                (k[0], k[1], current_meta[k].get("port"),
                 current_meta[k].get("protocol"), now.isoformat())
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
        return os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "netwatchm")
    return "/var/lib/netwatchm"
def _config_file() -> str:
    if _sys.platform == "win32":
        return os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "netwatchm", "netwatchm.yaml")
    return "/etc/netwatchm/netwatchm.yaml"
_DD = _data_dir()

SERVE_DIR = Path(os.environ.get("NETWATCHM_SERVE_DIR", _DD))
PORT = int(os.environ.get("NETWATCHM_PORT", "8765"))
NETWATCHM_CMD = os.environ.get("NETWATCHM_CMD", "netwatchm")
NETWATCHM_CONFIG = os.environ.get("NETWATCHM_CONFIG", _config_file())
DEFAULT_NETWORK = os.environ.get("NETWATCHM_NETWORK", "192.168.1.0/24")
GEOIP_DB    = os.environ.get("NETWATCHM_GEOIP_DB",      str(Path(_DD) / "GeoLite2-City.mmdb"))
FLOW_DB          = os.environ.get("NETWATCHM_FLOW_DB",         str(Path(_DD) / "flows.db"))
FLOW_HISTORY_DB  = os.environ.get("NETWATCHM_FLOW_HISTORY_DB", str(Path(_DD) / "flow-history.db"))
EVENT_DB    = os.environ.get("NETWATCHM_EVENT_DB",       str(Path(_DD) / "events.db"))
ADMIN_TOKEN = os.environ.get("NETWATCHM_ADMIN_TOKEN", "netwatchm-admin")
READ_TOKEN  = os.environ.get("NETWATCHM_READ_TOKEN", "")  # empty = public reads allowed
ALIASES_FILE   = Path(os.environ.get("NETWATCHM_ALIASES_FILE",   str(Path(_DD) / "aliases.json")))
VERIFIED_FILE  = Path(os.environ.get("NETWATCHM_VERIFIED_FILE",  str(Path(_DD) / "verified.json")))
SUPPRESSED_FILE = Path(os.environ.get("NETWATCHM_SUPPRESSED_FILE", str(Path(_DD) / "suppressed.json")))
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
            _nmap_state[target_ip] = {"status": "error", "output": "", "error": str(exc)}


# ---------------------------------------------------------------------------
# pcap analysis
# ---------------------------------------------------------------------------

_NINTENDO_KEYWORDS = ("nintendo", "nintend", "wup-", "lp1.", "nasc.", "ctest.")

_PORT_SERVICE = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 554: "RTSP",
    587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S", 1720: "H.323",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def _oui_lookup(mac: str) -> str:
    """Return vendor string for a MAC address using the Wireshark manuf file."""
    if not mac:
        return ""
    prefix6  = mac[:8].upper()   # e.g. "98:E2:55"
    prefix8  = mac[:11].upper()  # e.g. "98:E2:55:D4"
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
            capture_output=True, text=True, timeout=timeout,
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
        pcap_path, "-T", "fields", "-e", "ip.src", "-e", "eth.src",
        "-E", "separator=\t",
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
        "-Y", "tcp.flags.syn==1 and tcp.flags.ack==1",
        "-T", "fields", "-e", "ip.src", "-e", "tcp.srcport",
        "-E", "separator=\t",
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
        "-Y", "dns",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "dns.id",
        "-e", "dns.flags.response",
        "-e", "dns.qry.name",
        "-e", "dns.a",
        "-E", "separator=\t",
    )
    # key: (src_ip, dst_ip, dns_id) → query record
    dns_pending: dict[tuple, dict] = {}
    dns_results: list[dict] = []
    for line in dns_out.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            ts        = float(parts[0])
            src, dst  = parts[1], parts[2]
            dns_id    = parts[3].strip()
            is_resp   = parts[4].strip() == "1"
            qname     = parts[5].strip()
            a_records = parts[6].strip() if len(parts) > 6 else ""
        except (ValueError, IndexError):
            continue

        if not is_resp:
            # query: key by (client, server, id)
            dns_pending[(src, dst, dns_id)] = {
                "ts": ts, "src": src, "server": dst, "qname": qname,
            }
        else:
            # response: client was dst of query, server was src
            key = (dst, src, dns_id)
            q = dns_pending.pop(key, None)
            if q:
                latency_ms = round((ts - q["ts"]) * 1000, 2)
                nintendo   = any(k in q["qname"].lower() for k in _NINTENDO_KEYWORDS)
                resolved   = a_records.split(",")[0].strip() if a_records else ""
                dns_results.append({
                    "query":       q["qname"],
                    "src_ip":      q["src"],
                    "server_ip":   q["server"],
                    "resolved_ip": resolved,
                    "latency_ms":  latency_ms,
                    "nintendo":    nintendo,
                })

    dns_results.sort(key=lambda x: x["latency_ms"])

    # ── 5. TLS handshake latency ──────────────────────────────────────────────
    tls_out = _tshark(
        pcap_path,
        "-Y", "tls.handshake.type == 1 or tls.handshake.type == 2",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.stream",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.extensions_server_name",
        "-E", "separator=\t",
    )
    tls_pending: dict[str, dict] = {}  # tcp.stream → ClientHello info
    tls_results: list[dict] = []
    for line in tls_out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            ts     = float(parts[0])
            src, dst = parts[1], parts[2]
            stream = parts[3].strip()
            htype  = int(parts[4].strip())
            sni    = parts[5].strip() if len(parts) > 5 else ""
        except (ValueError, IndexError):
            continue

        if htype == 1:  # ClientHello
            tls_pending[stream] = {"ts": ts, "src": src, "dst": dst, "sni": sni}
        elif htype == 2:  # ServerHello
            ch = tls_pending.pop(stream, None)
            if ch:
                latency_ms = round((ts - ch["ts"]) * 1000, 2)
                name       = ch["sni"] or ch["dst"]
                nintendo   = any(k in name.lower() for k in _NINTENDO_KEYWORDS)
                tls_results.append({
                    "server_name": name,
                    "src_ip":      ch["src"],
                    "dst_ip":      ch["dst"],
                    "latency_ms":  latency_ms,
                    "nintendo":    nintendo,
                })

    tls_results.sort(key=lambda x: x["latency_ms"])

    # ── 6. Build device list ──────────────────────────────────────────────────
    all_ips = set(ip_to_mac) | set(ip_pkt_count)
    devices = []
    for ip in all_ips:
        mac    = ip_to_mac.get(ip, "")
        vendor = _oui_lookup(mac)
        ports  = sorted(set(open_ports_by_ip.get(ip, [])))
        port_labels = [
            f"{p}/{_PORT_SERVICE.get(p, 'unknown')}" for p in ports
        ]
        devices.append({
            "ip":          ip,
            "mac":         mac,
            "vendor":      vendor,
            "packet_count": ip_pkt_count.get(ip, 0),
            "open_ports":  port_labels,
            "nintendo":    "nintendo" in vendor.lower(),
        })
    devices.sort(key=lambda d: d["packet_count"], reverse=True)

    return {
        "summary": {
            "filename":      Path(pcap_path).name,
            "total_packets": total_packets,
            "duration_s":    duration_s,
        },
        "devices": devices,
        "dns":     dns_results,
        "tls":     tls_results,
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
        try:
            _update_flow_history(duration)
        except Exception:
            pass  # history update is best-effort
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


def _query_events_paged(
    limit: int = 50,
    offset: int = 0,
    alert_type: str | None = None,
    level: str | None = None,
    ip: str | None = None,
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
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        total = con.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        cur = con.execute(
            f"SELECT id, timestamp, alert_type, level, src_ip, dst_ip, description "
            f"FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return {"events": [dict(r) for r in cur.fetchall()], "total": total,
                "offset": offset, "limit": limit}
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
  [data-theme="light"] {
    --bg:#ffffff; --surface:#f6f8fa; --surface2:#eaeef2; --border:#d0d7de;
    --text:#1f2328; --muted:#6e7781; --accent:#0969da;
    --low:#1a7f37; --medium:#9a6700; --high:#cf222e; --critical:#a40e26;
  }
  [data-theme="light"] .badge-LOW      { background:#dcfce7; color:var(--low); }
  [data-theme="light"] .badge-MEDIUM   { background:#fef9c3; color:var(--medium); }
  [data-theme="light"] .badge-HIGH     { background:#fee2e2; color:var(--high); }
  [data-theme="light"] .badge-CRITICAL { background:#ffe4e6; color:var(--critical); }
  [data-theme="light"] .modal-box      { background:#ffffff; border-color:#d0d7de; }
  [data-theme="light"] .modal-box input { background:#f6f8fa; border-color:#d0d7de; color:#1f2328; }
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
  .pagination { display:flex; align-items:center; gap:8px; padding:10px 20px;
    background:var(--surface); border-top:1px solid var(--border); flex-wrap:wrap; }
  .page-btn { background:var(--surface2); color:var(--text); border:1px solid var(--border);
    padding:4px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px; }
  .page-btn:hover { border-color:var(--accent); color:var(--accent); }
  .page-btn:disabled { opacity:0.4; cursor:default; pointer-events:none; }
  .page-info { color:var(--muted); font-size:12px; }
  .page-size { background:var(--surface2); color:var(--text); border:1px solid var(--border);
    padding:4px 8px; border-radius:4px; font-size:12px; }
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
  .theme-btn {
    background:var(--surface2); color:var(--muted); border:1px solid var(--border);
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .theme-btn:hover { color:var(--accent); border-color:var(--accent); }
  .suppress-toggle {
    background:var(--surface2); color:var(--muted); border:1px solid var(--border);
    padding:5px 12px; border-radius:4px; cursor:pointer; font-family:monospace; font-size:12px;
  }
  .suppress-toggle:hover { color:#d29922; border-color:#d29922; }
  .suppress-toggle.active { color:#f85149; border-color:#f85149; }
  #suppressPanel {
    background:var(--surface); border-bottom:1px solid var(--border);
    padding:10px 20px; display:none; flex-wrap:wrap; gap:8px; align-items:center;
  }
  #suppressPanel span { color:var(--muted); font-size:12px; }
  .sup-tag {
    display:inline-flex; align-items:center; gap:5px;
    background:var(--surface2); border:1px solid #f85149;
    padding:2px 8px; border-radius:20px; font-size:11px; color:#f85149;
  }
  .sup-tag button { background:none; border:none; color:#f85149; cursor:pointer; font-size:13px; padding:0 2px; }
  .sup-btn {
    background:none; border:1px solid var(--border); color:var(--muted);
    padding:2px 8px; border-radius:4px; cursor:pointer; font-size:11px; font-family:monospace;
  }
  .sup-btn:hover { border-color:#d29922; color:#d29922; }
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
  /* ── Mobile ── */
  @media (max-width: 768px) {
    .topbar { flex-wrap:wrap; padding:8px 12px; gap:6px; }
    .topbar h1 { font-size:13px; width:100%; }
    .filterbar { flex-direction:column; align-items:flex-start; padding:8px 12px; gap:6px; }
    .filterbar input, .filterbar select { width:100%; }
    .result-count { margin-left:0; }
    .table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; }
    td, th { padding:5px 6px; font-size:11px; }
    thead th:nth-child(5), tbody td:nth-child(5) { display:none; }
    .pagination { flex-wrap:wrap; padding:8px 12px; }
    .refresh-btn, .export-btn, .notify-btn, .clear-btn,
    .theme-btn, .suppress-toggle, .page-btn {
      padding:7px 12px; min-height:38px;
    }
    .detail-grid { flex-direction:column; }
    #suppressPanel { flex-direction:column; align-items:flex-start; }
  }
</style>
</head>
<body>

<div class="topbar">
  <h1>&#9888; NetWatchM &mdash; Threat Events</h1>
  <a href="/connection-report.html">&#8592; Report</a>
  <a href="/inventory.html">Inventory</a>
  <a href="/analytics.html">Analytics</a>
  <a href="http://localhost:3000/d/netwatchm-inventory/" target="_blank">&#128202; Dashboard</a>
  <a href="/deep-inspect-web.html">&#128269; Deep Inspect</a>
  <div class="spacer"></div>
  <label class="auto-toggle">
    <input type="checkbox" id="autoRefresh" checked> Auto-refresh
  </label>
  <span class="countdown" id="countdown"></span>
  <button class="refresh-btn" onclick="loadEvents()">&#8635; Refresh</button>
  <button class="export-btn" onclick="exportCSV()">&#11123; CSV</button>
  <button class="notify-btn" id="testNtfyBtn" onclick="testNtfy()">&#128276; Test Notify</button>
  <button class="clear-btn" onclick="clearAlerts()">&#128465; Clear Alerts</button>
  <button class="suppress-toggle" id="suppressToggle" onclick="toggleSuppressPanel()">&#128274; Suppressions</button>
  <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">&#9788; Light</button>
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

<div id="suppressPanel">
  <span>&#128274; Suppressed types (new alerts of these types will be silenced):</span>
  <div id="suppressTags"></div>
</div>
<div class="filterbar">
  <label>Search:</label>
  <input type="text" id="search" placeholder="IP, type, description…" oninput="applyFilters()">
  <label>Level:</label>
  <select id="levelFilter" onchange="_pageOffset=0;loadEvents()">
    <option value="">All</option>
    <option value="LOW">LOW</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="HIGH">HIGH</option>
    <option value="CRITICAL">CRITICAL</option>
  </select>
  <label>Type:</label>
  <select id="typeFilter" onchange="_pageOffset=0;loadEvents()">
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
<div class="pagination" id="pagination" style="display:none">
  <button class="page-btn" id="prevBtn" onclick="changePage(-1)">&#8592; Prev</button>
  <span class="page-info" id="pageInfo"></span>
  <button class="page-btn" id="nextBtn" onclick="changePage(1)">Next &#8594;</button>
  <select class="page-size" id="pageSizeSelect" onchange="changePageSize()">
    <option value="50">50 / page</option>
    <option value="100">100 / page</option>
    <option value="200">200 / page</option>
  </select>
</div>

<script>
function _applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = theme === 'light' ? '\\u2600 Dark' : '\\u2600 Light';
  try { localStorage.setItem('nwm-theme', theme); } catch(_) {}
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  _applyTheme(cur === 'light' ? 'dark' : 'light');
}
(function(){ try { const t = localStorage.getItem('nwm-theme'); if(t) _applyTheme(t); } catch(_){} })();

let _suppressed = [];
let _suppressToken = '';

async function loadSuppressed() {
  try {
    const d = await fetch('/api/suppressed').then(r => r.json());
    _suppressed = d.types || [];
    _renderSuppressPanel();
  } catch(_) {}
}
function _renderSuppressPanel() {
  const btn = document.getElementById('suppressToggle');
  btn.classList.toggle('active', _suppressed.length > 0);
  const tags = document.getElementById('suppressTags');
  tags.innerHTML = _suppressed.length === 0
    ? '<em style="color:var(--muted);font-size:11px">None</em>'
    : _suppressed.map(t =>
        `<span class="sup-tag">${esc(t)}<button title="Unsuppress" onclick="unsuppress('${esc(t)}')">&#215;</button></span>`
      ).join('');
}
function toggleSuppressPanel() {
  const p = document.getElementById('suppressPanel');
  p.style.display = p.style.display === 'flex' ? 'none' : 'flex';
}
async function _getAdminToken() {
  if (_suppressToken) return _suppressToken;
  _suppressToken = prompt('Enter admin token:') || '';
  return _suppressToken;
}
async function suppress(alertType) {
  const token = await _getAdminToken(); if (!token) return;
  try {
    const r = await fetch('/api/suppressed', {
      method:'POST', headers:{'Content-Type':'application/json','X-Admin-Token':token},
      body: JSON.stringify({type: alertType})
    });
    const d = await r.json();
    if (r.ok && d.ok) { showToast('Suppressed: ' + alertType, true); await loadSuppressed(); }
    else { _suppressToken=''; showToast(d.error || 'Failed', false); }
  } catch(e) { showToast('Request failed', false); }
}
async function unsuppress(alertType) {
  const token = await _getAdminToken(); if (!token) return;
  try {
    const r = await fetch('/api/suppressed', {
      method:'DELETE', headers:{'Content-Type':'application/json','X-Admin-Token':token},
      body: JSON.stringify({type: alertType})
    });
    const d = await r.json();
    if (r.ok && d.ok) { showToast('Unsuppressed: ' + alertType, true); await loadSuppressed(); }
    else { _suppressToken=''; showToast(d.error || 'Failed', false); }
  } catch(e) { showToast('Request failed', false); }
}

let _allEvents = [];
let _pageOffset = 0;
let _pageLimit = 50;
let _totalEvents = 0;
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

function _buildFilterParams() {
  const level = document.getElementById('levelFilter').value;
  const type  = document.getElementById('typeFilter').value;
  const ip    = new URLSearchParams(window.location.search).get('ip') || '';
  let p = '';
  if (level) p += '&level=' + encodeURIComponent(level);
  if (type)  p += '&type='  + encodeURIComponent(type);
  if (ip)    p += '&ip='    + encodeURIComponent(ip);
  return p;
}

async function loadEvents() {
  resetCountdown();
  try {
    const url = '/api/events?offset=' + _pageOffset + '&limit=' + _pageLimit + _buildFilterParams();
    const [paged, types] = await Promise.all([
      fetch(url).then(r => r.json()),
      fetch('/api/events/types').then(r => r.json()),
    ]);
    _allEvents = paged.events;
    _totalEvents = paged.total;
    _expandedId = null;
    populateTypeFilter(types);
    applyFilters();
    _updatePagination();
  } catch(e) {
    document.getElementById('tbody').innerHTML =
      '<tr><td colspan="6" style="color:var(--high);padding:20px">Failed to load events: '+esc(String(e))+'</td></tr>';
  }
}

function _updatePagination() {
  const totalPages = Math.ceil(_totalEvents / _pageLimit) || 1;
  const currentPage = Math.floor(_pageOffset / _pageLimit) + 1;
  document.getElementById('pageInfo').textContent =
    'Page ' + currentPage + ' of ' + totalPages + ' (' + _totalEvents + ' total)';
  document.getElementById('prevBtn').disabled = _pageOffset === 0;
  document.getElementById('nextBtn').disabled = (_pageOffset + _pageLimit) >= _totalEvents;
  document.getElementById('pagination').style.display = _totalEvents > 0 ? 'flex' : 'none';
}

function changePage(dir) {
  _pageOffset = Math.max(0, _pageOffset + dir * _pageLimit);
  loadEvents();
}

function changePageSize() {
  _pageLimit = parseInt(document.getElementById('pageSizeSelect').value);
  _pageOffset = 0;
  loadEvents();
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

function _isPrivate(ip) {
  if (!ip || ip === '—') return true;
  return ip.startsWith('10.') || ip.startsWith('192.168.') ||
    ip.startsWith('127.') || ip.startsWith('169.254.') ||
    /^172\\.(1[6-9]|2\\d|3[01])\\./.test(ip);
}
function buildDetailRow(e) {
  const srcExt = e.src_ip && !_isPrivate(e.src_ip);
  const dstExt = e.dst_ip && !_isPrivate(e.dst_ip);
  const inspectIp = srcExt ? e.src_ip : (dstExt ? e.dst_ip : (e.src_ip && e.src_ip !== '—' ? e.src_ip : e.dst_ip || ''));
  const inspectLabel = srcExt ? e.src_ip : (dstExt ? `dst: ${e.dst_ip}` : e.src_ip || e.dst_ip || '');
  const deepLink = inspectIp
    ? `<a class="deep-btn" href="/inspect/${esc(inspectIp)}" target="_blank">&#128269; Deep Inspect ${esc(inspectLabel)}</a>`
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
      <button class="sup-btn" onclick="event.stopPropagation();suppress('${esc(e.alert_type)}')" style="margin-top:8px">&#128274; Suppress ${esc(e.alert_type)}</button>
    </td>
  </tr>`;
}

function toggleDetail(id) {
  _expandedId = (_expandedId === id) ? null : id;
  applyFilters();
}

async function exportCSV() {
  try {
    const allEvts = await fetch('/api/events?limit=1000' + _buildFilterParams()).then(r => r.json());
    const search = document.getElementById('search').value.toLowerCase();
    const filtered = search
      ? allEvts.filter(e => [e.alert_type,e.level,e.src_ip,e.dst_ip,e.description].join(' ').toLowerCase().includes(search))
      : allEvts;
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
  } catch(e) { showToast('CSV export failed: ' + e, false); }
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
loadSuppressed();
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
  .verified-btn{background:none;border:none;cursor:pointer;font-size:15px;padding:2px 4px;border-radius:4px;line-height:1;color:var(--muted)}
  .verified-btn:hover{background:rgba(255,255,255,.08)}
  .verified-btn.is-verified{color:var(--green)}
  .scan-btn{background:none;border:1px solid var(--border);cursor:pointer;font-size:11px;padding:2px 7px;border-radius:4px;color:var(--muted);white-space:nowrap}
  .scan-btn:hover{border-color:var(--blue);color:var(--blue)}
  .scan-btn.scanning{color:var(--yellow);border-color:var(--yellow)}
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center}
  .modal-overlay.open{display:flex}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:8px;width:min(860px,95vw);max-height:80vh;display:flex;flex-direction:column}
  .modal-header{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border)}
  .modal-header h2{font-size:14px;font-weight:600;color:var(--blue);flex:1}
  .modal-close{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:0 4px;line-height:1}
  .modal-close:hover{color:var(--text)}
  .modal-body{flex:1;overflow-y:auto;padding:14px 16px}
  pre.nmap-out{font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.55;margin:0}
  .nmap-status{color:var(--muted);font-size:12px;padding:20px 0;text-align:center}
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
    <a href="/pcap.html">&#128202; Pcap</a>
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
      <th data-col="verified" title="Verified device">&#10003;</th>
      <th data-col="label" class="sorted">Label &#9660;</th>
      <th data-col="ip">IP</th>
      <th data-col="hostname">Hostname</th>
      <th data-col="mac">MAC</th>
      <th data-col="vendor">Vendor</th>
      <th data-col="threat_level">Threat</th>
      <th data-col="bytes_sent">&#8593; Sent</th>
      <th data-col="bytes_received">&#8595; Recv</th>
      <th data-col="last_seen">Last Seen</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div class="empty-state" id="emptyState" style="display:none">No devices match your search.</div>
<div class="toast" id="toast"></div>

<div class="modal-overlay" id="nmapModal">
  <div class="modal">
    <div class="modal-header">
      <h2 id="nmapModalTitle">&#128270; nmap scan</h2>
      <button class="modal-close" id="nmapModalClose">&#10005;</button>
    </div>
    <div class="modal-body">
      <div id="nmapStatusMsg" class="nmap-status">Starting scan…</div>
      <pre class="nmap-out" id="nmapOutput" style="display:none"></pre>
    </div>
  </div>
</div>

<script>
let _devices = [], _aliases = {}, _verified = {}, _sortCol = 'label', _sortAsc = true;

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
  const [devResp, aliasResp, verResp] = await Promise.all([
    fetch('/inventory.json'),
    fetch('/api/aliases'),
    fetch('/api/verified')
  ]);
  _devices  = await devResp.json();
  _aliases  = await aliasResp.json();
  _verified = await verResp.json();
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
    } else if(_sortCol==='verified'){
      av=!!_verified[a.ip]?1:0;
      bv=!!_verified[b.ip]?1:0;
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
    if(q==='verified') return !!_verified[d.ip];
    if(q==='unverified') return !_verified[d.ip];
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
    const isVer = !!_verified[d.ip];
    return `<tr>
      <td style="text-align:center"><button class="verified-btn ${isVer?'is-verified':''}" data-ip="${esc(d.ip)}" data-verified="${isVer}" title="${isVer?'Verified — click to unverify':'Unverified — click to verify'}">${isVer?'&#10003;':'&#9711;'}</button></td>
      <td class="label-cell"><span class="label-display ${label?'':'empty'}" data-ip="${esc(d.ip)}">${label?esc(label):'Add label…'}</span></td>
      <td class="ip">${esc(d.ip)}</td>
      <td>${esc(d.hostname)||'—'}</td>
      <td class="ip">${esc(d.mac)||'—'}</td>
      <td>${esc(d.vendor)||'—'}</td>
      <td><span class="threat ${lvl}">${lvl}</span></td>
      <td>${fmtBytes(d.bytes_sent)}</td>
      <td>${fmtBytes(d.bytes_received)}</td>
      <td>${fmtTime(d.last_seen)}</td>
      <td><button class="scan-btn" data-ip="${esc(d.ip)}" title="Run nmap scan">&#128270; Scan</button></td>
    </tr>`;
  }).join('');
  attachLabelEditors();
  attachVerifyToggles();
  attachScanButtons();
}

function attachLabelEditors(){
  document.querySelectorAll('.label-display').forEach(el=>{
    el.addEventListener('click', startEdit);
  });
}

function attachVerifyToggles(){
  document.querySelectorAll('.verified-btn').forEach(btn=>{
    btn.addEventListener('click', async ()=>{
      const ip = btn.dataset.ip;
      const nowVerified = btn.dataset.verified === 'true';
      const next = !nowVerified;
      try{
        const r = await fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,verified:next})});
        const j = await r.json();
        if(j.ok){
          if(next) _verified[ip]=true; else delete _verified[ip];
          toast(next ? `Verified: ${ip}` : `Unverified: ${ip}`);
          render();
        } else { toast('Save failed',false); }
      } catch(_){ toast('Save failed',false); }
    });
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

// ── nmap scan modal ──────────────────────────────────────────────────────────
let _nmapPollTimer = null;

function openNmapModal(ip){
  document.getElementById('nmapModalTitle').textContent = '\\u{1F50E} nmap scan — ' + ip;
  document.getElementById('nmapStatusMsg').textContent = 'Starting scan…';
  document.getElementById('nmapStatusMsg').style.display = 'block';
  document.getElementById('nmapOutput').style.display = 'none';
  document.getElementById('nmapOutput').textContent = '';
  document.getElementById('nmapModal').classList.add('open');
}

function closeNmapModal(){
  document.getElementById('nmapModal').classList.remove('open');
  if(_nmapPollTimer){ clearInterval(_nmapPollTimer); _nmapPollTimer=null; }
}

document.getElementById('nmapModalClose').addEventListener('click', closeNmapModal);
document.getElementById('nmapModal').addEventListener('click', e=>{
  if(e.target===document.getElementById('nmapModal')) closeNmapModal();
});

async function startNmapScan(ip, btn){
  btn.classList.add('scanning');
  btn.textContent = '⏳ Scanning…';
  openNmapModal(ip);
  try{
    await fetch('/api/nmap?target='+encodeURIComponent(ip), {method:'POST'});
  } catch(_){}
  if(_nmapPollTimer) clearInterval(_nmapPollTimer);
  _nmapPollTimer = setInterval(async ()=>{
    try{
      const s = await fetch('/api/nmap/status?target='+encodeURIComponent(ip)).then(r=>r.json());
      if(s.status === 'running'){
        document.getElementById('nmapStatusMsg').textContent = '⏳ Scanning '+ip+'… (may take up to 60 s)';
      } else if(s.status === 'ready'){
        clearInterval(_nmapPollTimer); _nmapPollTimer = null;
        btn.classList.remove('scanning');
        btn.innerHTML = '\\u{1F50E} Scan';
        document.getElementById('nmapStatusMsg').style.display = 'none';
        const pre = document.getElementById('nmapOutput');
        pre.textContent = s.output || '(no output)';
        pre.style.display = 'block';
      } else if(s.status === 'error'){
        clearInterval(_nmapPollTimer); _nmapPollTimer = null;
        btn.classList.remove('scanning');
        btn.innerHTML = '\\u{1F50E} Scan';
        document.getElementById('nmapStatusMsg').textContent = '\\u274C Error: ' + (s.error||'unknown');
      }
    } catch(_){}
  }, 1500);
}

function attachScanButtons(){
  document.querySelectorAll('.scan-btn').forEach(btn=>{
    btn.addEventListener('click', ()=>startNmapScan(btn.dataset.ip, btn));
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


def _render_history_html() -> bytes:
    """Self-contained flow history SPA."""
    page = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatchM — Flow History</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--accent:#1f6feb;--purple:#bc8cff}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  header h1{font-size:15px;font-weight:600;color:var(--blue)}
  nav{display:flex;gap:16px;align-items:center;margin-left:auto}
  nav a{color:var(--muted);font-size:13px;text-decoration:none}
  nav a:hover{color:var(--text)}
  .toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:14px 20px;border-bottom:1px solid var(--border);background:var(--surface)}
  input[type=search]{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:6px;font-size:12px;width:240px}
  input[type=search]:focus{outline:none;border-color:var(--blue)}
  .btn{background:var(--accent);color:#fff;border:none;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px}
  .btn:hover{opacity:.85}
  .btn.danger{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.35)}
  .btn.danger:hover{background:rgba(248,81,73,.25)}
  .count{color:var(--muted);font-size:12px;margin-left:auto}
  .tbl-wrap{overflow-x:auto;padding:0 20px 20px}
  table{width:100%;border-collapse:collapse;margin-top:16px;font-size:12px}
  thead th{background:var(--surface);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
  thead th:hover{color:var(--text)}
  tbody tr{border-bottom:1px solid rgba(48,54,61,.5)}
  tbody tr:hover{background:rgba(255,255,255,.02)}
  tbody tr.pinned-row{background:rgba(188,140,255,.04)}
  td{padding:7px 10px;vertical-align:middle}
  .mono{font-family:monospace;font-size:11px}
  .pin-btn{background:none;border:1px solid var(--border);border-radius:4px;padding:3px 8px;cursor:pointer;font-size:11px;color:var(--muted);white-space:nowrap}
  .pin-btn:hover{border-color:var(--purple);color:var(--purple)}
  .pin-btn.pinned{background:rgba(188,140,255,.15);border-color:var(--purple);color:var(--purple)}
  .del-btn{background:none;border:none;cursor:pointer;color:var(--muted);font-size:14px;padding:2px 6px;border-radius:4px}
  .del-btn:hover{color:var(--red);background:rgba(248,81,73,.1)}
  .days{font-size:11px;white-space:nowrap}
  .days.ok{color:var(--green)}
  .days.warn{color:var(--yellow)}
  .days.urgent{color:var(--red)}
  .days.forever{color:var(--purple)}
  .empty{text-align:center;padding:60px;color:var(--muted)}
  .toast{position:fixed;bottom:20px;right:20px;background:var(--green);color:#000;padding:8px 16px;border-radius:6px;font-size:12px;opacity:0;transition:opacity .3s;pointer-events:none;z-index:99}
  .toast.show{opacity:1}
  .chk{width:14px;height:14px;cursor:pointer;accent-color:var(--accent)}
</style>
</head>
<body>
<header>
  <h1>&#128337; Flow History</h1>
  <nav>
    <a href="/connection-report.html">&#8592; Report</a>
    <a href="/inventory.html">Inventory</a>
    <a href="/events.html">Events</a>
    <a href="/deep-inspect-web.html">&#128269; Deep Inspect</a>
  </nav>
</header>
<div class="toolbar">
  <input type="search" id="searchBox" placeholder="Search IP, domain…">
  <button class="btn danger" id="deleteSelBtn" style="display:none" onclick="deleteSelected()">&#128465; Delete selected</button>
  <span class="count" id="countLabel">—</span>
</div>
<div class="tbl-wrap">
  <table id="histTable">
    <thead>
      <tr>
        <th style="width:28px"><input type="checkbox" class="chk" id="selectAll" title="Select all"></th>
        <th data-col="dst_ip">Destination IP</th>
        <th data-col="dns">Domain / DNS</th>
        <th data-col="last_active">Last Active</th>
        <th data-col="went_inactive">Inactive Since</th>
        <th data-col="expires_at">Expires</th>
        <th style="width:90px">Pin</th>
        <th style="width:36px"></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div class="empty" id="emptyState" style="display:none">No inactive flows yet.<br><span style="font-size:11px;margin-top:6px;display:block">Connections that disappear after a report run will appear here.</span></div>
</div>
<div class="toast" id="toast"></div>
<script>
let _rows = [];

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function toast(msg, ok=true){
  const t=document.getElementById('toast');
  t.textContent=msg; t.style.background=ok?'#3fb950':'#f85149';
  t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2200);
}

function fmtDate(s){
  if(!s) return '—';
  const d=new Date(s); return isNaN(d)?s:d.toLocaleString();
}

function daysLeft(expires, pinned){
  if(pinned) return {label:'&#x1F4CC; Pinned', cls:'forever'};
  if(!expires) return {label:'—', cls:''};
  const ms = new Date(expires) - Date.now();
  const d = Math.ceil(ms / 86400000);
  if(d < 0)  return {label:'Expired', cls:'urgent'};
  if(d <= 3) return {label:d+'d left', cls:'urgent'};
  if(d <= 7) return {label:d+'d left', cls:'warn'};
  return {label:d+'d left', cls:'ok'};
}

async function load(){
  const r = await fetch('/api/flow-history').then(r=>r.json()).catch(()=>[]);
  _rows = Array.isArray(r) ? r : [];
  render();
}

function render(){
  const q = document.getElementById('searchBox').value.toLowerCase();
  const filtered = q ? _rows.filter(r=>
    (r.dst_ip||'').includes(q)||(r.dns||'').toLowerCase().includes(q)
  ) : _rows;
  document.getElementById('countLabel').textContent = filtered.length + ' inactive flow' + (filtered.length!==1?'s':'');
  document.getElementById('emptyState').style.display = filtered.length ? 'none' : 'block';
  document.getElementById('histTable').style.display = filtered.length ? '' : 'none';
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = filtered.map(r=>{
    const dl = daysLeft(r.expires_at, r.pinned);
    const pinLabel = r.pinned ? '&#x1F4CC; Pinned' : '&#x1F513; Pin';
    return `<tr class="${r.pinned?'pinned-row':''}" data-id="${r.id}">
      <td><input type="checkbox" class="chk row-chk" data-id="${r.id}" onchange="updateDeleteBtn()"></td>
      <td class="mono">${esc(r.dst_ip)}</td>
      <td class="mono">${esc(r.dns)||'<span style="color:var(--muted)">—</span>'}</td>
      <td style="font-size:11px">${fmtDate(r.last_active)}</td>
      <td style="font-size:11px">${fmtDate(r.went_inactive)}</td>
      <td><span class="days ${dl.cls}">${dl.label}</span></td>
      <td><button class="pin-btn ${r.pinned?'pinned':''}" onclick="togglePin(${r.id},${r.pinned?0:1})">${pinLabel}</button></td>
      <td><button class="del-btn" title="Delete" onclick="deleteOne(${r.id})">&#x2715;</button></td>
    </tr>`;
  }).join('');
}

async function togglePin(id, newVal){
  const r = await fetch('/api/flow-history/pin',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,pinned:newVal})
  }).then(r=>r.json()).catch(()=>({}));
  if(r.ok){
    const row = _rows.find(x=>x.id===id);
    if(row){ row.pinned=newVal; row.expires_at=r.expires_at; }
    toast(newVal ? 'Pinned — will not be auto-deleted' : 'Unpinned — 30-day expiry restored');
    render();
  } else { toast('Failed',false); }
}

async function deleteOne(id){
  const r = await fetch('/api/flow-history/'+id,{method:'DELETE'}).then(r=>r.json()).catch(()=>({}));
  if(r.ok){ _rows = _rows.filter(x=>x.id!==id); toast('Deleted'); render(); }
  else { toast('Failed',false); }
}

async function deleteSelected(){
  const ids = [...document.querySelectorAll('.row-chk:checked')].map(c=>parseInt(c.dataset.id));
  if(!ids.length) return;
  for(const id of ids){
    await fetch('/api/flow-history/'+id,{method:'DELETE'});
  }
  _rows = _rows.filter(r=>!ids.includes(r.id));
  toast('Deleted '+ids.length+' entr'+(ids.length===1?'y':'ies'));
  updateDeleteBtn(); render();
}

function updateDeleteBtn(){
  const any = document.querySelectorAll('.row-chk:checked').length > 0;
  document.getElementById('deleteSelBtn').style.display = any ? '' : 'none';
}

document.getElementById('selectAll').addEventListener('change', e=>{
  document.querySelectorAll('.row-chk').forEach(c=>c.checked=e.target.checked);
  updateDeleteBtn();
});
document.getElementById('searchBox').addEventListener('input', render);

load();
setInterval(load, 30000);
</script>
</body>
</html>"""
    return page.encode()


def _render_pcap_html() -> bytes:
    """Self-contained pcap analysis SPA."""
    page = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatchM — Pcap Analyzer</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--accent:#1f6feb;--purple:#bc8cff;--nintendored:#e4000f}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  header h1{font-size:15px;font-weight:600;color:var(--blue)}
  nav{display:flex;gap:16px;align-items:center;margin-left:auto}
  nav a{color:var(--muted);font-size:13px;text-decoration:none}
  nav a:hover{color:var(--text)}
  .main{max-width:1200px;margin:0 auto;padding:24px 20px}
  /* drop zone */
  .dropzone{border:2px dashed var(--border);border-radius:10px;padding:50px 30px;text-align:center;cursor:pointer;transition:border-color .2s,background .2s;margin-bottom:28px}
  .dropzone.over{border-color:var(--blue);background:rgba(88,166,255,.06)}
  .dropzone h2{font-size:16px;font-weight:500;color:var(--muted);margin-bottom:8px}
  .dropzone p{color:var(--muted);font-size:12px}
  .dropzone input{display:none}
  .btn{background:var(--accent);color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px}
  .btn:hover{opacity:.85}
  .btn.sec{background:var(--surface);border:1px solid var(--border);color:var(--text)}
  /* progress */
  .progress{display:none;text-align:center;padding:30px;color:var(--muted)}
  .spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 12px}
  @keyframes spin{to{transform:rotate(360deg)}}
  /* sections */
  section{margin-bottom:32px}
  section h2{font-size:14px;font-weight:600;color:var(--blue);border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:14px}
  /* summary cards */
  .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:0}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 20px;min-width:150px;flex:1}
  .card .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
  .card .value{font-size:22px;font-weight:700;color:var(--text)}
  .card .sub{font-size:11px;color:var(--muted);margin-top:2px}
  /* tables */
  .tbl-wrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:12px}
  thead th{background:var(--surface);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
  tbody tr{border-bottom:1px solid rgba(48,54,61,.6)}
  tbody tr:hover{background:rgba(255,255,255,.02)}
  td{padding:7px 10px;vertical-align:middle}
  .mono{font-family:monospace;font-size:11px}
  .tag{font-size:10px;font-weight:600;padding:2px 7px;border-radius:10px;display:inline-block;white-space:nowrap}
  .tag.nintendo{background:rgba(228,0,15,.15);color:var(--nintendored)}
  .tag.open{background:rgba(63,185,80,.15);color:var(--green)}
  .tag.vendor{background:rgba(88,166,255,.12);color:var(--blue)}
  .lat-good{color:var(--green)}
  .lat-ok{color:var(--yellow)}
  .lat-bad{color:var(--red)}
  .dim{color:var(--muted)}
  .error-box{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);border-radius:6px;padding:14px 18px;color:var(--red);margin-bottom:20px}
  #results{display:none}
</style>
</head>
<body>
<header>
  <h1>&#128202; Pcap Analyzer</h1>
  <nav>
    <a href="/inventory.html">&#8592; Inventory</a>
    <a href="/events.html">Events</a>
    <a href="/connection-report.html">Report</a>
    <a href="/deep-inspect-web.html">&#128269; Deep Inspect</a>
  </nav>
</header>
<div class="main">

  <!-- Upload area -->
  <div class="dropzone" id="dropzone">
    <h2>&#128229; Drop a .pcap or .pcapng file here</h2>
    <p>or click to browse &mdash; max 200 MB</p>
    <p style="margin-top:10px"><button class="btn" onclick="document.getElementById('fileInput').click()">Choose File</button></p>
    <input type="file" id="fileInput" accept=".pcap,.pcapng,.cap">
  </div>

  <!-- Progress -->
  <div class="progress" id="progress">
    <div class="spinner"></div>
    <div id="progressMsg">Uploading…</div>
  </div>

  <!-- Error -->
  <div class="error-box" id="errorBox" style="display:none"></div>

  <!-- Results -->
  <div id="results">

    <section>
      <h2>&#128203; Summary</h2>
      <div class="cards" id="summaryCards"></div>
    </section>

    <section>
      <h2>&#128241; Devices Detected</h2>
      <div class="tbl-wrap">
      <table id="devTable">
        <thead><tr>
          <th>IP</th><th>MAC</th><th>Vendor</th>
          <th style="text-align:right">Packets</th>
          <th>Open Ports</th>
        </tr></thead>
        <tbody id="devBody"></tbody>
      </table>
      </div>
    </section>

    <section id="dnsSection">
      <h2>&#127758; DNS Resolution Latency</h2>
      <div class="tbl-wrap">
      <table id="dnsTable">
        <thead><tr>
          <th>Query</th><th>Client IP</th><th>DNS Server</th>
          <th>Resolved IP</th><th style="text-align:right">Latency</th>
          <th></th>
        </tr></thead>
        <tbody id="dnsBody"></tbody>
      </table>
      </div>
      <p id="dnsEmpty" class="dim" style="display:none;padding:12px 0;font-size:12px">No DNS traffic found in this capture.</p>
    </section>

    <section id="tlsSection">
      <h2>&#128274; TLS Handshake Latency</h2>
      <div class="tbl-wrap">
      <table id="tlsTable">
        <thead><tr>
          <th>Server / SNI</th><th>Client IP</th><th>Server IP</th>
          <th style="text-align:right">Handshake Time</th><th></th>
        </tr></thead>
        <tbody id="tlsBody"></tbody>
      </table>
      </div>
      <p id="tlsEmpty" class="dim" style="display:none;padding:12px 0;font-size:12px">No TLS handshakes found in this capture.</p>
    </section>

  </div><!-- /results -->
</div><!-- /main -->
<script>
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmtLat(ms){
  const s=parseFloat(ms);
  const cls=s<50?'lat-good':s<200?'lat-ok':'lat-bad';
  return `<span class="${cls}">${s.toFixed(1)} ms</span>`;
}
function fmtPkts(n){return n>=1000?(n/1000).toFixed(1)+'k':String(n);}

// ── drag and drop ────────────────────────────────────────────────────────────
const dz=document.getElementById('dropzone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over');});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');handleFile(e.dataTransfer.files[0]);});
document.getElementById('fileInput').addEventListener('change',e=>handleFile(e.target.files[0]));

// ── upload + poll ────────────────────────────────────────────────────────────
async function handleFile(file){
  if(!file) return;
  const ext=file.name.split('.').pop().toLowerCase();
  if(!['pcap','pcapng','cap'].includes(ext)){showError('Please upload a .pcap or .pcapng file.');return;}
  if(file.size>200*1024*1024){showError('File exceeds 200 MB limit.');return;}

  showProgress('Uploading '+file.name+' ('+fmtMB(file.size)+')…');
  hideResults();

  let jobId;
  try{
    const r=await fetch('/api/pcap/upload?filename='+encodeURIComponent(file.name),{
      method:'POST',
      headers:{'Content-Type':'application/octet-stream'},
      body:file
    });
    const j=await r.json();
    if(!j.job_id){showError(j.error||'Upload failed');return;}
    jobId=j.job_id;
  }catch(e){showError('Upload error: '+e);return;}

  setProgress('Analysing with tshark — this may take a moment…');
  pollStatus(jobId);
}

function fmtMB(b){return (b/1048576).toFixed(1)+' MB';}

async function pollStatus(jobId){
  for(let i=0;i<120;i++){
    await new Promise(r=>setTimeout(r,1500));
    try{
      const s=await fetch('/api/pcap/status?id='+jobId).then(r=>r.json());
      if(s.status==='ready'){hideProgress();renderResults(s.result);return;}
      if(s.status==='error'){showError(s.error||'Analysis failed');return;}
    }catch(_){}
  }
  showError('Analysis timed out.');
}

// ── render ────────────────────────────────────────────────────────────────────
function renderResults(r){
  hideError();

  // Summary
  const sum=r.summary;
  document.getElementById('summaryCards').innerHTML=`
    <div class="card"><div class="label">File</div><div class="value" style="font-size:14px">${esc(sum.filename)}</div></div>
    <div class="card"><div class="label">Total Packets</div><div class="value">${sum.total_packets.toLocaleString()}</div></div>
    <div class="card"><div class="label">Duration</div><div class="value">${sum.duration_s}s</div></div>
    <div class="card"><div class="label">Devices</div><div class="value">${r.devices.length}</div></div>
    <div class="card"><div class="label">DNS queries</div><div class="value">${r.dns.length}</div></div>
    <div class="card"><div class="label">TLS handshakes</div><div class="value">${r.tls.length}</div></div>
  `;

  // Devices
  const db=document.getElementById('devBody');
  db.innerHTML=r.devices.map(d=>{
    const nTag=d.nintendo?`<span class="tag nintendo">Nintendo</span> `:'';
    const vTag=d.vendor?`<span class="tag vendor">${esc(d.vendor)}</span>`:'<span class="dim">—</span>';
    const ports=d.open_ports.length
      ? d.open_ports.map(p=>`<span class="tag open">${esc(p)}</span>`).join(' ')
      : '<span class="dim">none (all RST)</span>';
    return `<tr>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono">${esc(d.mac)||'—'}</td>
      <td>${nTag}${vTag}</td>
      <td style="text-align:right">${fmtPkts(d.packet_count)}</td>
      <td>${ports}</td>
    </tr>`;
  }).join('');

  // DNS
  const dnsB=document.getElementById('dnsBody');
  if(r.dns.length===0){
    document.getElementById('dnsEmpty').style.display='block';
    document.getElementById('dnsTable').style.display='none';
  } else {
    document.getElementById('dnsEmpty').style.display='none';
    document.getElementById('dnsTable').style.display='';
    dnsB.innerHTML=r.dns.map(d=>{
      const tag=d.nintendo?`<span class="tag nintendo">Nintendo</span>`:'';
      return `<tr>
        <td class="mono">${esc(d.query)}</td>
        <td class="mono">${esc(d.src_ip)}</td>
        <td class="mono">${esc(d.server_ip)}</td>
        <td class="mono">${esc(d.resolved_ip)||'—'}</td>
        <td style="text-align:right">${fmtLat(d.latency_ms)}</td>
        <td>${tag}</td>
      </tr>`;
    }).join('');
  }

  // TLS
  const tlsB=document.getElementById('tlsBody');
  if(r.tls.length===0){
    document.getElementById('tlsEmpty').style.display='block';
    document.getElementById('tlsTable').style.display='none';
  } else {
    document.getElementById('tlsEmpty').style.display='none';
    document.getElementById('tlsTable').style.display='';
    tlsB.innerHTML=r.tls.map(t=>{
      const tag=t.nintendo?`<span class="tag nintendo">Nintendo</span>`:'';
      return `<tr>
        <td class="mono">${esc(t.server_name)}</td>
        <td class="mono">${esc(t.src_ip)}</td>
        <td class="mono">${esc(t.dst_ip)}</td>
        <td style="text-align:right">${fmtLat(t.latency_ms)}</td>
        <td>${tag}</td>
      </tr>`;
    }).join('');
  }

  document.getElementById('results').style.display='block';
}

function showProgress(msg){
  document.getElementById('dropzone').style.display='none';
  document.getElementById('progress').style.display='block';
  document.getElementById('progressMsg').textContent=msg;
}
function setProgress(msg){document.getElementById('progressMsg').textContent=msg;}
function hideProgress(){
  document.getElementById('progress').style.display='none';
  document.getElementById('dropzone').style.display='block';
}
function showError(msg){
  document.getElementById('errorBox').textContent=msg;
  document.getElementById('errorBox').style.display='block';
  hideProgress();
}
function hideError(){document.getElementById('errorBox').style.display='none';}
function hideResults(){document.getElementById('results').style.display='none';}
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
            if not _check_read_auth(self.headers):
                self._send_json({"error": "unauthorized — set X-Read-Token header"}, 401)
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
                self._send_json({"error": "unauthorized — set X-Read-Token header"}, 401)
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

        if path == "/api/nmap/status":
            target = parse_qs(parsed.query).get("target", [""])[0].strip()
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            with _nmap_lock:
                state = _nmap_state.get(target, {"status": "unknown", "output": "", "error": None})
            self._send_json(state)
            return

        if path == "/api/connections/status":
            self._send_json({"connected": True, "status": "ok"})
            return

        if path.startswith("/api/connections/status/"):
            target = path.removeprefix("/api/connections/status/").strip()
            try:
                r = subprocess.run(
                    ["ping", "-c", "3", "-W", "2", target],
                    capture_output=True, text=True, timeout=10
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
                self._send_json({
                    "connected": connected,
                    "target": target,
                    "latency_ms": latency_ms,
                    "avg_latency_ms": avg_latency_ms,
                })
            except Exception as exc:
                self._send_json({"connected": False, "target": target, "error": str(exc)})
            return

        if path == "/api/deep-inspect/history":
            files = sorted(SERVE_DIR.glob("deep-inspect-*.html"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
            result = []
            for f in files[:20]:
                ip = f.name.removeprefix("deep-inspect-").removesuffix(".html")
                result.append({
                    "capture_id": ip,
                    "target_ip": ip,
                    "timestamp": int(f.stat().st_mtime * 1000),
                    "report_url": f"/{f.name}",
                })
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
                            "FROM flows WHERE src_ip=? OR dst_ip=?", (target, target)
                        ).fetchone()
                        packet_count = row["p"]
                        byte_count   = row["b"]
                        if byte_count > 0:
                            bandwidth_mbps = round(byte_count * 8 / 1_000_000, 2)
                        proto_rows = cur.execute(
                            "SELECT COALESCE(protocol,'Other') AS protocol, "
                            "COUNT(*) AS cnt FROM flows "
                            "WHERE src_ip=? OR dst_ip=? GROUP BY protocol ORDER BY cnt DESC",
                            (target, target)
                        ).fetchall()
                        total_flows = sum(r["cnt"] for r in proto_rows) or 1
                        protocols = [{"protocol": r["protocol"],
                                      "count": r["cnt"],
                                      "percentage": round(r["cnt"] * 100 / total_flows, 1)}
                                     for r in proto_rows]
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
                            "WHERE src_ip=? ORDER BY created_at DESC LIMIT 10", (target,)
                        ).fetchall():
                            alerts.append(f"[{er['level']}] {er['alert_type']}")
                            if er["description"]:
                                findings.append(er["description"])
                    finally:
                        econ.close()

                # Latency via ping
                latency_ms = None
                hop_count  = None
                pr = subprocess.run(
                    ["ping", "-c", "3", "-W", "2", target],
                    capture_output=True, text=True, timeout=10
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

                self._send_json({
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
                        if (SERVE_DIR / f"deep-inspect-{target}.html").exists() else None,
                })
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
            body = _render_history_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/pcap/status":
            job_id = parse_qs(parsed.query).get("id", [""])[0].strip()
            if not job_id:
                self._send_json({"error": "id required"}, 400)
                return
            with _pcap_lock:
                state = _pcap_state.get(job_id, {"status": "unknown", "result": None, "error": None})
            self._send_json(state)
            return

        if path == "/pcap.html":
            body = _render_pcap_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
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
            ports  = qs.get("ports",  [""])[0].strip()
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
            ports  = body.get("ports", "").strip()
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
            row_id  = body.get("id")
            pinned  = int(bool(body.get("pinned", 1)))
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
                        new_exp = (datetime.now(timezone.utc) + timedelta(days=_RETENTION_DAYS)).isoformat()
                        hc.execute(
                            "UPDATE flow_history SET pinned=0, expires_at=? WHERE id=?",
                            (new_exp, row_id),
                        )
                    hc.commit()
                    row = hc.execute(
                        "SELECT expires_at FROM flow_history WHERE id=?", (row_id,)
                    ).fetchone()
                    expires_at = row["expires_at"] if row else None
                self._send_json({"ok": True, "pinned": pinned, "expires_at": expires_at})
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
            job_id  = str(_uuid.uuid4())
            tmp_path = tmp_dir / f"{job_id}_{safe_name}"
            try:
                data = self.rfile.read(length)
                tmp_path.write_bytes(data)
            except Exception as exc:
                self._send_json({"error": f"Write failed: {exc}"}, 500)
                return
            with _pcap_lock:
                _pcap_state[job_id] = {"status": "running", "result": None, "error": None}
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
                aliases  = _load_aliases()
                verified = _load_verified()
                for d in devices:
                    d["ip_category"] = _classify_ip(d.get("ip", ""))
                    d["label"]    = aliases.get(d.get("ip", ""), "")
                    d["verified"] = verified.get(d.get("ip", ""), False)
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
