"""Connection report: capture LAN outgoing flows and render as table/CSV/HTML."""
from __future__ import annotations

import csv
import html
import io
import ipaddress
import json
import logging
import pwd
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Service name lookup
# ---------------------------------------------------------------------------

_SERVICE_MAP: dict[int, str] = {
    20: "FTP-data",   21: "FTP",        22: "SSH",         23: "Telnet",
    25: "SMTP",       53: "DNS",        67: "DHCP",        68: "DHCP",
    69: "TFTP",       80: "HTTP",       110: "POP3",       119: "NNTP",
    123: "NTP",       143: "IMAP",      161: "SNMP",       162: "SNMP-trap",
    179: "BGP",       194: "IRC",       389: "LDAP",       443: "HTTPS",
    445: "SMB",       465: "SMTPS",     514: "Syslog",     515: "LPD",
    587: "SMTP",      636: "LDAPS",     993: "IMAPS",      995: "POP3S",
    1080: "SOCKS",    1194: "OpenVPN",  1433: "MSSQL",     1723: "PPTP",
    3306: "MySQL",    3389: "RDP",      4443: "HTTPS-alt", 5222: "XMPP",
    5353: "mDNS",     5432: "PostgreSQL", 5900: "VNC",     6379: "Redis",
    6881: "BitTorrent", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Descriptive application names by port (shown when no process info available)
_APP_MAP: dict[int, str] = {
    20: "FTP Data Transfer",      21: "FTP Client",
    22: "SSH / SFTP",             23: "Telnet Client",
    25: "Mail (SMTP)",            53: "DNS Query",
    67: "DHCP Client",            68: "DHCP Client",
    80: "Web Browser (HTTP)",     110: "Mail Client (POP3)",
    123: "Time Sync (NTP)",       143: "Mail Client (IMAP)",
    161: "Network Mgmt (SNMP)",   389: "Directory (LDAP)",
    443: "Web Browser (HTTPS)",   445: "File Share (SMB)",
    465: "Secure Mail (SMTPS)",   587: "Mail Submission",
    636: "Secure Directory",      993: "Secure Mail (IMAP)",
    995: "Secure Mail (POP3)",    1080: "SOCKS Proxy",
    1194: "VPN (OpenVPN)",        1433: "Database (MSSQL)",
    3306: "Database (MySQL)",     3389: "Remote Desktop (RDP)",
    4443: "Web Browser (HTTPS)",  5222: "Chat (XMPP)",
    5353: "Local Discovery",      5432: "Database (PostgreSQL)",
    5900: "Remote Desktop (VNC)", 6379: "Cache (Redis)",
    6881: "P2P (BitTorrent)",     8080: "Web Browser (HTTP)",
    8443: "Web Browser (HTTPS)",  9200: "Search (Elasticsearch)",
    27017: "Database (MongoDB)",
}


def _service_name(port: int | None) -> str:
    if port is None:
        return "—"
    if port in _SERVICE_MAP:
        return _SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return str(port)


def _app_from_port(port: int | None) -> str:
    """Descriptive application name derived from port number."""
    if port is None:
        return "—"
    return _APP_MAP.get(port, f"Port {port} App")


def _resolve_protocol(tshark_proto: str | None, port: int | None) -> str:
    """Return a meaningful protocol name.

    Prefers tshark's dissected name (DNS, TLS, QUIC, HTTP, NTP …).
    Falls back to service/port lookup when tshark only says TCP or UDP.
    """
    if tshark_proto and tshark_proto not in ("TCP", "UDP", "Unknown", ""):
        return tshark_proto
    svc = _SERVICE_MAP.get(port) if port else None
    if svc:
        transport = tshark_proto if tshark_proto in ("TCP", "UDP") else "TCP"
        return f"{svc}/{transport}"
    return tshark_proto or "Unknown"


# ---------------------------------------------------------------------------
# Hostname lookup from inventory
# ---------------------------------------------------------------------------

_INVENTORY_PATH = Path("/var/lib/netwatchm/inventory.json")


def _load_hostnames(path: Path = _INVENTORY_PATH) -> dict[str, str]:
    """Return {ip: hostname} from the persisted inventory JSON."""
    try:
        data = json.loads(path.read_text())
        return {
            item["ip"]: item["hostname"]
            for item in data
            if item.get("hostname")
        }
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


# ---------------------------------------------------------------------------
# Process / user lookup (Linux only, via ss -tupn)
# ---------------------------------------------------------------------------

@dataclass
class _ProcInfo:
    app_name: str
    username: str


def _get_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _snapshot_connections() -> dict[tuple[str, int], _ProcInfo]:
    """Run `ss -tupn` and return {(dst_ip, dst_port): _ProcInfo}."""
    if sys.platform == "win32":
        return {}
    mapping: dict[tuple[str, int], _ProcInfo] = {}
    try:
        result = subprocess.run(
            ["ss", "-tupn"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return mapping

    pid_re = re.compile(r'pid=(\d+)')
    addr_re = re.compile(r'(\S+):(\d+)\s+(\S+):(\d+)')

    for line in result.stdout.splitlines()[1:]:
        addr_match = addr_re.search(line)
        if not addr_match:
            continue
        dst_ip = addr_match.group(3)
        try:
            dst_port = int(addr_match.group(4))
        except ValueError:
            continue

        pid_match = pid_re.search(line)
        if not pid_match:
            continue
        pid = int(pid_match.group(1))

        # Prefer full cmdline argv[0] over comm (truncated at 15 chars)
        app_name = "?"
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
            if cmdline:
                argv0 = cmdline[0].decode(errors="replace")
                app_name = Path(argv0).name or argv0  # basename only
        except OSError:
            try:
                app_name = Path(f"/proc/{pid}/comm").read_text().strip()
            except OSError:
                pass

        uid = None
        try:
            for status_line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if status_line.startswith("Uid:"):
                    uid = int(status_line.split()[1])
                    break
        except OSError:
            pass

        username = _get_username(uid) if uid is not None else "?"
        mapping[(dst_ip, dst_port)] = _ProcInfo(app_name=app_name, username=username)

    return mapping


# ---------------------------------------------------------------------------
# FlowRecord
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    src_ip: str
    src_hostname: str       # from inventory; "—" if not resolved
    dst_ip: str
    dst_port: int | None
    protocol: str           # dissected protocol name (DNS, TLS, QUIC, HTTP …)
    service: str            # port-based service name
    domain: str             # SNI / HTTP host / DNS name; "—" if unknown
    app_name: str           # process name (local) or port-based name (remote)
    username: str           # logged-in user (local machine only; "—" = remote)
    packet_count: int = 0
    bytes_total: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


# ---------------------------------------------------------------------------
# Flow capture (blocking subprocess)
# ---------------------------------------------------------------------------

_REPORT_FIELDS = [
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.dstport",
    "-e", "udp.dstport",
    "-e", "frame.len",
    "-e", "ip.proto",
    "-e", "_ws.col.Protocol",
    "-e", "tls.handshake.extensions_server_name",
    "-e", "http.host",
    "-e", "dns.qry.name",
]


def _first(val: list | str | None) -> str | None:
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _parse_report_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    layers = obj.get("layers")
    if not layers:
        return None
    return layers


def capture_flows(
    interface: str,
    duration: int = 30,
    network: str = "192.168.1.0/24",
) -> list[FlowRecord]:
    """Run tshark for `duration` seconds, return aggregated FlowRecords sorted by bytes desc."""

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.error("Invalid network CIDR: %s", network)
        net = ipaddress.ip_network("192.168.1.0/24")

    # Load hostname map and process snapshot before capture
    hostnames = _load_hostnames()
    proc_map = _snapshot_connections()

    cmd = [
        "tshark",
        "-i", interface,
        "-T", "ek",
        "-q",
        "-a", f"duration:{duration}",
        "-f", f"src net {network}",
        *_REPORT_FIELDS,
    ]
    logger.debug("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30,
        )
        output = result.stdout
    except FileNotFoundError:
        logger.error("tshark not found. Install tshark/wireshark-cli.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("tshark timed out.")
        return []
    except OSError as exc:
        logger.error("Failed to run tshark: %s", exc)
        return []

    flows: dict[tuple, FlowRecord] = {}
    domain_hints: dict[tuple, str] = {}

    for line in output.splitlines():
        layers = _parse_report_line(line)
        if layers is None:
            continue

        def _str(key: str) -> str | None:
            v = _first(layers.get(key))
            return str(v) if v is not None else None

        def _int(key: str) -> int | None:
            v = _first(layers.get(key))
            if v is None:
                return None
            try:
                return int(v)
            except (ValueError, TypeError):
                return None

        def _float(key: str) -> float | None:
            v = _first(layers.get(key))
            if v is None:
                return None
            try:
                return float(v)
            except (ValueError, TypeError):
                return None

        src_ip = _str("ip_src")
        dst_ip = _str("ip_dst")
        if src_ip is None or dst_ip is None:
            continue

        try:
            if ipaddress.ip_address(src_ip) not in net:
                continue
        except ValueError:
            continue

        dst_port = _int("tcp_dstport") or _int("udp_dstport")
        tshark_proto = _str("_ws_col_Protocol")
        proto = _resolve_protocol(tshark_proto, dst_port)
        length = _int("frame_len") or 0
        ts = _float("frame_time_epoch") or 0.0

        flow_key = (src_ip, dst_ip, dst_port, proto)
        hint_key = (src_ip, dst_ip, dst_port)

        sni = _str("tls_handshake_extensions_server_name")
        http_host = _str("http_host")
        dns_name = _str("dns_qry_name")
        domain = sni or http_host or dns_name
        if domain and hint_key not in domain_hints:
            domain_hints[hint_key] = domain

        if flow_key not in flows:
            proc = proc_map.get((dst_ip, dst_port)) if dst_port else None
            src_hostname = hostnames.get(src_ip, "—")
            # App name: process name (local) → port-based description (remote)
            app_name = proc.app_name if proc else _app_from_port(dst_port)
            username = proc.username if proc else "— (remote)"
            flows[flow_key] = FlowRecord(
                src_ip=src_ip,
                src_hostname=src_hostname,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=_service_name(dst_port),
                domain="—",
                app_name=app_name,
                username=username,
                first_seen=ts,
                last_seen=ts,
            )

        rec = flows[flow_key]
        rec.packet_count += 1
        rec.bytes_total += length
        if ts < rec.first_seen:
            rec.first_seen = ts
        if ts > rec.last_seen:
            rec.last_seen = ts

    for flow_key, rec in flows.items():
        hint_key = (flow_key[0], flow_key[1], flow_key[2])
        if hint_key in domain_hints:
            rec.domain = domain_hints[hint_key]

    return sorted(flows.values(), key=lambda r: r.bytes_total, reverse=True)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


def _fmt_ts(ts: float) -> str:
    if ts == 0.0:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def render_table(flows: list[FlowRecord]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"Connection Report — {len(flows)} flows", show_lines=False)
    table.add_column("Src IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("Dst IP", style="yellow")
    table.add_column("Port", justify="right")
    table.add_column("Protocol")
    table.add_column("Domain / SNI")
    table.add_column("Application")
    table.add_column("User")
    table.add_column("Pkts", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("First")
    table.add_column("Last")

    for rec in flows:
        table.add_row(
            rec.src_ip,
            rec.src_hostname,
            rec.dst_ip,
            str(rec.dst_port) if rec.dst_port is not None else "—",
            rec.protocol,
            rec.domain,
            rec.app_name,
            rec.username,
            str(rec.packet_count),
            _fmt_bytes(rec.bytes_total),
            _fmt_ts(rec.first_seen),
            _fmt_ts(rec.last_seen),
        )

    console.print(table)


def render_csv(flows: list[FlowRecord], output: str | None) -> None:
    fieldnames = [
        "src_ip", "src_hostname", "dst_ip", "dst_port", "protocol", "service",
        "domain", "app_name", "username", "packet_count", "bytes_total",
        "first_seen", "last_seen",
    ]

    def _write(f: IO[str]) -> None:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in flows:
            writer.writerow({
                "src_ip": rec.src_ip,
                "src_hostname": rec.src_hostname,
                "dst_ip": rec.dst_ip,
                "dst_port": rec.dst_port if rec.dst_port is not None else "",
                "protocol": rec.protocol,
                "service": rec.service,
                "domain": rec.domain,
                "app_name": rec.app_name,
                "username": rec.username,
                "packet_count": rec.packet_count,
                "bytes_total": rec.bytes_total,
                "first_seen": _fmt_ts(rec.first_seen),
                "last_seen": _fmt_ts(rec.last_seen),
            })

    if output is None or output == "-":
        _write(sys.stdout)
    else:
        with open(output, "w", newline="") as f:
            _write(f)
        print(f"CSV saved to {output}")


def render_html(
    flows: list[FlowRecord],
    output: str | None,
    network: str = "192.168.1.0/24",
    duration: int = 30,
) -> None:
    total_packets = sum(r.packet_count for r in flows)
    total_bytes = sum(r.bytes_total for r in flows)
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _esc(s: str) -> str:
        return html.escape(str(s))

    rows_html = io.StringIO()
    for rec in flows:
        rows_html.write(
            f"<tr>"
            f"<td><div>{_esc(rec.src_ip)}</div>"
            f"<div style='color:var(--muted);font-size:11px'>{_esc(rec.src_hostname)}</div></td>"
            f"<td>{_esc(rec.dst_ip)}</td>"
            f"<td class='num'>{_esc(str(rec.dst_port) if rec.dst_port is not None else '—')}</td>"
            f"<td><span class='proto-badge'>{_esc(rec.protocol)}</span></td>"
            f"<td>{_esc(rec.domain)}</td>"
            f"<td>{_esc(rec.app_name)}</td>"
            f"<td>{_esc(rec.username)}</td>"
            f"<td class='num'>{rec.packet_count}</td>"
            f"<td class='num' data-bytes='{rec.bytes_total}'>{_esc(_fmt_bytes(rec.bytes_total))}</td>"
            f"<td>{_esc(_fmt_ts(rec.first_seen))}</td>"
            f"<td>{_esc(_fmt_ts(rec.last_seen))}</td>"
            f"<td><button class=\"inv-btn\""
            f" data-src=\"{_esc(rec.src_ip)}\""
            f" data-srch=\"{_esc(rec.src_hostname)}\""
            f" data-dst=\"{_esc(rec.dst_ip)}\""
            f" data-port=\"{rec.dst_port if rec.dst_port is not None else ''}\""
            f" data-svc=\"{_esc(rec.service)}\""
            f" data-proto=\"{_esc(rec.protocol)}\""
            f" data-domain=\"{_esc(rec.domain)}\""
            f" data-app=\"{_esc(rec.app_name)}\""
            f" onclick=\"openInvestigate(this)\">&#x1F50D; Investigate</button></td>"
            f"</tr>\n"
        )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatchM Connection Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: monospace; font-size: 13px; padding: 24px; }}
  h1 {{ color: var(--accent); font-size: 20px; margin-bottom: 8px; }}
  .meta {{ color: var(--muted); margin-bottom: 20px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px 20px; }}
  .stat-label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
  .stat-value {{ color: var(--accent); font-size: 22px; font-weight: bold; margin-top: 4px; }}
  .toolbar {{ display:flex; flex-direction:column; gap:8px; margin-bottom:12px; }}
  .toolbar-row {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .toolbar-row.ext-row {{ justify-content:center; padding-left:200px; }}
  .toolbar input {{
    background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 4px; width: 280px; font-family: monospace;
  }}
  .toolbar button {{
    background: var(--accent); color: #fff; border: none; padding: 7px 16px;
    border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600;
  }}
  .toolbar select {{
    background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 6px 10px; border-radius: 4px; font-family: monospace; font-size: 12px;
    cursor: pointer;
  }}
  #refresh-countdown {{ color: var(--muted); font-size: 11px; white-space: nowrap; }}
  .dash-group {{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; }}
  .ext-btn {{ background:rgba(188,140,255,.15); color:#bc8cff; border:1px solid rgba(188,140,255,.35);
    border-radius:4px; padding:7px 14px; font-size:13px; font-weight:600; cursor:pointer;
    text-decoration:none; white-space:nowrap; }}
  .ext-btn:hover {{ opacity:.85; }}
  .toggle-wrap {{ display:flex; align-items:center; gap:5px; font-size:11px; color:var(--muted); white-space:nowrap; }}
  .toggle-wrap input[type=checkbox] {{ appearance:none; width:30px; height:16px;
    background:var(--border); border-radius:8px; cursor:pointer; position:relative; transition:background .2s; }}
  .toggle-wrap input[type=checkbox]:checked {{ background:#bc8cff; }}
  .toggle-wrap input[type=checkbox]::after {{ content:''; position:absolute; width:12px; height:12px;
    background:#fff; border-radius:50%; top:2px; left:2px; transition:left .2s; }}
  .toggle-wrap input[type=checkbox]:checked::after {{ left:16px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: var(--surface); color: var(--muted); text-transform: uppercase;
    font-size: 11px; padding: 8px 10px; text-align: left; border-bottom: 2px solid var(--border);
    cursor: pointer; user-select: none; white-space: nowrap;
  }}
  th:hover {{ color: var(--accent); }}
  th.sort-asc::after {{ content: " ▲"; }}
  th.sort-desc::after {{ content: " ▼"; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  tr:hover td {{ background: var(--surface); }}
  .num {{ text-align: right; }}
  .proto-badge {{
    background: rgba(88,166,255,0.12); color: var(--accent);
    border: 1px solid rgba(88,166,255,0.3); border-radius: 4px;
    padding: 1px 7px; font-size: 11px; font-weight: 600; white-space: nowrap;
  }}
  .inv-btn {{
    background: rgba(88,166,255,0.08); color: var(--accent);
    border: 1px solid rgba(88,166,255,0.25); border-radius: 4px;
    padding: 2px 8px; font-size: 11px; cursor: pointer; font-family: monospace;
  }}
  .inv-btn:hover {{ background: rgba(88,166,255,0.2); }}
  .inv-overlay {{
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,0.75); z-index: 1000;
    align-items: center; justify-content: center;
  }}
  .inv-overlay.active {{ display: flex; }}
  .inv-modal {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 24px; max-width: 620px; width: 90%;
    position: relative;
  }}
  .inv-modal h3 {{ color: var(--accent); margin-bottom: 16px; font-size: 16px; }}
  .inv-modal h4 {{ color: var(--muted); font-size: 11px; text-transform: uppercase; margin: 14px 0 8px; }}
  .inv-close {{
    position: absolute; top: 12px; right: 14px;
    background: none; border: none; color: var(--muted);
    font-size: 20px; cursor: pointer; line-height: 1;
  }}
  .inv-close:hover {{ color: var(--text); }}
  .inv-detail-table {{ width: 100%; border-collapse: collapse; margin-bottom: 4px; }}
  .inv-detail-table th {{
    color: var(--muted); font-size: 11px; text-align: left;
    padding: 4px 8px 4px 0; width: 160px; font-weight: normal;
  }}
  .inv-detail-table td {{ color: var(--text); font-size: 13px; padding: 4px 0; }}
  .inv-targets {{ display: flex; gap: 10px; margin-bottom: 12px; }}
  .inv-targets button {{
    flex: 1; background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: 8px 12px; border-radius: 4px;
    cursor: pointer; font-family: monospace; font-size: 12px;
  }}
  .inv-targets button.active {{
    border-color: var(--accent); color: var(--accent);
    background: rgba(88,166,255,0.1);
  }}
  .inv-cmd-box {{
    background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
    padding: 10px 12px; display: flex; align-items: center; gap: 8px;
    margin-bottom: 8px;
  }}
  .inv-cmd-box code {{ flex: 1; color: #7ee787; font-size: 12px; word-break: break-all; }}
  .inv-cmd-box button {{
    background: var(--surface); border: 1px solid var(--border);
    color: var(--muted); padding: 4px 10px; border-radius: 4px;
    cursor: pointer; font-size: 11px; white-space: nowrap;
  }}
  .inv-cmd-box button:hover {{ color: var(--accent); }}
  .inv-note {{ color: var(--muted); font-size: 11px; }}
  .inv-deep {{ background: rgba(63,185,80,0.15); border-color: #3fb950; color: #3fb950; }}
  .inv-deep:hover {{ background: rgba(63,185,80,0.25); }}
  .inv-sep {{ font-size: 11px; color: var(--muted); text-align: center; margin: 8px 0 4px; }}
  .inv-context {{
    background: rgba(88,166,255,0.05); border: 1px solid var(--border);
    border-radius: 4px; padding: 10px 12px; margin: 12px 0; font-size: 12px; line-height: 1.6;
  }}
  .ctx-traffic {{ color: var(--muted); margin-bottom: 4px; }}
  .ctx-what {{ color: var(--text); margin-bottom: 8px; }}
  .ctx-risk {{
    display: inline-block; font-size: 10px; font-weight: 700;
    padding: 2px 8px; border-radius: 3px; margin-bottom: 6px; text-transform: uppercase;
  }}
  .ctx-risk.low {{ background: rgba(46,160,67,0.2); color: #3fb950; }}
  .ctx-risk.medium {{ background: rgba(210,153,34,0.2); color: #d29922; }}
  .ctx-risk.high {{ background: rgba(248,81,73,0.2); color: #f85149; }}
  .ctx-action {{ color: var(--muted); font-style: italic; margin-top: 4px; font-size: 11px; }}
</style>
</head>
<body>
<h1>NetWatchM — Connection Report</h1>
<div class="meta">Network: {_esc(network)} &nbsp;|&nbsp; Duration: {duration}s &nbsp;|&nbsp; Generated: {generated_at}</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Flows</div><div class="stat-value">{len(flows)}</div></div>
  <div class="stat"><div class="stat-label">Packets</div><div class="stat-value">{total_packets:,}</div></div>
  <div class="stat"><div class="stat-label">Total Data</div><div class="stat-value">{_esc(_fmt_bytes(total_bytes))}</div></div>
</div>
<div class="toolbar">
  <div class="toolbar-row">
    <input type="text" id="search" placeholder="Filter rows…" oninput="filterTable()" />
    <button onclick="exportCSV()">⬇ Download CSV</button>
    <button id="analytics-btn" onclick="openAnalytics()" style="background:rgba(88,166,255,.15);color:#58a6ff;border-color:#58a6ff55">&#x1F4CA; Analytics</button>
    <a href="/reports" target="_blank" style="background:rgba(88,166,255,.08);color:#58a6ff;border:1px solid rgba(88,166,255,.25);border-radius:4px;padding:7px 14px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap">&#x1F4C1; History</a>
    <a href="/inventory.html" style="background:rgba(63,185,80,.08);color:#3fb950;border:1px solid rgba(63,185,80,.25);border-radius:4px;padding:7px 14px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap">&#x1F4F1; Inventory</a>
    <a href="/history.html" style="background:rgba(88,166,255,.08);color:#58a6ff;border:1px solid rgba(88,166,255,.25);border-radius:4px;padding:7px 14px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap">&#x23F1; History</a>
    <button id="refresh-btn" onclick="triggerRefresh()" style="background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.35)">&#x21BB; Refresh</button>
    <select id="auto-refresh" onchange="setAutoRefresh(this.value)">
      <option value="0">Auto: Off</option>
      <option value="60">Auto: 1 min</option>
      <option value="300">Auto: 5 min</option>
      <option value="600">Auto: 10 min</option>
    </select>
    <span id="refresh-countdown"></span>
  </div>
  <div class="toolbar-row ext-row">
    <a class="ext-btn" href="http://localhost:3000" onclick="return openLink('http://localhost:3000',event)">&#x1F4CA; Dashboard</a>
    <a class="ext-btn" href="http://localhost:3000/d/netwatchm-inventory/" onclick="return openLink('http://localhost:3000/d/netwatchm-inventory/',event)">&#x1F4F2; Inventory Dashboard</a>
    <a class="ext-btn" href="https://localhost:8765/" onclick="return openLink('https://localhost:8765/',event)">&#x1F3E0; NetWatchM</a>
    <label class="toggle-wrap" title="Open links in new tab or same page">
      <input type="checkbox" id="dash-newtab" onchange="saveDashPref(this.checked)">
      New tab
    </label>
  </div>
</div>
<table id="flows-table">
<thead>
<tr>
  <th onclick="sortTable(0)">Src IP / Hostname</th>
  <th onclick="sortTable(1)">Dst IP</th>
  <th onclick="sortTable(2)" class="num">Port</th>
  <th onclick="sortTable(3)">Protocol</th>
  <th onclick="sortTable(4)">Domain / SNI</th>
  <th onclick="sortTable(5)">Application</th>
  <th onclick="sortTable(6)">User</th>
  <th onclick="sortTable(7)" class="num">Pkts</th>
  <th onclick="sortTable(8)" class="num">Bytes</th>
  <th onclick="sortTable(9)">First</th>
  <th onclick="sortTable(10)">Last</th>
  <th>Actions</th>
</tr>
</thead>
<tbody>
{rows_html.getvalue()}</tbody>
</table>
<script>
const REPORT_DURATION = {duration};
const REPORT_NETWORK  = "{_esc(network)}";

// ── External link buttons: shared new-tab toggle ─────────────────────────
(function() {{
  const chk = document.getElementById('dash-newtab');
  const saved = localStorage.getItem('netwatchm_dash_newtab');
  chk.checked = saved === null ? true : saved === 'true';
}})();

function saveDashPref(val) {{
  localStorage.setItem('netwatchm_dash_newtab', val);
}}

function openLink(url, e) {{
  const newTab = document.getElementById('dash-newtab').checked;
  if (newTab) {{ window.open(url, '_blank'); }}
  else {{ window.location.href = url; }}
  return false;
}}

let sortCol = 8, sortAsc = false;

function cellVal(row, col) {{
  const td = row.cells[col];
  if (col === 8) return parseInt(td.dataset.bytes || '0', 10);
  const n = parseFloat(td.textContent);
  return isNaN(n) ? td.textContent.trim().toLowerCase() : n;
}}

function sortTable(col) {{
  const table = document.getElementById('flows-table');
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const ths = table.tHead.rows[0].cells;
  if (sortCol === col) {{ sortAsc = !sortAsc; }}
  else {{ sortCol = col; sortAsc = true; }}
  for (let th of ths) th.className = th.className.replace(/sort-\\w+/g, '').trim();
  ths[col].className += (sortAsc ? ' sort-asc' : ' sort-desc');
  if ([2,7,8].includes(col)) ths[col].className += ' num';
  rows.sort((a, b) => {{
    const av = cellVal(a, col), bv = cellVal(b, col);
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ? 1 : -1;
    return 0;
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

function filterTable() {{
  const q = document.getElementById('search').value.toLowerCase();
  const rows = document.getElementById('flows-table').tBodies[0].rows;
  for (let row of rows) {{
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }}
}}

function exportCSV() {{
  const table = document.getElementById('flows-table');
  const colCount = table.tHead.rows[0].cells.length - 1; // exclude Actions column
  const headers = Array.from(table.tHead.rows[0].cells).slice(0, colCount).map(th => th.textContent.trim());
  const rows = [headers.join(',')];
  for (const row of table.tBodies[0].rows) {{
    if (row.style.display === 'none') continue;
    const cells = Array.from(row.cells).slice(0, colCount).map(td => {{
      const v = td.textContent.trim().replace(/\\s+/g, ' ');
      return (v.includes(',') || v.includes('"') || v.includes('\\n'))
        ? '"' + v.replace(/"/g, '""') + '"' : v;
    }});
    rows.push(cells.join(','));
  }}
  const blob = new Blob([rows.join('\\n')], {{type: 'text/csv'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'connection-report.csv';
  a.click();
}}

let _invSrcIp = '', _invDstIp = '', _invPort = '';

const PORT_INFO = {{
  1900:  {{ what: 'SSDP (UPnP device discovery). Devices broadcast this to find services like printers, media servers, and smart home hubs on the local network.', risk: 'low', action: 'Normal for smart devices. Investigate if sent to an external IP or from an unexpected host.' }},
  5353:  {{ what: 'mDNS (Multicast DNS). Used for zero-config name resolution — Apple Bonjour, Avahi, Chromecast, printers.', risk: 'low', action: 'Normal LAN traffic. External mDNS leakage indicates a firewall misconfiguration.' }},
  443:   {{ what: 'HTTPS — TLS-encrypted web and API traffic. Extremely common for browsers, background services, and apps.', risk: 'low', action: 'Check the Domain / SNI column to confirm the destination hostname is expected.' }},
  80:    {{ what: 'HTTP — unencrypted web traffic. Less common today since most services enforce HTTPS.', risk: 'medium', riskReason: 'Credentials and data travel in plaintext', action: 'Verify the app should not be using HTTPS instead.' }},
  53:    {{ what: 'DNS — resolves domain names to IP addresses. Nearly all internet traffic starts here.', risk: 'low', action: 'Flag if the destination is not your router or ISP DNS. Could indicate DNS tunneling or a rogue resolver.' }},
  22:    {{ what: 'SSH — encrypted remote shell and file transfer (SFTP/SCP). Outbound SSH is normal for developers and sysadmins.', risk: 'medium', riskReason: 'Remote shell access — confirm user and destination are authorized', action: 'Confirm the source host and user are expected to have SSH access to this destination.' }},
  3389:  {{ what: 'RDP (Remote Desktop Protocol) — GUI remote access to Windows machines.', risk: 'high', riskReason: 'Remote desktop to external IP — high-value attack vector', action: 'Verify this is an authorized session. External RDP is a top ransomware entry point.' }},
  445:   {{ what: 'SMB — Windows file sharing. Used for mapped drives and printer sharing.', risk: 'high', riskReason: 'SMB to external IP — common vector for lateral movement and data exfiltration', action: 'SMB should never leave your LAN. Investigate immediately if destination is external.' }},
  23:    {{ what: 'Telnet — unencrypted remote shell. Obsolete and insecure; fully replaced by SSH.', risk: 'high', riskReason: 'Credentials and session data sent in plaintext', action: 'Telnet should not exist on modern networks. Identify the device and replace with SSH.' }},
  21:    {{ what: 'FTP — unencrypted file transfer. Legacy protocol; credentials sent in cleartext.', risk: 'high', riskReason: 'Credentials and data sent in plaintext', action: 'Replace with SFTP (port 22) or FTPS. Investigate any external FTP connections.' }},
  25:    {{ what: 'SMTP — email delivery between mail servers. Outbound port 25 from a workstation is unusual.', risk: 'medium', riskReason: 'Direct SMTP from an endpoint — may indicate spam or malware', action: 'Only mail servers should originate port 25 traffic. Investigate if the source is a workstation.' }},
  1194:  {{ what: 'OpenVPN — encrypted VPN tunnel. The source device is connected to a VPN service.', risk: 'low', action: 'Verify this is an authorized VPN from a known user and device.' }},
  4443:  {{ what: 'HTTPS alternate port. Used by VPN services, corporate proxies, and admin panels to avoid standard port filtering.', risk: 'medium', riskReason: 'Non-standard HTTPS port — may bypass firewall rules', action: 'Identify the application and confirm it is an expected service.' }},
  8080:  {{ what: 'HTTP proxy or alternate web port. Used by web proxies, development servers, and some management interfaces.', risk: 'medium', riskReason: 'Unencrypted or proxy traffic on non-standard port', action: 'Confirm this is a known proxy or dev service, not an unauthorized tunnel.' }},
  8443:  {{ what: 'HTTPS alternate port. Common for admin panels, VPN portals, and development servers.', risk: 'low', action: 'Verify the domain matches an expected service.' }},
  1433:  {{ what: 'Microsoft SQL Server — database access port.', risk: 'high', riskReason: 'Database port reachable from network', action: 'Database connections should be local or VPN-only. External access is critical risk.' }},
  3306:  {{ what: 'MySQL — database access port.', risk: 'high', riskReason: 'Database port reachable from network', action: 'Database connections should be local or VPN-only. External access is critical risk.' }},
  5432:  {{ what: 'PostgreSQL — database access port.', risk: 'high', riskReason: 'Database port reachable from network', action: 'Database connections should be local or VPN-only. External access is critical risk.' }},
  6379:  {{ what: 'Redis — in-memory data store. Frequently deployed without authentication.', risk: 'high', riskReason: 'Redis is often unauthenticated and exposes all stored data', action: 'Redis must never be internet-facing. Investigate immediately.' }},
  27017: {{ what: 'MongoDB — NoSQL database port.', risk: 'high', riskReason: 'Database port on network — misconfigured MongoDB has caused major breaches', action: 'Verify this is not publicly accessible. Restrict to localhost or VPN.' }},
  5900:  {{ what: 'VNC — graphical remote desktop. Older protocol, often unencrypted or weakly secured.', risk: 'high', riskReason: 'Remote desktop access, often without strong encryption', action: 'Tunnel VNC over SSH or VPN. Direct exposure is a serious risk.' }},
}};

function getConnectionContext(dstIp, port, domain, app) {{
  const portNum = parseInt(port) || 0;
  const isMulticast = /^2(2[4-9]|3\d)\./.test(dstIp);
  const isBroadcast = dstIp === '255.255.255.255' || dstIp.endsWith('.255');
  const isPrivate   = /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(dstIp);
  const isLoopback  = dstIp.startsWith('127.');
  const isExternal  = !isMulticast && !isBroadcast && !isPrivate && !isLoopback;

  let traffic = '';
  if (isMulticast)     traffic = 'Local multicast — stays within your LAN, never routed to the internet.';
  else if (isBroadcast) traffic = 'Broadcast — delivered to all devices on the local subnet.';
  else if (isLoopback)  traffic = 'Loopback — local machine communication only.';
  else if (isPrivate)   traffic = 'Internal LAN — destination is another device on your local network.';
  else                  traffic = 'External internet — traffic is leaving your network to a public IP address.';

  const info = PORT_INFO[portNum];
  let what = '', risk = 'low', riskReason = '', action = '';

  if (info) {{
    what       = info.what;
    risk       = info.risk || 'low';
    riskReason = info.riskReason || '';
    action     = info.action || '';
  }} else if (portNum >= 30000) {{
    what   = 'High/dynamic port — likely an ephemeral or application-specific port chosen at runtime.';
    risk   = isExternal ? 'medium' : 'low';
    riskReason = isExternal ? 'High port to external IP — verify intended' : '';
    action = 'Check the Application column to identify which process opened this connection.';
  }} else if (portNum > 1024) {{
    what   = 'Registered application port (1025–29999).';
    risk   = isExternal ? 'medium' : 'low';
    riskReason = isExternal ? 'Uncommon port to external IP — verify intended' : '';
    action = 'Confirm this port is expected behavior for the listed application.';
  }} else {{
    what   = 'System/well-known port not in common database.';
    risk   = 'medium';
    action = 'Look up port ' + portNum + ' to understand the expected service.';
  }}

  // Elevate risk: standard-looking ports going external when they shouldn't
  if (isExternal && [445, 1433, 3306, 5432, 6379, 27017, 5900, 23, 21].includes(portNum)) risk = 'high';

  const domainLine = (domain && domain !== '\u2014') ? '<div class="ctx-traffic">Observed domain/SNI: <strong>' + domain + '</strong></div>' : '';
  const appLine    = (app && app !== '\u2014' && app !== '? ') ? '<div class="ctx-traffic">Application: <strong>' + app + '</strong></div>' : '';

  return '<div class="ctx-traffic">' + traffic + '</div>'
       + '<div class="ctx-what">' + what + '</div>'
       + domainLine + appLine
       + '<span class="ctx-risk ' + risk + '">' + risk + ' risk' + (riskReason ? ': ' + riskReason : '') + '</span>'
       + (action ? '<div class="ctx-action">&#9656; ' + action + '</div>' : '');
}}

function openInvestigate(btn) {{
  _invSrcIp = btn.dataset.src;
  _invDstIp = btn.dataset.dst;
  _invPort  = btn.dataset.port;
  const srcLabel = btn.dataset.src + (btn.dataset.srch && btn.dataset.srch !== '\u2014' ? ' (' + btn.dataset.srch + ')' : '');
  document.getElementById('inv-src').textContent   = srcLabel;
  document.getElementById('inv-dst').textContent   = btn.dataset.dst;
  document.getElementById('inv-port').textContent  = btn.dataset.port || '\u2014';
  document.getElementById('inv-proto').textContent = btn.dataset.proto + ' / ' + btn.dataset.svc;
  document.getElementById('inv-context').innerHTML = getConnectionContext(btn.dataset.dst, btn.dataset.port, btn.dataset.domain, btn.dataset.app);
  document.getElementById('inv-src-btn').classList.remove('active');
  document.getElementById('inv-dst-btn').classList.remove('active');
  document.getElementById('inv-status').textContent = '';
  document.getElementById('inv-overlay').classList.add('active');
}}

function closeInvestigate() {{
  document.getElementById('inv-overlay').classList.remove('active');
}}

function setInvTarget(which) {{
  const ip  = which === 'src' ? _invSrcIp : _invDstIp;
  document.getElementById('inv-src-btn').classList.toggle('active', which === 'src');
  document.getElementById('inv-dst-btn').classList.toggle('active', which === 'dst');
  document.getElementById('inv-status').textContent = '';

  const statusEl = document.getElementById('inv-status');
  statusEl.style.color = 'var(--muted)';
  statusEl.textContent = 'Starting scan on ' + ip + '...';

  const url = '/api/investigate?target=' + encodeURIComponent(ip) +
              (_invPort ? '&ports=' + encodeURIComponent(_invPort) : '');

  fetch(url, {{ method: 'POST' }})
    .then(r => r.json())
    .then(data => {{
      if (data.error) {{
        statusEl.style.color = 'var(--red, #f85149)';
        statusEl.textContent = 'Error: ' + data.error;
        return;
      }}
      statusEl.textContent = 'Scanning ' + ip + '... (this may take up to 2 min)';
      _pollInvestigate(ip, data.result_url, statusEl);
    }})
    .catch(err => {{
      statusEl.style.color = 'var(--red, #f85149)';
      statusEl.textContent = 'Failed to reach server: ' + err;
    }});
}}

function _pollInvestigate(ip, resultUrl, statusEl) {{
  const check = () => {{
    fetch('/api/investigate/status?target=' + encodeURIComponent(ip))
      .then(r => r.json())
      .then(data => {{
        if (data.status === 'ready') {{
          statusEl.style.color = '#3fb950';
          statusEl.textContent = 'Scan complete — opening report...';
          setTimeout(() => window.open(resultUrl, '_blank'), 400);
        }} else if (data.status === 'error') {{
          statusEl.style.color = '#f85149';
          statusEl.textContent = 'Scan error: ' + (data.error || 'unknown');
        }} else {{
          setTimeout(check, 2000);
        }}
      }})
      .catch(() => setTimeout(check, 3000));
  }};
  setTimeout(check, 2000);
}}

function setDeepInspect(which) {{
  const target = which === 'src' ? _invSrcIp : _invDstIp;
  const ports  = _invPort || '';
  setInvStatus('running', 'Deep inspect started on ' + target + '...');
  fetch('/api/deep-inspect?target=' + encodeURIComponent(target) + '&ports=' + encodeURIComponent(ports), {{method: 'POST'}})
    .then(r => r.json())
    .then(data => {{
      if (data.error) {{ setInvStatus('error', data.error); return; }}
      _pollDeepInspect(target, data.result_url);
    }})
    .catch(e => setInvStatus('error', e.message));
}}

function _pollDeepInspect(target, resultUrl) {{
  const check = () => {{
    fetch('/api/deep-inspect/status?target=' + encodeURIComponent(target))
      .then(r => r.json())
      .then(data => {{
        if (data.status === 'ready') {{
          setInvStatus('ready', 'Done \u2014 opening report...');
          setTimeout(() => window.open(resultUrl, '_blank'), 400);
        }} else if (data.status === 'error') {{
          setInvStatus('error', data.error || 'Deep inspect failed');
        }} else {{
          setTimeout(check, 3000);
        }}
      }})
      .catch(() => setTimeout(check, 3000));
  }};
  setTimeout(check, 2000);
}}

function setInvStatus(state, msg) {{
  const statusEl = document.getElementById('inv-status');
  if (state === 'error') {{
    statusEl.style.color = '#f85149';
  }} else if (state === 'ready') {{
    statusEl.style.color = '#3fb950';
  }} else {{
    statusEl.style.color = 'var(--muted)';
  }}
  statusEl.textContent = msg;
}}

// ── Refresh / Auto-refresh ─────────────────────────────────────────────────
let _autoInterval = 0, _autoTimer = null, _cdownTimer = null, _nextRefresh = null;

function triggerRefresh() {{
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Capturing…';
  clearTimeout(_autoTimer);
  clearInterval(_cdownTimer);
  document.getElementById('refresh-countdown').textContent = '';
  fetch('/api/report?duration=' + REPORT_DURATION + '&network=' + encodeURIComponent(REPORT_NETWORK), {{method: 'POST'}})
    .then(r => r.json())
    .then(data => {{
      if (data.error && data.error !== 'Report already running') {{
        btn.textContent = '↻ Refresh'; btn.disabled = false;
        alert('Error: ' + data.error); return;
      }}
      _pollReport(btn);
    }})
    .catch(e => {{ btn.textContent = '↻ Refresh'; btn.disabled = false; alert('Failed: ' + e); }});
}}

function _pollReport(btn) {{
  fetch('/api/report/status')
    .then(r => r.json())
    .then(data => {{
      if      (data.status === 'ready') {{ location.reload(); }}
      else if (data.status === 'error') {{
        btn.textContent = '↻ Refresh'; btn.disabled = false;
        alert('Report error: ' + (data.error || 'unknown'));
      }} else {{ setTimeout(() => _pollReport(btn), 2000); }}
    }})
    .catch(() => setTimeout(() => _pollReport(btn), 3000));
}}

function setAutoRefresh(val) {{
  _autoInterval = parseInt(val) || 0;
  localStorage.setItem('nwm_auto_refresh', String(_autoInterval));
  clearTimeout(_autoTimer); clearInterval(_cdownTimer);
  document.getElementById('refresh-countdown').textContent = '';
  _nextRefresh = null;
  if (_autoInterval > 0) _scheduleNext();
}}

function _scheduleNext() {{
  _nextRefresh = Date.now() + _autoInterval * 1000;
  _autoTimer   = setTimeout(triggerRefresh, _autoInterval * 1000);
  _cdownTimer  = setInterval(_updateCountdown, 1000);
  _updateCountdown();
}}

function _updateCountdown() {{
  if (_nextRefresh === null) {{ clearInterval(_cdownTimer); return; }}
  const secs = Math.max(0, Math.round((_nextRefresh - Date.now()) / 1000));
  const m = Math.floor(secs / 60), s = secs % 60;
  document.getElementById('refresh-countdown').textContent =
    'Next refresh in ' + m + ':' + String(s).padStart(2, '0');
}}

document.addEventListener('DOMContentLoaded', () => {{
  const saved = localStorage.getItem('nwm_auto_refresh');
  if (saved && saved !== '0') {{
    const sel = document.getElementById('auto-refresh');
    // only restore if the saved value matches one of the options
    if ([...sel.options].some(o => o.value === saved)) {{
      sel.value = saved;
      setAutoRefresh(saved);
    }}
  }}
}});

// ── Analytics ──────────────────────────────────────────────────────────────
function openAnalytics() {{
  const btn = document.getElementById('analytics-btn');
  btn.textContent = '⏳ Generating…';
  btn.disabled = true;
  fetch('/api/analytics', {{method: 'POST'}})
    .then(r => r.json())
    .then(() => _pollAnalytics())
    .catch(e => {{
      btn.textContent = '📊 Analytics';
      btn.disabled = false;
      alert('Analytics error: ' + e);
    }});
}}

function _pollAnalytics() {{
  fetch('/api/analytics/status')
    .then(r => r.json())
    .then(data => {{
      const btn = document.getElementById('analytics-btn');
      if (data.status === 'ready') {{
        btn.textContent = '📊 Analytics';
        btn.disabled = false;
        window.open('/analytics.html', '_blank');
      }} else if (data.status === 'error') {{
        btn.textContent = '📊 Analytics';
        btn.disabled = false;
        alert('Analytics error: ' + (data.error || 'unknown'));
      }} else {{
        setTimeout(_pollAnalytics, 1000);
      }}
    }})
    .catch(() => setTimeout(_pollAnalytics, 2000));
}}
</script>

<div id="inv-overlay" class="inv-overlay" onclick="closeInvestigate()">
  <div class="inv-modal" onclick="event.stopPropagation()">
    <button class="inv-close" onclick="closeInvestigate()">&#x2715;</button>
    <h3>Investigate Connection</h3>
    <table class="inv-detail-table">
      <tr><th>Source (local)</th><td id="inv-src"></td></tr>
      <tr><th>Destination (remote)</th><td id="inv-dst"></td></tr>
      <tr><th>Observed Port</th><td id="inv-port"></td></tr>
      <tr><th>Protocol / Service</th><td id="inv-proto"></td></tr>
    </table>
    <div id="inv-context" class="inv-context"></div>
    <h4>Select target to investigate:</h4>
    <div class="inv-targets">
      <button id="inv-src-btn" onclick="setInvTarget('src')">Investigate Source</button>
      <button id="inv-dst-btn" onclick="setInvTarget('dst')">Investigate Destination</button>
    </div>
    <div class="inv-sep">\u2014 Deep Inspect (GeoIP + security checks) \u2014</div>
    <div class="inv-targets">
      <button class="inv-deep" onclick="setDeepInspect('src')">Deep Inspect Source</button>
      <button class="inv-deep" onclick="setDeepInspect('dst')">Deep Inspect Dest</button>
    </div>
    <div class="inv-note" id="inv-status"></div>
  </div>
</div>
</body>
</html>"""

    if output is None or output == "-":
        sys.stdout.write(page)
    else:
        with open(output, "w") as f:
            f.write(page)
        print(f"HTML report saved to {output}")
