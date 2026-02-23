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
from typing import IO

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Service name lookup
# ---------------------------------------------------------------------------

_SERVICE_MAP: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS-alt",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6881: "BitTorrent",
    8080: "HTTP-proxy",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
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

    # Example ss line:
    # tcp  ESTAB 0 0 192.168.1.5:52134 8.8.8.8:443 users:(("chrome",pid=1234,fd=12))
    pid_re = re.compile(r'pid=(\d+)')
    addr_re = re.compile(r'(\S+):(\d+)\s+(\S+):(\d+)')

    for line in result.stdout.splitlines()[1:]:  # skip header
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

        # Get process name and uid from /proc
        try:
            with open(f"/proc/{pid}/comm") as f:
                app_name = f.read().strip()
        except OSError:
            app_name = "?"

        uid = None
        try:
            with open(f"/proc/{pid}/status") as f:
                for status_line in f:
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
    dst_ip: str
    dst_port: int | None
    protocol: str
    service: str
    domain: str        # SNI / HTTP host / DNS name; "—" if unknown
    app_name: str      # "—" for remote devices
    username: str      # "—" for remote devices
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
    """Parse a single tshark ek JSON line into a flat dict of fields."""
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

    # Validate network
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.error("Invalid network CIDR: %s", network)
        net = ipaddress.ip_network("192.168.1.0/24")

    # Snapshot process/user info before capture
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

    # Aggregate into flows: key = (src_ip, dst_ip, dst_port, protocol)
    flows: dict[tuple, FlowRecord] = {}
    # Track SNI/domain hints per (src_ip, dst_ip, dst_port)
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

        # Verify src is in target network
        try:
            if ipaddress.ip_address(src_ip) not in net:
                continue
        except ValueError:
            continue

        dst_port = _int("tcp_dstport") or _int("udp_dstport")
        proto = _str("_ws_col_Protocol") or "Unknown"
        length = _int("frame_len") or 0
        ts = _float("frame_time_epoch") or 0.0

        flow_key = (src_ip, dst_ip, dst_port, proto)
        hint_key = (src_ip, dst_ip, dst_port)

        # Collect domain hints
        sni = _str("tls_handshake_extensions_server_name")
        http_host = _str("http_host")
        dns_name = _str("dns_qry_name")
        domain = sni or http_host or dns_name
        if domain and hint_key not in domain_hints:
            domain_hints[hint_key] = domain

        if flow_key not in flows:
            # Look up process info (only works for local machine's own sockets)
            proc = proc_map.get((dst_ip, dst_port)) if dst_port else None
            flows[flow_key] = FlowRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=_service_name(dst_port),
                domain="—",
                app_name=proc.app_name if proc else "—",
                username=proc.username if proc else "—",
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

    # Apply domain hints
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
    """Print a Rich table of flows to the console."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(
        title=f"Connection Report — {len(flows)} flows",
        show_lines=False,
    )
    table.add_column("Src IP", style="cyan")
    table.add_column("Dst IP", style="yellow")
    table.add_column("Port", justify="right")
    table.add_column("Service")
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
            rec.dst_ip,
            str(rec.dst_port) if rec.dst_port is not None else "—",
            rec.service,
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
    """Write CSV to file path, stdout ('-'), or stdout if output is None."""
    fieldnames = [
        "src_ip", "dst_ip", "dst_port", "protocol", "service",
        "domain", "app_name", "username", "packet_count", "bytes_total",
        "first_seen", "last_seen",
    ]

    def _write(f: IO[str]) -> None:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in flows:
            writer.writerow({
                "src_ip": rec.src_ip,
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
    """Write a self-contained dark-themed HTML report."""
    total_packets = sum(r.packet_count for r in flows)
    total_bytes = sum(r.bytes_total for r in flows)
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _esc(s: str) -> str:
        return html.escape(str(s))

    rows_html = io.StringIO()
    for rec in flows:
        rows_html.write(
            f"<tr>"
            f"<td>{_esc(rec.src_ip)}</td>"
            f"<td>{_esc(rec.dst_ip)}</td>"
            f"<td>{_esc(str(rec.dst_port) if rec.dst_port is not None else '—')}</td>"
            f"<td>{_esc(rec.service)}</td>"
            f"<td>{_esc(rec.protocol)}</td>"
            f"<td>{_esc(rec.domain)}</td>"
            f"<td>{_esc(rec.app_name)}</td>"
            f"<td>{_esc(rec.username)}</td>"
            f"<td>{rec.packet_count}</td>"
            f"<td data-bytes='{rec.bytes_total}'>{_esc(_fmt_bytes(rec.bytes_total))}</td>"
            f"<td>{_esc(_fmt_ts(rec.first_seen))}</td>"
            f"<td>{_esc(_fmt_ts(rec.last_seen))}</td>"
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
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: monospace; font-size: 13px; padding: 24px; }}
  h1 {{ color: var(--accent); font-size: 20px; margin-bottom: 8px; }}
  .meta {{ color: var(--muted); margin-bottom: 20px; }}
  .stats {{ display: flex; gap: 32px; margin-bottom: 24px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px 20px; }}
  .stat-label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
  .stat-value {{ color: var(--accent); font-size: 22px; font-weight: bold; margin-top: 4px; }}
  .search-bar {{ margin-bottom: 12px; }}
  .search-bar input {{
    background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 4px; width: 300px; font-family: monospace;
  }}
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
<div class="search-bar">
  <input type="text" id="search" placeholder="Filter rows..." oninput="filterTable()" />
</div>
<table id="flows-table">
<thead>
<tr>
  <th onclick="sortTable(0)">Src IP</th>
  <th onclick="sortTable(1)">Dst IP</th>
  <th onclick="sortTable(2)" class="num">Port</th>
  <th onclick="sortTable(3)">Service</th>
  <th onclick="sortTable(4)">Protocol</th>
  <th onclick="sortTable(5)">Domain / SNI</th>
  <th onclick="sortTable(6)">Application</th>
  <th onclick="sortTable(7)">User</th>
  <th onclick="sortTable(8)" class="num">Pkts</th>
  <th onclick="sortTable(9)" class="num">Bytes</th>
  <th onclick="sortTable(10)">First</th>
  <th onclick="sortTable(11)">Last</th>
</tr>
</thead>
<tbody>
{rows_html.getvalue()}</tbody>
</table>
<script>
let sortCol = 9, sortAsc = false;

function cellVal(row, col) {{
  const td = row.cells[col];
  if (col === 9) return parseInt(td.dataset.bytes || '0', 10);
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

  for (let th of ths) th.className = '';
  ths[col].className = sortAsc ? 'sort-asc' : 'sort-desc';
  if ([2,8,9].includes(col)) ths[col].className += ' num';

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
</script>
</body>
</html>"""

    if output is None or output == "-":
        sys.stdout.write(page)
    else:
        with open(output, "w") as f:
            f.write(page)
        print(f"HTML report saved to {output}")
