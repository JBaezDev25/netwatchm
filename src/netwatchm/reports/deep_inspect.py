"""Deep security inspection engine: GeoIP, SSH, SMB, HTTP, RDP, port scan."""
from __future__ import annotations

import ipaddress
import socket
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]
DEFAULT_GEOIP_DB = "/var/lib/netwatchm/GeoLite2-City.mmdb"

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


@dataclass
class GeoIPInfo:
    country: str
    city: str
    isp: str
    asn: str
    abuse: str


@dataclass
class Finding:
    title: str
    detail: str
    severity: str  # "info" | "medium" | "high"


@dataclass
class InspectionResult:
    target: str
    geoip: Optional[GeoIPInfo]
    open_ports: list[int]
    services: dict[int, str]
    findings: list[Finding]
    risk_level: str  # "low" | "medium" | "high"
    raw_output: str
    error: Optional[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _geoip_lookup(target: str, db_path: str = "") -> Optional[GeoIPInfo]:
    if not db_path:
        db_path = DEFAULT_GEOIP_DB

    if _is_private(target):
        return None

    db_file = Path(db_path)
    if not db_file.exists():
        return None

    try:
        import geoip2.database
        import geoip2.errors

        with geoip2.database.Reader(str(db_file)) as reader:
            try:
                response = reader.city(target)
                country = (response.country.name
                           or response.registered_country.name
                           or "Unknown")
                city = response.city.name or "Unknown"
                # GeoLite2-City doesn't have ISP/ASN — use placeholders
                isp = "N/A (use GeoLite2-ASN for ISP)"
                asn = str(response.traits.autonomous_system_number or "N/A")
                abuse = "N/A"
                return GeoIPInfo(country=country, city=city, isp=isp, asn=asn, abuse=abuse)
            except geoip2.errors.AddressNotFoundError:
                return None
    except Exception:
        return None


def _port_scan(target: str, port_list: list[int]) -> dict[int, str]:
    open_services: dict[int, str] = {}
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_services[port] = PORT_SERVICE_MAP.get(port, f"port-{port}")
        except Exception:
            pass
    return open_services


def _ssh_check(target: str, open_ports: list[int]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    raw = ""
    if 22 not in open_ports:
        return findings, raw

    try:
        import paramiko

        transport = paramiko.Transport((target, 22))
        try:
            transport.start_client(timeout=5)
            banner = transport.remote_version or "Unknown"
            raw += f"SSH banner: {banner}\n"
            findings.append(Finding(
                title="SSH service exposed",
                detail=f"SSH banner: {banner}",
                severity="medium",
            ))
            # Try password auth with test credentials
            try:
                transport.auth_password("root", "password")
                findings.append(Finding(
                    title="SSH accepts password auth with weak credentials",
                    detail="Successfully authenticated with root:password — immediate risk!",
                    severity="high",
                ))
                raw += "SSH: password auth accepted for root:password\n"
            except paramiko.AuthenticationException:
                raw += "SSH: password auth rejected (expected)\n"
            except Exception as e:
                raw += f"SSH auth probe: {e}\n"
        finally:
            transport.close()
    except Exception as e:
        raw += f"SSH check error: {e}\n"

    return findings, raw


def _smb_check(target: str, open_ports: list[int]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    raw = ""
    if 445 not in open_ports:
        return findings, raw

    try:
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(target, target, sess_port=445, timeout=5)
        try:
            smb.login("", "")
            findings.append(Finding(
                title="SMB null/anonymous session allowed",
                detail="Connected to SMB with empty username and password — information disclosure risk.",
                severity="high",
            ))
            raw += "SMB: null session login succeeded\n"
        except Exception as e:
            raw += f"SMB: null session rejected ({e})\n"

        try:
            signing = smb.isSigningRequired()
            raw += f"SMB signing required: {signing}\n"
            if not signing:
                findings.append(Finding(
                    title="SMB signing not required",
                    detail="SMB message signing is disabled, enabling relay attacks (e.g., NTLM relay).",
                    severity="high",
                ))
        except Exception as e:
            raw += f"SMB signing check error: {e}\n"

        try:
            smb.logoff()
        except Exception:
            pass
    except Exception as e:
        raw += f"SMB check error: {e}\n"

    return findings, raw


def _http_check(target: str) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    raw = ""

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    try:
        import requests

        for scheme in ("http", "https"):
            url = f"{scheme}://{target}"
            try:
                resp = requests.get(url, verify=False, timeout=5, allow_redirects=True)
                server_hdr = resp.headers.get("Server", "")
                raw += f"HTTP {scheme}: status={resp.status_code}, Server={server_hdr}\n"

                if server_hdr:
                    # Check for version number in Server header
                    import re
                    if re.search(r"[\d]+\.[\d]+", server_hdr):
                        findings.append(Finding(
                            title=f"Server version disclosure ({scheme.upper()})",
                            detail=f"Server header reveals software version: {server_hdr}",
                            severity="medium",
                        ))

                # Try basic auth with common weak credentials
                for creds in [("admin", "admin"), ("admin", "password")]:
                    try:
                        auth_resp = requests.get(
                            url, auth=creds, verify=False, timeout=5, allow_redirects=True
                        )
                        if auth_resp.status_code == 200 and resp.status_code in (401, 403):
                            findings.append(Finding(
                                title=f"Weak HTTP credentials accepted ({scheme.upper()})",
                                detail=f"Login succeeded with {creds[0]}:{creds[1]} — immediate risk!",
                                severity="high",
                            ))
                            raw += f"HTTP {scheme}: weak creds {creds[0]}:{creds[1]} accepted\n"
                    except Exception:
                        pass

            except requests.exceptions.ConnectionError:
                raw += f"HTTP {scheme}: connection refused\n"
            except Exception as e:
                raw += f"HTTP {scheme} error: {e}\n"
    except ImportError:
        raw += "requests not available for HTTP check\n"

    return findings, raw


def _rdp_check(target: str, open_ports: list[int]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    raw = ""
    if 3389 not in open_ports:
        return findings, raw

    findings.append(Finding(
        title="RDP service exposed",
        detail="Remote Desktop Protocol (port 3389) is open — high-value target for brute force.",
        severity="high",
    ))
    raw += "RDP: port 3389 open\n"

    # Basic NLA probe: connect and read initial bytes
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, 3389))
        # Send RDP negotiation request
        rdp_req = bytes([
            0x03, 0x00, 0x00, 0x13,  # TPKT header
            0x0e, 0xe0, 0x00, 0x00,  # Connection request
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x08, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ])
        sock.sendall(rdp_req)
        resp = sock.recv(64)
        raw += f"RDP: response bytes={resp.hex()[:32]}...\n"
        # If NLA is required, byte at offset 11 has bit 0x02 set
        if len(resp) > 11 and resp[11] & 0x02:
            raw += "RDP: NLA (Network Level Auth) appears required\n"
        else:
            findings.append(Finding(
                title="RDP NLA not enforced",
                detail="RDP may accept connections without Network Level Authentication.",
                severity="medium",
            ))
        sock.close()
    except Exception as e:
        raw += f"RDP NLA probe error: {e}\n"

    return findings, raw


def _compute_risk(
    findings: list[Finding],
    geoip: Optional[GeoIPInfo],
    open_ports: list[int],
    target: str,
) -> str:
    if any(f.severity == "high" for f in findings):
        return "high"
    # External IP with 445 or 3389 open
    if not _is_private(target) and (445 in open_ports or 3389 in open_ports):
        return "high"
    if any(f.severity == "medium" for f in findings):
        return "medium"
    if 22 in open_ports:
        return "medium"
    return "low"


def run_deep_inspect(target: str, ports: str = "", db_path: str = "") -> InspectionResult:
    """Run all deep inspection checks against target. Catches per-check exceptions."""
    raw_parts: list[str] = []
    all_findings: list[Finding] = []
    error_msg: Optional[str] = None

    # Parse ports
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError:
            port_list = DEFAULT_PORTS
    else:
        port_list = DEFAULT_PORTS

    # Port scan
    open_services: dict[int, str] = {}
    try:
        open_services = _port_scan(target, port_list)
        raw_parts.append(f"Open ports: {sorted(open_services.keys()) or 'none'}")
    except Exception as e:
        raw_parts.append(f"Port scan error: {e}")
        error_msg = str(e)

    open_ports = sorted(open_services.keys())

    # GeoIP
    geoip: Optional[GeoIPInfo] = None
    try:
        geoip = _geoip_lookup(target, db_path)
        if geoip:
            raw_parts.append(f"GeoIP: {geoip.country}, {geoip.city}, ASN={geoip.asn}")
        else:
            raw_parts.append("GeoIP: no data (private IP or DB missing)")
    except Exception as e:
        raw_parts.append(f"GeoIP error: {e}")

    # SSH
    try:
        ssh_findings, ssh_raw = _ssh_check(target, open_ports)
        all_findings.extend(ssh_findings)
        if ssh_raw:
            raw_parts.append(ssh_raw.rstrip())
    except Exception as e:
        raw_parts.append(f"SSH check failed: {e}")

    # SMB
    try:
        smb_findings, smb_raw = _smb_check(target, open_ports)
        all_findings.extend(smb_findings)
        if smb_raw:
            raw_parts.append(smb_raw.rstrip())
    except Exception as e:
        raw_parts.append(f"SMB check failed: {e}")

    # HTTP
    try:
        http_findings, http_raw = _http_check(target)
        all_findings.extend(http_findings)
        if http_raw:
            raw_parts.append(http_raw.rstrip())
    except Exception as e:
        raw_parts.append(f"HTTP check failed: {e}")

    # RDP
    try:
        rdp_findings, rdp_raw = _rdp_check(target, open_ports)
        all_findings.extend(rdp_findings)
        if rdp_raw:
            raw_parts.append(rdp_raw.rstrip())
    except Exception as e:
        raw_parts.append(f"RDP check failed: {e}")

    risk = _compute_risk(all_findings, geoip, open_ports, target)

    return InspectionResult(
        target=target,
        geoip=geoip,
        open_ports=open_ports,
        services=open_services,
        findings=all_findings,
        risk_level=risk,
        raw_output="\n".join(raw_parts),
        error=error_msg,
    )


def render_deep_inspect_html(result: InspectionResult, output_path: str) -> None:
    """Write standalone dark-theme HTML report to output_path."""

    severity_color = {"info": "#58a6ff", "medium": "#e3b341", "high": "#f85149"}
    severity_bg = {
        "info": "rgba(88,166,255,0.1)",
        "medium": "rgba(227,179,65,0.1)",
        "high": "rgba(248,81,73,0.1)",
    }
    risk_color = {"low": "#3fb950", "medium": "#e3b341", "high": "#f85149"}

    def _badge(text: str, color: str, bg: str) -> str:
        return (
            f'<span style="background:{bg};color:{color};border:1px solid {color}33;'
            f'border-radius:4px;padding:2px 8px;font-size:12px;font-weight:600">{text}</span>'
        )

    # GeoIP section
    if result.geoip:
        g = result.geoip
        geoip_html = f"""
        <div class="card">
          <div class="card-title">GeoIP Information</div>
          <table class="info-table">
            <tr><th>Country</th><td>{g.country}</td></tr>
            <tr><th>City</th><td>{g.city}</td></tr>
            <tr><th>ISP</th><td>{g.isp}</td></tr>
            <tr><th>ASN</th><td>{g.asn}</td></tr>
            <tr><th>Abuse</th><td>{g.abuse}</td></tr>
          </table>
        </div>"""
    else:
        geoip_html = """
        <div class="card">
          <div class="card-title">GeoIP Information</div>
          <p style="color:var(--muted);font-size:13px">No GeoIP data — private IP or database not found.</p>
        </div>"""

    # Open ports table
    if result.open_ports:
        rows = "".join(
            f"<tr><td>{p}</td><td>{result.services.get(p, '?')}</td>"
            f"<td style='color:#3fb950'>Open</td></tr>"
            for p in result.open_ports
        )
        ports_html = f"""
        <div class="card">
          <div class="card-title">Open Ports ({len(result.open_ports)})</div>
          <table class="ports-table">
            <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""
    else:
        ports_html = """
        <div class="card">
          <div class="card-title">Open Ports</div>
          <p style="color:var(--muted);font-size:13px">No open ports found on scanned range.</p>
        </div>"""

    # Findings
    if result.findings:
        finding_items = ""
        for f in result.findings:
            col = severity_color.get(f.severity, "#58a6ff")
            bg = severity_bg.get(f.severity, "rgba(88,166,255,0.1)")
            badge = _badge(f.severity.upper(), col, bg)
            finding_items += f"""
        <div class="finding" style="border-left:3px solid {col}">
          <div class="finding-header">{badge} <span class="finding-title">{f.title}</span></div>
          <div class="finding-detail">{f.detail}</div>
        </div>"""
        findings_html = f"""
        <div class="card">
          <div class="card-title">Security Findings ({len(result.findings)})</div>
          {finding_items}
        </div>"""
    else:
        findings_html = """
        <div class="card">
          <div class="card-title">Security Findings</div>
          <p style="color:#3fb950;font-size:13px">No security findings detected.</p>
        </div>"""

    risk_col = risk_color.get(result.risk_level, "#58a6ff")
    risk_badge = _badge(result.risk_level.upper() + " RISK", risk_col, f"{risk_col}1a")

    raw_escaped = result.raw_output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    error_html = ""
    if result.error:
        error_html = f'<div class="error-bar">Scan error: {result.error}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deep Inspect — {result.target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: monospace; padding: 24px; }}
  h1 {{ color: var(--accent); font-size: 20px; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); font-size: 12px; margin-bottom: 24px; }}
  .error-bar {{ background: rgba(248,81,73,0.15); border: 1px solid #f85149;
    border-radius: 4px; padding: 8px 12px; margin-bottom: 16px;
    color: #f85149; font-size: 12px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }}
  .card-title {{ color: var(--accent); font-size: 13px; font-weight: 600;
    margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .info-table {{ width: 100%; border-collapse: collapse; }}
  .info-table th {{ color: var(--muted); font-size: 12px; text-align: left;
    padding: 4px 12px 4px 0; width: 120px; font-weight: normal; }}
  .info-table td {{ color: var(--text); font-size: 13px; padding: 4px 0; }}
  .ports-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .ports-table th {{ color: var(--muted); text-align: left; padding: 4px 12px 4px 0;
    font-size: 11px; border-bottom: 1px solid var(--border); }}
  .ports-table td {{ padding: 5px 12px 5px 0; }}
  .finding {{ padding: 10px 14px; margin-bottom: 10px;
    background: var(--bg); border-radius: 4px; }}
  .finding-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
  .finding-title {{ font-size: 13px; font-weight: 600; }}
  .finding-detail {{ color: var(--muted); font-size: 12px; line-height: 1.5; }}
  details summary {{ cursor: pointer; color: var(--muted); font-size: 12px;
    padding: 8px 0; user-select: none; }}
  details summary:hover {{ color: var(--text); }}
  pre {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
    padding: 12px; font-size: 11px; color: #7ee787; overflow-x: auto;
    white-space: pre-wrap; word-break: break-word; margin-top: 8px; }}
  .navbar {{ display: flex; align-items: center; gap: 12px; padding: 10px 0 18px 0;
    border-bottom: 1px solid var(--border); margin-bottom: 20px; flex-wrap: wrap; }}
  .navbar a {{ color: var(--muted); font-size: 12px; text-decoration: none;
    padding: 4px 10px; border: 1px solid var(--border); border-radius: 4px; }}
  .navbar a:hover {{ color: var(--accent); border-color: var(--accent); }}
</style>
</head>
<body>
<div class="navbar">
  <a href="/inventory.html">&#8592; Inventory</a>
  <a href="/events.html?q={result.target}">&#9888; Events</a>
  <a href="http://localhost:3000/d/netwatchm-inventory/" target="_blank">&#128202; Dashboard</a>
</div>
<h1>Deep Inspect: {result.target}</h1>
<div class="subtitle">
  {result.timestamp} &nbsp;|&nbsp; Risk: {risk_badge}
</div>
{error_html}
{geoip_html}
{ports_html}
{findings_html}
<div class="card">
  <details>
    <summary>Raw Output</summary>
    <pre>{raw_escaped}</pre>
  </details>
</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
