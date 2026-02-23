"""Metasploit-backed investigation report for a single target IP."""
from __future__ import annotations

import html
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5900,8080,8443"

# Metasploit auxiliary modules to run (module, description, condition-port or None)
_MSF_MODULES = [
    ("auxiliary/scanner/portscan/tcp",       "TCP Port Scan",      None),
    ("auxiliary/scanner/smb/smb_version",    "SMB Version",        445),
    ("auxiliary/scanner/ssh/ssh_version",    "SSH Version",        22),
    ("auxiliary/scanner/http/http_version",  "HTTP Version",       80),
]


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

def _msfconsole_available() -> bool:
    return shutil.which("msfconsole") is not None


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


# ---------------------------------------------------------------------------
# Metasploit runner
# ---------------------------------------------------------------------------

def _build_rc_script(target_ip: str, ports: str) -> str:
    """Build a Metasploit resource script (.rc) for the given target."""
    lines: list[str] = []
    for module, _desc, _cond_port in _MSF_MODULES:
        lines.append(f"use {module}")
        lines.append(f"set RHOSTS {target_ip}")
        if module == "auxiliary/scanner/portscan/tcp":
            lines.append(f"set PORTS {ports}")
        lines.append("run")
        lines.append("back")
    lines.append("exit")
    return "\n".join(lines)


def _parse_msf_output(raw: str, target_ip: str) -> dict:
    """Extract open ports and service info from msfconsole stdout."""
    open_ports: list[int] = []
    services: dict[int, str] = {}
    findings: list[str] = []

    for line in raw.splitlines():
        line = line.strip()
        # TCP port scan open lines: "[*] <ip>:<port> - TCP OPEN"
        if "TCP OPEN" in line and target_ip in line:
            parts = line.split()
            for part in parts:
                if ":" in part:
                    try:
                        port = int(part.split(":")[1])
                        if port not in open_ports:
                            open_ports.append(port)
                    except (ValueError, IndexError):
                        pass
        # Service version lines
        if "[+]" in line or "[*]" in line:
            for keyword in ("version", "banner", "os", "authentication"):
                if keyword in line.lower():
                    clean = line.lstrip("[+]").lstrip("[*]").strip()
                    if clean and clean not in findings:
                        findings.append(clean)
                    break

    # Build services map from open ports
    _SVCMAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-proxy",
        8443: "HTTPS-alt",
    }
    for port in open_ports:
        services[port] = _SVCMAP.get(port, f"port-{port}")

    return {
        "target": target_ip,
        "open_ports": sorted(open_ports),
        "services": services,
        "findings": findings,
        "raw_output": raw,
        "tool_used": "msfconsole",
    }


# ---------------------------------------------------------------------------
# nmap fallback
# ---------------------------------------------------------------------------

def _nmap_fallback(target_ip: str, ports: str) -> dict:
    """Run nmap -sV and return structured results."""
    cmd = ["nmap", "-sV", "--open", "-p", ports, target_ip]
    logger.debug("Running nmap fallback: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = result.stdout + result.stderr
    except FileNotFoundError:
        return {
            "target": target_ip,
            "open_ports": [],
            "services": {},
            "findings": ["nmap not found — install nmap or msfconsole"],
            "raw_output": "",
            "tool_used": "none",
        }
    except subprocess.TimeoutExpired:
        return {
            "target": target_ip,
            "open_ports": [],
            "services": {},
            "findings": ["nmap timed out"],
            "raw_output": "",
            "tool_used": "nmap",
        }

    open_ports: list[int] = []
    services: dict[int, str] = {}
    findings: list[str] = []

    for line in raw.splitlines():
        # Example: "22/tcp   open  ssh     OpenSSH 8.9 ..."
        parts = line.split()
        if len(parts) >= 3 and "/tcp" in parts[0] and parts[1] == "open":
            try:
                port = int(parts[0].split("/")[0])
                svc = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                open_ports.append(port)
                services[port] = svc
                if version:
                    findings.append(f"Port {port}/{svc}: {version}")
            except (ValueError, IndexError):
                pass

    return {
        "target": target_ip,
        "open_ports": sorted(open_ports),
        "services": services,
        "findings": findings,
        "raw_output": raw,
        "tool_used": "nmap",
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_msf_scan(target_ip: str, ports: str | None = None) -> dict:
    """
    Scan target_ip using Metasploit auxiliary modules.
    Falls back to nmap if msfconsole is unavailable.
    Returns dict: {target, open_ports, services, findings, raw_output, tool_used}
    """
    effective_ports = ports or COMMON_PORTS

    if not _msfconsole_available():
        logger.info("msfconsole not found, falling back to nmap")
        return _nmap_fallback(target_ip, effective_ports)

    rc_content = _build_rc_script(target_ip, effective_ports)
    rc_path = os.path.join(tempfile.gettempdir(), f"msf_rc_{target_ip.replace('.', '_')}.rc")
    try:
        with open(rc_path, "w") as f:
            f.write(rc_content)

        cmd = ["msfconsole", "-q", "-r", rc_path]
        logger.debug("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        logger.error("msfconsole timed out")
        return {
            "target": target_ip,
            "open_ports": [],
            "services": {},
            "findings": ["msfconsole timed out after 300 s"],
            "raw_output": "",
            "tool_used": "msfconsole",
        }
    except OSError as exc:
        logger.error("Failed to run msfconsole: %s", exc)
        return _nmap_fallback(target_ip, effective_ports)
    finally:
        try:
            os.unlink(rc_path)
        except OSError:
            pass

    return _parse_msf_output(raw, target_ip)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def render_investigation_html(results: dict, output: str) -> None:
    """Render investigation results as a styled HTML report."""
    target      = results.get("target", "unknown")
    open_ports  = results.get("open_ports", [])
    services    = results.get("services", {})
    findings    = results.get("findings", [])
    raw_output  = results.get("raw_output", "")
    tool_used   = results.get("tool_used", "unknown")
    generated   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _e(s: str) -> str:
        return html.escape(str(s))

    # Open ports table rows
    port_rows = ""
    if open_ports:
        for port in open_ports:
            svc = services.get(port, "—")
            port_rows += (
                f"<tr>"
                f"<td class='num'>{port}</td>"
                f"<td><span class='badge'>{_e(svc)}</span></td>"
                f"</tr>\n"
            )
    else:
        port_rows = "<tr><td colspan='2' class='muted'>No open ports detected</td></tr>"

    # Findings list items
    findings_html = ""
    if findings:
        for f_item in findings:
            findings_html += f"<li>{_e(f_item)}</li>\n"
    else:
        findings_html = "<li class='muted'>No additional findings</li>"

    # Summary badge colour
    risk_color = "#f85149" if open_ports else "#3fb950"
    risk_label = f"{len(open_ports)} open port(s) found" if open_ports else "No open ports"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatchM — Investigation: {_e(target)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --muted: #8b949e;
    --green: #3fb950; --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: monospace; font-size: 13px; padding: 24px; }}
  h1 {{ color: var(--accent); font-size: 20px; margin-bottom: 8px; }}
  h2 {{ color: var(--text); font-size: 15px; margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  .meta {{ color: var(--muted); margin-bottom: 20px; font-size: 12px; }}
  .summary {{
    display: inline-flex; align-items: center; gap: 10px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 20px; margin-bottom: 24px;
  }}
  .risk-dot {{ width: 12px; height: 12px; border-radius: 50%; background: {risk_color}; flex-shrink: 0; }}
  .risk-label {{ font-size: 14px; font-weight: bold; color: {risk_color}; }}
  .tool-badge {{
    margin-left: 16px; background: rgba(88,166,255,0.1); color: var(--accent);
    border: 1px solid rgba(88,166,255,0.3); border-radius: 4px;
    padding: 1px 8px; font-size: 11px;
  }}
  table {{ border-collapse: collapse; width: 100%; max-width: 480px; }}
  th {{
    background: var(--surface); color: var(--muted); text-transform: uppercase;
    font-size: 11px; padding: 8px 10px; text-align: left;
    border-bottom: 2px solid var(--border);
  }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface); }}
  .num {{ text-align: right; width: 80px; }}
  .badge {{
    background: rgba(88,166,255,0.12); color: var(--accent);
    border: 1px solid rgba(88,166,255,0.3); border-radius: 4px;
    padding: 1px 7px; font-size: 11px; font-weight: 600;
  }}
  .muted {{ color: var(--muted); }}
  ul {{ padding-left: 20px; }}
  li {{ margin: 4px 0; line-height: 1.5; }}
  .raw-toggle {{
    background: none; border: 1px solid var(--border); color: var(--muted);
    padding: 4px 12px; border-radius: 4px; cursor: pointer;
    font-family: monospace; font-size: 12px; margin-bottom: 8px;
  }}
  .raw-toggle:hover {{ color: var(--text); }}
  .raw-output {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: 12px; font-size: 11px;
    white-space: pre-wrap; overflow-x: auto; max-height: 400px;
    overflow-y: auto; color: var(--muted);
  }}
</style>
</head>
<body>
<h1>NetWatchM — Investigation Report</h1>
<div class="meta">Target: <strong style="color:var(--text)">{_e(target)}</strong> &nbsp;|&nbsp; Tool: {_e(tool_used)} &nbsp;|&nbsp; Generated: {_e(generated)}</div>

<div class="summary">
  <span class="risk-dot"></span>
  <span class="risk-label">{_e(risk_label)}</span>
  <span class="tool-badge">{_e(tool_used)}</span>
</div>

<h2>Open Ports</h2>
<table>
<thead><tr><th class="num">Port</th><th>Service</th></tr></thead>
<tbody>
{port_rows}
</tbody>
</table>

<h2>Findings</h2>
<ul>
{findings_html}
</ul>

<h2>Raw Output</h2>
<button class="raw-toggle" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">Toggle raw output</button>
<pre class="raw-output" style="display:none">{_e(raw_output)}</pre>
</body>
</html>"""

    with open(output, "w") as f:
        f.write(page)
