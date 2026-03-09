#!/usr/bin/env python3
"""
netwatchm-notify — sends an email when a NetWatchM service goes down.

Called by netwatchm-notify@.service via systemd OnFailure=.
Usage: notify-down.py <service-name>

Reads credentials from /etc/netwatchm/env
Reads SMTP config from /etc/netwatchm/netwatchm.yaml
"""
from __future__ import annotations

import os
import smtplib
import socket
import subprocess
import sys
import textwrap
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CONFIG_FILE = "/etc/netwatchm/netwatchm.yaml"
ENV_FILE    = "/etc/netwatchm/env"

# ── Exit-code / result reasons ─────────────────────────────────────────────
EXIT_REASONS: dict[str, str] = {
    "success":         "The service exited cleanly (code 0). This may be an intentional stop.",
    "exit-code":       "The process exited with a non-zero code — usually an unhandled "
                       "exception, a missing file, or a configuration error. Check the log "
                       "lines below for the exact Python traceback.",
    "signal":          "The process was killed by an OS signal. Common causes: the system ran "
                       "out of memory (OOM killer sent SIGKILL), or the service was stopped "
                       "manually with 'systemctl kill'.",
    "core-dump":       "The process crashed and produced a core dump — likely a fatal "
                       "Python error or a bug in a C extension (tshark, pygame, etc.).",
    "watchdog":        "The service did not respond to systemd's watchdog ping in time. "
                       "The process may be frozen or stuck in an infinite loop.",
    "start-limit-hit": "The service crashed and restarted too many times in a short period. "
                       "systemd has stopped retrying to prevent a crash loop. Fix the root "
                       "cause before restarting manually.",
    "timeout":         "The service took too long to start or stop and was killed by systemd.",
    "oom-kill":        "The process was killed by the Linux Out-Of-Memory (OOM) killer because "
                       "the system ran out of RAM. Consider reducing memory usage or adding swap.",
}

CODE_REASONS: dict[int, str] = {
    0:   "Clean exit — service was stopped intentionally.",
    1:   "General error — an unhandled exception occurred. See log lines below.",
    2:   "Configuration or startup error — check netwatchm.yaml for syntax issues.",
    126: "Permission denied — the executable cannot be run. Check file permissions.",
    127: "Command not found — the executable path is wrong or uv/.venv is missing.",
    137: "Force-killed (SIGKILL, signal 9) — OOM killer or 'systemctl kill' was used.",
    143: "Graceful shutdown (SIGTERM, signal 15) — 'systemctl stop' or system shutdown.",
}


def _load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return env


def _load_yaml_email() -> dict:
    """Very small YAML parser — only extracts the email section."""
    cfg: dict = {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username":  "",
        "recipient": "",
        "password":  "",
    }
    try:
        import yaml  # type: ignore
        with open(CONFIG_FILE) as f:
            raw = yaml.safe_load(f) or {}
        email = raw.get("alerts", {}).get("email", {})
        cfg.update({k: v for k, v in email.items() if v})
    except Exception:
        # Fall back to manual key=value scan if yaml unavailable
        try:
            section = False
            with open(CONFIG_FILE) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("email:"):
                        section = True
                        continue
                    if section:
                        if stripped and not stripped.startswith(" ") and not stripped.startswith("\t"):
                            break  # left the email section
                        for key in ("smtp_host", "smtp_port", "username", "recipient"):
                            if stripped.startswith(key + ":"):
                                val = stripped.split(":", 1)[1].strip()
                                cfg[key] = int(val) if key == "smtp_port" else val
        except Exception:
            pass
    return cfg


def _service_info(service: str) -> tuple[str, int, str]:
    """Return (result, exit_code, active_state) from systemctl show."""
    result = "unknown"
    exit_code = -1
    active = "unknown"
    try:
        out = subprocess.check_output(
            ["systemctl", "show", service,
             "--property=Result,ExecMainStatus,ActiveState",
             "--no-pager"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            if line.startswith("Result="):
                result = line.split("=", 1)[1].strip()
            elif line.startswith("ExecMainStatus="):
                try:
                    exit_code = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("ActiveState="):
                active = line.split("=", 1)[1].strip()
    except Exception:
        pass
    return result, exit_code, active


def _last_logs(service: str, lines: int = 25) -> str:
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", service, f"-n{lines}",
             "--no-pager", "--output=short-iso"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except Exception:
        return "(could not retrieve logs)"


def _human_reason(result: str, exit_code: int) -> str:
    if result in EXIT_REASONS:
        base = EXIT_REASONS[result]
    elif exit_code in CODE_REASONS:
        base = CODE_REASONS[exit_code]
    else:
        base = (f"The service stopped unexpectedly (systemd result: '{result}', "
                f"exit code: {exit_code}). Review the log lines below.")
    return base


def send_alert(service: str) -> None:
    env_vars   = _load_env()
    email_cfg  = _load_yaml_email()

    password  = env_vars.get("NETWATCHM_EMAIL_PASSWORD") or email_cfg.get("password", "")
    username  = email_cfg.get("username", "")
    recipient = email_cfg.get("recipient", "") or username
    smtp_host = email_cfg.get("smtp_host", "smtp.gmail.com")
    smtp_port = int(email_cfg.get("smtp_port", 587))

    if not password or not username or not recipient:
        print(
            "notify-down: missing email credentials — "
            "set NETWATCHM_EMAIL_PASSWORD in /etc/netwatchm/env and "
            "configure alerts.email in netwatchm.yaml",
            file=sys.stderr,
        )
        sys.exit(1)

    hostname   = socket.gethostname()
    now        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result, exit_code, active = _service_info(service)
    reason     = _human_reason(result, exit_code)
    logs       = _last_logs(service)

    subject = f"[NetWatchM] ⚠ Service DOWN: {service} on {hostname}"

    body = textwrap.dedent(f"""\
        NetWatchM Service Failure Alert
        ================================

        Service  : {service}
        Host     : {hostname}
        Time     : {now}
        State    : {active.upper()}
        Result   : {result}
        Exit code: {exit_code}

        WHY THIS IS HAPPENING
        ─────────────────────
        {textwrap.fill(reason, width=72)}

        LAST {min(25, logs.count(chr(10)) + 1)} LOG LINES
        ─────────────────────
        {logs}

        HOW TO RECOVER
        ──────────────
        1. Check full logs:
               journalctl -u {service} -n 50 --no-pager

        2. Restart the service:
               sudo systemctl start {service}

        3. Check status:
               systemctl status {service}

        ──────────────────────────────────────────────
        This alert was sent by NetWatchM on {hostname}.
        To disable these alerts, remove OnFailure= from
        /etc/systemd/system/{service}.service
    """)

    dashboard_url = f"https://{hostname}:8765/events.html"
    html_body = f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:monospace,sans-serif;color:#c9d1d9">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:24px 0">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden">
      <tr><td style="background:#da3633;padding:16px 24px">
        <span style="color:#fff;font-size:18px;font-weight:bold">&#9888; NetWatchM Service DOWN</span>
      </td></tr>
      <tr><td style="padding:24px">
        <table width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse;margin-bottom:20px">
          <tr><td style="color:#8b949e;width:100px">Service</td><td style="color:#f0f6fc">{service}</td></tr>
          <tr><td style="color:#8b949e">Host</td><td style="color:#f0f6fc">{hostname}</td></tr>
          <tr><td style="color:#8b949e">Time</td><td style="color:#f0f6fc">{now}</td></tr>
          <tr><td style="color:#8b949e">State</td><td style="color:#f85149;font-weight:bold">{active.upper()}</td></tr>
          <tr><td style="color:#8b949e">Result</td><td style="color:#f0f6fc">{result}</td></tr>
          <tr><td style="color:#8b949e">Exit code</td><td style="color:#f0f6fc">{exit_code}</td></tr>
        </table>

        <div style="background:#1c2128;border-left:3px solid #d29922;padding:12px 16px;margin-bottom:20px;border-radius:0 4px 4px 0">
          <div style="color:#d29922;font-size:11px;font-weight:bold;margin-bottom:6px">WHY THIS IS HAPPENING</div>
          <div style="color:#c9d1d9;font-size:13px">{reason}</div>
        </div>

        <div style="margin-bottom:20px">
          <div style="color:#8b949e;font-size:11px;font-weight:bold;margin-bottom:8px">HOW TO RECOVER</div>
          <table cellpadding="0" cellspacing="8">
            <tr><td>
              <a href="mailto:?body=sudo%20systemctl%20start%20{service}" style="display:inline-block;background:#238636;color:#fff;text-decoration:none;padding:8px 16px;border-radius:4px;font-size:13px;font-weight:bold">
                &#9654; Restart {service}
              </a>
            </td><td style="padding-left:12px">
              <a href="{dashboard_url}" style="display:inline-block;background:#1f6feb;color:#fff;text-decoration:none;padding:8px 16px;border-radius:4px;font-size:13px;font-weight:bold">
                &#128269; View Events Dashboard
              </a>
            </td></tr>
          </table>
          <div style="background:#1c2128;border:1px solid #30363d;border-radius:4px;padding:12px;margin-top:12px;font-size:12px;color:#8b949e">
            <div style="color:#58a6ff;margin-bottom:4px"># Run these commands on {hostname}:</div>
            <div>journalctl -u {service} -n 50 --no-pager</div>
            <div>sudo systemctl start {service}</div>
            <div>systemctl status {service}</div>
          </div>
        </div>

        <details>
          <summary style="color:#8b949e;font-size:12px;cursor:pointer;margin-bottom:8px">Last log lines (click to expand)</summary>
          <pre style="background:#1c2128;border:1px solid #30363d;border-radius:4px;padding:12px;font-size:11px;color:#8b949e;overflow-x:auto;white-space:pre-wrap">{logs}</pre>
        </details>
      </td></tr>
      <tr><td style="padding:12px 24px;border-top:1px solid #30363d;color:#484f58;font-size:11px">
        Sent by NetWatchM on {hostname} &mdash;
        <a href="{dashboard_url}" style="color:#58a6ff">Open Dashboard</a>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = username
    msg["To"]      = recipient
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
            s.starttls()
            s.login(username, password)
            s.sendmail(username, [recipient], msg.as_string())
        print(f"notify-down: alert sent to {recipient} for service '{service}'")
    except Exception as exc:
        print(f"notify-down: failed to send email: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <service-name>", file=sys.stderr)
        sys.exit(1)
    send_alert(sys.argv[1])
