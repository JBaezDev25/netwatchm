"""Email alert handler: Gmail SMTP with App Password."""
from __future__ import annotations

import asyncio
import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..config import EmailAlertConfig
from ..models import Alert, ThreatLevel
from .base import AlertHandler

logger = logging.getLogger(__name__)


class EmailAlert(AlertHandler):
    """Send HTML email alerts via Gmail SMTP.

    Password MUST come from NETWATCHM_EMAIL_PASSWORD env var.
    Per-alert-type cooldown prevents email flooding.
    """

    def __init__(self, config: EmailAlertConfig) -> None:
        self._config = config
        self._enabled = config.enabled and bool(config.password) and bool(config.recipient)
        self._min_level = ThreatLevel[config.min_level]
        # alert_type -> last_sent epoch
        self._last_sent: dict[str, float] = {}

        if config.enabled and not config.password:
            logger.warning(
                "Email alerts enabled but NETWATCHM_EMAIL_PASSWORD not set — disabled"
            )

    async def send(self, alert: Alert) -> None:
        if not self._enabled:
            return
        if alert.level < self._min_level:
            return

        # Cooldown check
        now = time.time()
        last = self._last_sent.get(alert.alert_type, 0.0)
        if now - last < self._config.cooldown_seconds:
            return
        self._last_sent[alert.alert_type] = now

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_sync, alert)

    def _send_sync(self, alert: Alert) -> None:
        cfg = self._config
        subject = f"[NetWatchM] {alert.level.name} — {alert.alert_type}"
        body = self._build_html(alert)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.username
        msg["To"] = cfg.recipient
        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(cfg.username, cfg.password)
                server.sendmail(cfg.username, cfg.recipient, msg.as_string())
            logger.info("Alert email sent for %s", alert.alert_type)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to send alert email: %s", exc)

    def _build_html(self, alert: Alert) -> str:
        color_map = {
            "LOW": "#28a745",
            "MEDIUM": "#ffc107",
            "HIGH": "#dc3545",
            "CRITICAL": "#6f0000",
        }
        color = color_map.get(alert.level.name, "#333")
        return f"""
<html><body style="font-family:monospace;background:#111;color:#eee;padding:20px">
<h2 style="color:{color}">[{alert.level.name}] {alert.alert_type}</h2>
<table>
  <tr><td><b>Time</b></td><td>{alert.timestamp.isoformat()}</td></tr>
  <tr><td><b>Source IP</b></td><td>{alert.src_ip or "—"}</td></tr>
  <tr><td><b>Destination IP</b></td><td>{alert.dst_ip or "—"}</td></tr>
  <tr><td><b>Description</b></td><td>{alert.description}</td></tr>
</table>
<p style="color:#888;font-size:0.8em">Sent by NetWatchM</p>
</body></html>
"""
