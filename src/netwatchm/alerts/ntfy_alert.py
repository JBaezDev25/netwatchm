"""ntfy.sh push notification alert handler."""
from __future__ import annotations

import asyncio
import logging
import time
import urllib.request
from urllib.error import URLError

from ..config import NtfyAlertConfig
from ..models import Alert, ThreatLevel
from .base import AlertHandler

logger = logging.getLogger(__name__)

# Map ThreatLevel → ntfy priority (1=min … 5=max)
_PRIORITY: dict[ThreatLevel, int] = {
    ThreatLevel.LOW: 2,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.HIGH: 4,
    ThreatLevel.CRITICAL: 5,
}


class NtfyAlert(AlertHandler):
    """Send push notifications via ntfy.sh (or self-hosted ntfy server).

    Token (for private topics) is read from NETWATCHM_NTFY_TOKEN env var.
    Per-alert-type cooldown prevents notification flooding.
    """

    def __init__(self, config: NtfyAlertConfig) -> None:
        self._config = config
        self._enabled = config.enabled and bool(config.topic)
        self._min_level = ThreatLevel[config.min_level]
        # alert_type -> last_sent epoch
        self._last_sent: dict[str, float] = {}

        if config.enabled and not config.topic:
            logger.warning("ntfy alerts enabled but topic is not set — disabled")

    async def send(self, alert: Alert) -> None:
        if not self._enabled:
            return
        if alert.level < self._min_level:
            return

        now = time.time()
        last = self._last_sent.get(alert.alert_type, 0.0)
        if now - last < self._config.cooldown_seconds:
            return
        self._last_sent[alert.alert_type] = now

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_sync, alert)

    def _send_sync(self, alert: Alert) -> None:
        cfg = self._config
        url = f"{cfg.server.rstrip('/')}/{cfg.topic}"

        lines = [alert.description]
        if alert.src_ip:
            lines.append(f"Src: {alert.src_ip}")
        if alert.dst_ip:
            lines.append(f"Dst: {alert.dst_ip}")
        body = "\n".join(lines).encode()

        priority = str(_PRIORITY.get(alert.level, 3))
        title = f"[{alert.level.name}] {alert.alert_type}"
        tag = alert.alert_type.lower().replace("_", "-")

        headers = {
            "X-Title": title,
            "X-Priority": priority,
            "X-Tags": tag,
            "Content-Type": "text/plain",
        }
        if cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10):
                logger.info("ntfy notification sent for %s", alert.alert_type)
        except URLError as exc:
            logger.warning("Failed to send ntfy notification: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ntfy unexpected error: %s", exc)
