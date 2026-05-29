"""SIEM forwarding alert handler — emits ArcSight CEF over syslog.

Every alert at/above ``min_level`` is rendered as a CEF (Common Event Format)
record wrapped in an RFC 3164 syslog header and shipped to a SIEM collector
over UDP or TCP. CEF is ingested natively by Splunk, IBM QRadar, Elastic,
Wazuh, Graylog, Microsoft Sentinel, and most other SIEMs.

The socket write runs in a thread executor so the asyncio alert pipeline is
never blocked, and every send is best-effort: a transport failure is logged
and dropped, never raised into the pipeline.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from datetime import datetime

from ..config import SiemConfig
from ..models import Alert, ThreatLevel
from .alert_labels import get_title
from .base import AlertHandler

logger = logging.getLogger(__name__)

# ThreatLevel → CEF severity (0–10 scale).
_SEVERITY: dict[ThreatLevel, int] = {
    ThreatLevel.LOW: 3,
    ThreatLevel.MEDIUM: 5,
    ThreatLevel.HIGH: 8,
    ThreatLevel.CRITICAL: 10,
}

_VENDOR = "NetWatchM"
_PRODUCT = "netwatchm"
_CEF_VERSION = "0"


def _escape_header(value: str) -> str:
    """CEF header fields escape backslash and pipe."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_ext(value: str) -> str:
    """CEF extension values escape backslash, equals, and newlines."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def format_cef(alert: Alert, *, product_version: str = "0.2") -> str:
    """Render an Alert as a single CEF line (no syslog header)."""
    severity = _SEVERITY.get(alert.level, 5)
    name = _escape_header(get_title(alert.alert_type) or alert.alert_type)
    sig = _escape_header(alert.alert_type)

    header = (
        f"CEF:{_CEF_VERSION}|{_VENDOR}|{_PRODUCT}|{product_version}"
        f"|{sig}|{name}|{severity}"
    )

    rt = int(alert.timestamp.timestamp() * 1000)
    ext = [f"rt={rt}", f"cat={_escape_ext(alert.alert_type)}"]
    if alert.src_ip:
        ext.append(f"src={_escape_ext(alert.src_ip)}")
    if alert.dst_ip:
        ext.append(f"dst={_escape_ext(alert.dst_ip)}")
    ext.append(f"msg={_escape_ext(alert.description)}")
    ext.append(f"NetWatchMThreatLevel={alert.level.name}")

    return f"{header}|{' '.join(ext)}"


class SiemHandler(AlertHandler):
    """Forward alerts to a SIEM collector as CEF over syslog (UDP/TCP)."""

    def __init__(self, config: SiemConfig, product_version: str = "0.2") -> None:
        self._config = config
        self._version = product_version
        self._min_level = ThreatLevel[config.min_level]
        self._proto = config.protocol.lower()
        self._hostname = socket.gethostname()
        # syslog PRI = facility * 8 + severity(notice=5)
        self._pri = config.facility * 8 + 5
        self._enabled = config.enabled and bool(config.host)

        if config.enabled and not config.host:
            logger.warning("SIEM forwarding enabled but host is not set — disabled")
        if self._proto not in ("udp", "tcp"):
            logger.warning("SIEM protocol %r invalid; defaulting to udp", config.protocol)
            self._proto = "udp"

    async def send(self, alert: Alert) -> None:
        if not self._enabled:
            return
        if alert.level < self._min_level:
            return
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_sync, alert)

    def _frame(self, alert: Alert) -> bytes:
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        cef = format_cef(alert, product_version=self._version)
        return f"<{self._pri}>{ts} {self._hostname} {cef}\n".encode()

    def _send_sync(self, alert: Alert) -> None:
        payload = self._frame(alert)
        try:
            if self._proto == "tcp":
                with socket.create_connection(
                    (self._config.host, self._config.port), timeout=self._config.timeout
                ) as sock:
                    sock.sendall(payload)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(payload, (self._config.host, self._config.port))
            logger.info("SIEM event forwarded for %s", alert.alert_type)
        except OSError as exc:
            logger.warning("SIEM forward failed (%s:%s): %s",
                           self._config.host, self._config.port, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SIEM forward unexpected error: %s", exc)
