"""Data hog detector: fires HIGH alert when a device uses excessive bandwidth over 24 h."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from ..config import DataHogConfig
from ..models import Alert, Packet, ThreatLevel
from ..util import format_bytes
from .base import Detector, trim_pairs

log = logging.getLogger("netwatchm.data_hog")

_LOCAL_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.",
)


def _is_local(ip: str) -> bool:
    return ip.startswith(_LOCAL_PREFIXES)


def _fmt_bytes(n: int) -> str:
    return format_bytes(n, units=("B", "KB", "MB", "GB", "TB"), overflow="PB")


class DataHogDetector(Detector):
    """Detect devices consuming excessive bandwidth over a rolling 24-hour window.

    Tracks bytes sent AND received per local IP.  Fires a HIGH alert when the
    rolling total exceeds ``config.bytes_per_24h``.  Deduplicates per device
    with a configurable re-alert window so a sustained hog does not flood the
    alert queue.
    """

    def __init__(self, config: DataHogConfig) -> None:
        self._config = config
        # ip -> deque of (wall_time, bytes)
        self._windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}  # ip -> last_alert_time

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _trim(self, dq: deque[tuple[float, int]], now: float) -> None:
        trim_pairs(dq, now - self._config.window_seconds)

    def _check_ip(self, ip: str, length: int, now: float, packet: Packet) -> Alert | None:
        """Accumulate bytes for ``ip`` and return an alert if threshold crossed."""
        dq = self._windows[ip]
        dq.append((now, length))
        self._trim(dq, now)
        total = sum(b for _, b in dq)
        if total < self._config.bytes_per_24h:
            return None
        # Threshold exceeded — dedup check
        window = self._config.alert_window_seconds
        if now - self._alerted.get(ip, 0.0) < window:
            return None
        self._alerted[ip] = now
        threshold_str = _fmt_bytes(self._config.bytes_per_24h)
        total_str = _fmt_bytes(total)
        hours = self._config.window_seconds / 3600
        return Alert(
            alert_type="DATA_HOG",
            level=ThreatLevel.HIGH,
            src_ip=ip,
            dst_ip=packet.dst_ip if packet.src_ip == ip else packet.src_ip,
            description=(
                f"Data hog {ip}: {total_str} in {hours:.0f}h "
                f"(threshold: {threshold_str})"
            ),
        )

    # ------------------------------------------------------------------
    # Detector interface
    # ------------------------------------------------------------------

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled:
            return None

        now = time.time()
        # Check src IP (bytes sent by device)
        if packet.src_ip and _is_local(packet.src_ip):
            alert = self._check_ip(packet.src_ip, packet.length, now, packet)
            if alert:
                return alert
        # Check dst IP (bytes received by device), only when src is external
        # to avoid double-counting local-to-local traffic
        if (
            packet.dst_ip
            and _is_local(packet.dst_ip)
            and packet.src_ip
            and not _is_local(packet.src_ip)
        ):
            alert = self._check_ip(packet.dst_ip, packet.length, now, packet)
            if alert:
                return alert
        return None

    def flush_expired(self) -> None:
        """Trim old window entries and prune expired dedup records."""
        now = time.time()
        for ip, dq in list(self._windows.items()):
            self._trim(dq, now)
            if not dq:
                del self._windows[ip]
        window = self._config.alert_window_seconds
        expired = [ip for ip, t in self._alerted.items() if now - t >= window]
        for ip in expired:
            del self._alerted[ip]
