"""Exfiltration detector: fires CRITICAL when large outbound volume to new IP."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from ..config import ExfiltrationThreshold
from ..models import Alert, Packet, ThreatLevel
from .base import Detector


class ExfiltrationDetector(Detector):
    """Detect potential data exfiltration.

    Alert fires when a source IP sends >= bytes_per_window bytes to a single
    destination IP within window_seconds using wall-clock time.
    """

    def __init__(
        self,
        threshold: ExfiltrationThreshold,
        local_networks: list[str] | None = None,
    ) -> None:
        self._threshold = threshold
        # Track local networks to distinguish outbound vs inbound
        self._local_nets = local_networks or ["192.168.", "10.", "172.16.", "172.17.",
                                               "172.18.", "172.19.", "172.20.", "172.21.",
                                               "172.22.", "172.23.", "172.24.", "172.25.",
                                               "172.26.", "172.27.", "172.28.", "172.29.",
                                               "172.30.", "172.31.", "127."]
        # key: (src_ip, dst_ip) -> deque of (wall_time, bytes)
        self._windows: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()

    def _is_local(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self._local_nets)

    def process(self, packet: Packet) -> Alert | None:
        if not packet.src_ip or not packet.dst_ip:
            return None
        # Only flag outbound traffic (local → external)
        if not self._is_local(packet.src_ip) or self._is_local(packet.dst_ip):
            return None

        now = time.time()
        key = (packet.src_ip, packet.dst_ip)
        dq = self._windows[key]
        dq.append((now, packet.length))
        self._trim(dq, now)

        total_bytes = sum(b for _, b in dq)
        if total_bytes >= self._threshold.bytes_per_window:
            if key not in self._alerted:
                self._alerted.add(key)
                mb = total_bytes / 1_048_576
                return Alert(
                    alert_type="EXFILTRATION",
                    level=ThreatLevel.CRITICAL,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=(
                        f"Possible exfiltration {packet.src_ip} → {packet.dst_ip}: "
                        f"{mb:.1f} MB in {self._threshold.window_seconds}s"
                    ),
                    expires_at=now + self._threshold.window_seconds,
                )
        else:
            self._alerted.discard(key)
        return None

    def flush_expired(self) -> None:
        now = time.time()
        for key, dq in list(self._windows.items()):
            self._trim(dq, now)
            if not dq:
                del self._windows[key]
                self._alerted.discard(key)

    def _trim(self, dq: deque[tuple[float, int]], now: float) -> None:
        cutoff = now - self._threshold.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
