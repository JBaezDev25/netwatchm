"""Brute-force detector: fires HIGH alert when N auth attempts in T seconds."""
from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from ..config import BruteForceThreshold
from ..models import Alert, Packet, ThreatLevel
from .base import Detector


class BruteForceDetector(Detector):
    """Detect brute-force authentication attacks.

    Alert fires when a single source IP makes >= attempts_per_window connections
    to any auth port (SSH/RDP/FTP/MySQL/VNC) within window_seconds.
    """

    def __init__(self, threshold: BruteForceThreshold) -> None:
        self._threshold = threshold
        self._ports: frozenset[int] = frozenset(threshold.ports)
        # key: (src_ip, dst_port) -> deque of wall_time
        self._windows: dict[tuple[str, int], deque[float]] = defaultdict(deque)
        self._alerted: set[tuple[str, int]] = set()

    def process(self, packet: Packet) -> Alert | None:
        if not packet.src_ip or packet.dst_port is None:
            return None
        if packet.dst_port not in self._ports:
            return None
        try:
            if ipaddress.ip_address(packet.src_ip).is_private:
                return None
        except ValueError:
            return None

        now = time.time()
        key = (packet.src_ip, packet.dst_port)
        dq = self._windows[key]
        dq.append(now)
        self._trim(dq, now)

        if len(dq) >= self._threshold.attempts_per_window:
            if key not in self._alerted:
                self._alerted.add(key)
                return Alert(
                    alert_type="BRUTE_FORCE",
                    level=ThreatLevel.HIGH,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=(
                        f"Brute-force from {packet.src_ip} → port {packet.dst_port}: "
                        f"{len(dq)} attempts in {self._threshold.window_seconds}s"
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

    def _trim(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._threshold.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
