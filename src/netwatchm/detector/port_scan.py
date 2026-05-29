"""Port scan detector: fires HIGH alert when a src IP hits N distinct ports in T seconds."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from ..config import PortScanThreshold
from ..models import Alert, Packet, ThreatLevel
from .base import Detector, trim_pairs


class PortScanDetector(Detector):
    """Detect port scan behaviour.

    Alert fires when a single source IP contacts >= ports_per_window distinct
    destination ports within window_seconds using wall-clock time.
    """

    def __init__(self, threshold: PortScanThreshold) -> None:
        self._threshold = threshold
        # src_ip -> deque of (wall_time, dst_port)
        self._windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # Track already-alerted IPs to avoid alert flood; reset after window expires
        self._alerted: set[str] = set()

    def process(self, packet: Packet) -> Alert | None:
        if not packet.src_ip or packet.dst_port is None:
            return None

        now = time.time()
        src = packet.src_ip
        dq = self._windows[src]
        dq.append((now, packet.dst_port))
        self._trim(dq, now)

        distinct_ports = {port for _, port in dq}
        if len(distinct_ports) >= self._threshold.ports_per_window:
            if src not in self._alerted:
                self._alerted.add(src)
                return Alert(
                    alert_type="PORT_SCAN",
                    level=ThreatLevel.HIGH,
                    src_ip=src,
                    dst_ip=packet.dst_ip,
                    description=(
                        f"Port scan from {src}: "
                        f"{len(distinct_ports)} distinct ports in "
                        f"{self._threshold.window_seconds}s window"
                    ),
                    expires_at=now + self._threshold.window_seconds,
                )
        else:
            self._alerted.discard(src)
        return None

    def flush_expired(self) -> None:
        now = time.time()
        for src, dq in list(self._windows.items()):
            self._trim(dq, now)
            if not dq:
                del self._windows[src]
                self._alerted.discard(src)

    def _trim(self, dq: deque[tuple[float, int]], now: float) -> None:
        trim_pairs(dq, now - self._threshold.window_seconds)
