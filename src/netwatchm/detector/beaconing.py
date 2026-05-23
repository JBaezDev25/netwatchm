"""C2 beaconing detector: HIGH alert on regular periodic outbound contacts."""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque

from ..config import BeaconingConfig
from ..models import Alert, Packet, ThreatLevel
from .base import Detector


class BeaconingDetector(Detector):
    """Detect C2-style beaconing: periodic outbound contacts to a single dst.

    Tracks contact timestamps per ``(src_ip, dst_ip)`` pair (outbound only).
    Fires HIGH alert when:
      • at least ``min_contacts`` timestamps fall within ``window_seconds``
      • mean inter-contact interval is in
        ``[min_interval_seconds, max_interval_seconds]``
      • coefficient of variation (stddev / mean) is below ``max_jitter_ratio``

    Only flags local → external traffic (RFC 1918 prefixes).
    Successive packets within 1s of the prior contact are folded into the
    same connection (not counted as separate beacons).
    """

    def __init__(
        self,
        config: BeaconingConfig,
        local_networks: list[str] | None = None,
    ) -> None:
        self._config = config
        self._local_nets = local_networks or [
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "127.",
        ]
        self._contacts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._alerted: dict[tuple[str, str], float] = {}

    def _is_local(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self._local_nets)

    def process(self, packet: Packet) -> Alert | None:
        cfg = self._config
        if not cfg.enabled or not packet.src_ip or not packet.dst_ip:
            return None
        if not self._is_local(packet.src_ip) or self._is_local(packet.dst_ip):
            return None

        key = (packet.src_ip, packet.dst_ip)
        now = time.time()
        dq = self._contacts[key]
        if dq and now - dq[-1] < 1.0:
            return None
        dq.append(now)
        cutoff = now - cfg.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < cfg.min_contacts:
            return None

        intervals = [dq[i] - dq[i - 1] for i in range(1, len(dq))]
        mean = sum(intervals) / len(intervals)
        if mean < cfg.min_interval_seconds or mean > cfg.max_interval_seconds:
            return None
        if mean == 0:
            return None
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std = math.sqrt(variance)
        cov = std / mean
        if cov > cfg.max_jitter_ratio:
            return None

        last = self._alerted.get(key, 0.0)
        if now - last < cfg.alert_window_seconds:
            return None
        self._alerted[key] = now

        return Alert(
            alert_type="BEACONING",
            level=ThreatLevel.HIGH,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=(
                f"Beacon-like pattern {packet.src_ip} → {packet.dst_ip}: "
                f"{len(dq)} contacts at {mean:.0f}s ± {std:.1f}s "
                f"(jitter {cov * 100:.0f}%)"
            ),
        )

    def flush_expired(self) -> None:
        now = time.time()
        cfg = self._config
        cutoff = now - cfg.window_seconds
        for key in list(self._contacts.keys()):
            dq = self._contacts[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._contacts[key]

        alert_cutoff = now - cfg.alert_window_seconds
        expired = [k for k, t in self._alerted.items() if t < alert_cutoff]
        for k in expired:
            del self._alerted[k]
