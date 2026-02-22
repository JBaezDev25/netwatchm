"""New IP detector: fires LOW alert for first-seen IPs after baseline period."""
from __future__ import annotations

import time

from ..config import NewIPThreshold
from ..models import Alert, Packet, ThreatLevel
from .base import Detector


class NewIPDetector(Detector):
    """Detect new IP addresses appearing on the network.

    During the baseline_period, IPs are silently collected.
    After the baseline period, any new IP triggers a LOW alert.
    """

    def __init__(self, threshold: NewIPThreshold, baseline_period: float) -> None:
        self._threshold = threshold
        self._baseline_period = baseline_period
        self._start_time = time.time()
        self._known_ips: set[str] = set()

    @property
    def _in_baseline(self) -> bool:
        return (time.time() - self._start_time) < self._baseline_period

    def process(self, packet: Packet) -> Alert | None:
        if not self._threshold.enabled:
            return None

        # Collect all new IPs first, add them all to known_ips
        new_ips: list[str] = []
        for ip in (packet.src_ip, packet.dst_ip):
            if not ip:
                continue
            if ip not in self._known_ips:
                self._known_ips.add(ip)
                new_ips.append(ip)

        if not new_ips or self._in_baseline:
            return None

        # Alert for the first newly seen IP
        ip = new_ips[0]
        return Alert(
            alert_type="NEW_IP",
            level=ThreatLevel.LOW,
            src_ip=ip,
            dst_ip=None,
            description=f"New IP address observed: {ip}",
            expires_at=time.time() + 60,
        )

    def flush_expired(self) -> None:
        # No windowed state to flush; known_ips grows monotonically
        pass

    def add_known_ip(self, ip: str) -> None:
        """Manually add an IP to the known set (e.g., from inventory persistence)."""
        self._known_ips.add(ip)
