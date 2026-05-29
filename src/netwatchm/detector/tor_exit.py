"""Tor exit node detector: fires HIGH alert when traffic involves a known Tor exit IP."""
from __future__ import annotations

import logging
import time
from collections.abc import Iterable

from ..config import TorExitConfig
from ..models import Alert, Packet, ThreatLevel
from .base import RemoteListDetector


class TorExitDetector(RemoteListDetector):
    """Detect traffic involving known Tor exit nodes.

    Downloads the Tor bulk exit list at startup and refreshes it every
    ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``exit_ips`` in tests to skip the HTTP call entirely.
    """

    log = logging.getLogger("netwatchm.tor_exit")
    thread_name = "tor-refresh"
    list_label = "Tor exit list"

    def __init__(
        self,
        config: TorExitConfig,
        exit_ips: Iterable[str] | None = None,
    ) -> None:
        super().__init__(config, injected=exit_ips)

    def _parse(self, raw: str) -> frozenset[str]:
        return frozenset(
            line.strip()
            for line in raw.splitlines()
            if line.strip() and not line.startswith("#")
        )

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled or not self._items:
            return None

        matched_ip: str | None = None
        direction: str = ""

        if packet.src_ip and packet.src_ip in self._items:
            matched_ip = packet.src_ip
            direction = "inbound from Tor"
        elif packet.dst_ip and packet.dst_ip in self._items:
            matched_ip = packet.dst_ip
            direction = "outbound to Tor"

        if matched_ip is None:
            return None

        if not self._should_alert(matched_ip, time.time()):
            return None

        # Outbound: an internal device is reaching out to Tor — investigate but not HIGH.
        # Inbound: a Tor exit node is connecting to us — HIGH.
        level = ThreatLevel.MEDIUM if direction == "outbound to Tor" else ThreatLevel.HIGH
        return Alert(
            alert_type="TOR_EXIT",
            level=level,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=f"Tor exit node {direction}: {matched_ip}",
        )
