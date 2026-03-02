"""Tor exit node detector: fires HIGH alert when traffic involves a known Tor exit IP."""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from collections.abc import Iterable

from ..config import TorExitConfig
from ..models import Alert, Packet, ThreatLevel
from .base import Detector

log = logging.getLogger("netwatchm.tor_exit")


class TorExitDetector(Detector):
    """Detect traffic involving known Tor exit nodes.

    Downloads the Tor bulk exit list at startup and refreshes it every
    ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``exit_ips`` in tests to skip the HTTP call entirely.
    """

    def __init__(
        self,
        config: TorExitConfig,
        exit_ips: Iterable[str] | None = None,
    ) -> None:
        self._config = config
        self._exit_ips: frozenset[str] = frozenset()
        self._alerted: dict[str, float] = {}  # tor_ip -> last_alert_time

        if exit_ips is not None:
            # Test path: use provided set directly, no network call
            self._exit_ips = frozenset(exit_ips)
        else:
            # Production path: fetch list now, then keep refreshing
            self._refresh()
            t = threading.Thread(target=self._refresh_loop, daemon=True, name="tor-refresh")
            t.start()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Download and replace the exit-node IP set."""
        try:
            with urllib.request.urlopen(self._config.list_url, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            ips = frozenset(
                line.strip()
                for line in raw.splitlines()
                if line.strip() and not line.startswith("#")
            )
            self._exit_ips = ips
            log.info("Tor exit list loaded: %d IPs", len(ips))
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to refresh Tor exit list: %s (keeping old list)", exc)

    def _refresh_loop(self) -> None:
        """Background daemon: sleep, refresh, repeat."""
        interval = self._config.refresh_hours * 3600
        while True:
            time.sleep(interval)
            self._refresh()

    # ------------------------------------------------------------------
    # Detector interface
    # ------------------------------------------------------------------

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled or not self._exit_ips:
            return None

        matched_ip: str | None = None
        direction: str = ""

        if packet.src_ip and packet.src_ip in self._exit_ips:
            matched_ip = packet.src_ip
            direction = "inbound from Tor"
        elif packet.dst_ip and packet.dst_ip in self._exit_ips:
            matched_ip = packet.dst_ip
            direction = "outbound to Tor"

        if matched_ip is None:
            return None

        # Deduplication: suppress if re-alert window not yet expired
        now = time.time()
        window = self._config.alert_window_seconds
        if now - self._alerted.get(matched_ip, 0.0) < window:
            return None

        self._alerted[matched_ip] = now
        return Alert(
            alert_type="TOR_EXIT",
            level=ThreatLevel.HIGH,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=f"Tor exit node {direction}: {matched_ip}",
        )

    def flush_expired(self) -> None:
        """Remove dedup entries older than the alert window."""
        now = time.time()
        window = self._config.alert_window_seconds
        expired = [ip for ip, t in self._alerted.items() if now - t >= window]
        for ip in expired:
            del self._alerted[ip]
