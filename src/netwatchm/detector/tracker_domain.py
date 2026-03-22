"""Tracker/ad domain detector: fires LOW alert on DNS/TLS SNI match."""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from collections.abc import Iterable

from ..config import TrackerDomainConfig
from ..models import Alert, Packet, ThreatLevel
from .base import Detector

log = logging.getLogger("netwatchm.tracker_domain")


class TrackerDomainDetector(Detector):
    """Detect DNS queries or TLS SNI hostnames matching known tracker/ad domains.

    Downloads Steven Black's unified adware+malware hosts list at startup and
    refreshes it every ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``domain_set`` in tests to skip the HTTP call entirely.
    """

    def __init__(
        self,
        config: TrackerDomainConfig,
        domain_set: Iterable[str] | None = None,
    ) -> None:
        self._config = config
        self._domains: frozenset[str] = frozenset()
        self._alerted: dict[str, float] = {}  # "src_ip:domain" -> last_alert_time

        if domain_set is not None:
            all_domains = set(domain_set) | set(config.extra_domains)
            self._domains = frozenset(all_domains)
        else:
            self._refresh()
            t = threading.Thread(target=self._refresh_loop, daemon=True, name="tracker-domain-refresh")
            t.start()

    def _refresh(self) -> None:
        try:
            with urllib.request.urlopen(self._config.list_url, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            domains: set[str] = set()
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                domain = parts[1]
                if domain == "localhost" or domain.startswith("#"):
                    continue
                domains.add(domain)
            domains.update(self._config.extra_domains)
            self._domains = frozenset(domains)
            log.info("Tracker domain list loaded: %d domains", len(self._domains))
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to refresh tracker domain list: %s (keeping old list)", exc)

    def _refresh_loop(self) -> None:
        interval = self._config.refresh_hours * 3600
        while True:
            time.sleep(interval)
            self._refresh()

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled or not self._domains:
            return None

        domain = packet.dns_query or packet.sni
        if domain is None:
            return None

        domain = domain.rstrip(".")

        if domain not in self._domains:
            return None

        now = time.time()
        window = self._config.alert_window_seconds
        key = f"{packet.src_ip}:{domain}"
        if now - self._alerted.get(key, 0.0) < window:
            return None

        self._alerted[key] = now
        source = "DNS" if packet.dns_query else "SNI"
        return Alert(
            alert_type="TRACKER_DOMAIN",
            level=ThreatLevel.LOW,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=f"Tracker/ad domain contacted ({source}): {domain}",
        )

    def flush_expired(self) -> None:
        now = time.time()
        window = self._config.alert_window_seconds
        expired = [k for k, t in self._alerted.items() if now - t >= window]
        for k in expired:
            del self._alerted[k]
