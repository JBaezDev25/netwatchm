"""Adult content domain detector: fires MEDIUM alert on DNS/TLS SNI match."""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from collections.abc import Iterable

from ..config import AdultDomainConfig
from ..models import Alert, Packet, ThreatLevel
from .base import Detector

log = logging.getLogger("netwatchm.adult_domain")


class AdultDomainDetector(Detector):
    """Detect DNS queries or TLS SNI hostnames matching known adult-content domains.

    Downloads Steven Black's porn hosts list at startup and refreshes it every
    ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``domain_set`` in tests to skip the HTTP call entirely.
    """

    def __init__(
        self,
        config: AdultDomainConfig,
        domain_set: Iterable[str] | None = None,
    ) -> None:
        self._config = config
        self._domains: frozenset[str] = frozenset()
        self._alerted: dict[str, float] = {}  # "src_ip:domain" -> last_alert_time

        if domain_set is not None:
            # Test path: use provided set directly, no network call
            all_domains = set(domain_set) | set(config.extra_domains)
            self._domains = frozenset(all_domains)
        else:
            # Production path: fetch list now, then keep refreshing
            self._refresh()
            t = threading.Thread(target=self._refresh_loop, daemon=True, name="adult-domain-refresh")
            t.start()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Download and replace the adult domain set."""
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
            log.info("Adult domain list loaded: %d domains", len(self._domains))
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to refresh adult domain list: %s (keeping old list)", exc)

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
        if not self._config.enabled or not self._domains:
            return None

        domain = packet.dns_query or packet.sni
        if domain is None:
            return None

        # Normalize: strip trailing dot (DNS FQDN)
        domain = domain.rstrip(".")

        if domain not in self._domains:
            return None

        # Deduplication: suppress if re-alert window not yet expired
        now = time.time()
        window = self._config.alert_window_seconds
        key = f"{packet.src_ip}:{domain}"
        if now - self._alerted.get(key, 0.0) < window:
            return None

        self._alerted[key] = now
        source = "DNS" if packet.dns_query else "SNI"
        return Alert(
            alert_type="ADULT_DOMAIN",
            level=ThreatLevel.MEDIUM,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=f"Adult domain accessed ({source}): {domain}",
        )

    def flush_expired(self) -> None:
        """Remove dedup entries older than the alert window."""
        now = time.time()
        window = self._config.alert_window_seconds
        expired = [k for k, t in self._alerted.items() if now - t >= window]
        for k in expired:
            del self._alerted[k]
