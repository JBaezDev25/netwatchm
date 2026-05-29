"""Abstract base class for threat detectors."""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable
from typing import Any

from ..models import Alert, Packet


def trim_pairs(dq: deque[tuple[float, Any]], cutoff: float) -> None:
    """Drop leading ``(timestamp, value)`` entries with timestamp older than cutoff."""
    while dq and dq[0][0] < cutoff:
        dq.popleft()


class Detector(ABC):
    """Base class for all threat detectors.

    Each detector maintains a sliding window of observations and fires
    an Alert when a threshold is exceeded.
    """

    @abstractmethod
    def process(self, packet: Packet) -> Alert | None:
        """Process a single packet and return an Alert if a threat is detected."""
        ...

    @abstractmethod
    def flush_expired(self) -> None:
        """Remove stale entries from the sliding window. Called every second."""
        ...


class RemoteListDetector(Detector):
    """Base for detectors backed by a periodically-refreshed remote list.

    Handles the shared lifecycle: a blocking fetch at startup, a daemon thread
    that re-downloads every ``config.refresh_hours`` hours, per-key alert dedup
    over ``config.alert_window_seconds``, and stale-entry flushing. Subclasses
    provide ``_parse`` (raw text -> item set) and ``process``.

    Tests inject the item set directly (via the subclass constructor) to skip
    all network access.
    """

    log = logging.getLogger("netwatchm.remote_list")
    thread_name = "remote-list-refresh"
    list_label = "remote list"

    def __init__(self, config: object, injected: Iterable[str] | None = None) -> None:
        self._config = config
        self._items: frozenset[str] = frozenset()
        self._alerted: dict[str, float] = {}  # dedup key -> last_alert_time

        if injected is not None:
            self._items = self._build_injected(injected)
        else:
            self._refresh()
            threading.Thread(
                target=self._refresh_loop, daemon=True, name=self.thread_name
            ).start()

    def _build_injected(self, injected: Iterable[str]) -> frozenset[str]:
        """Build the item set from a test-injected iterable. Override to merge extras."""
        return frozenset(injected)

    @abstractmethod
    def _parse(self, raw: str) -> frozenset[str]:
        """Parse downloaded list text into the item set."""
        ...

    def _refresh(self) -> None:
        """Download and replace the item set; keep the old set on failure."""
        try:
            with urllib.request.urlopen(self._config.list_url, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            self._items = self._parse(raw)
            self.log.info("%s loaded: %d entries", self.list_label, len(self._items))
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "Failed to refresh %s: %s (keeping old list)", self.list_label, exc
            )

    def _refresh_loop(self) -> None:
        """Background daemon: sleep, refresh, repeat."""
        interval = self._config.refresh_hours * 3600
        while True:
            time.sleep(interval)
            self._refresh()

    def _should_alert(self, key: str, now: float) -> bool:
        """Return True (and record the alert) if the dedup window has elapsed for key."""
        if now - self._alerted.get(key, 0.0) < self._config.alert_window_seconds:
            return False
        self._alerted[key] = now
        return True

    def flush_expired(self) -> None:
        """Remove dedup entries older than the alert window."""
        now = time.time()
        window = self._config.alert_window_seconds
        for key in [k for k, t in self._alerted.items() if now - t >= window]:
            del self._alerted[key]


class DomainListDetector(RemoteListDetector):
    """Remote-list detector that matches DNS query / TLS SNI hostnames.

    Subclasses set ``alert_type``, ``level`` and ``description_prefix``. The
    default ``_parse`` reads a Steven Black-style hosts file (``IP<tab>domain``).
    """

    alert_type = ""
    level: object = None
    description_prefix = ""

    def _build_injected(self, injected: Iterable[str]) -> frozenset[str]:
        return frozenset(set(injected) | set(self._config.extra_domains))

    def _parse(self, raw: str) -> frozenset[str]:
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
        return frozenset(domains)

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled or not self._items:
            return None

        domain = packet.dns_query or packet.sni
        if domain is None:
            return None

        domain = domain.rstrip(".")
        if domain not in self._items:
            return None

        if not self._should_alert(f"{packet.src_ip}:{domain}", time.time()):
            return None

        source = "DNS" if packet.dns_query else "SNI"
        return Alert(
            alert_type=self.alert_type,
            level=self.level,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=f"{self.description_prefix} ({source}): {domain}",
        )
