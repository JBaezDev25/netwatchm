"""Tracker/ad domain detector: fires LOW alert on DNS/TLS SNI match."""
from __future__ import annotations

import logging
from collections.abc import Iterable

from ..config import TrackerDomainConfig
from ..models import ThreatLevel
from .base import DomainListDetector


class TrackerDomainDetector(DomainListDetector):
    """Detect DNS queries or TLS SNI hostnames matching known tracker/ad domains.

    Downloads Steven Black's unified adware+malware hosts list at startup and
    refreshes it every ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``domain_set`` in tests to skip the HTTP call entirely.
    """

    log = logging.getLogger("netwatchm.tracker_domain")
    thread_name = "tracker-domain-refresh"
    list_label = "Tracker domain list"
    alert_type = "TRACKER_DOMAIN"
    level = ThreatLevel.LOW
    description_prefix = "Tracker/ad domain contacted"

    def __init__(
        self,
        config: TrackerDomainConfig,
        domain_set: Iterable[str] | None = None,
    ) -> None:
        super().__init__(config, injected=domain_set)
