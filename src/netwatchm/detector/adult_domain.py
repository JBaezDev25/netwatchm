"""Adult content domain detector: fires MEDIUM alert on DNS/TLS SNI match."""
from __future__ import annotations

import logging
from collections.abc import Iterable

from ..config import AdultDomainConfig
from ..models import ThreatLevel
from .base import DomainListDetector


class AdultDomainDetector(DomainListDetector):
    """Detect DNS queries or TLS SNI hostnames matching known adult-content domains.

    Downloads Steven Black's porn hosts list at startup and refreshes it every
    ``config.refresh_hours`` hours in a background daemon thread.

    Pass ``domain_set`` in tests to skip the HTTP call entirely.
    """

    log = logging.getLogger("netwatchm.adult_domain")
    thread_name = "adult-domain-refresh"
    list_label = "Adult domain list"
    alert_type = "ADULT_DOMAIN"
    level = ThreatLevel.MEDIUM
    description_prefix = "Adult domain accessed"

    def __init__(
        self,
        config: AdultDomainConfig,
        domain_set: Iterable[str] | None = None,
    ) -> None:
        super().__init__(config, injected=domain_set)
