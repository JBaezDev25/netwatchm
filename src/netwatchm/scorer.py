"""Aggregate threat level from active alerts."""
from __future__ import annotations

import time
from collections import deque

from .models import Alert, ThreatLevel


class ThreatScorer:
    """Maintain a set of active alerts and compute the current aggregate threat level.

    Alerts with expires_at > 0 are automatically expired when their time passes.
    """

    def __init__(self) -> None:
        self._active: deque[Alert] = deque()

    def add_alert(self, alert: Alert) -> None:
        """Add an alert to the active set."""
        self._active.append(alert)

    def flush_expired(self) -> None:
        """Remove expired alerts."""
        now = time.time()
        while self._active and self._active[0].expires_at != 0 and self._active[0].expires_at < now:
            self._active.popleft()
        # Also remove from anywhere in the deque (non-zero expires_at)
        self._active = deque(
            a for a in self._active
            if a.expires_at == 0 or a.expires_at >= now
        )

    def current_level(self) -> ThreatLevel:
        """Return max threat level of active alerts, or LOW if none."""
        self.flush_expired()
        if not self._active:
            return ThreatLevel.LOW
        return max(a.level for a in self._active)

    def active_alerts(self) -> list[Alert]:
        """Return list of currently active alerts (unexpired)."""
        self.flush_expired()
        return list(self._active)

    def alert_count_today(self) -> int:
        """Return the total count of active alerts (approximation)."""
        return len(self._active)
