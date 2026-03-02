"""Alert handler that persists events to SQLite EventStore."""
from __future__ import annotations

import logging

from ..models import Alert
from .base import AlertHandler
from .event_store import DEFAULT_DB, EventStore

log = logging.getLogger("netwatchm.event_handler")


class EventStoreHandler(AlertHandler):
    """Persist each alert to the SQLite event store for the events portal."""

    def __init__(self, db_path: str = DEFAULT_DB) -> None:
        self._store = EventStore(db_path).open()

    async def send(self, alert: Alert) -> None:
        try:
            self._store.insert(alert)
        except Exception as exc:  # noqa: BLE001
            log.warning("EventStore insert failed: %s", exc)
