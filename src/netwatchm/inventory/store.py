"""DeviceStore: in-memory device inventory with JSON persistence."""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import DeviceRecord, Packet, ThreatLevel

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _default_inventory_path() -> Path:
    if sys.platform == "win32":
        import os
        appdata = os.environ.get("APPDATA", str(Path.home()))
        return Path(appdata) / "netwatchm" / "inventory.json"
    return Path("/var/lib/netwatchm/inventory.json")


class DeviceStore:
    """In-memory store of DeviceRecord objects, keyed by IP address.

    Thread-safe for asyncio via asyncio.Lock.
    """

    def __init__(self) -> None:
        self._records: dict[str, DeviceRecord] = {}
        self._lock = asyncio.Lock()

    async def update(self, packet: Packet) -> None:
        """Upsert device records for src and dst IPs in packet."""
        now = datetime.now()
        async with self._lock:
            for ip, is_src in ((packet.src_ip, True), (packet.dst_ip, False)):
                if not ip:
                    continue
                if ip not in self._records:
                    self._records[ip] = DeviceRecord(
                        ip=ip,
                        first_seen=now,
                        last_seen=now,
                    )
                rec = self._records[ip]
                rec.last_seen = now
                if is_src:
                    rec.bytes_sent += packet.length
                    if packet.dst_port is not None:
                        rec.ports_observed.add(packet.dst_port)
                else:
                    rec.bytes_received += packet.length
                    if packet.src_port is not None:
                        rec.ports_observed.add(packet.src_port)

    async def update_threat(self, ip: str, level: ThreatLevel) -> None:
        """Update the threat level for an IP if the new level is higher."""
        async with self._lock:
            if ip in self._records:
                if level > self._records[ip].threat_level:
                    self._records[ip].threat_level = level

    async def update_hostname(self, ip: str, hostname: str | None) -> None:
        """Set resolved hostname for an IP."""
        async with self._lock:
            if ip in self._records:
                self._records[ip].hostname = hostname

    async def get_all(self, filter_query: str | None = None) -> list[DeviceRecord]:
        """Return list of all records, optionally filtered by substring."""
        async with self._lock:
            records = list(self._records.values())

        if not filter_query:
            return records

        query = filter_query.lower()
        return [
            r for r in records
            if query in (r.ip or "").lower()
            or query in (r.hostname or "").lower()
            or query in (r.mac or "").lower()
            or query in (r.vendor or "").lower()
        ]

    async def get_unresolved_ips(self) -> list[str]:
        """Return IPs that have no hostname yet."""
        async with self._lock:
            return [ip for ip, rec in self._records.items() if rec.hostname is None]

    def get_all_ips(self) -> list[str]:
        """Return all known IPs (no lock needed for read-only listing)."""
        return list(self._records.keys())

    async def persist(self, path: Path | None = None) -> None:
        """Serialize records to JSON file."""
        if path is None:
            path = _default_inventory_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            async with self._lock:
                data = [rec.to_dict() for rec in self._records.values()]
            path.write_text(json.dumps(data, indent=2))
            logger.debug("Inventory persisted to %s (%d records)", path, len(data))
        except OSError as exc:
            logger.warning("Failed to persist inventory: %s", exc)

    async def load(self, path: Path | None = None) -> None:
        """Load records from JSON file (replaces current in-memory state)."""
        if path is None:
            path = _default_inventory_path()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            async with self._lock:
                self._records = {
                    item["ip"]: DeviceRecord.from_dict(item) for item in data
                }
            logger.info("Loaded %d inventory records from %s", len(self._records), path)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to load inventory: %s", exc)

    async def run_persist_loop(
        self,
        interval: int,
        stop_event: asyncio.Event,
        path: Path | None = None,
    ) -> None:
        """Background coroutine: auto-save every interval seconds."""
        while not stop_event.is_set():
            await asyncio.sleep(interval)
            if not stop_event.is_set():
                await self.persist(path)
