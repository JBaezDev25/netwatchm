"""MAC OUI → vendor name lookup backed by /var/lib/netwatchm/oui.json.

Build the database with: bash scripts/update-oui-db.sh
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_OUI_PATH = Path(
    r"C:\ProgramData\netwatchm\oui.json"
    if sys.platform == "win32"
    else "/var/lib/netwatchm/oui.json"
)

_db: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _db
    if _db is None:
        if _OUI_PATH.exists():
            try:
                _db = json.loads(_OUI_PATH.read_text(encoding="utf-8"))
                logger.debug("OUI database loaded: %d entries", len(_db))
            except Exception as exc:
                logger.warning("Failed to load OUI database: %s", exc)
                _db = {}
        else:
            logger.debug(
                "OUI database not found at %s — run scripts/update-oui-db.sh",
                _OUI_PATH,
            )
            _db = {}
    return _db


def lookup(mac: str) -> str | None:
    """Return vendor name for a MAC address, or None if not found.

    Accepts any common format: 'aa:bb:cc:dd:ee:ff', 'AA-BB-CC', '30C6F7…', etc.
    Only the first three octets (OUI prefix) are used.
    """
    if not mac:
        return None
    normalized = mac.lower().replace("-", ":").replace(".", ":")
    parts = normalized.split(":")
    if len(parts) < 3:
        return None
    oui = ":".join(parts[:3])
    return _load().get(oui)


def reload() -> None:
    """Force reload from disk (call after update-oui-db.sh runs)."""
    global _db
    _db = None
    _load()
