"""CSV export for device inventory."""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Sequence

from ..models import DeviceRecord

COLUMNS = [
    "Label",
    "IP",
    "Hostname",
    "MAC",
    "Vendor",
    "First Seen",
    "Last Seen",
    "Bytes Sent",
    "Bytes Received",
    "Ports Observed",
    "Threat Level",
]


def _default_aliases_path() -> Path:
    if sys.platform == "win32":
        import os
        appdata = os.environ.get("APPDATA", str(Path.home()))
        return Path(appdata) / "netwatchm" / "aliases.json"
    return Path("/var/lib/netwatchm/aliases.json")


def _load_aliases(path: Path | None = None) -> dict[str, str]:
    p = path or _default_aliases_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _record_to_row(rec: DeviceRecord, aliases: dict[str, str]) -> dict[str, str]:
    return {
        "Label": aliases.get(rec.ip, ""),
        "IP": rec.ip,
        "Hostname": rec.hostname or "",
        "MAC": rec.mac or "",
        "Vendor": rec.vendor or "",
        "First Seen": rec.first_seen.strftime("%Y-%m-%dT%H:%M:%S"),
        "Last Seen": rec.last_seen.strftime("%Y-%m-%dT%H:%M:%S"),
        "Bytes Sent": str(rec.bytes_sent),
        "Bytes Received": str(rec.bytes_received),
        "Ports Observed": ";".join(str(p) for p in sorted(rec.ports_observed)),
        "Threat Level": rec.threat_level.name,
    }


def export_inventory(
    records: Sequence[DeviceRecord],
    path: str | Path | None = None,
    aliases: dict[str, str] | None = None,
) -> str | None:
    """Export device records to CSV.

    Args:
        records: sequence of DeviceRecord objects to export
        path: destination file path, or None to return CSV string
              (use "-" for stdout equivalent — returns string)
        aliases: optional {ip: label} dict; loaded from disk if not provided

    Returns:
        CSV content as string if path is None or "-", else None.
    """
    resolved_aliases = aliases if aliases is not None else _load_aliases()

    if path is None or str(path) == "-":
        buf = io.StringIO()
        _write_csv(buf, records, resolved_aliases)
        return buf.getvalue()

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        _write_csv(f, records, resolved_aliases)
    return None


def _write_csv(f: io.IOBase, records: Sequence[DeviceRecord], aliases: dict[str, str]) -> None:
    writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for rec in records:
        writer.writerow(_record_to_row(rec, aliases))
