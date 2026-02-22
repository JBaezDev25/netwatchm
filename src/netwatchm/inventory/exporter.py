"""CSV export for device inventory."""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Sequence

from ..models import DeviceRecord

COLUMNS = [
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


def _record_to_row(rec: DeviceRecord) -> dict[str, str]:
    return {
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
) -> str | None:
    """Export device records to CSV.

    Args:
        records: sequence of DeviceRecord objects to export
        path: destination file path, or None to return CSV string
              (use "-" for stdout equivalent — returns string)

    Returns:
        CSV content as string if path is None or "-", else None.
    """
    if path is None or str(path) == "-":
        buf = io.StringIO()
        _write_csv(buf, records)
        return buf.getvalue()

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        _write_csv(f, records)
    return None


def _write_csv(f: io.IOBase, records: Sequence[DeviceRecord]) -> None:
    writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for rec in records:
        writer.writerow(_record_to_row(rec))
