"""Tests for CSV inventory exporter."""
from __future__ import annotations

import csv
import io
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from netwatchm.inventory.exporter import COLUMNS, export_inventory
from netwatchm.models import DeviceRecord, ThreatLevel


def make_record(
    ip: str = "10.0.0.1",
    hostname: str | None = "myhost.local",
    mac: str | None = "aa:bb:cc:dd:ee:ff",
    ports: set[int] | None = None,
    threat: ThreatLevel = ThreatLevel.LOW,
    bytes_sent: int = 1024,
    bytes_received: int = 2048,
) -> DeviceRecord:
    return DeviceRecord(
        ip=ip,
        hostname=hostname,
        mac=mac,
        ports_observed=ports or {80, 443},
        threat_level=threat,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        first_seen=datetime(2025, 1, 15, 10, 0, 0),
        last_seen=datetime(2025, 1, 15, 14, 22, 1),
    )


class TestExportInventory:
    def test_returns_string_when_no_path(self) -> None:
        rec = make_record()
        result = export_inventory([rec], None)
        assert isinstance(result, str)
        assert "10.0.0.1" in result

    def test_csv_has_all_columns(self) -> None:
        rec = make_record()
        csv_str = export_inventory([rec], None)
        assert csv_str is not None
        reader = csv.DictReader(io.StringIO(csv_str))
        assert reader.fieldnames == COLUMNS

    def test_csv_row_values(self) -> None:
        rec = make_record(ports={22, 80, 443}, threat=ThreatLevel.HIGH)
        csv_str = export_inventory([rec], None)
        assert csv_str is not None
        reader = csv.DictReader(io.StringIO(csv_str))
        row = next(reader)
        assert row["IP"] == "10.0.0.1"
        assert row["Hostname"] == "myhost.local"
        assert row["MAC"] == "aa:bb:cc:dd:ee:ff"
        assert row["Threat Level"] == "HIGH"
        # Ports sorted semicolon separated
        assert row["Ports Observed"] == "22;80;443"
        assert row["First Seen"] == "2025-01-15T10:00:00"
        assert row["Last Seen"] == "2025-01-15T14:22:01"

    def test_writes_file(self) -> None:
        rec = make_record()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.csv"
            result = export_inventory([rec], path)
            assert result is None
            assert path.exists()
            content = path.read_text()
            assert "10.0.0.1" in content

    def test_stdout_flag(self) -> None:
        rec = make_record()
        result = export_inventory([rec], "-")
        assert isinstance(result, str)
        assert "10.0.0.1" in result

    def test_empty_records(self) -> None:
        csv_str = export_inventory([], None)
        assert csv_str is not None
        lines = [l for l in csv_str.splitlines() if l]
        assert len(lines) == 1  # header only

    def test_none_fields_empty_string(self) -> None:
        rec = make_record(hostname=None, mac=None)
        csv_str = export_inventory([rec], None)
        assert csv_str is not None
        reader = csv.DictReader(io.StringIO(csv_str))
        row = next(reader)
        assert row["Hostname"] == ""
        assert row["MAC"] == ""

    def test_multiple_records(self) -> None:
        records = [make_record(ip=f"10.0.0.{i}") for i in range(1, 6)]
        csv_str = export_inventory(records, None)
        assert csv_str is not None
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 5
