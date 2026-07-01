"""Tests for DeviceStore."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from netwatchm.inventory.store import DeviceStore
from netwatchm.models import ThreatLevel
from .conftest import make_packet


class TestDeviceStore:
    @pytest.mark.asyncio
    async def test_update_creates_record(self) -> None:
        store = DeviceStore()
        pkt = make_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, length=200)
        await store.update(pkt)
        records = await store.get_all()
        ips = {r.ip for r in records}
        assert "10.0.0.1" in ips
        assert "8.8.8.8" in ips

    @pytest.mark.asyncio
    async def test_bytes_accumulated(self) -> None:
        store = DeviceStore()
        pkt = make_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8", length=500)
        await store.update(pkt)
        await store.update(pkt)
        records = await store.get_all()
        src_rec = next(r for r in records if r.ip == "10.0.0.1")
        assert src_rec.bytes_sent == 1000

    @pytest.mark.asyncio
    async def test_ports_accumulated(self) -> None:
        store = DeviceStore()
        for port in (80, 443, 22):
            await store.update(make_packet(src_ip="10.0.0.2", dst_port=port))
        records = await store.get_all()
        src_rec = next(r for r in records if r.ip == "10.0.0.2")
        assert {80, 443, 22} <= src_rec.ports_observed

    @pytest.mark.asyncio
    async def test_filter_by_ip(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="10.0.0.1"))
        await store.update(make_packet(src_ip="10.0.0.2"))
        await store.update(make_packet(src_ip="10.0.0.1"))
        results = await store.get_all("10.0")
        ips = {r.ip for r in results}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        assert "10.0.0.1" not in ips

    @pytest.mark.asyncio
    async def test_update_hostname(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="1.1.1.1"))
        await store.update_hostname("1.1.1.1", "one.one.one.one")
        records = await store.get_all()
        rec = next(r for r in records if r.ip == "1.1.1.1")
        assert rec.hostname == "one.one.one.one"

    @pytest.mark.asyncio
    async def test_update_threat_level(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="5.5.5.5"))
        await store.update_threat("5.5.5.5", ThreatLevel.HIGH)
        records = await store.get_all()
        rec = next(r for r in records if r.ip == "5.5.5.5")
        assert rec.threat_level == ThreatLevel.HIGH

    @pytest.mark.asyncio
    async def test_update_threat_does_not_downgrade(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="5.5.5.5"))
        await store.update_threat("5.5.5.5", ThreatLevel.CRITICAL)
        await store.update_threat("5.5.5.5", ThreatLevel.LOW)
        records = await store.get_all()
        rec = next(r for r in records if r.ip == "5.5.5.5")
        assert rec.threat_level == ThreatLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_persist_and_load(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="172.16.0.1", dst_ip="8.8.8.8", length=100))
        await store.update_hostname("172.16.0.1", "router.local")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "inventory.json"
            await store.persist(path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert any(r["ip"] == "172.16.0.1" for r in data)

            store2 = DeviceStore()
            await store2.load(path)
            records = await store2.get_all()
            ips = {r.ip for r in records}
            assert "172.16.0.1" in ips
            rec = next(r for r in records if r.ip == "172.16.0.1")
            assert rec.hostname == "router.local"

    @pytest.mark.asyncio
    async def test_get_unresolved_ips(self) -> None:
        store = DeviceStore()
        await store.update(make_packet(src_ip="1.2.3.4"))
        await store.update(make_packet(src_ip="5.6.7.8"))
        await store.update_hostname("1.2.3.4", "resolved.host")
        unresolved = await store.get_unresolved_ips()
        assert "5.6.7.8" in unresolved
        assert "1.2.3.4" not in unresolved

    @pytest.mark.asyncio
    async def test_update_arp_returns_true_for_new_device(self) -> None:
        store = DeviceStore()
        is_new = await store.update_arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "Acme Corp")
        assert is_new is True
        records = await store.get_all()
        rec = next(r for r in records if r.ip == "10.0.0.1")
        assert rec.mac == "aa:bb:cc:dd:ee:ff"
        assert rec.vendor == "Acme Corp"

    @pytest.mark.asyncio
    async def test_update_arp_returns_false_for_known_device(self) -> None:
        store = DeviceStore()
        await store.update_arp("10.0.0.2", "11:22:33:44:55:66", "Vendor A")
        is_new = await store.update_arp("10.0.0.2", "11:22:33:44:55:66", "Vendor A")
        assert is_new is False

    @pytest.mark.asyncio
    async def test_update_arp_returns_false_for_device_in_traffic(self) -> None:
        """Devices already seen in packet traffic should not be flagged as new."""
        store = DeviceStore()
        await store.update(make_packet(src_ip="10.0.0.3"))
        is_new = await store.update_arp("10.0.0.3", "aa:aa:aa:aa:aa:aa", None)
        assert is_new is False
