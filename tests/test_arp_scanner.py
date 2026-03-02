"""Tests for arp-scan new-device alert emission."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from netwatchm.inventory.arp_scanner import run_arp_scan_loop
from netwatchm.inventory.store import DeviceStore
from netwatchm.models import ThreatLevel


async def _run_once(store, scan_results, alert_queue=None):
    """Run the arp-scan loop for one iteration then stop it."""
    stop_event = asyncio.Event()
    with patch(
        "netwatchm.inventory.arp_scanner._run_arp_scan",
        return_value=scan_results,
    ):
        task = asyncio.create_task(
            run_arp_scan_loop(
                store,
                interval=0,
                network="auto",
                stop_event=stop_event,
                alert_queue=alert_queue,
            )
        )
        # Yield control so the loop body executes, then stop it
        await asyncio.sleep(0.05)
        stop_event.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_new_device_emits_alert() -> None:
    """First arp-scan sighting of an IP produces a NEW_DEVICE alert."""
    store = DeviceStore()
    alert_queue: asyncio.Queue = asyncio.Queue()

    scan_results = [("192.168.1.50", "aa:bb:cc:dd:ee:ff", "Acme Corp")]
    await _run_once(store, scan_results, alert_queue)

    assert not alert_queue.empty()
    alert = alert_queue.get_nowait()
    assert alert.alert_type == "NEW_DEVICE"
    assert alert.src_ip == "192.168.1.50"
    assert alert.level == ThreatLevel.MEDIUM
    assert "aa:bb:cc:dd:ee:ff" in alert.description
    assert "Acme Corp" in alert.description


@pytest.mark.asyncio
async def test_known_device_no_alert() -> None:
    """Device already in inventory does not produce an alert."""
    store = DeviceStore()
    alert_queue: asyncio.Queue = asyncio.Queue()

    # Pre-populate inventory so the device is already known
    await store.update_arp("192.168.1.1", "11:22:33:44:55:66", "Router Corp")

    scan_results = [("192.168.1.1", "11:22:33:44:55:66", "Router Corp")]
    await _run_once(store, scan_results, alert_queue)

    assert alert_queue.empty()


@pytest.mark.asyncio
async def test_no_alert_queue_no_error() -> None:
    """New device with alert_queue=None (default) should not raise."""
    store = DeviceStore()

    scan_results = [("10.0.0.99", "ff:ee:dd:cc:bb:aa", None)]
    await _run_once(store, scan_results, alert_queue=None)

    records = await store.get_all()
    assert any(r.ip == "10.0.0.99" for r in records)


@pytest.mark.asyncio
async def test_unknown_vendor_fallback() -> None:
    """Vendor=None shows 'unknown vendor' in description."""
    store = DeviceStore()
    alert_queue: asyncio.Queue = asyncio.Queue()

    scan_results = [("192.168.1.99", "de:ad:be:ef:00:01", None)]
    await _run_once(store, scan_results, alert_queue)

    assert not alert_queue.empty()
    alert = alert_queue.get_nowait()
    assert "unknown vendor" in alert.description
