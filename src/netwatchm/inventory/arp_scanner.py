"""Active LAN device discovery using arp-scan."""
from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from typing import TYPE_CHECKING

from ..models import Alert, ThreatLevel
from . import oui_lookup

if TYPE_CHECKING:
    from .store import DeviceStore

logger = logging.getLogger(__name__)

# Matches: "192.168.1.1    aa:bb:cc:dd:ee:ff    NETGEAR"
_LINE_RE = re.compile(
    r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
    r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*'
    r'(.*)',
    re.IGNORECASE,
)


def _run_arp_scan(network: str) -> list[tuple[str, str, str | None]]:
    """Run arp-scan and return list of (ip, mac, vendor). Blocking."""
    # No sudo needed — cap_net_raw+ep set on the binary via:
    #   sudo setcap cap_net_raw+ep /usr/sbin/arp-scan
    cmd = ["arp-scan", "--quiet"]
    if network == "auto":
        cmd.append("--localnet")
    else:
        cmd.append(network)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        logger.warning("arp-scan not found. Install with: sudo apt install arp-scan")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out")
        return []
    except OSError as exc:
        logger.warning("arp-scan failed: %s", exc)
        return []

    results = []
    for line in result.stdout.splitlines():
        m = _LINE_RE.match(line.strip())
        if m:
            ip = m.group(1)
            mac = m.group(2).lower()
            vendor = m.group(3).strip() or None
            # Fall back to OUI database when arp-scan doesn't know the vendor
            if not vendor:
                vendor = oui_lookup.lookup(mac)
            results.append((ip, mac, vendor))

    return results


async def run_arp_scan_loop(
    store: "DeviceStore",
    interval: int,
    network: str,
    stop_event: asyncio.Event,
    alert_queue: "asyncio.Queue[Alert] | None" = None,
) -> None:
    """Periodically run arp-scan and update DeviceStore with MAC/vendor.

    When a device is seen for the first time (not in inventory), emits a
    NEW_DEVICE alert into alert_queue if one is provided.
    """
    logger.info("ARP scanner started (interval=%ds, network=%s)", interval, network)

    # Run immediately on start, then on interval
    while not stop_event.is_set():
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, _run_arp_scan, network)

        if results:
            logger.debug("arp-scan found %d devices", len(results))
            for ip, mac, vendor in results:
                is_new = await store.update_arp(ip, mac, vendor)
                if is_new and alert_queue is not None:
                    vendor_str = vendor or "unknown vendor"
                    alert = Alert(
                        alert_type="NEW_DEVICE",
                        level=ThreatLevel.MEDIUM,
                        src_ip=ip,
                        dst_ip=None,
                        description=(
                            f"New device detected by arp-scan: {ip}"
                            f"  MAC: {mac}  Vendor: {vendor_str}"
                        ),
                    )
                    await alert_queue.put(alert)
                    logger.warning("New device on network: %s (MAC: %s, Vendor: %s)", ip, mac, vendor_str)

        # Wait for next scan
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
