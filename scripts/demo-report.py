#!/usr/bin/env python3
"""Generate a demo connection report with synthetic flows including high/medium/low risk examples.

Usage:
    sudo bash -c 'cd /path/to/netwatchm && uv run python scripts/demo-report.py'

Writes to /tmp/connection-report.html and deploys to /var/lib/netwatchm/.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from netwatchm.reports.connection_report import FlowRecord, render_html

now = time.time()

flows = [
    # HIGH RISK — RDP to external IP
    FlowRecord(
        src_ip="10.0.0.180", src_hostname="ai-rnd-01",
        dst_ip="198.51.100.47", dst_port=3389,
        protocol="Unknown", service="RDP",
        domain="—", app_name="rdesktop", username="jbaez120",
        packet_count=312, bytes_total=48200,
        first_seen=now - 60, last_seen=now - 5,
    ),
    # HIGH RISK — SMB to external IP
    FlowRecord(
        src_ip="10.0.0.180", src_hostname="ai-rnd-01",
        dst_ip="198.51.100.47", dst_port=445,
        protocol="SMB", service="SMB",
        domain="—", app_name="smbclient", username="jbaez120",
        packet_count=88, bytes_total=12400,
        first_seen=now - 55, last_seen=now - 10,
    ),
    # MEDIUM RISK — SSH to external
    FlowRecord(
        src_ip="10.0.0.180", src_hostname="ai-rnd-01",
        dst_ip="198.51.100.88", dst_port=22,
        protocol="SSH/TCP", service="SSH",
        domain="—", app_name="ssh", username="jbaez120",
        packet_count=45, bytes_total=8800,
        first_seen=now - 50, last_seen=now - 30,
    ),
    # LOW RISK — HTTPS to known service
    FlowRecord(
        src_ip="10.0.0.180", src_hostname="ai-rnd-01",
        dst_ip="34.149.66.137", dst_port=443,
        protocol="HTTPS/TCP", service="HTTPS",
        domain="relays-do.twingate.com", app_name="claude", username="jbaez120",
        packet_count=4, bytes_total=7168,
        first_seen=now - 45, last_seen=now - 44,
    ),
    # LOW RISK — HTTPS telemetry
    FlowRecord(
        src_ip="10.0.0.180", src_hostname="ai-rnd-01",
        dst_ip="20.189.173.3", dst_port=443,
        protocol="HTTPS/TCP", service="HTTPS",
        domain="browser.events.data.microsoft.com", app_name="Web Browser (HTTPS)", username="— (remote)",
        packet_count=21, bytes_total=9216,
        first_seen=now - 40, last_seen=now - 20,
    ),
    # LOW RISK — SSDP multicast
    FlowRecord(
        src_ip="10.0.0.245", src_hostname="DXP4800-BAB8",
        dst_ip="239.255.255.250", dst_port=1900,
        protocol="Unknown", service="1900",
        domain="239.255.255.250:1900", app_name="Port 1900 App", username="— (remote)",
        packet_count=54, bytes_total=9216,
        first_seen=now - 35, last_seen=now - 15,
    ),
]

out = "/tmp/connection-report.html"
render_html(flows, out, network="10.0.0.0/24 (demo)", duration=30)

import shutil
shutil.copy(out, "/var/lib/netwatchm/connection-report.html")
print(f"Demo report deployed to https://localhost:8765/connection-report.html")
