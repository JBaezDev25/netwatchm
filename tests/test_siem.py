"""Tests for the SIEM CEF/syslog forwarding handler."""
from __future__ import annotations

import socket
from datetime import datetime

import pytest

from netwatchm.alerts.siem_alert import SiemHandler, format_cef
from netwatchm.config import SiemConfig
from netwatchm.models import Alert, ThreatLevel


def _alert(level=ThreatLevel.HIGH, **kw) -> Alert:
    base = dict(
        alert_type="PORT_SCAN",
        level=level,
        src_ip="203.0.113.5",
        dst_ip="192.168.1.10",
        description="scan of 12 ports",
        timestamp=datetime(2026, 5, 28, 10, 0, 0),
    )
    base.update(kw)
    return Alert(**base)


def test_format_cef_structure():
    line = format_cef(_alert(), product_version="0.2.42")
    assert line.startswith("CEF:0|NetWatchM|netwatchm|0.2.42|PORT_SCAN|")
    # severity field for HIGH is 8
    assert "|8|" in line
    assert "src=203.0.113.5" in line
    assert "dst=192.168.1.10" in line
    assert "msg=scan of 12 ports" in line
    assert "NetWatchMThreatLevel=HIGH" in line


def test_format_cef_severity_mapping():
    assert "|3|" in format_cef(_alert(level=ThreatLevel.LOW))
    assert "|5|" in format_cef(_alert(level=ThreatLevel.MEDIUM))
    assert "|10|" in format_cef(_alert(level=ThreatLevel.CRITICAL))


def test_cef_escapes_pipe_and_equals():
    line = format_cef(_alert(description="a=b|c"))
    # description lives in an extension value → escape '='
    assert r"msg=a\=b|c" in line


async def test_disabled_when_no_host():
    h = SiemHandler(SiemConfig(enabled=True, host=""))
    # Should be a no-op, not raise
    await h.send(_alert())


async def test_min_level_gate(monkeypatch):
    sent: list = []
    h = SiemHandler(SiemConfig(enabled=True, host="127.0.0.1", min_level="HIGH"))
    monkeypatch.setattr(h, "_send_sync", lambda a: sent.append(a))
    await h.send(_alert(level=ThreatLevel.LOW))
    assert sent == []
    await h.send(_alert(level=ThreatLevel.HIGH))
    assert len(sent) == 1


async def test_udp_send_over_socket():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2)
    port = srv.getsockname()[1]
    try:
        h = SiemHandler(SiemConfig(enabled=True, host="127.0.0.1", port=port,
                                   protocol="udp", min_level="LOW"))
        await h.send(_alert())
        data, _ = srv.recvfrom(4096)
    finally:
        srv.close()
    text = data.decode()
    assert text.startswith("<")  # syslog PRI
    assert "CEF:0|NetWatchM|netwatchm|" in text
