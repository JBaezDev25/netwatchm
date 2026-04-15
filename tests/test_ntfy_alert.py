"""Tests for NtfyAlert handler."""
from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from netwatchm.alerts.ntfy_alert import NtfyAlert, _PRIORITY
from netwatchm.config import NtfyAlertConfig
from netwatchm.models import Alert, ThreatLevel


def _make_config(**kwargs) -> NtfyAlertConfig:
    defaults = dict(
        enabled=True,
        server="https://ntfy.sh",
        topic="test-topic",
        token="",
        min_level="HIGH",
        cooldown_seconds=0,
    )
    defaults.update(kwargs)
    return NtfyAlertConfig(**defaults)


def _alert(
    alert_type: str = "PORT_SCAN",
    level: ThreatLevel = ThreatLevel.HIGH,
    src_ip: str = "192.168.1.5",
    dst_ip: str = "10.0.0.1",
    description: str = "test alert",
) -> Alert:
    return Alert(alert_type=alert_type, level=level, src_ip=src_ip, dst_ip=dst_ip, description=description)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --- Priority mapping ---

def test_priority_low():
    assert _PRIORITY[ThreatLevel.LOW] == 2

def test_priority_medium():
    assert _PRIORITY[ThreatLevel.MEDIUM] == 3

def test_priority_high():
    assert _PRIORITY[ThreatLevel.HIGH] == 4

def test_priority_critical():
    assert _PRIORITY[ThreatLevel.CRITICAL] == 5


# --- Disabled when topic is empty ---

def test_disabled_when_no_topic():
    handler = NtfyAlert(_make_config(topic=""))
    assert not handler._enabled


def test_disabled_when_enabled_false():
    handler = NtfyAlert(_make_config(enabled=False))
    assert not handler._enabled


# --- min_level filter ---

def test_below_min_level_not_sent():
    handler = NtfyAlert(_make_config(min_level="HIGH"))
    alert = _alert(level=ThreatLevel.MEDIUM)
    with patch("urllib.request.urlopen") as mock_open:
        _run(handler.send(alert))
        mock_open.assert_not_called()


def test_at_min_level_is_sent():
    handler = NtfyAlert(_make_config(min_level="HIGH"))
    alert = _alert(level=ThreatLevel.HIGH)
    mock_response = MagicMock()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_response):
        _run(handler.send(alert))


def test_critical_above_min_level_is_sent():
    handler = NtfyAlert(_make_config(min_level="HIGH"))
    alert = _alert(level=ThreatLevel.CRITICAL)
    mock_response = MagicMock()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_response):
        _run(handler.send(alert))


# --- Cooldown ---

def test_cooldown_blocks_second_send():
    handler = NtfyAlert(_make_config(cooldown_seconds=300))
    alert = _alert()
    mock_response = MagicMock()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
        _run(handler.send(alert))
        _run(handler.send(alert))
        assert mock_open.call_count == 1


def test_cooldown_different_types_both_sent():
    handler = NtfyAlert(_make_config(cooldown_seconds=300))
    mock_response = MagicMock()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
        _run(handler.send(_alert(alert_type="PORT_SCAN")))
        _run(handler.send(_alert(alert_type="BRUTE_FORCE")))
        assert mock_open.call_count == 2


# --- HTTP request content ---

def _capture_request(handler: NtfyAlert, alert: Alert):
    """Run send() and return the Request object passed to urlopen."""
    captured = {}
    mock_response = MagicMock()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return mock_response

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        _run(handler.send(alert))
    return captured.get("req")


def test_request_url():
    handler = NtfyAlert(_make_config(server="https://ntfy.sh", topic="my-topic"))
    req = _capture_request(handler, _alert())
    assert req.full_url == "https://ntfy.sh/my-topic"


def test_request_priority_header():
    handler = NtfyAlert(_make_config())
    req = _capture_request(handler, _alert(level=ThreatLevel.HIGH))
    assert req.get_header("X-priority") == "4"


def test_request_title_header():
    handler = NtfyAlert(_make_config())
    req = _capture_request(handler, _alert(alert_type="PORT_SCAN", level=ThreatLevel.HIGH))
    assert req.get_header("X-title") == "[HIGH] Network scan detected"


def test_request_tag_header():
    handler = NtfyAlert(_make_config())
    req = _capture_request(handler, _alert(alert_type="PORT_SCAN"))
    assert req.get_header("X-tags") == "port-scan"


def test_request_body_contains_description():
    handler = NtfyAlert(_make_config())
    req = _capture_request(handler, _alert(description="suspicious traffic"))
    assert b"suspicious traffic" in req.data


def test_request_body_contains_src_ip():
    handler = NtfyAlert(_make_config())
    req = _capture_request(handler, _alert(src_ip="10.0.0.5"))
    assert b"10.0.0.5" in req.data


def test_no_auth_header_without_token():
    handler = NtfyAlert(_make_config(token=""))
    req = _capture_request(handler, _alert())
    assert req.get_header("Authorization") is None


def test_bearer_token_header():
    handler = NtfyAlert(_make_config(token="secret123"))
    req = _capture_request(handler, _alert())
    assert req.get_header("Authorization") == "Bearer secret123"


# --- Network error is swallowed ---

def test_url_error_does_not_raise():
    from urllib.error import URLError
    handler = NtfyAlert(_make_config())
    with patch("urllib.request.urlopen", side_effect=URLError("unreachable")):
        _run(handler.send(_alert()))  # must not raise
