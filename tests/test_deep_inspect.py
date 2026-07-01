"""Unit tests for deep_inspect module (all network calls mocked)."""
from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from netwatchm.reports.deep_inspect import (
    Finding,
    GeoIPInfo,
    InspectionResult,
    _compute_risk,
    _geoip_lookup,
    _http_check,
    _port_scan,
    _ssh_check,
    render_deep_inspect_html,
    run_deep_inspect,
)


# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------

def test_port_scan_open():
    """connect_ex returns 0 → port is open and SSH service mapped."""
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock
        result = _port_scan("192.0.2.1", [22])
    assert 22 in result
    assert result[22] == "SSH"


def test_port_scan_closed():
    """connect_ex returns non-zero → port is closed."""
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_sock_cls.return_value = mock_sock
        result = _port_scan("192.0.2.1", [22, 80])
    assert result == {}


# ---------------------------------------------------------------------------
# GeoIP lookup
# ---------------------------------------------------------------------------

def test_geoip_lookup_private_ip():
    """Private IPs should return None without touching the DB."""
    result = _geoip_lookup("10.0.0.1", db_path="/nonexistent/path.mmdb")
    assert result is None


def test_geoip_lookup_missing_db():
    """Missing mmdb file should return None gracefully."""
    result = _geoip_lookup("8.8.8.8", db_path="/tmp/does_not_exist_netwatchm.mmdb")
    assert result is None


# ---------------------------------------------------------------------------
# SSH check
# ---------------------------------------------------------------------------

def test_ssh_check_no_port():
    """If port 22 is not in open_ports, no findings returned."""
    findings, raw = _ssh_check("192.0.2.1", open_ports=[80, 443])
    assert findings == []
    assert raw == ""


def test_ssh_check_banner_captured():
    """If port 22 open and transport connects, banner is captured."""
    mock_transport = MagicMock()
    mock_transport.remote_version = "SSH-2.0-OpenSSH_8.9"
    mock_transport.auth_password.side_effect = __import__(
        "paramiko", fromlist=["AuthenticationException"]
    ).AuthenticationException("auth failed")

    with patch("paramiko.Transport", return_value=mock_transport):
        findings, raw = _ssh_check("192.0.2.1", open_ports=[22])

    assert any("SSH" in f.title for f in findings)
    assert "SSH-2.0-OpenSSH_8.9" in raw


# ---------------------------------------------------------------------------
# HTTP check
# ---------------------------------------------------------------------------

def test_http_check_server_header():
    """Server header with version number triggers version disclosure finding."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Server": "Apache/2.4.1"}

    with patch("requests.get", return_value=mock_response):
        findings, raw = _http_check("192.0.2.1")

    titles = [f.title for f in findings]
    assert any("version disclosure" in t.lower() for t in titles)


def test_http_check_no_server_header():
    """No Server header → no version disclosure finding."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}

    with patch("requests.get", return_value=mock_response):
        findings, _ = _http_check("192.0.2.1")

    assert not any("version disclosure" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Risk computation
# ---------------------------------------------------------------------------

def test_compute_risk_high_severity():
    """A high-severity finding → risk is 'high'."""
    findings = [Finding(title="RDP exposed", detail="...", severity="high")]
    risk = _compute_risk(findings, geoip=None, open_ports=[3389], target="8.8.8.8")
    assert risk == "high"


def test_compute_risk_medium_ssh():
    """SSH open on external IP, no findings → risk is 'medium'."""
    risk = _compute_risk([], geoip=None, open_ports=[22], target="8.8.8.8")
    assert risk == "medium"


def test_compute_risk_low():
    """No findings, no sensitive ports → low risk."""
    risk = _compute_risk([], geoip=None, open_ports=[80], target="8.8.8.8")
    assert risk == "low"


# ---------------------------------------------------------------------------
# run_deep_inspect — resilience to per-check failures
# ---------------------------------------------------------------------------

def test_run_deep_inspect_handles_per_check_exception():
    """If individual checks raise, others still run and error is captured."""
    # Patch port scan to return port 80 open so HTTP check runs
    with patch(
        "netwatchm.reports.deep_inspect._port_scan",
        return_value={80: "HTTP"},
    ), patch(
        "netwatchm.reports.deep_inspect._geoip_lookup",
        side_effect=RuntimeError("geoip kaboom"),
    ), patch(
        "netwatchm.reports.deep_inspect._ssh_check",
        return_value=([], ""),
    ), patch(
        "netwatchm.reports.deep_inspect._smb_check",
        return_value=([], ""),
    ), patch(
        "netwatchm.reports.deep_inspect._http_check",
        return_value=([], "HTTP 200 ok"),
    ), patch(
        "netwatchm.reports.deep_inspect._rdp_check",
        return_value=([], ""),
    ):
        result = run_deep_inspect("8.8.8.8")

    # GeoIP failed but HTTP ran fine
    assert result.geoip is None
    assert "geoip kaboom" in result.raw_output.lower() or "GeoIP error" in result.raw_output
    assert "HTTP 200 ok" in result.raw_output


# ---------------------------------------------------------------------------
# render_deep_inspect_html
# ---------------------------------------------------------------------------

def test_render_html_contains_target():
    """Rendered HTML includes the target IP."""
    result = InspectionResult(
        target="1.2.3.4",
        geoip=GeoIPInfo(country="US", city="New York", isp="ExampleISP", asn="AS15169", abuse="N/A"),
        open_ports=[22, 80],
        services={22: "SSH", 80: "HTTP"},
        findings=[Finding(title="SSH service exposed", detail="Banner: OpenSSH", severity="medium")],
        risk_level="medium",
        raw_output="Open ports: [22, 80]",
        error=None,
    )
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        tmp_path = f.name

    try:
        render_deep_inspect_html(result, tmp_path)
        content = open(tmp_path, encoding="utf-8").read()
        assert "1.2.3.4" in content
        assert "SSH service exposed" in content
        assert "medium" in content.lower()
        assert "GeoIP" in content
    finally:
        os.unlink(tmp_path)
