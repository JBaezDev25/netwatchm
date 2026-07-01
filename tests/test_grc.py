"""Tests for the GRC risk-scoring + CIS control assessment engine."""
from __future__ import annotations

from netwatchm.grc import assess_controls, assess_device, risk_level


def test_risk_level_bands():
    assert risk_level(0) == "low"
    assert risk_level(24) == "low"
    assert risk_level(25) == "medium"
    assert risk_level(50) == "high"
    assert risk_level(75) == "critical"
    assert risk_level(100) == "critical"


def test_clean_device_is_low_risk():
    r = assess_device(ip="10.0.0.10", ports=[443], verified=True)
    assert r.level == "low"
    assert r.score == 0
    assert r.recommendations == ["No elevated risk indicators"]


def test_risky_ports_drive_exposure():
    r = assess_device(ip="10.0.0.20", ports=[23, 445, 3389])
    assert "23/Telnet" in r.risky_ports
    assert r.exposure > 0
    assert any("Close or firewall" in rec for rec in r.recommendations)


def test_threat_activity_scales_score():
    low = assess_device(ip="10.0.0.1", alert_count=0)
    hot = assess_device(ip="10.0.0.1", alert_count=8, max_alert_level="CRITICAL")
    assert hot.threat > low.threat
    assert hot.score > low.score


def test_external_intel_counts_only_for_public():
    ext = assess_device(ip="203.0.113.5", intel_verdict="malicious", is_external=True)
    internal = assess_device(ip="10.0.0.5", intel_verdict="malicious", is_external=False)
    assert ext.intel == 40
    assert internal.intel == 0


def test_verified_reduces_score():
    unv = assess_device(ip="10.0.0.2", ports=[3389, 445], verified=False)
    ver = assess_device(ip="10.0.0.2", ports=[3389, 445], verified=True)
    assert ver.score < unv.score


def test_score_capped_at_100():
    r = assess_device(
        ip="203.0.113.9", ports=list(RISKY := [21, 23, 445, 3389, 5900, 1433, 161]),
        alert_count=20, max_alert_level="CRITICAL",
        intel_verdict="malicious", is_external=True,
    )
    assert r.score == 100
    assert r.level == "critical"


def _dev(ip, ports=(), verified=True, label="x", level="low"):
    return {
        "ip": ip, "ports": list(ports), "verified": verified, "label": label,
        "risk": {"level": level},
    }


def test_controls_all_pass_for_clean_fleet():
    devices = [_dev("10.0.0.10", ports=[443]), _dev("10.0.0.11", ports=[80])]
    out = assess_controls(devices, events_present=True, monitor_active=True)
    assert out["compliance"] == 100
    assert out["summary"]["failed"] == 0


def test_controls_flag_cleartext_and_admin_exposure():
    devices = [
        _dev("10.0.0.20", ports=[23], verified=False, level="high"),  # telnet, unverified
    ]
    out = assess_controls(devices)
    by_id = {c["control_id"]: c for c in out["controls"]}
    assert by_id["4.8"]["status"] == "fail"          # cleartext service
    assert "10.0.0.20" in by_id["4.8"]["affected"]
    assert by_id["6.4"]["status"] == "fail"          # unverified admin port
    assert by_id["13.1"]["status"] == "fail"         # high-risk device
    assert out["compliance"] < 100


def test_controls_empty_inventory_warns():
    out = assess_controls([])
    by_id = {c["control_id"]: c for c in out["controls"]}
    assert by_id["1.1"]["status"] == "warn"


def test_asset_controls_ignore_external_peers():
    """Asset/config/access controls (1.1, 4.8, 6.4) count owned devices only;
    external peers must not dilute the inventory ratio or raise findings."""
    owned = [
        dict(_dev("10.0.0.10", ports=[443], verified=True), owned=True),
        dict(_dev("10.0.0.11", ports=[80], verified=True), owned=True),
    ]
    external = [
        dict(_dev("203.0.113.5", ports=[23], verified=False, level="high"),
             owned=False),  # external telnet host — should NOT trip 4.8
    ]
    out = assess_controls(owned + external)
    by_id = {c["control_id"]: c for c in out["controls"]}
    # 1.1 sees only the 2 owned (both verified) → pass, not diluted to 2/3
    assert by_id["1.1"]["status"] == "pass"
    # 4.8 ignores the external telnet host
    assert by_id["4.8"]["status"] == "pass"
    assert "203.0.113.5" not in by_id["4.8"]["affected"]
    assert out["summary"]["owned_devices"] == 2
    assert out["summary"]["devices"] == 3
