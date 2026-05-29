"""Tests for incident forensics: store, reputation folding, handler gating."""
from __future__ import annotations

import json

import pytest

from netwatchm.config import ForensicsConfig
from netwatchm.enrich import reputation
from netwatchm.enrich.reputation import ReputationResult, enrich_ip
from netwatchm.forensics.store import (
    STATUS_FALSE_POSITIVE,
    STATUS_REVIEWED,
    Incident,
    IncidentStore,
)
from netwatchm.alerts.forensic_handler import ForensicHandler, _is_external
from netwatchm.models import Alert, ThreatLevel


# ── store ────────────────────────────────────────────────────────────────────
def test_store_insert_and_query(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(Incident(
        alert_type="PORT_SCAN", level="HIGH", src_ip="8.8.8.8",
        dst_ip="10.0.0.1", description="scan",
    ))
    assert iid > 0
    rows = store.query()
    assert len(rows) == 1
    assert rows[0]["alert_type"] == "PORT_SCAN"
    assert rows[0]["status"] == "open"
    assert rows[0]["intel"] == {}


def test_store_update_artifacts(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(Incident(alert_type="EXFILTRATION", level="CRITICAL",
                                src_ip="10.0.0.5", dst_ip="1.2.3.4", description="x"))
    store.update_artifacts(iid, verdict="malicious", score=88,
                           intel_summary="bad", intel_json=json.dumps({"k": 1}),
                           pcap_path="/tmp/x.pcap", pcap_bytes=999)
    row = store.get(iid)
    assert row["verdict"] == "malicious"
    assert row["score"] == 88
    assert row["pcap_bytes"] == 999
    assert row["intel"] == {"k": 1}


def test_store_status_transitions(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(Incident(alert_type="TOR_EXIT", level="HIGH",
                                src_ip="1.2.3.4", dst_ip="10.0.0.1", description="x"))
    assert store.set_status(iid, STATUS_REVIEWED) is True
    assert store.get(iid)["status"] == STATUS_REVIEWED
    assert store.set_status(iid, STATUS_FALSE_POSITIVE) is True
    assert store.set_status(iid, "garbage") is False


def test_store_query_filters(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    store.insert(Incident(alert_type="A", level="HIGH", src_ip="1.1.1.1",
                          dst_ip="10.0.0.1", description="x"))
    store.insert(Incident(alert_type="B", level="HIGH", src_ip="2.2.2.2",
                          dst_ip="10.0.0.2", description="y"))
    assert len(store.query(ip="1.1.1.1")) == 1
    assert len(store.query(status="open")) == 2
    assert len(store.query(status="reviewed")) == 0


# ── reputation folding ───────────────────────────────────────────────────────
def test_private_ip_short_circuits():
    r = enrich_ip("192.168.1.50", ForensicsConfig())
    assert r.is_private is True
    assert r.verdict == "benign"
    assert r.providers == {}


def test_verdict_folds_to_worst(monkeypatch):
    cfg = ForensicsConfig(intel_enabled=True)
    monkeypatch.setattr(reputation, "_geoip", lambda ip, db: {})
    monkeypatch.setattr(reputation, "_greynoise",
                        lambda ip, k, t: {"verdict": "benign"})
    monkeypatch.setattr(reputation, "_abuseipdb",
                        lambda ip, k, t: {"verdict": "malicious", "score": 75})
    monkeypatch.setattr(reputation, "_virustotal",
                        lambda ip, k, t: {"verdict": "suspicious", "malicious": 1})
    r = enrich_ip("9.9.9.9", cfg)
    assert r.verdict == "malicious"
    assert r.score == 75


def test_intel_disabled_skips_providers(monkeypatch):
    cfg = ForensicsConfig(intel_enabled=False)
    monkeypatch.setattr(reputation, "_geoip",
                        lambda ip, db: {"country": "US", "city": "NY", "asn": "15169"})
    r = enrich_ip("8.8.8.8", cfg)
    assert r.providers == {}
    assert r.geo_country == "US"


# ── handler gating ───────────────────────────────────────────────────────────
def test_is_external():
    assert _is_external("8.8.8.8") is True
    assert _is_external("192.168.1.1") is False
    assert _is_external("127.0.0.1") is False
    assert _is_external(None) is False


def _alert(level=ThreatLevel.HIGH, src="192.168.1.10", dst="8.8.8.8"):
    return Alert(alert_type="PORT_SCAN", level=level, src_ip=src, dst_ip=dst,
                 description="test")


async def test_handler_disabled_is_noop(tmp_path):
    cfg = ForensicsConfig(enabled=False)
    h = ForensicHandler(cfg)
    await h.send(_alert())  # must not raise


async def test_handler_below_min_level_skipped(tmp_path, monkeypatch):
    cfg = ForensicsConfig(enabled=True, min_level="HIGH",
                          capture_enabled=False, intel_enabled=False,
                          db_path=str(tmp_path / "f.db"))
    h = ForensicHandler(cfg)
    await h.send(_alert(level=ThreatLevel.LOW))
    assert h._store.query() == []


async def test_handler_opens_case_and_cooldown(tmp_path, monkeypatch):
    cfg = ForensicsConfig(enabled=True, min_level="HIGH", cooldown_seconds=600,
                          capture_enabled=False, intel_enabled=False,
                          db_path=str(tmp_path / "f.db"))
    h = ForensicHandler(cfg)
    # Stop the background collect task from doing real work.
    monkeypatch.setattr(h, "_collect", lambda *a, **k: _noop())
    await h.send(_alert())
    await h.send(_alert())  # same IP within cooldown — suppressed
    rows = h._store.query()
    assert len(rows) == 1
    assert rows[0]["dst_ip"] == "8.8.8.8"


async def _noop():
    return None


def test_handler_picks_external_target():
    cfg = ForensicsConfig(enabled=False)
    h = ForensicHandler(cfg)
    # external dst preferred
    assert h._pick_target(_alert(src="192.168.1.10", dst="8.8.8.8")) == "8.8.8.8"
    # external src when dst is local (e.g. inbound scan)
    assert h._pick_target(_alert(src="5.6.7.8", dst="192.168.1.10")) == "5.6.7.8"
