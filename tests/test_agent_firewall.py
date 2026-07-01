"""Phase 5 tests: firewall mitigation (Store, Controller, Reaper, guardrails, executor)."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netwatchm.agent.audit import AuditLog
from netwatchm.agent.executor import Executor
from netwatchm.agent.firewall import (
    BlockEntry,
    FirewallController,
    FirewallStore,
    _process_expired_once,
)
from netwatchm.agent.guardrails import (
    GuardrailLimits,
    Guardrails,
    _ip_route_default_gateways,
    detect_host_network_info,
)
from netwatchm.agent.state import AgentWhitelistStore, SuppressedTypesStore
from netwatchm.agent.tools import ACTION_TOOL_SCHEMAS


# ---------- helpers ----------


def _make_audit(path: Path) -> AuditLog:
    audit = AuditLog(str(path))
    audit.open()
    return audit


def _gr(
    tmp_path: Path,
    *,
    firewall_store=None,
    gateway_ips=None,
    host_ips=None,
    global_whitelist_ips=None,
    limits=None,
) -> Guardrails:
    return Guardrails(
        audit_db_path=str(tmp_path / "a.db"),
        events_db_path=str(tmp_path / "e.db"),
        limits=limits,
        firewall_store=firewall_store,
        gateway_ips=gateway_ips,
        host_ips=host_ips,
        global_whitelist_ips=global_whitelist_ips,
    )


# ============================================================================
# Guardrails.check_block — refusal cases
# ============================================================================


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.5", "172.16.5.5", "10.0.0.5", "127.0.0.1", "169.254.1.1"],
)
def test_check_block_refuses_internal_or_loopback(tmp_path: Path, ip: str) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block({"ip": ip, "reason": "x"})
    assert not ok
    assert "internal" in reason or "loopback" in reason or "link-local" in reason


def test_check_block_refuses_cidr(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block({"ip": "8.8.8.0/24", "reason": "x"})
    assert not ok
    assert "ip" in reason.lower()


def test_check_block_refuses_gateway(tmp_path: Path) -> None:
    gr = _gr(tmp_path, gateway_ips=["1.2.3.4"])
    ok, reason = gr.check_block({"ip": "1.2.3.4", "reason": "x"})
    assert not ok
    assert "gateway" in reason


def test_check_block_refuses_host_ip(tmp_path: Path) -> None:
    gr = _gr(tmp_path, host_ips=["4.4.4.4"])
    ok, reason = gr.check_block({"ip": "4.4.4.4", "reason": "x"})
    assert not ok
    assert "host" in reason


def test_check_block_refuses_whitelisted_ip(tmp_path: Path) -> None:
    gr = _gr(tmp_path, global_whitelist_ips=["9.9.9.9"])
    ok, reason = gr.check_block({"ip": "9.9.9.9", "reason": "x"})
    assert not ok
    assert "whitelist" in reason


def test_check_block_refuses_port_22(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block({"ip": "8.8.8.8", "port": 22, "reason": "x"})
    assert not ok
    assert "22" in reason


def test_check_block_refuses_port_out_of_range(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block({"ip": "8.8.8.8", "port": 99999, "reason": "x"})
    assert not ok
    assert "port" in reason.lower()


def test_check_block_refuses_bad_protocol(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block(
        {"ip": "8.8.8.8", "port": 80, "protocol": "icmp", "reason": "x"}
    )
    assert not ok
    assert "protocol" in reason.lower()


def test_check_block_refuses_duration_above_cap(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block(
        {"ip": "8.8.8.8", "duration_minutes": 99999, "reason": "x"}
    )
    assert not ok
    assert "duration" in reason.lower()


def test_check_block_refuses_empty_reason(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block({"ip": "8.8.8.8", "reason": "   "})
    assert not ok
    assert "reason" in reason.lower()


def test_check_block_refuses_when_active_ceiling_hit(tmp_path: Path) -> None:
    store = FirewallStore(str(tmp_path / "blocks.json"))
    # Seed 10 active blocks
    for i in range(10):
        store.add(
            ip=f"203.0.113.{i + 1}", port=None, protocol=None,
            ttl_seconds=3600, reason="seed", decision_id=None,
        )
    gr = _gr(tmp_path, firewall_store=store)
    ok, reason = gr.check_block({"ip": "8.8.8.8", "reason": "x"})
    assert not ok
    assert "ceiling" in reason or "active blocks" in reason


def test_check_block_refuses_when_rate_cap_hit(tmp_path: Path) -> None:
    audit_db = tmp_path / "a.db"
    audit = _make_audit(audit_db)
    try:
        d_id = audit.record_decision(
            model="m", mode="live", events_seen=0,
            max_severity=None, rationale=None, raw_response=None,
        )
        for _ in range(5):
            audit.record_tool_call(
                decision_id=d_id, tool_name="add_temporary_block",
                args={"ip": "1.1.1.1"}, status="executed",
            )
    finally:
        audit.close()
    gr = Guardrails(
        audit_db_path=str(audit_db),
        events_db_path=str(tmp_path / "e.db"),
    )
    ok, reason = gr.check_block({"ip": "8.8.8.8", "reason": "x"})
    assert not ok
    assert "rate" in reason.lower()


def test_check_block_accepts_clean_external(tmp_path: Path) -> None:
    gr = _gr(tmp_path)
    ok, reason = gr.check_block(
        {"ip": "8.8.8.8", "port": 8080, "protocol": "tcp",
         "duration_minutes": 30, "reason": "abuse"}
    )
    assert ok, reason


def test_check_remove_block_allows_rfc1918_for_cleanup(tmp_path: Path) -> None:
    # remove_block must accept internal IPs so we can clean up rules that
    # might have been added before guardrails tightened.
    gr = _gr(tmp_path)
    ok, _ = gr.check_remove_block({"ip": "10.0.0.5"})
    assert ok


# ============================================================================
# FirewallStore
# ============================================================================


def test_store_add_persists_to_disk(tmp_path: Path) -> None:
    p = tmp_path / "blocks.json"
    store = FirewallStore(str(p))
    e = store.add(
        ip="8.8.8.8", port=443, protocol="tcp",
        ttl_seconds=3600, reason="x", decision_id=7,
    )
    assert e.id
    assert e.port == 443
    assert e.protocol == "tcp"
    data = json.loads(p.read_text())
    assert len(data["entries"]) == 1
    assert data["entries"][0]["ip"] == "8.8.8.8"


def test_store_expired_active_excludes_rolled_back(tmp_path: Path) -> None:
    p = tmp_path / "blocks.json"
    store = FirewallStore(str(p))
    e = store.add(
        ip="8.8.8.8", port=None, protocol=None,
        ttl_seconds=-10, reason="x", decision_id=None,  # already expired
    )
    assert len(store.expired_active()) == 1
    store.mark_rolled_back(e.id)
    assert store.expired_active() == []


def test_store_active_entries_excludes_expired(tmp_path: Path) -> None:
    store = FirewallStore(str(tmp_path / "blocks.json"))
    store.add(
        ip="8.8.8.8", port=None, protocol=None,
        ttl_seconds=-5, reason="old", decision_id=None,
    )
    store.add(
        ip="1.1.1.1", port=None, protocol=None,
        ttl_seconds=3600, reason="new", decision_id=None,
    )
    active = store.active_entries()
    assert len(active) == 1
    assert active[0]["ip"] == "1.1.1.1"
    assert store.count_active() == 1


def test_store_mark_rolled_back_returns_entry(tmp_path: Path) -> None:
    store = FirewallStore(str(tmp_path / "blocks.json"))
    e = store.add(
        ip="8.8.8.8", port=80, protocol=None,
        ttl_seconds=3600, reason="x", decision_id=None,
    )
    touched = store.mark_rolled_back(e.id)
    assert touched is not None
    assert touched["ip"] == "8.8.8.8"
    # Second call returns None (already rolled back)
    assert store.mark_rolled_back(e.id) is None


def test_store_corrupted_file_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "blocks.json"
    p.write_text("{not valid json")
    store = FirewallStore(str(p))
    assert store.active_entries() == []
    assert store.count_active() == 0


# ============================================================================
# FirewallController
# ============================================================================


def test_controller_build_args_add_no_port() -> None:
    c = FirewallController(ufw_binary="/usr/sbin/ufw", sudo_binary="/usr/bin/sudo")
    args = c._build_args(ip="8.8.8.8", port=None, action="add")
    assert args == ["/usr/bin/sudo", "-n", "/usr/sbin/ufw", "deny", "from", "8.8.8.8"]


def test_controller_build_args_add_with_port() -> None:
    c = FirewallController(ufw_binary="/usr/sbin/ufw", sudo_binary="/usr/bin/sudo")
    args = c._build_args(ip="8.8.8.8", port=443, action="add")
    assert args == [
        "/usr/bin/sudo", "-n", "/usr/sbin/ufw",
        "deny", "from", "8.8.8.8", "to", "any", "port", "443",
    ]


def test_controller_build_args_remove_with_port() -> None:
    c = FirewallController(ufw_binary="/usr/sbin/ufw", sudo_binary="/usr/bin/sudo")
    args = c._build_args(ip="1.1.1.1", port=80, action="remove")
    assert args == [
        "/usr/bin/sudo", "-n", "/usr/sbin/ufw",
        "delete", "deny", "from", "1.1.1.1", "to", "any", "port", "80",
    ]


def test_controller_rejects_shell_injection_in_ip() -> None:
    c = FirewallController()
    with pytest.raises(ValueError):
        c._build_args(ip="1.2.3.4; rm -rf /", port=None, action="add")


def test_controller_rejects_oob_port() -> None:
    c = FirewallController()
    with pytest.raises(ValueError):
        c._build_args(ip="8.8.8.8", port=70000, action="add")


def test_controller_add_block_invokes_subprocess(monkeypatch) -> None:
    c = FirewallController(ufw_binary="/usr/sbin/ufw", sudo_binary="/usr/bin/sudo")
    captured = {}

    def fake_run(args, **kw):
        captured["args"] = args
        return MagicMock(returncode=0, stdout="Rule added\n", stderr="")

    monkeypatch.setattr("netwatchm.agent.firewall.subprocess.run", fake_run)
    result = c.add_block(ip="8.8.8.8", port=80)
    assert result["ok"] is True
    assert "deny" in captured["args"]
    assert "8.8.8.8" in captured["args"]


def test_controller_remove_soft_ok_on_nonexistent_rule(monkeypatch) -> None:
    c = FirewallController()

    def fake_run(args, **kw):
        return MagicMock(
            returncode=1, stdout="",
            stderr="Could not delete non-existent rule\n",
        )

    monkeypatch.setattr("netwatchm.agent.firewall.subprocess.run", fake_run)
    result = c.remove_block(ip="8.8.8.8")
    assert result["ok"] is True
    assert result["soft_ok"] is True


# ============================================================================
# Reaper
# ============================================================================


def test_reaper_removes_expired_blocks(tmp_path: Path) -> None:
    store = FirewallStore(str(tmp_path / "blocks.json"))
    audit = _make_audit(tmp_path / "a.db")
    try:
        e_old = store.add(
            ip="8.8.8.8", port=None, protocol=None,
            ttl_seconds=-10, reason="x", decision_id=None,
        )
        e_new = store.add(
            ip="1.1.1.1", port=None, protocol=None,
            ttl_seconds=3600, reason="x", decision_id=None,
        )
        controller = MagicMock()
        controller.remove_block.return_value = {"ok": True, "returncode": 0}

        n = _process_expired_once(store=store, controller=controller, audit=audit)
        assert n == 1
        # Only the expired one was removed
        controller.remove_block.assert_called_once_with(ip="8.8.8.8", port=None)
        active = store.active_entries()
        assert len(active) == 1
        assert active[0]["ip"] == "1.1.1.1"
    finally:
        audit.close()


def test_reaper_marks_rolled_back_even_on_ufw_failure(tmp_path: Path) -> None:
    """Reaper must drop the store entry even if ufw delete fails — TTL has
    passed so we never want this in 'active' again."""
    store = FirewallStore(str(tmp_path / "blocks.json"))
    e = store.add(
        ip="8.8.8.8", port=None, protocol=None,
        ttl_seconds=-10, reason="x", decision_id=None,
    )
    controller = MagicMock()
    controller.remove_block.return_value = {"ok": False, "returncode": 1, "stderr_tail": "boom"}

    _process_expired_once(store=store, controller=controller, audit=None)
    assert store.expired_active() == []
    assert store.count_active() == 0


# ============================================================================
# Executor dispatch
# ============================================================================


def _build_executor(tmp_path: Path, *, controller=None) -> tuple[Executor, FirewallStore]:
    fw_store = FirewallStore(str(tmp_path / "blocks.json"))
    gr = Guardrails(
        audit_db_path=str(tmp_path / "a.db"),
        events_db_path=str(tmp_path / "e.db"),
        firewall_store=fw_store,
    )
    ex = Executor(
        guardrails=gr,
        whitelist_store=AgentWhitelistStore(str(tmp_path / "wl.json")),
        suppressed_store=SuppressedTypesStore(str(tmp_path / "supp.json")),
        ntfy_config=None,
        firewall_store=fw_store,
        firewall_controller=controller or MagicMock(),
    )
    return ex, fw_store


def test_executor_add_block_happy_path(tmp_path: Path) -> None:
    controller = MagicMock()
    controller.add_block.return_value = {"ok": True, "returncode": 0}
    ex, store = _build_executor(tmp_path, controller=controller)

    res = ex.dispatch(
        "add_temporary_block",
        {"ip": "8.8.8.8", "port": 80, "duration_minutes": 30, "reason": "abuse"},
        decision_id=42,
    )
    assert res["ok"] is True
    assert res.get("blocked") is not True
    assert "entry_id" in res
    controller.add_block.assert_called_once_with(ip="8.8.8.8", port=80)
    assert store.count_active() == 1


def test_executor_add_block_blocked_by_guardrails(tmp_path: Path) -> None:
    controller = MagicMock()
    ex, store = _build_executor(tmp_path, controller=controller)
    res = ex.dispatch(
        "add_temporary_block",
        {"ip": "10.0.0.5", "reason": "x"},  # RFC1918 → refused
        decision_id=1,
    )
    assert res["ok"] is False
    assert res["blocked"] is True
    controller.add_block.assert_not_called()
    assert store.count_active() == 0


def test_executor_add_block_ufw_failure_returns_error_not_blocked(tmp_path: Path) -> None:
    controller = MagicMock()
    controller.add_block.return_value = {
        "ok": False, "returncode": 4, "stderr_tail": "ERROR: command failed",
    }
    ex, store = _build_executor(tmp_path, controller=controller)
    res = ex.dispatch(
        "add_temporary_block",
        {"ip": "8.8.8.8", "reason": "x"},
        decision_id=1,
    )
    assert res["ok"] is False
    assert res.get("blocked") is not True   # NOT a guardrail block — a runtime error
    assert "ufw" in res["reason"].lower()
    assert store.count_active() == 0


def test_executor_remove_block_happy_path(tmp_path: Path) -> None:
    controller = MagicMock()
    controller.add_block.return_value = {"ok": True, "returncode": 0}
    controller.remove_block.return_value = {"ok": True, "returncode": 0}
    ex, store = _build_executor(tmp_path, controller=controller)
    ex.dispatch(
        "add_temporary_block",
        {"ip": "8.8.8.8", "reason": "x"},
        decision_id=1,
    )
    assert store.count_active() == 1

    res = ex.dispatch("remove_block", {"ip": "8.8.8.8"}, decision_id=2)
    assert res["ok"] is True
    assert res["entries_rolled_back"] == 1
    assert store.count_active() == 0


# ============================================================================
# Tool schemas
# ============================================================================


def test_schemas_include_new_block_tools() -> None:
    names = {s["function"]["name"] for s in ACTION_TOOL_SCHEMAS}
    assert "add_temporary_block" in names
    assert "remove_block" in names


def test_add_block_schema_requires_ip_and_reason() -> None:
    schema = next(
        s for s in ACTION_TOOL_SCHEMAS if s["function"]["name"] == "add_temporary_block"
    )
    required = set(schema["function"]["parameters"]["required"])
    assert required == {"ip", "reason"}


def test_ntfy_schema_includes_unblock_entry_id() -> None:
    schema = next(
        s for s in ACTION_TOOL_SCHEMAS if s["function"]["name"] == "send_ntfy_alert"
    )
    props = schema["function"]["parameters"]["properties"]
    assert "unblock_entry_id" in props


# ============================================================================
# detect_host_network_info — smoke test (may return empty if `ip` missing)
# ============================================================================


def test_detect_host_network_info_returns_two_lists() -> None:
    gateways, hosts = detect_host_network_info()
    assert isinstance(gateways, list)
    assert isinstance(hosts, list)
    # Each IP, if present, must parse
    import ipaddress
    for ip in gateways + hosts:
        ipaddress.ip_address(ip)
