"""Tests for WhitelistChecker and WhitelistConfig."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from netwatchm.config import WhitelistConfig, load_config
from netwatchm.models import Alert, ThreatLevel
from netwatchm.whitelist import WhitelistChecker


def make_alert(src_ip: str | None = None, dst_ip: str | None = None) -> Alert:
    return Alert(
        alert_type="TEST",
        level=ThreatLevel.HIGH,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description="test alert",
    )


class TestWhitelistCheckerPlainIPs:
    def test_empty_list_never_whitelists(self) -> None:
        checker = WhitelistChecker([])
        assert checker.is_whitelisted(make_alert("1.2.3.4")) is False

    def test_src_ip_match(self) -> None:
        checker = WhitelistChecker(["10.0.0.1"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1")) is True

    def test_dst_ip_match(self) -> None:
        checker = WhitelistChecker(["10.0.0.180"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1", dst_ip="10.0.0.180")) is True

    def test_no_match(self) -> None:
        checker = WhitelistChecker(["10.0.0.1"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.99", dst_ip="8.8.8.8")) is False

    def test_multiple_ips_one_matches(self) -> None:
        checker = WhitelistChecker(["10.0.0.1", "10.0.0.180", "10.0.0.1"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1")) is True

    def test_both_ips_none(self) -> None:
        checker = WhitelistChecker(["1.2.3.4"])
        assert checker.is_whitelisted(make_alert(src_ip=None, dst_ip=None)) is False

    def test_src_none_dst_matches(self) -> None:
        checker = WhitelistChecker(["5.6.7.8"])
        assert checker.is_whitelisted(make_alert(src_ip=None, dst_ip="5.6.7.8")) is True

    def test_invalid_entry_ignored(self) -> None:
        checker = WhitelistChecker(["not-an-ip", "10.0.0.1"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1")) is True
        assert checker.is_whitelisted(make_alert(src_ip="not-an-ip")) is False


class TestWhitelistCheckerCIDR:
    def test_cidr_src_ip_in_range(self) -> None:
        checker = WhitelistChecker(["10.0.0.0/24"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.50")) is True

    def test_cidr_dst_ip_in_range(self) -> None:
        checker = WhitelistChecker(["10.0.0.0/8"])
        assert checker.is_whitelisted(make_alert(src_ip="8.8.8.8", dst_ip="10.20.30.40")) is True

    def test_cidr_ip_outside_range(self) -> None:
        checker = WhitelistChecker(["10.0.0.0/24"])
        assert checker.is_whitelisted(make_alert(src_ip="192.168.2.1")) is False

    def test_cidr_boundary_first_host(self) -> None:
        checker = WhitelistChecker(["172.16.0.0/16"])
        assert checker.is_whitelisted(make_alert(src_ip="172.16.0.1")) is True

    def test_cidr_boundary_last_host(self) -> None:
        checker = WhitelistChecker(["172.16.0.0/16"])
        assert checker.is_whitelisted(make_alert(src_ip="172.16.255.254")) is True

    def test_cidr_outside_boundary(self) -> None:
        checker = WhitelistChecker(["172.16.0.0/16"])
        assert checker.is_whitelisted(make_alert(src_ip="172.17.0.1")) is False

    def test_invalid_cidr_ignored(self) -> None:
        checker = WhitelistChecker(["999.999.999.0/24", "10.0.0.1"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1")) is True

    def test_mixed_plain_and_cidr(self) -> None:
        checker = WhitelistChecker(["10.0.0.1", "10.0.0.0/8"])
        assert checker.is_whitelisted(make_alert(src_ip="10.0.0.1")) is True
        assert checker.is_whitelisted(make_alert(src_ip="10.99.0.1")) is True
        assert checker.is_whitelisted(make_alert(src_ip="172.16.0.1")) is False


class TestWhitelistConfig:
    def test_default_disabled(self) -> None:
        cfg = load_config(None)
        assert cfg.whitelist.enabled is False
        assert cfg.whitelist.ips == []

    def test_whitelist_parsed_from_yaml(self) -> None:
        data = {
            "whitelist": {
                "enabled": True,
                "ips": ["10.0.0.1", "10.0.0.0/8"],
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            assert cfg.whitelist.enabled is True
            assert cfg.whitelist.ips == ["10.0.0.1", "10.0.0.0/8"]
        finally:
            Path(tmp_path).unlink()

    def test_whitelist_disabled_in_yaml(self) -> None:
        data = {
            "whitelist": {
                "enabled": False,
                "ips": ["10.0.0.1"],
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            assert cfg.whitelist.enabled is False
        finally:
            Path(tmp_path).unlink()

    def test_whitelist_empty_ips_list(self) -> None:
        data = {"whitelist": {"enabled": True, "ips": []}}
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            assert cfg.whitelist.enabled is True
            assert cfg.whitelist.ips == []
        finally:
            Path(tmp_path).unlink()

    def test_no_whitelist_section_uses_defaults(self) -> None:
        data = {"interface": "eth0"}
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.dump(data, f)
            tmp_path = f.name
        try:
            cfg = load_config(tmp_path)
            assert cfg.whitelist.enabled is False
            assert cfg.whitelist.ips == []
        finally:
            Path(tmp_path).unlink()
