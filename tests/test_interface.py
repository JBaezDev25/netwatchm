"""Tests for interface auto-detection."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from netwatchm.interface import _list_tshark_interfaces, detect_interface


def test_explicit_interface() -> None:
    assert detect_interface("eth0") == "eth0"
    assert detect_interface("wlan0") == "wlan0"


def test_auto_prefers_enp6s0() -> None:
    with patch("netwatchm.interface._list_tshark_interfaces") as mock_list:
        mock_list.return_value = ["lo", "enp6s0", "wlan0"]
        with patch("netwatchm.interface.sys") as mock_sys:
            mock_sys.platform = "linux"
            result = detect_interface("auto")
    assert result == "enp6s0"


def test_auto_first_nonloopback_linux() -> None:
    with patch("netwatchm.interface._list_tshark_interfaces") as mock_list:
        mock_list.return_value = ["lo", "eth0", "wlan0"]
        with patch("netwatchm.interface.sys") as mock_sys:
            mock_sys.platform = "linux"
            result = detect_interface("auto")
    assert result == "eth0"


def test_auto_fallback_empty() -> None:
    with patch("netwatchm.interface._list_tshark_interfaces") as mock_list:
        mock_list.return_value = []
        result = detect_interface("auto")
    assert result == "eth0"


def test_list_tshark_interfaces_parses_output() -> None:
    fake_output = "1. lo\n2. enp6s0\n3. wlan0\n"
    mock_result = MagicMock()
    mock_result.stdout = fake_output
    with patch("subprocess.run", return_value=mock_result):
        ifaces = _list_tshark_interfaces()
    assert "lo" in ifaces
    assert "enp6s0" in ifaces


def test_list_tshark_interfaces_not_found() -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        ifaces = _list_tshark_interfaces()
    assert ifaces == []
