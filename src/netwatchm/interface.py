"""Auto-detect the best network interface for packet capture."""
from __future__ import annotations

import re
import subprocess
import sys


def detect_interface(config_value: str = "auto") -> str:
    """Return the network interface to capture on.

    Priority:
    1. If config_value is not 'auto', use it as-is.
    2. Parse `tshark -D` output.
    3. On Linux: prefer 'enp6s0' if present, else first non-loopback.
    4. On Windows: prefer first Ethernet/Wi-Fi interface.
    5. Fall back to 'eth0'.
    """
    if config_value != "auto":
        return config_value

    interfaces = _list_tshark_interfaces()
    if not interfaces:
        return "eth0"

    # Linux: prefer enp6s0
    if sys.platform != "win32":
        for iface in interfaces:
            if iface == "enp6s0":
                return iface
        # First non-loopback
        for iface in interfaces:
            if iface not in ("lo", "loopback", "any"):
                return iface

    # Windows: prefer Ethernet / Wi-Fi
    else:
        for iface in interfaces:
            lower = iface.lower()
            if "ethernet" in lower or "wi-fi" in lower or "wireless" in lower:
                return iface

    return interfaces[0] if interfaces else "eth0"


def _list_tshark_interfaces() -> list[str]:
    """Run `tshark -D` and return list of interface names."""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        interfaces: list[str] = []
        for line in result.stdout.splitlines():
            # Format: "1. enp6s0\n2. lo\n..."  or  "1. \Device\NPF_{...} (Ethernet)"
            match = re.match(r"^\d+\.\s+(.+?)(?:\s+\(.*\))?\s*$", line)
            if match:
                name = match.group(1).strip()
                if name:
                    interfaces.append(name)
        return interfaces
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
