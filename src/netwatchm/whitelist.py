"""Whitelist checker — skips alerts for trusted IPs (plain or CIDR)."""
from __future__ import annotations

from ipaddress import ip_address, ip_network

from .models import Alert


class WhitelistChecker:
    def __init__(self, ips: list[str]) -> None:
        self._ips: set[str] = set()
        self._networks: list = []
        for entry in ips:
            try:
                if "/" in entry:
                    self._networks.append(ip_network(entry, strict=False))
                else:
                    ip_address(entry)  # validate before storing
                    self._ips.add(entry)
            except ValueError:
                pass

    def is_ip_whitelisted(self, ip: str) -> bool:
        """Return True if a plain IP string is whitelisted."""
        if ip in self._ips:
            return True
        try:
            addr = ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def is_whitelisted(self, alert: Alert) -> bool:
        for ip in (alert.src_ip, alert.dst_ip):
            if ip is None:
                continue
            if self.is_ip_whitelisted(ip):
                return True
        return False
