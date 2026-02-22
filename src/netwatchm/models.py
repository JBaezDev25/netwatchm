"""Core data models for NetWatchM."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class ThreatLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            ThreatLevel.LOW: "green",
            ThreatLevel.MEDIUM: "yellow",
            ThreatLevel.HIGH: "red",
            ThreatLevel.CRITICAL: "bold red",
        }[self]


@dataclass
class Packet:
    timestamp: float          # epoch seconds
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    length: int               # frame length in bytes
    protocol: str | None      # e.g. "TCP", "UDP", "DNS"
    ip_proto: int | None      # IP protocol number


@dataclass
class Alert:
    alert_type: str           # e.g. "PORT_SCAN", "BRUTE_FORCE"
    level: ThreatLevel
    src_ip: str | None
    dst_ip: str | None
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    expires_at: float = 0.0   # epoch seconds; 0 = never expires

    def __hash__(self) -> int:
        return hash((self.alert_type, self.src_ip, self.dst_ip))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Alert):
            return NotImplemented
        return (
            self.alert_type == other.alert_type
            and self.src_ip == other.src_ip
            and self.dst_ip == other.dst_ip
        )


@dataclass
class DeviceRecord:
    ip: str
    mac: str | None = None          # from ARP frames; None if not seen
    hostname: str | None = None     # from reverse DNS; None until resolved
    vendor: str | None = None       # from MAC OUI prefix; None if unknown
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    bytes_sent: int = 0
    bytes_received: int = 0
    ports_observed: set[int] = field(default_factory=set)
    threat_level: ThreatLevel = ThreatLevel.LOW

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "ports_observed": sorted(self.ports_observed),
            "threat_level": self.threat_level.name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceRecord":
        return cls(
            ip=data["ip"],
            mac=data.get("mac"),
            hostname=data.get("hostname"),
            vendor=data.get("vendor"),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            bytes_sent=data.get("bytes_sent", 0),
            bytes_received=data.get("bytes_received", 0),
            ports_observed=set(data.get("ports_observed", [])),
            threat_level=ThreatLevel[data.get("threat_level", "LOW")],
        )
