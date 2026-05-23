"""Shared test fixtures."""
from __future__ import annotations

import time
from datetime import datetime

import pytest

from netwatchm.config import (
    AdultDomainConfig,
    BeaconingConfig,
    BruteForceThreshold,
    Config,
    DataHogConfig,
    DnsTunnelingConfig,
    ExfiltrationThreshold,
    InventoryConfig,
    MalwareDomainConfig,
    NewIPThreshold,
    PortScanThreshold,
    Thresholds,
    TorExitConfig,
)
from netwatchm.models import Packet, ThreatLevel


def make_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int | None = 54321,
    dst_port: int | None = 80,
    length: int = 100,
    protocol: str | None = "TCP",
    timestamp: float | None = None,
    dns_query: str | None = None,
    sni: str | None = None,
) -> Packet:
    return Packet(
        timestamp=timestamp or time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        protocol=protocol,
        ip_proto=6,
        dns_query=dns_query,
        sni=sni,
    )


@pytest.fixture
def default_config() -> Config:
    return Config()


@pytest.fixture
def port_scan_threshold() -> PortScanThreshold:
    return PortScanThreshold(ports_per_window=5, window_seconds=10)


@pytest.fixture
def brute_force_threshold() -> BruteForceThreshold:
    return BruteForceThreshold(attempts_per_window=3, window_seconds=10, ports=[22])


@pytest.fixture
def exfiltration_threshold() -> ExfiltrationThreshold:
    return ExfiltrationThreshold(bytes_per_window=1000, window_seconds=10)


@pytest.fixture
def new_ip_threshold() -> NewIPThreshold:
    return NewIPThreshold(enabled=True)


@pytest.fixture
def tor_exit_config() -> TorExitConfig:
    return TorExitConfig(alert_window_seconds=10)


@pytest.fixture
def adult_domain_config() -> AdultDomainConfig:
    return AdultDomainConfig(alert_window_seconds=10)


@pytest.fixture
def data_hog_config() -> DataHogConfig:
    return DataHogConfig(bytes_per_24h=1000, window_seconds=86400, alert_window_seconds=10)
