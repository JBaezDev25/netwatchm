"""Load and validate netwatchm.yaml configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PortScanThreshold:
    ports_per_window: int = 15
    window_seconds: int = 10


@dataclass
class BruteForceThreshold:
    attempts_per_window: int = 10
    window_seconds: int = 30
    ports: list[int] = field(default_factory=lambda: [22, 3389, 21, 3306, 5900])


@dataclass
class ExfiltrationThreshold:
    bytes_per_window: int = 10_485_760  # 10 MB
    window_seconds: int = 60


@dataclass
class NewIPThreshold:
    enabled: bool = True


@dataclass
class TorExitConfig:
    enabled: bool = True
    list_url: str = "https://check.torproject.org/torbulkexitlist"
    refresh_hours: int = 24
    alert_window_seconds: int = 300  # re-alert same IP after 5 min


@dataclass
class Thresholds:
    port_scan: PortScanThreshold = field(default_factory=PortScanThreshold)
    brute_force: BruteForceThreshold = field(default_factory=BruteForceThreshold)
    exfiltration: ExfiltrationThreshold = field(default_factory=ExfiltrationThreshold)
    new_ip: NewIPThreshold = field(default_factory=NewIPThreshold)
    tor_exit: TorExitConfig = field(default_factory=TorExitConfig)


@dataclass
class LogAlertConfig:
    enabled: bool = True
    path: str = "/var/log/netwatchm/netwatchm.log"
    max_bytes: int = 10_485_760
    backup_count: int = 5


@dataclass
class SoundAlertConfig:
    enabled: bool = True
    file: str = "assets/alert.wav"
    min_level: str = "HIGH"


@dataclass
class EmailAlertConfig:
    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    username: str = ""
    password: str = ""  # always loaded from env var NETWATCHM_EMAIL_PASSWORD
    recipient: str = ""
    min_level: str = "HIGH"
    cooldown_seconds: int = 300


@dataclass
class AlertsConfig:
    terminal: bool = True
    log: LogAlertConfig = field(default_factory=LogAlertConfig)
    sound: SoundAlertConfig = field(default_factory=SoundAlertConfig)
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)


@dataclass
class ArpScanConfig:
    enabled: bool = True
    interval: int = 300       # seconds between scans
    network: str = "auto"     # "auto" = --localnet, or explicit CIDR


@dataclass
class InventoryConfig:
    enabled: bool = True
    persist_interval: int = 60
    dns_timeout: int = 2
    dns_cache_ttl: int = 300
    export_dir: str = "."
    local_networks: list[str] = field(default_factory=list)
    arp_scan: ArpScanConfig = field(default_factory=ArpScanConfig)


@dataclass
class WhitelistConfig:
    enabled: bool = False
    ips: list[str] = field(default_factory=list)


@dataclass
class Config:
    interface: str = "auto"
    baseline_period: int = 300
    thresholds: Thresholds = field(default_factory=Thresholds)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    inventory: InventoryConfig = field(default_factory=InventoryConfig)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)

    def __post_init__(self) -> None:
        # Always load email password from env var
        env_pass = os.environ.get("NETWATCHM_EMAIL_PASSWORD", "")
        if env_pass:
            self.alerts.email.password = env_pass


def _merge(base: Any, override: Any) -> Any:
    """Recursively merge override dict into base dict."""
    if isinstance(base, dict) and isinstance(override, dict):
        result = dict(base)
        for key, val in override.items():
            result[key] = _merge(base.get(key), val)
        return result
    return override if override is not None else base


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML file. Missing keys use defaults."""
    raw: dict = {}
    if path is not None:
        cfg_path = Path(path)
        if cfg_path.exists():
            with cfg_path.open() as f:
                raw = yaml.safe_load(f) or {}

    def get(d: dict, *keys: str, default: Any = None) -> Any:
        for k in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(k, default)  # type: ignore[assignment]
        return d

    thresh_raw = raw.get("thresholds", {})
    ps = thresh_raw.get("port_scan", {})
    bf = thresh_raw.get("brute_force", {})
    ex = thresh_raw.get("exfiltration", {})
    ni = thresh_raw.get("new_ip", {})

    alerts_raw = raw.get("alerts", {})
    log_raw = alerts_raw.get("log", {})
    sound_raw = alerts_raw.get("sound", {})
    email_raw = alerts_raw.get("email", {})

    inv_raw = raw.get("inventory", {})

    config = Config(
        interface=raw.get("interface", "auto"),
        baseline_period=raw.get("baseline_period", 300),
        thresholds=Thresholds(
            port_scan=PortScanThreshold(
                ports_per_window=ps.get("ports_per_window", 15),
                window_seconds=ps.get("window_seconds", 10),
            ),
            brute_force=BruteForceThreshold(
                attempts_per_window=bf.get("attempts_per_window", 10),
                window_seconds=bf.get("window_seconds", 30),
                ports=bf.get("ports", [22, 3389, 21, 3306, 5900]),
            ),
            exfiltration=ExfiltrationThreshold(
                bytes_per_window=ex.get("bytes_per_window", 10_485_760),
                window_seconds=ex.get("window_seconds", 60),
            ),
            new_ip=NewIPThreshold(
                enabled=ni.get("enabled", True),
            ),
        ),
        alerts=AlertsConfig(
            terminal=alerts_raw.get("terminal", True),
            log=LogAlertConfig(
                enabled=log_raw.get("enabled", True),
                path=log_raw.get("path", "/var/log/netwatchm/netwatchm.log"),
                max_bytes=log_raw.get("max_bytes", 10_485_760),
                backup_count=log_raw.get("backup_count", 5),
            ),
            sound=SoundAlertConfig(
                enabled=sound_raw.get("enabled", True),
                file=sound_raw.get("file", "assets/alert.wav"),
                min_level=sound_raw.get("min_level", "HIGH"),
            ),
            email=EmailAlertConfig(
                enabled=email_raw.get("enabled", False),
                smtp_host=email_raw.get("smtp_host", "smtp.gmail.com"),
                smtp_port=email_raw.get("smtp_port", 587),
                username=email_raw.get("username", ""),
                password=email_raw.get("password", ""),
                recipient=email_raw.get("recipient", ""),
                min_level=email_raw.get("min_level", "HIGH"),
                cooldown_seconds=email_raw.get("cooldown_seconds", 300),
            ),
        ),
        inventory=InventoryConfig(
            enabled=inv_raw.get("enabled", True),
            persist_interval=inv_raw.get("persist_interval", 60),
            dns_timeout=inv_raw.get("dns_timeout", 2),
            dns_cache_ttl=inv_raw.get("dns_cache_ttl", 300),
            export_dir=inv_raw.get("export_dir", "."),
            local_networks=inv_raw.get("local_networks", []),
            arp_scan=ArpScanConfig(
                enabled=inv_raw.get("arp_scan", {}).get("enabled", True),
                interval=inv_raw.get("arp_scan", {}).get("interval", 300),
                network=inv_raw.get("arp_scan", {}).get("network", "auto"),
            ),
        ),
    )

    wl_raw = raw.get("whitelist", {})
    if wl_raw:
        config.whitelist = WhitelistConfig(
            enabled=wl_raw.get("enabled", False),
            ips=wl_raw.get("ips", []),
        )

    # Post-init to load env var password
    config.__post_init__()
    return config
