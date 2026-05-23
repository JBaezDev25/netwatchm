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
class DataHogConfig:
    enabled: bool = True
    bytes_per_24h: int = 10_737_418_240  # 10 GiB
    window_seconds: int = 86400          # 24 hours
    alert_window_seconds: int = 3600     # re-alert same device after 1 hour


@dataclass
class AdultDomainConfig:
    enabled: bool = True
    list_url: str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"
    refresh_hours: int = 24
    alert_window_seconds: int = 3600  # re-alert same src_ip after 1 hour
    extra_domains: list[str] = field(default_factory=list)


@dataclass
class TrackerDomainConfig:
    enabled: bool = True
    # Steven Black unified adware+malware list (no adult content — kept separate)
    list_url: str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    refresh_hours: int = 24
    alert_window_seconds: int = 3600  # re-alert same src_ip after 1 hour
    extra_domains: list[str] = field(default_factory=list)


@dataclass
class MalwareDomainConfig:
    enabled: bool = True
    # abuse.ch URLhaus active malware C2 / payload distribution hosts
    list_url: str = "https://urlhaus.abuse.ch/downloads/hostfile/"
    refresh_hours: int = 6
    alert_window_seconds: int = 1800  # re-alert same (src,domain) after 30 min
    extra_domains: list[str] = field(default_factory=list)


@dataclass
class DnsTunnelingConfig:
    enabled: bool = True
    queries_per_window: int = 10      # suspicious queries needed to fire
    window_seconds: int = 60
    min_label_length: int = 30        # leftmost label longer than this = suspicious
    min_query_length: int = 60        # full FQDN longer than this = suspicious
    entropy_threshold: float = 4.0    # Shannon entropy of leftmost label
    alert_window_seconds: int = 600   # re-alert same src_ip after 10 min


@dataclass
class BeaconingConfig:
    enabled: bool = True
    min_contacts: int = 6                    # need this many to compute jitter
    min_interval_seconds: float = 30.0       # ignore intervals shorter than this
    max_interval_seconds: float = 3600.0     # ignore intervals longer than this
    max_jitter_ratio: float = 0.15           # CoV threshold; below = regular beacon
    window_seconds: int = 7200               # how long timestamps are kept per pair
    alert_window_seconds: int = 1800         # re-alert same pair after 30 min


@dataclass
class Thresholds:
    port_scan: PortScanThreshold = field(default_factory=PortScanThreshold)
    brute_force: BruteForceThreshold = field(default_factory=BruteForceThreshold)
    exfiltration: ExfiltrationThreshold = field(default_factory=ExfiltrationThreshold)
    new_ip: NewIPThreshold = field(default_factory=NewIPThreshold)
    tor_exit: TorExitConfig = field(default_factory=TorExitConfig)
    adult_domain: AdultDomainConfig = field(default_factory=AdultDomainConfig)
    tracker_domain: TrackerDomainConfig = field(default_factory=TrackerDomainConfig)
    malware_domain: MalwareDomainConfig = field(default_factory=MalwareDomainConfig)
    dns_tunneling: DnsTunnelingConfig = field(default_factory=DnsTunnelingConfig)
    beaconing: BeaconingConfig = field(default_factory=BeaconingConfig)
    data_hog: DataHogConfig = field(default_factory=DataHogConfig)


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
    cooldown_seconds: int = 3600


@dataclass
class NtfyAlertConfig:
    enabled: bool = False
    server: str = "https://ntfy.sh"
    topic: str = ""
    token: str = ""  # always loaded from env var NETWATCHM_NTFY_TOKEN
    min_level: str = "HIGH"
    cooldown_seconds: int = 300


@dataclass
class EventStoreConfig:
    retention_hours: int = 72


@dataclass
class AlertsConfig:
    terminal: bool = True
    log: LogAlertConfig = field(default_factory=LogAlertConfig)
    sound: SoundAlertConfig = field(default_factory=SoundAlertConfig)
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)
    ntfy: NtfyAlertConfig = field(default_factory=NtfyAlertConfig)
    event_store: EventStoreConfig = field(default_factory=EventStoreConfig)


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
class DetectorWhitelistConfig:
    """Per-detector IP suppression: suppress a specific alert type from specific IPs only.
    Keys are alert type names (PORT_SCAN, BRUTE_FORCE, etc.), values are IP lists."""
    rules: dict[str, list[str]] = field(default_factory=dict)

    def is_suppressed(self, alert_type: str, src_ip: str) -> bool:
        if not self.rules or not src_ip:
            return False
        ips = self.rules.get(alert_type.upper(), [])
        return src_ip in ips


@dataclass
class AgentConfig:
    """Autonomous agent loop (Phase 1: dry-run only).

    The agent observes recent events and queries the LLM for a recommended
    action. With ``dry_run`` true (the default), no state-changing tools
    exist — recommendations are recorded to the audit DB only.
    """
    enabled: bool = False
    dry_run: bool = True
    model: str = "qwen3:14b"
    ollama_base_url: str = "http://127.0.0.1:11434"
    interval_seconds: int = 300        # 5 min between ticks
    timeout_seconds: int = 120         # per LLM call
    temperature: float = 0.2
    context_hours_back: int = 4
    context_max_events: int = 50
    context_prompt_char_cap: int = 16000
    max_tool_hops: int = 4             # max read-only tool round-trips per tick


@dataclass
class Config:
    interface: str = "auto"
    baseline_period: int = 300
    thresholds: Thresholds = field(default_factory=Thresholds)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    inventory: InventoryConfig = field(default_factory=InventoryConfig)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)
    detector_whitelist: DetectorWhitelistConfig = field(default_factory=DetectorWhitelistConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)

    def __post_init__(self) -> None:
        # Always load email password from env var
        env_pass = os.environ.get("NETWATCHM_EMAIL_PASSWORD", "")
        if env_pass:
            self.alerts.email.password = env_pass
        # Always load ntfy token from env var
        env_token = os.environ.get("NETWATCHM_NTFY_TOKEN", "")
        if env_token:
            self.alerts.ntfy.token = env_token


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
    ad = thresh_raw.get("adult_domain", {})
    td = thresh_raw.get("tracker_domain", {})
    md = thresh_raw.get("malware_domain", {})
    dt = thresh_raw.get("dns_tunneling", {})
    bc = thresh_raw.get("beaconing", {})
    dh = thresh_raw.get("data_hog", {})

    alerts_raw = raw.get("alerts", {})
    log_raw = alerts_raw.get("log", {})
    sound_raw = alerts_raw.get("sound", {})
    email_raw = alerts_raw.get("email", {})
    ntfy_raw = alerts_raw.get("ntfy", {})
    es_raw = alerts_raw.get("event_store", {})

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
            adult_domain=AdultDomainConfig(
                enabled=ad.get("enabled", True),
                list_url=ad.get("list_url", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"),
                refresh_hours=ad.get("refresh_hours", 24),
                alert_window_seconds=ad.get("alert_window_seconds", 3600),
                extra_domains=ad.get("extra_domains", []),
            ),
            tracker_domain=TrackerDomainConfig(
                enabled=td.get("enabled", True),
                list_url=td.get("list_url", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
                refresh_hours=td.get("refresh_hours", 24),
                alert_window_seconds=td.get("alert_window_seconds", 3600),
                extra_domains=td.get("extra_domains", []),
            ),
            malware_domain=MalwareDomainConfig(
                enabled=md.get("enabled", True),
                list_url=md.get("list_url", "https://urlhaus.abuse.ch/downloads/hostfile/"),
                refresh_hours=md.get("refresh_hours", 6),
                alert_window_seconds=md.get("alert_window_seconds", 1800),
                extra_domains=md.get("extra_domains", []),
            ),
            dns_tunneling=DnsTunnelingConfig(
                enabled=dt.get("enabled", True),
                queries_per_window=dt.get("queries_per_window", 10),
                window_seconds=dt.get("window_seconds", 60),
                min_label_length=dt.get("min_label_length", 30),
                min_query_length=dt.get("min_query_length", 60),
                entropy_threshold=dt.get("entropy_threshold", 4.0),
                alert_window_seconds=dt.get("alert_window_seconds", 600),
            ),
            beaconing=BeaconingConfig(
                enabled=bc.get("enabled", True),
                min_contacts=bc.get("min_contacts", 6),
                min_interval_seconds=bc.get("min_interval_seconds", 30.0),
                max_interval_seconds=bc.get("max_interval_seconds", 3600.0),
                max_jitter_ratio=bc.get("max_jitter_ratio", 0.15),
                window_seconds=bc.get("window_seconds", 7200),
                alert_window_seconds=bc.get("alert_window_seconds", 1800),
            ),
            data_hog=DataHogConfig(
                enabled=dh.get("enabled", True),
                bytes_per_24h=dh.get("bytes_per_24h", 10_737_418_240),
                window_seconds=dh.get("window_seconds", 86400),
                alert_window_seconds=dh.get("alert_window_seconds", 3600),
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
            ntfy=NtfyAlertConfig(
                enabled=ntfy_raw.get("enabled", False),
                server=ntfy_raw.get("server", "https://ntfy.sh"),
                topic=ntfy_raw.get("topic", ""),
                token=ntfy_raw.get("token", ""),
                min_level=ntfy_raw.get("min_level", "HIGH"),
                cooldown_seconds=ntfy_raw.get("cooldown_seconds", 300),
            ),
            event_store=EventStoreConfig(
                retention_hours=es_raw.get("retention_hours", 72),
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

    dwl_raw = raw.get("detector_whitelist", {})
    if dwl_raw:
        # Normalise keys to upper-case alert type names
        config.detector_whitelist = DetectorWhitelistConfig(
            rules={k.upper(): list(v) for k, v in dwl_raw.items() if isinstance(v, list)}
        )

    ag_raw = raw.get("agent", {})
    if ag_raw:
        config.agent = AgentConfig(
            enabled=ag_raw.get("enabled", False),
            dry_run=ag_raw.get("dry_run", True),
            model=ag_raw.get("model", "qwen3:14b"),
            ollama_base_url=ag_raw.get("ollama_base_url", "http://127.0.0.1:11434"),
            interval_seconds=ag_raw.get("interval_seconds", 300),
            timeout_seconds=ag_raw.get("timeout_seconds", 120),
            temperature=ag_raw.get("temperature", 0.2),
            context_hours_back=ag_raw.get("context_hours_back", 4),
            context_max_events=ag_raw.get("context_max_events", 50),
            context_prompt_char_cap=ag_raw.get("context_prompt_char_cap", 16000),
            max_tool_hops=ag_raw.get("max_tool_hops", 4),
        )

    # Post-init to load env var password
    config.__post_init__()
    return config
