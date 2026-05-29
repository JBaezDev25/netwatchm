"""CLI entry point for NetWatchM."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

from rich.console import Console

from .alerts.email_alert import EmailAlert
from .alerts.ntfy_alert import NtfyAlert
from .alerts.event_handler import EventStoreHandler
from .alerts.forensic_handler import ForensicHandler
from .alerts.logfile import LogFileAlert
from .alerts.sound import SoundAlert
from .alerts.terminal import TerminalAlert
from .capture import capture_packets
from .config import Config, load_config
from .detector import (
    AdultDomainDetector,
    BeaconingDetector,
    BruteForceDetector,
    DataHogDetector,
    DnsTunnelingDetector,
    ExfiltrationDetector,
    MalwareDomainDetector,
    NewIPDetector,
    PortScanDetector,
    TorExitDetector,
    TrackerDomainDetector,
)
from .interface import detect_interface
from .inventory.exporter import export_inventory
from .inventory.resolver import DNSResolver
from .inventory.store import DeviceStore
from .models import Alert, Packet, ThreatLevel
from .scorer import ThreatScorer
from .util import format_bytes
from .whitelist import WhitelistChecker

logger = logging.getLogger("netwatchm")

DEFAULT_CONFIG_LINUX = "/etc/netwatchm/netwatchm.yaml"
DEFAULT_CONFIG_WINDOWS = r"C:\ProgramData\netwatchm\netwatchm.yaml"


def _default_config_path() -> str:
    if sys.platform == "win32":
        return DEFAULT_CONFIG_WINDOWS
    return DEFAULT_CONFIG_LINUX


def _setup_logging(level: str) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


def _get_suppressed_types() -> None:
    """Namespace for suppression cache state (populated in alert_dispatch_loop)."""

_get_suppressed_types.__cache: set = set()  # type: ignore[attr-defined]
_get_suppressed_types.__cache_ts: float = 0.0  # type: ignore[attr-defined]


def _get_agent_whitelist() -> None:
    """Namespace for the agent_whitelist.json hot-reload cache."""

_get_agent_whitelist.__store = None  # type: ignore[attr-defined]
_get_agent_whitelist.__cache_ts: float = 0.0  # type: ignore[attr-defined]
_get_agent_whitelist.__cached_entries: list = []  # type: ignore[attr-defined]


async def run_monitor(config: Config, no_ui: bool = False) -> None:
    """Main monitoring coroutine."""
    interface = detect_interface(config.interface)
    logger.info("Monitoring interface: %s", interface)

    console = Console()
    stop_event = asyncio.Event()
    packet_queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=10_000)
    alert_queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=1_000)

    # --- Inventory ---
    store = DeviceStore(local_networks=config.inventory.local_networks)
    inventory_path = None  # use default platform path
    await store.load(inventory_path)

    # --- Detectors ---
    detectors = [
        PortScanDetector(config.thresholds.port_scan),
        BruteForceDetector(config.thresholds.brute_force),
        ExfiltrationDetector(config.thresholds.exfiltration),
        NewIPDetector(config.thresholds.new_ip, config.baseline_period),
        TorExitDetector(config.thresholds.tor_exit),
        AdultDomainDetector(config.thresholds.adult_domain),
        TrackerDomainDetector(config.thresholds.tracker_domain),
        MalwareDomainDetector(config.thresholds.malware_domain),
        DnsTunnelingDetector(config.thresholds.dns_tunneling),
        BeaconingDetector(config.thresholds.beaconing),
        DataHogDetector(config.thresholds.data_hog),
    ]

    # --- Scorer ---
    scorer = ThreatScorer()

    # --- Whitelist ---
    _whitelist = WhitelistChecker(config.whitelist.ips) if config.whitelist.enabled else None

    # Reset persisted HIGH threats for now-whitelisted IPs
    if _whitelist:
        await store.reset_whitelisted_threats(_whitelist)

    # --- Alert handlers ---
    handlers = []
    if config.alerts.terminal and not no_ui:
        handlers.append(TerminalAlert(console))
    if config.alerts.log.enabled:
        handlers.append(LogFileAlert(config.alerts.log))
    if config.alerts.sound.enabled:
        handlers.append(SoundAlert(config.alerts.sound))
    if config.alerts.email.enabled:
        handlers.append(EmailAlert(config.alerts.email))
    if config.alerts.ntfy.enabled:
        handlers.append(NtfyAlert(config.alerts.ntfy))
    handlers.append(EventStoreHandler(retention_hours=config.alerts.event_store.retention_hours))
    if config.alerts.forensics.enabled:
        handlers.append(ForensicHandler(config.alerts.forensics, interface=interface))

    # --- UI ---
    dashboard = None
    inventory_view = None
    input_handler = None
    live = None

    if not no_ui:
        from .ui.dashboard import Dashboard
        from .ui.input_handler import InputHandler
        from .ui.inventory_view import InventoryView

        dashboard = Dashboard(interface, console)
        inventory_view = InventoryView(store, console)
        input_handler = InputHandler()
        input_handler.start()
        live = dashboard.start()

    # --- DNS Resolver ---
    resolver = DNSResolver(
        timeout=config.inventory.dns_timeout,
        cache_ttl=config.inventory.dns_cache_ttl,
    )

    async def capture_loop() -> None:
        await capture_packets(interface, packet_queue, stop_event)

    async def detector_loop() -> None:
        while not stop_event.is_set():
            try:
                packet = await asyncio.wait_for(packet_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                for det in detectors:
                    det.flush_expired()
                continue

            # Update inventory
            if config.inventory.enabled:
                await store.update(packet)

            # Run detectors
            for det in detectors:
                alert = det.process(packet)
                if alert is not None:
                    await alert_queue.put(alert)

            # Update dashboard traffic
            if dashboard:
                dashboard.add_packet(packet)

            packet_queue.task_done()

    async def alert_dispatch_loop() -> None:
        while not stop_event.is_set():
            try:
                alert = await asyncio.wait_for(alert_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if _whitelist and _whitelist.is_whitelisted(alert):
                alert_queue.task_done()
                continue

            # Per-detector whitelist: suppress specific alert type from specific IPs
            if config.detector_whitelist.is_suppressed(
                alert.alert_type or "", alert.src_ip or ""
            ):
                alert_queue.task_done()
                continue

            # Agent-managed whitelist (5s cached file read) — Phase 2 actions
            if _get_agent_whitelist.__cache_ts + 5 < time.time():
                _get_agent_whitelist.__cache_ts = time.time()
                try:
                    if _get_agent_whitelist.__store is None:
                        from .agent.state import AgentWhitelistStore
                        _get_agent_whitelist.__store = AgentWhitelistStore()
                    _get_agent_whitelist.__cached_entries = (
                        _get_agent_whitelist.__store.active_entries()
                    )
                except Exception:  # noqa: BLE001
                    _get_agent_whitelist.__cached_entries = []
            for _e in _get_agent_whitelist.__cached_entries:
                if _e.get("ip") != alert.src_ip:
                    continue
                if _e.get("scope") == "global":
                    alert.__dict__["_agent_suppressed"] = True
                    break
                if (
                    _e.get("scope") == "detector"
                    and (_e.get("alert_type") or "").upper() == (alert.alert_type or "").upper()
                ):
                    alert.__dict__["_agent_suppressed"] = True
                    break
            if alert.__dict__.get("_agent_suppressed"):
                alert_queue.task_done()
                continue

            # Suppression check (5s cached file read)
            if _get_suppressed_types.__cache_ts + 5 < time.time():
                _get_suppressed_types.__cache_ts = time.time()
                try:
                    _dd = (Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm") \
                        if sys.platform == "win32" else Path("/var/lib/netwatchm")
                    _sf = Path(os.environ.get("NETWATCHM_SUPPRESSED_FILE", str(_dd / "suppressed.json")))
                    _get_suppressed_types.__cache = set(json.loads(_sf.read_text()).get("types", [])) \
                        if _sf.exists() else set()
                except Exception:  # noqa: BLE001
                    _get_suppressed_types.__cache = set()
            if alert.alert_type in _get_suppressed_types.__cache:
                alert_queue.task_done()
                continue

            scorer.add_alert(alert)
            level = scorer.current_level()

            if dashboard:
                dashboard.add_alert(alert)
                dashboard.set_threat_level(level)

            # Update device threat levels
            if alert.src_ip:
                await store.update_threat(alert.src_ip, alert.level)

            for handler in handlers:
                try:
                    await handler.send(alert)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Alert handler %s failed: %s", type(handler).__name__, exc)

            alert_queue.task_done()

    async def scorer_loop() -> None:
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            scorer.flush_expired()
            if dashboard:
                dashboard.set_threat_level(scorer.current_level())

    async def ui_refresh_loop() -> None:
        if not dashboard and not inventory_view:
            return
        in_inventory = False
        search_mode = False

        while not stop_event.is_set():
            await asyncio.sleep(0.5)

            # Process key inputs
            if input_handler:
                while True:
                    key = input_handler.get_key()
                    if key is None:
                        break
                    key_lower = key.lower()

                    if key_lower == "q":
                        stop_event.set()
                        return

                    if key_lower == "i" and not in_inventory:
                        in_inventory = True
                        search_mode = False
                        if dashboard:
                            dashboard.stop()
                        if inventory_view:
                            inventory_view.start()

                    elif key_lower == "m" and in_inventory:
                        in_inventory = False
                        search_mode = False
                        if inventory_view:
                            inventory_view.stop()
                        if dashboard:
                            dashboard.start()

                    elif key_lower == "e" and in_inventory and inventory_view:
                        inventory_view.export_csv(config.inventory.export_dir)

                    elif key == "/" and in_inventory:
                        search_mode = True

                    elif key == "\x1b":  # Escape
                        if in_inventory and inventory_view:
                            inventory_view.clear_filter()
                        search_mode = False

                    elif key == "\x7f" and search_mode and inventory_view:
                        inventory_view.backspace_filter()

                    elif search_mode and key.isprintable() and inventory_view:
                        inventory_view.append_filter_char(key)

            # Refresh active view
            if in_inventory and inventory_view:
                await inventory_view.refresh_records()
                inventory_view.update()
            elif dashboard:
                dashboard.update()

    tasks = [
        asyncio.create_task(capture_loop(), name="capture"),
        asyncio.create_task(detector_loop(), name="detector"),
        asyncio.create_task(alert_dispatch_loop(), name="alerts"),
        asyncio.create_task(scorer_loop(), name="scorer"),
        asyncio.create_task(ui_refresh_loop(), name="ui"),
    ]

    if config.inventory.enabled:
        tasks.append(
            asyncio.create_task(
                resolver.run_resolver_loop(store, stop_event),
                name="resolver",
            )
        )
        tasks.append(
            asyncio.create_task(
                store.run_persist_loop(
                    config.inventory.persist_interval,
                    stop_event,
                    inventory_path,
                ),
                name="persist",
            )
        )
        if config.inventory.arp_scan.enabled:
            from .inventory.arp_scanner import run_arp_scan_loop
            tasks.append(
                asyncio.create_task(
                    run_arp_scan_loop(
                        store,
                        config.inventory.arp_scan.interval,
                        config.inventory.arp_scan.network,
                        stop_event,
                        alert_queue,
                    ),
                    name="arp_scanner",
                )
            )

    if config.agent.enabled:
        from .agent.agent_loop import run_agent_loop
        from .alerts.event_store import DEFAULT_DB as DEFAULT_EVENTS_DB
        data_dir = (
            str(Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm")
            if sys.platform == "win32"
            else "/var/lib/netwatchm"
        )
        tasks.append(
            asyncio.create_task(
                run_agent_loop(
                    agent_cfg=config.agent,
                    config=config,
                    stop_event=stop_event,
                    events_db_path=os.environ.get("NETWATCHM_EVENT_DB", DEFAULT_EVENTS_DB),
                    inventory_path=os.environ.get(
                        "NETWATCHM_INVENTORY_FILE",
                        str(Path(data_dir) / "inventory.json"),
                    ),
                    data_dir=data_dir,
                ),
                name="agent",
            )
        )

        # Firewall reaper — runs in live mode only. Removes expired ufw
        # blocks even if the agent's LLM call is stuck, so no rule
        # survives past its TTL.
        if not config.agent.dry_run:
            from .agent.audit import AuditLog, DEFAULT_AUDIT_DB
            from .agent.firewall import (
                FirewallController,
                FirewallStore,
                run_firewall_reaper,
            )
            tasks.append(
                asyncio.create_task(
                    run_firewall_reaper(
                        store=FirewallStore(),
                        controller=FirewallController(),
                        audit=AuditLog(DEFAULT_AUDIT_DB).open(),
                        stop_event=stop_event,
                        interval_seconds=60,
                    ),
                    name="firewall_reaper",
                )
            )

    # Retention sweep — runs always (not gated on agent.enabled). Prunes
    # agent_actions.db rows + compacts JSON sidecars older than the
    # configured retention window. Text-log rotation is handled by the
    # logrotate drop-in (scripts/install-log-retention.sh), so it works
    # even when this service is down.
    if config.retention.enabled:
        from .retention import run_retention_loop
        from .agent.audit import DEFAULT_AUDIT_DB
        from .agent.state import AgentWhitelistStore
        from .agent.firewall import FirewallStore as _FirewallStore
        tasks.append(
            asyncio.create_task(
                run_retention_loop(
                    audit_db_path=DEFAULT_AUDIT_DB,
                    whitelist_store=AgentWhitelistStore(),
                    blocks_store=_FirewallStore(),
                    stop_event=stop_event,
                    retention_days=config.retention.retention_days,
                    interval_seconds=config.retention.interval_seconds,
                ),
                name="retention",
            )
        )

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        stop_event.set()
        if dashboard:
            dashboard.stop()
        if inventory_view:
            inventory_view.stop()
        if input_handler:
            input_handler.stop()
        # Final inventory save
        if config.inventory.enabled:
            await store.persist(inventory_path)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def _inventory_subcommand(args: argparse.Namespace, config: Config) -> None:
    """Handle `netwatchm inventory` subcommand (offline, reads JSON)."""
    import sys

    store = DeviceStore()

    async def _load_and_export() -> None:
        await store.load()
        records = await store.get_all(args.filter)

        # Sort
        sort_key = getattr(args, "sort_by", "ip")
        if sort_key == "ip":
            records.sort(key=lambda r: r.ip)
        elif sort_key == "hostname":
            records.sort(key=lambda r: r.hostname or "")
        elif sort_key == "mac":
            records.sort(key=lambda r: r.mac or "")
        elif sort_key == "threat":
            records.sort(key=lambda r: r.threat_level, reverse=True)
        elif sort_key == "bytes":
            records.sort(key=lambda r: r.bytes_sent + r.bytes_received, reverse=True)
        elif sort_key == "last_seen":
            records.sort(key=lambda r: r.last_seen, reverse=True)

        export_path = getattr(args, "export", None)
        fmt = getattr(args, "format", "TABLE")

        if export_path:
            if export_path == "-":
                content = export_inventory(records, None)
                sys.stdout.write(content or "")
            else:
                export_inventory(records, export_path)
                print(f"Exported {len(records)} records to {export_path}")
            return

        if fmt == "CSV":
            content = export_inventory(records, None)
            sys.stdout.write(content or "")
            return

        # Default: Rich table
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title=f"Device Inventory ({len(records)} devices)")
        table.add_column("IP")
        table.add_column("Hostname")
        table.add_column("MAC")
        table.add_column("Threat")
        table.add_column("Last Seen")
        table.add_column("Bytes")

        for rec in records:
            color = rec.threat_level.color
            table.add_row(
                rec.ip,
                rec.hostname or "—",
                rec.mac or "—",
                f"[{color}]{rec.threat_level.name}[/{color}]",
                rec.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                _fmt_bytes(rec.bytes_sent + rec.bytes_received),
            )
        console.print(table)

    asyncio.run(_load_and_export())


def _fmt_bytes(n: int) -> str:
    return format_bytes(n, precision=0)


def _deep_inspect_subcommand(args: argparse.Namespace, _config: Config) -> None:
    """Handle `netwatchm deep-inspect` subcommand."""
    from .reports.deep_inspect import render_deep_inspect_html, run_deep_inspect

    result = run_deep_inspect(args.target, args.ports, db_path=args.db_path or "")
    render_deep_inspect_html(result, args.output)
    print(f"Deep inspect report written to {args.output}")


def _investigate_subcommand(args: argparse.Namespace, _config: Config) -> None:
    """Handle `netwatchm investigate` subcommand."""
    from .reports.investigate_report import render_investigation_html, run_msf_scan

    target = args.target
    output = args.output or f"/tmp/netwatchm-investigate-{target}.html"
    print(f"Investigating {target}…", flush=True)
    results = run_msf_scan(target, ports=args.ports)
    render_investigation_html(results, output=output)
    tool = results.get("tool_used", "unknown")
    ports_found = results.get("open_ports", [])
    print(f"Scan complete ({tool}): {len(ports_found)} open port(s) found.")
    print(f"Report saved: {output}")


def _analytics_subcommand(args: argparse.Namespace, _config: Config) -> None:
    """Handle `netwatchm analytics` subcommand."""
    import os
    from .reports.analytics_report import render_analytics_html
    from .reports.flow_store import DEFAULT_DB, FlowStore

    db_path = args.db_path or os.environ.get("NETWATCHM_FLOW_DB", DEFAULT_DB)
    with FlowStore(db_path) as store:
        data = store.query_analytics()
    render_analytics_html(data, args.output)
    print(f"Analytics report written to {args.output}")


def _report_subcommand(args: argparse.Namespace, config: Config) -> None:
    """Handle `netwatchm report` subcommand."""
    from .reports.connection_report import capture_flows, render_csv, render_html, render_table

    interface = detect_interface(config.interface)
    network = args.network
    duration = args.duration
    output = args.output
    fmt = args.format

    # Auto-detect format from output extension
    if fmt is None and output:
        if output.endswith(".html") or output.endswith(".htm"):
            fmt = "html"
        elif output.endswith(".csv"):
            fmt = "csv"

    if fmt is None:
        fmt = "table"

    print(
        f"Capturing {network} traffic on {interface} for {duration}s "
        f"(format: {fmt})…",
        flush=True,
    )

    flows = capture_flows(interface=interface, duration=duration, network=network)

    if not flows:
        print("No flows captured. (Try running with sudo for full packet access.)")
        return

    # Persist to flow store (best-effort — never blocks rendering)
    import os
    from .reports.flow_store import DEFAULT_DB, FlowStore
    db_path = os.environ.get("NETWATCHM_FLOW_DB", DEFAULT_DB)
    try:
        with FlowStore(db_path) as store:
            store.insert_flows(flows)
    except Exception as exc:
        logger.warning("Could not persist flows to store: %s", exc)

    if fmt == "html":
        render_html(flows, output=output, network=network, duration=duration)
    elif fmt == "csv":
        render_csv(flows, output=output)
    else:
        render_table(flows)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netwatchm",
        description="NetWatchM — real-time network threat monitor",
    )
    parser.add_argument(
        "--config",
        default=_default_config_path(),
        help="path to netwatchm.yaml",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="override network interface",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="log-only mode (no Rich dashboard)",
    )
    parser.add_argument(
        "--install-service",
        action="store_true",
        help="install and enable system service",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    subparsers = parser.add_subparsers(dest="subcommand")
    inv_parser = subparsers.add_parser("inventory", help="query inventory offline")
    inv_parser.add_argument("--filter", default=None, help="substring filter on IP/hostname/MAC/vendor")
    inv_parser.add_argument("--export", default=None, metavar="FILE", help="write CSV to FILE ('-' for stdout)")
    inv_parser.add_argument(
        "--sort-by",
        default="ip",
        choices=["ip", "hostname", "mac", "threat", "bytes", "last_seen"],
        dest="sort_by",
    )
    inv_parser.add_argument(
        "--format",
        default="TABLE",
        choices=["TABLE", "CSV"],
    )

    rep_parser = subparsers.add_parser("report", help="capture outgoing connections and generate report")
    rep_parser.add_argument(
        "--duration",
        type=int,
        default=30,
        metavar="SECONDS",
        help="capture duration in seconds (default: 30)",
    )
    rep_parser.add_argument(
        "--network",
        default="192.168.1.0/24",
        metavar="CIDR",
        help="source network filter (default: 192.168.1.0/24)",
    )
    rep_parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="output file path; format auto-detected from .html/.csv extension",
    )
    rep_parser.add_argument(
        "--format",
        default=None,
        choices=["table", "csv", "html"],
        help="output format (overrides auto-detection from --output extension)",
    )

    msf_parser = subparsers.add_parser(
        "investigate",
        help="run Metasploit (or nmap) scan on a target IP and generate HTML report",
    )
    msf_parser.add_argument(
        "--target",
        required=True,
        metavar="IP",
        help="IP address to investigate",
    )
    msf_parser.add_argument(
        "--ports",
        default=None,
        help="comma-separated ports to scan (default: common ports)",
    )
    msf_parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="output HTML path (default: /tmp/netwatchm-investigate-<ip>.html)",
    )

    deep_p = subparsers.add_parser("deep-inspect", help="Deep security inspection of a target IP")
    deep_p.add_argument("--target", required=True, metavar="IP", help="IP address to inspect")
    deep_p.add_argument("--ports", default="", help="comma-separated ports to scan (default: common ports)")
    deep_p.add_argument("--output", default="deep-inspect.html", metavar="FILE", help="output HTML path")
    deep_p.add_argument("--db-path", default="", metavar="PATH", help="path to GeoLite2-City.mmdb (overrides default)")

    anal_p = subparsers.add_parser("analytics", help="Render analytics portal from flow store")
    anal_p.add_argument("--output", default="analytics.html", metavar="FILE", help="output HTML path")
    anal_p.add_argument("--db-path", default="", metavar="PATH", help="path to flows.db (overrides default)")

    args = parser.parse_args()
    _setup_logging(args.log_level)

    config = load_config(args.config)
    if args.interface:
        config.interface = args.interface

    if args.install_service:
        if sys.platform == "win32":
            from .service.windows import install_service
        else:
            from .service.linux import install_service
        install_service(args.config)
        return

    if args.subcommand == "inventory":
        _inventory_subcommand(args, config)
        return

    if args.subcommand == "report":
        _report_subcommand(args, config)
        return

    if args.subcommand == "investigate":
        _investigate_subcommand(args, config)
        return

    if args.subcommand == "deep-inspect":
        _deep_inspect_subcommand(args, config)
        return

    if args.subcommand == "analytics":
        _analytics_subcommand(args, config)
        return

    try:
        asyncio.run(run_monitor(config, no_ui=args.no_ui))
    except KeyboardInterrupt:
        print("\nShutting down NetWatchM.")


if __name__ == "__main__":
    main()
