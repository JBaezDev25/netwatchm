"""CLI entry point for NetWatchM."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

from rich.console import Console

from .alerts.email_alert import EmailAlert
from .alerts.logfile import LogFileAlert
from .alerts.sound import SoundAlert
from .alerts.terminal import TerminalAlert
from .capture import capture_packets
from .config import Config, load_config
from .detector import (
    BruteForceDetector,
    ExfiltrationDetector,
    NewIPDetector,
    PortScanDetector,
)
from .interface import detect_interface
from .inventory.exporter import export_inventory
from .inventory.resolver import DNSResolver
from .inventory.store import DeviceStore
from .models import Alert, Packet, ThreatLevel
from .scorer import ThreatScorer

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


async def run_monitor(config: Config, no_ui: bool = False) -> None:
    """Main monitoring coroutine."""
    interface = detect_interface(config.interface)
    logger.info("Monitoring interface: %s", interface)

    console = Console()
    stop_event = asyncio.Event()
    packet_queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=10_000)
    alert_queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=1_000)

    # --- Inventory ---
    store = DeviceStore()
    inventory_path = None  # use default platform path
    await store.load(inventory_path)

    # --- Detectors ---
    detectors = [
        PortScanDetector(config.thresholds.port_scan),
        BruteForceDetector(config.thresholds.brute_force),
        ExfiltrationDetector(config.thresholds.exfiltration),
        NewIPDetector(config.thresholds.new_ip, config.baseline_period),
    ]

    # --- Scorer ---
    scorer = ThreatScorer()

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
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} TB"


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

    try:
        asyncio.run(run_monitor(config, no_ui=args.no_ui))
    except KeyboardInterrupt:
        print("\nShutting down NetWatchM.")


if __name__ == "__main__":
    main()
