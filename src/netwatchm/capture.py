"""tshark subprocess capture and NDJSON packet parser."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator

from .models import Packet

logger = logging.getLogger(__name__)

TSHARK_FIELDS = [
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "frame.len",
    "-e", "ip.proto",
    "-e", "_ws.col.Protocol",
]


def _build_tshark_cmd(interface: str) -> list[str]:
    return [
        "tshark",
        "-i", interface,
        "-T", "ek",
        "-l",
        "-q",
        *TSHARK_FIELDS,
    ]


def _first(val: list | str | None) -> str | None:
    """Return first element if list, else val as-is."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _parse_line(line: str) -> Packet | None:
    """Parse a single NDJSON line from tshark -T ek output into a Packet."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # tshark -T ek emits two types of lines: index lines and source lines
    # Source lines contain the 'layers' key
    layers = obj.get("layers")
    if not layers:
        return None

    def _int(key: str) -> int | None:
        v = _first(layers.get(key))
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    def _float(key: str) -> float | None:
        v = _first(layers.get(key))
        if v is None:
            return None
        try:
            return float(v)
        except (ValueError, TypeError):
            return None

    def _str(key: str) -> str | None:
        v = _first(layers.get(key))
        return str(v) if v is not None else None

    timestamp = _float("frame_time_epoch") or 0.0

    # TCP ports take priority over UDP
    src_port = _int("tcp_srcport") or _int("udp_srcport")
    dst_port = _int("tcp_dstport") or _int("udp_dstport")

    return Packet(
        timestamp=timestamp,
        src_ip=_str("ip_src"),
        dst_ip=_str("ip_dst"),
        src_port=src_port,
        dst_port=dst_port,
        length=_int("frame_len") or 0,
        protocol=_str("_ws_col_Protocol"),
        ip_proto=_int("ip_proto"),
    )


async def capture_packets(
    interface: str,
    packet_queue: asyncio.Queue[Packet],
    stop_event: asyncio.Event,
) -> None:
    """Run tshark and stream packets into packet_queue until stop_event is set."""
    cmd = _build_tshark_cmd(interface)
    logger.info("Starting tshark: %s", " ".join(cmd))

    while not stop_event.is_set():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            logger.error("tshark not found. Please install tshark/wireshark-cli.")
            await asyncio.sleep(5)
            continue
        except OSError as exc:
            logger.error("Failed to start tshark: %s", exc)
            await asyncio.sleep(5)
            continue

        try:
            assert proc.stdout is not None
            async for raw_line in proc.stdout:
                if stop_event.is_set():
                    break
                line = raw_line.decode("utf-8", errors="replace")
                packet = _parse_line(line)
                if packet is not None:
                    await packet_queue.put(packet)
        except Exception as exc:  # noqa: BLE001
            logger.warning("tshark stream error: %s", exc)
        finally:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()

        if not stop_event.is_set():
            logger.warning("tshark exited unexpectedly; restarting in 2s")
            await asyncio.sleep(2)
