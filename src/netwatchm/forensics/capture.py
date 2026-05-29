"""Short-burst pcap capture for incident evidence.

Spawns a bounded ``tshark`` process filtered to the offending IP and writes a
pcap into the forensics dir. Bounded by both a duration (-a duration:N) and a
packet cap (-c) so a flood can't fill the disk. Returns (path, byte_count) or
("", 0) on failure — capture is best-effort and never blocks the alert path.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

log = logging.getLogger("netwatchm.forensics.capture")

MAX_PACKETS = 5000


def _safe_ip(ip: str) -> str:
    return "".join(c for c in ip if c.isalnum() or c in ".:").replace(":", "-")


def capture_ip(ip: str, interface: str, seconds: int, out_dir: str,
               max_packets: int = MAX_PACKETS) -> tuple[str, int]:
    """Capture traffic to/from ``ip`` for ``seconds``. Synchronous; run in executor."""
    if not ip or not interface:
        return ("", 0)
    if shutil.which("tshark") is None:
        log.warning("tshark not found — skipping forensic capture for %s", ip)
        return ("", 0)

    out = Path(out_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("cannot create capture dir %s: %s", out_dir, exc)
        return ("", 0)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = out / f"{_safe_ip(ip)}-{ts}.pcap"

    cmd = [
        "tshark", "-i", interface,
        "-f", f"host {ip}",
        "-a", f"duration:{int(seconds)}",
        "-c", str(int(max_packets)),
        "-w", str(path),
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, timeout=seconds + 15, check=False
        )
    except subprocess.TimeoutExpired:
        log.warning("forensic capture timed out for %s", ip)
    except Exception as exc:  # noqa: BLE001
        log.warning("forensic capture failed for %s: %s", ip, exc)
        return ("", 0)

    if path.exists() and path.stat().st_size > 0:
        return (str(path), path.stat().st_size)
    # tshark may create an empty file when no packets match; clean it up.
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
    return ("", 0)
