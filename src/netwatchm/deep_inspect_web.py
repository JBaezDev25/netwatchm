"""Web-based Deep Inspect with tshark/nmap integration."""
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# Config
DEFAULT_DB_PATH = Path("/var/lib/netwatchm/flows.db")
CAPTURES_DIR = Path("/var/lib/netwatchm/deep-inspect-captures")
DEEP_INSPECT_DIR = Path("/var/lib/netwatchm/reports/deep-inspect")
ANALYSIS_DIR = DEEP_INSPECT_DIR / "analysis"

# Ensure directories exist
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

# API
app = FastAPI(title="Deep Inspect Web API")


# Models
class StartCaptureRequest(BaseModel):
    target_ip: str
    duration: int = 60
    device_ip: Optional[str] = None


class ScanRequest(BaseModel):
    target_ip: str
    scan_type: str = "full"  # full, service, ports
    port_range: str = "1-1024"


class AnalysisResult(BaseModel):
    target_ip: str
    captured_at: str
    device_ip: Optional[str]
    duration: int
    packet_count: int
    byte_count: int
    bandwidth_mbps: float
    hop_count: Optional[int]
    latency_ms: Optional[float]
    devices: List[Dict]
    destinations: List[Dict]
    protocols: Dict
    top_apps: List[Dict]
    browser_activity: List[Dict]
    adult_domains: List[Dict]
    port_summary: Dict[str, int]
    findings: List[str]
    alerts: List[str]


class ConnectionStatus(BaseModel):
    ip: str
    connected: bool
    latency_ms: Optional[float]
    last_seen: Optional[str]
    avg_latency_ms: Optional[float]


# State
active_captures: Dict[str, Dict] = {}
scans_in_progress: Dict[str, Dict] = {}


def run_tshark_save(filepath: Path, target_ip: str, duration: int, device_ip: Optional[str] = None) -> Dict:
    """Run tshark and save pcap to file."""
    interface = "enp6s0"  # TODO: make configurable

    cmd = [
        "tshark",
        "-i", interface,
        "-f", f"host {target_ip}",
        "-a", f"duration:{duration}",
        "-w", str(filepath)
    ]

    if device_ip:
        cmd.extend(["-f", f"host {device_ip} and host {target_ip}"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 10
        )

        packet_count = 0
        byte_count = 0

        if filepath.exists():
            # Get packet/byte counts from file
            stats_cmd = ["tshark", "-r", str(filepath), "-q", "-z", "io,phs"]
            stats = subprocess.run(stats_cmd, capture_output=True, text=True)
            for line in stats.stdout.split('\n'):
                if line.strip():
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 4:
                        packet_count = int(parts[3])

        bandwidth = (byte_count * 8) / (duration * 1_000_000) if duration > 0 else 0

        return {
            "success": True,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "bandwidth_mbps": bandwidth,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Capture timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_traceroute(target_ip: str) -> Tuple[Optional[int], Optional[float]]:
    """Run traceroute and get hop count and latency."""
    try:
        result = subprocess.run(
            ["traceroute", "-q", "1", "-w", "1", target_ip],
            capture_output=True,
            text=True,
            timeout=30
        )

        lines = result.stdout.strip().split('\n')
        hop_count = len(lines)

        # Extract latency from first hop
        latency = None
        if hop_count > 0:
            first_hop = lines[0].strip()
            match = re.search(r'(\d+\.\d+)\s*ms', first_hop)
            if match:
                latency = float(match.group(1))

        return hop_count, latency
    except Exception:
        return None, None


def run_nmap(target_ip: str, scan_type: str = "full", port_range: str = "1-1024") -> Dict:
    """Run nmap scan."""
    cmd = ["nmap", "-sV", "--open", "-T4", "-p", port_range, target_ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        return {
            "success": True,
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def analyze_pcap(filepath: Path, target_ip: str, device_ip: Optional[str] = None) -> Dict:
    """Analyze saved pcap file."""
    try:
        # Get packet count
        count_cmd = ["tshark", "-r", str(filepath), "-q", "-z", "io,phs"]
        count_result = subprocess.run(count_cmd, capture_output=True, text=True)

        byte_count = 0
        packet_count = 0
        protocols = {}
        top_apps = []
        browser_activity = []
        destinations = {}
        port_summary = {}

        for line in count_result.stdout.split('\n'):
            if line.strip():
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    packet_count = int(parts[3])

        # Get byte count
        bytes_cmd = ["tshark", "-r", str(filepath), "-q", "-z", "io,ns"]
        bytes_result = subprocess.run(bytes_cmd, capture_output=True, text=True)
        byte_count = int(re.search(r'(\d+)', bytes_result.stdout).group(1))

        # Protocol breakdown
        proto_cmd = ["tshark", "-r", str(filepath), "-q", "-z", "conv,ip"]
        proto_result = subprocess.run(proto_cmd, capture_output=True, text=True)

        # Port summary
        ports_cmd = ["tshark", "-r", str(filepath), "-q", "-z", "conv,tcp"]
        ports_result = subprocess.run(ports_cmd, capture_output=True, text=True)

        return {
            "success": True,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "protocols": protocols,
            "top_apps": top_apps,
            "browser_activity": browser_activity,
            "destinations": destinations,
            "port_summary": port_summary,
            "findings": ["Traffic captured successfully", "Pcap file ready for analysis"],
            "alerts": []
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_connection_status(ip: str) -> ConnectionStatus:
    """Check if device has active connection."""
    try:
        # Try ping first
        ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
        ping_result = subprocess.run(ping_cmd, capture_output=True, text=True)

        latency = None
        if ping_result.returncode == 0:
            match = re.search(r'(\d+\.\d+)\s*ms', ping_result.stdout)
            if match:
                latency = float(match.group(1))

        # Try traceroute to check reachability
        hop_count, hop_latency = run_traceroute(ip)

        return ConnectionStatus(
            ip=ip,
            connected=(ping_result.returncode == 0),
            latency_ms=latency,
            last_seen=datetime.now().isoformat(),
            avg_latency_ms=hop_latency
        )
    except Exception:
        return ConnectionStatus(
            ip=ip,
            connected=False,
            latency_ms=None,
            last_seen=None,
            avg_latency_ms=None
        )


# Endpoints
@app.post("/api/deep-inspect/start")
async def start_deep_inspect(req: StartCaptureRequest):
    """Start deep inspect capture."""
    capture_id = f"{req.target_ip}_{int(time.time())}"

    filepath = CAPTURES_DIR / f"{capture_id}.pcap"

    # Cancel any existing capture for this target
    if capture_id in active_captures:
        return {"error": "Capture already in progress for this target"}

    capture_info = {
        "id": capture_id,
        "target_ip": req.target_ip,
        "device_ip": req.device_ip,
        "duration": req.duration,
        "filepath": filepath,
        "status": "running",
        "started_at": datetime.now().isoformat()
    }

    active_captures[capture_id] = capture_info

    # Run in background thread
    def capture_thread():
        result = run_tshark_save(
            filepath=filepath,
            target_ip=req.target_ip,
            duration=req.duration,
            device_ip=req.device_ip
        )
        capture_info["status"] = "completed"
        capture_info["result"] = result

    threading.Thread(target=capture_thread, daemon=True).start()

    return {"capture_id": capture_id, "status": "started"}


@app.get("/api/deep-inspect/status/{capture_id}")
async def get_capture_status(capture_id: str):
    """Get capture status."""
    if capture_id not in active_captures:
        return {"error": "Capture not found"}

    return active_captures[capture_id]


@app.post("/api/deep-inspect/stop")
async def stop_deep_inspect(capture_id: str):
    """Stop capture (not currently supported in tshark - manual stop needed)."""
    if capture_id not in active_captures:
        return {"error": "Capture not found"}

    return {"message": "Stop not supported - use duration limit instead"}


@app.post("/api/nmap/scan")
async def start_nmap_scan(req: ScanRequest):
    """Start nmap scan."""
    scan_id = f"{req.target_ip}_{int(time.time())}"

    scan_info = {
        "id": scan_id,
        "target_ip": req.target_ip,
        "scan_type": req.scan_type,
        "port_range": req.port_range,
        "status": "running",
        "started_at": datetime.now().isoformat()
    }

    scans_in_progress[scan_id] = scan_info

    # Run in background thread
    def scan_thread():
        result = run_nmap(req.target_ip, req.scan_type, req.port_range)
        scan_info["status"] = "completed"
        scan_info["result"] = result

    threading.Thread(target=scan_thread, daemon=True).start()

    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/nmap/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get nmap scan status."""
    if scan_id not in scans_in_progress:
        return {"error": "Scan not found"}

    return scans_in_progress[scan_id]


@app.get("/api/deep-inspect/history")
async def get_capture_history():
    """Get list of all captures."""
    captures = []

    for pcap_file in CAPTURES_DIR.glob("*.pcap"):
        # Extract metadata from filename
        parts = pcap_file.stem.split('_')
        if len(parts) >= 2:
            target_ip = parts[0]
            timestamp = parts[1]
            captures.append({
                "id": pcap_file.stem,
                "target_ip": target_ip,
                "timestamp": timestamp,
                "filepath": str(pcap_file),
                "exists": pcap_file.exists()
            })

    # Sort by timestamp desc
    captures.sort(key=lambda x: x["timestamp"], reverse=True)

    return captures


@app.post("/api/deep-inspect/analyze/{capture_id}")
async def analyze_capture(capture_id: str):
    """Analyze a saved capture."""
    capture = next((c for c in CAPTURES_DIR.glob("*.pcap") if c.stem == capture_id), None)

    if not capture:
        raise HTTPException(404, "Capture not found")

    # Get metadata from filename
    parts = capture.stem.split('_')
    target_ip = parts[0] if len(parts) > 0 else "unknown"
    timestamp = parts[1] if len(parts) > 1 else "unknown"
    device_ip = parts[2] if len(parts) > 2 else None

    # Run analysis
    result = analyze_pcap(capture, target_ip, device_ip)

    # Get hop count and latency
    hop_count, latency = run_traceroute(target_ip)

    # Determine findings and alerts
    findings = []
    alerts = []

    if result.get("packet_count", 0) == 0:
        findings.append("No packets captured - target may be unreachable")
        alerts.append("WARNING: No traffic captured")

    if hop_count is not None and hop_count > 10:
        findings.append(f"High hop count detected: {hop_count} hops")
        alerts.append(f"WARNING: High latency path ({hop_count} hops)")

    if latency is not None and latency > 200:
        findings.append(f"High latency detected: {latency:.2f}ms")
        alerts.append(f"WARNING: High latency to destination")

    if not result.get("alerts"):
        alerts.append("No critical issues detected")

    return AnalysisResult(
        target_ip=target_ip,
        captured_at=timestamp,
        device_ip=device_ip,
        duration=60,  # Default
        packet_count=result.get("packet_count", 0),
        byte_count=result.get("byte_count", 0),
        bandwidth_mbps=(result.get("byte_count", 0) * 8) / (60 * 1_000_000),
        hop_count=hop_count,
        latency_ms=latency,
        devices=[],
        destinations=[],
        protocols=result.get("protocols", {}),
        top_apps=result.get("top_apps", []),
        browser_activity=result.get("browser_activity", []),
        adult_domains=[],
        port_summary=result.get("port_summary", {}),
        findings=findings,
        alerts=alerts
    )


@app.get("/api/connections/status")
async def get_all_connections():
    """Get connection status for all tracked devices."""
    try:
        # Read inventory to get all device IPs
        inventory_path = Path("/var/lib/netwatchm/inventory.json")
        if inventory_path.exists():
            with open(inventory_path) as f:
                inventory = json.load(f)

            statuses = []
            for ip in inventory.get("devices", []):
                status = check_connection_status(ip)
                statuses.append(status.model_dump())
            return statuses

        return []
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/connections/status/{ip}")
async def get_connection_status(ip: str):
    """Get connection status for specific IP."""
    status = check_connection_status(ip)
    return status.model_dump()


# Cleanup old captures
def cleanup_old_captures():
    """Remove captures older than 30 days."""
    cutoff = time.time() - (30 * 24 * 60 * 60)
    for pcap_file in CAPTURES_DIR.glob("*.pcap"):
        if pcap_file.stat().st_mtime < cutoff:
            pcap_file.unlink()

# Run cleanup on startup
cleanup_old_captures()