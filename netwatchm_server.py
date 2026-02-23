#!/usr/bin/env python3
"""NetWatchM web server — serves dashboard and triggers connection reports via API."""
from __future__ import annotations

import json
import mimetypes
import os
import ssl
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SERVE_DIR = Path(os.environ.get("NETWATCHM_SERVE_DIR", "/var/lib/netwatchm"))
PORT = int(os.environ.get("NETWATCHM_PORT", "8765"))
NETWATCHM_CMD = os.environ.get("NETWATCHM_CMD", "netwatchm")
NETWATCHM_CONFIG = os.environ.get("NETWATCHM_CONFIG", "/etc/netwatchm/netwatchm.yaml")
DEFAULT_NETWORK = os.environ.get("NETWATCHM_NETWORK", "192.168.1.0/24")

_lock = threading.Lock()
_state: dict = {
    "status": "idle",       # idle | running | ready | error
    "generated_at": None,
    "duration": None,
    "network": None,
    "error": None,
}


def _run_report(duration: int, network: str) -> None:
    """Run netwatchm report in background thread, write HTML to SERVE_DIR."""
    html_path = SERVE_DIR / "connection-report.html"
    try:
        result = subprocess.run(
            [
                NETWATCHM_CMD,
                "--config", NETWATCHM_CONFIG,
                "report",
                "--duration", str(duration),
                "--network", network,
                "--output", str(html_path),
            ],
            capture_output=True,
            text=True,
            timeout=duration + 60,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "netwatchm report failed")
        with _lock:
            _state.update({
                "status": "ready",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            })
    except Exception as exc:
        with _lock:
            _state.update({
                "status": "error",
                "generated_at": None,
                "error": str(exc),
            })


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        pass

    def _send_json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists():
            self.send_error(404, "Not Found")
            return
        mime, _ = mimetypes.guess_type(str(path))
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/report/status":
            with _lock:
                self._send_json(dict(_state))
            return

        # Static file serving — prevent path traversal
        if path in ("/", "/index.html"):
            self._send_file(SERVE_DIR / "report.html")
            return

        rel = path.lstrip("/")
        if ".." in rel:
            self.send_error(403, "Forbidden")
            return
        self._send_file(SERVE_DIR / rel)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/report":
            qs = parse_qs(parsed.query)
            duration = int(qs.get("duration", ["30"])[0])
            network = qs.get("network", [DEFAULT_NETWORK])[0]
            duration = max(5, min(300, duration))

            with _lock:
                if _state["status"] == "running":
                    self._send_json({"error": "Report already running"}, 409)
                    return
                _state.update({
                    "status": "running",
                    "duration": duration,
                    "network": network,
                    "error": None,
                    "generated_at": None,
                })

            thread = threading.Thread(
                target=_run_report, args=(duration, network), daemon=True
            )
            thread.start()
            self._send_json({"status": "running", "duration": duration, "network": network})
            return

        self.send_error(404, "Not Found")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()


CERT_DIR = Path(os.environ.get("NETWATCHM_CERT_DIR", "/var/lib/netwatchm"))
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE  = CERT_DIR / "server.key"


def _ensure_cert() -> None:
    """Generate a self-signed TLS certificate if one doesn't already exist."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    print("Generating self-signed TLS certificate…", flush=True)
    subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", str(KEY_FILE),
            "-out", str(CERT_FILE),
            "-days", "3650",
            "-nodes",
            "-subj", "/CN=localhost/O=NetWatchM",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(KEY_FILE, 0o600)
    print(f"Certificate written to {CERT_FILE}", flush=True)


if __name__ == "__main__":
    SERVE_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"NetWatchM web server listening on https://0.0.0.0:{PORT}", flush=True)
    print("Note: browser will show a self-signed cert warning — click 'Advanced > Proceed'.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
