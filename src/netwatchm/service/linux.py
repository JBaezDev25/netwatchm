"""Write and enable a systemd service unit for NetWatchM."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

UNIT_PATH = Path("/etc/systemd/system/netwatchm.service")

UNIT_TEMPLATE = """\
[Unit]
Description=NetWatchM Network Monitor
After=network.target
OnFailure=netwatchm-notify@%n.service

[Service]
Type=simple
ExecStart={exec_start}
Restart=always
RestartSec=5
StartLimitIntervalSec=120
StartLimitBurst=5
Environment=NETWATCHM_EMAIL_PASSWORD={email_password}

[Install]
WantedBy=multi-user.target
"""


def install_service(config_path: str = "/etc/netwatchm/netwatchm.yaml") -> None:
    """Write /etc/systemd/system/netwatchm.service and enable it."""
    if sys.platform == "win32":
        raise RuntimeError("Use service/windows.py on Windows")

    exec_path = shutil.which("netwatchm") or sys.executable + " -m netwatchm"
    email_password = os.environ.get("NETWATCHM_EMAIL_PASSWORD", "")

    unit_content = UNIT_TEMPLATE.format(
        exec_start=f"{exec_path} --config {config_path} --no-ui",
        email_password=email_password,
    )

    try:
        UNIT_PATH.write_text(unit_content)
        print(f"Wrote {UNIT_PATH}")
    except PermissionError:
        print(
            f"Permission denied writing {UNIT_PATH}. Run as root.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "netwatchm"], check=True)
        subprocess.run(["systemctl", "start", "netwatchm"], check=True)
        print("NetWatchM service installed, enabled, and started.")
        print("Check status: systemctl status netwatchm")
    except subprocess.CalledProcessError as exc:
        print(f"systemctl error: {exc}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("systemctl not found — is this a systemd system?", file=sys.stderr)
        sys.exit(1)
