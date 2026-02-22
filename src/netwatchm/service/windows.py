"""Windows Service for NetWatchM via pywin32."""
from __future__ import annotations

import asyncio
import sys


def install_service() -> None:
    """Install NetWatchM as a Windows Service."""
    if sys.platform != "win32":
        raise RuntimeError("Windows service only supported on Windows")
    try:
        import win32serviceutil  # type: ignore[import]
        win32serviceutil.HandleCommandLine(NetWatchMService)
    except ImportError:
        print("pywin32 not installed. Run: pip install pywin32", file=sys.stderr)
        sys.exit(1)


try:
    import win32service  # type: ignore[import]
    import win32serviceutil  # type: ignore[import]
    import win32event  # type: ignore[import]

    class NetWatchMService(win32serviceutil.ServiceFramework):
        _svc_name_ = "netwatchm"
        _svc_display_name_ = "NetWatchM Network Monitor"
        _svc_description_ = "Real-time network threat detection and alerting"

        def __init__(self, args: tuple) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._loop: asyncio.AbstractEventLoop | None = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._loop:
                self._loop.call_soon_threadsafe(self._loop.stop)

        def SvcDoRun(self) -> None:
            import os
            # Import here to avoid top-level circular imports
            from netwatchm.__main__ import run_monitor
            from netwatchm.config import load_config

            config_path = os.environ.get(
                "NETWATCHM_CONFIG",
                r"C:\ProgramData\netwatchm\netwatchm.yaml",
            )
            config = load_config(config_path)
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(run_monitor(config, no_ui=True))
            finally:
                self._loop.close()

except ImportError:
    # pywin32 not available on this platform
    pass
