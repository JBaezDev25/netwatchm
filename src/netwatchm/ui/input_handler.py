"""Background thread for raw stdin keystroke reading."""
from __future__ import annotations

import queue
import sys
import threading


class InputHandler:
    """Read raw keystrokes in a daemon thread and put them into a queue.

    Linux: uses termios/tty to set raw mode.
    Windows: uses msvcrt.getwch().
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="input-handler",
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def get_key(self, block: bool = False) -> str | None:
        """Return next key from queue, or None if empty."""
        try:
            return self._queue.get(block=block, timeout=0.1 if block else None)
        except queue.Empty:
            return None

    def _run(self) -> None:
        if sys.platform == "win32":
            self._run_windows()
        else:
            self._run_linux()

    def _run_linux(self) -> None:
        import termios
        import tty

        if not sys.stdin.isatty():
            return

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not self._stop.is_set():
                ch = sys.stdin.read(1)
                if ch:
                    self._queue.put(ch)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:  # noqa: BLE001
                pass

    def _run_windows(self) -> None:
        import msvcrt  # type: ignore[import]

        while not self._stop.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                self._queue.put(ch)
            else:
                self._stop.wait(timeout=0.05)
