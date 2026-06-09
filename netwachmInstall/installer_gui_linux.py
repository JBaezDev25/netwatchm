#!/usr/bin/env python3
"""
NetWatchM — Linux GUI installer.

A friendly front-end over `reinstall-all.sh`. Pick what to install (NetWatchM core
is always installed; local AI and the nic-asst-ai helper are optional), optionally
drop in an OpenRouter key, and watch the live log.

Run:
    python3 netwachmInstall/installer_gui_linux.py

Build a standalone binary (optional):
    pip install pyinstaller
    pyinstaller --onefile --windowed --name netwatchm-installer \
        --add-data "netwachmInstall/assets:assets" \
        netwachmInstall/installer_gui_linux.py
"""
from __future__ import annotations

import os
import queue
import subprocess
import threading
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext

SCRIPT_DIR = Path(__file__).resolve().parent
BOOTSTRAP = SCRIPT_DIR / "reinstall-all.sh"
ASSETS = SCRIPT_DIR / "assets"

# palette (matches the NetWatchM/diagSystem dashboards)
BG, CARD, LINE, TXT, MUTED, TEAL, OKC = (
    "#0e1320", "#1a1e27", "#26365c", "#e6e9ef", "#8b93a7", "#36d6c3", "#3ecf8e",
)


class Installer(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetWatchM Installer")
        self.configure(bg=BG)
        self.geometry("680x560")
        self.minsize(620, 500)
        self._log_q: queue.Queue[str] = queue.Queue()
        self._proc: subprocess.Popen | None = None
        self._icon = None

        self._set_icon()
        self._build()
        self.after(80, self._drain_log)

    # ---- window icon ----
    def _set_icon(self) -> None:
        png = ASSETS / "netwatchm-icon-256.png"
        if png.exists():
            try:
                self._icon = tk.PhotoImage(file=str(png))
                self.iconphoto(True, self._icon)
            except Exception:
                self._icon = None

    # ---- layout ----
    def _build(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=20, pady=(18, 8))
        if self._icon is not None:
            small = self._icon.subsample(max(1, self._icon.width() // 64))
            self._icon_small = small
            tk.Label(header, image=small, bg=BG).pack(side="left", padx=(0, 14))
        title = tk.Frame(header, bg=BG)
        title.pack(side="left", anchor="w")
        tk.Label(title, text="NetWatchM Installer", bg=BG, fg=TXT,
                 font=("Helvetica", 17, "bold")).pack(anchor="w")
        tk.Label(title, text="Network monitor + local AI + the Claude assistant",
                 bg=BG, fg=MUTED, font=("Helvetica", 10)).pack(anchor="w")

        # options card
        card = tk.Frame(self, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        card.pack(fill="x", padx=20, pady=10)
        tk.Label(card, text="WHAT TO INSTALL", bg=CARD, fg=MUTED,
                 font=("Helvetica", 9, "bold")).pack(anchor="w", padx=14, pady=(12, 6))

        tk.Label(card, text="✓  NetWatchM core  (monitor + web dashboard, port 8765)",
                 bg=CARD, fg=OKC, font=("Helvetica", 11)).pack(anchor="w", padx=16, pady=2)

        self.var_ai = tk.BooleanVar(value=True)
        self.var_nic = tk.BooleanVar(value=True)
        self._check(card, self.var_ai,
                    "Local AI  —  Ollama + models (mistral, nomic-embed-text, ~5 GB)")
        self._check(card, self.var_nic,
                    "nic-asst-ai  —  Claude/OpenRouter network assistant")

        keyrow = tk.Frame(card, bg=CARD)
        keyrow.pack(fill="x", padx=16, pady=(8, 14))
        tk.Label(keyrow, text="OpenRouter key (optional):", bg=CARD, fg=MUTED,
                 font=("Helvetica", 10)).pack(side="left")
        self.var_key = tk.StringVar(value=os.environ.get("OPENROUTER_API_KEY", ""))
        tk.Entry(keyrow, textvariable=self.var_key, show="•", width=34,
                 bg=BG, fg=TXT, insertbackground=TXT,
                 relief="flat").pack(side="left", padx=8, ipady=3)

        # action row
        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=20, pady=(0, 6))
        self.btn = tk.Button(actions, text="Install", command=self._start,
                             bg=TEAL, fg="#06231f", activebackground="#2bb9a8",
                             font=("Helvetica", 12, "bold"), relief="flat",
                             padx=22, pady=8, cursor="hand2")
        self.btn.pack(side="left")
        self.status = tk.Label(actions, text="ready", bg=BG, fg=MUTED,
                               font=("Helvetica", 10))
        self.status.pack(side="left", padx=14)

        # log
        self.log = scrolledtext.ScrolledText(
            self, bg="#0a0d14", fg="#cdd3df", insertbackground=TXT,
            font=("monospace", 9), relief="flat", height=14, wrap="word")
        self.log.pack(fill="both", expand=True, padx=20, pady=(8, 18))
        self.log.configure(state="disabled")

    def _check(self, parent, var, text) -> None:
        cb = tk.Checkbutton(parent, text=text, variable=var, bg=CARD, fg=TXT,
                            selectcolor=BG, activebackground=CARD, activeforeground=TXT,
                            font=("Helvetica", 11), anchor="w", padx=4)
        cb.pack(anchor="w", padx=12, pady=2)

    # ---- run ----
    def _start(self) -> None:
        if self._proc is not None:
            return
        if not BOOTSTRAP.exists():
            self._write(f"error: {BOOTSTRAP} not found\n")
            return
        cmd = ["bash", str(BOOTSTRAP), "--yes"]
        if not self.var_ai.get():
            cmd.append("--no-ai")
        if not self.var_nic.get():
            cmd.append("--no-nic")
        env = dict(os.environ)
        if self.var_key.get().strip():
            env["OPENROUTER_API_KEY"] = self.var_key.get().strip()

        self.btn.configure(state="disabled", text="Installing…")
        self.status.configure(text="running…", fg=TEAL)
        self._write(f"$ {' '.join(cmd)}\n\n")
        threading.Thread(target=self._run, args=(cmd, env), daemon=True).start()

    def _run(self, cmd, env) -> None:
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env)
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                self._log_q.put(line)
            rc = self._proc.wait()
        except Exception as exc:  # noqa: BLE001
            self._log_q.put(f"\n[installer error] {exc}\n")
            rc = 1
        self._proc = None
        self._log_q.put(f"\n__DONE__{rc}\n")

    def _drain_log(self) -> None:
        try:
            while True:
                line = self._log_q.get_nowait()
                if line.startswith("\n__DONE__"):
                    rc = line.strip().removeprefix("__DONE__")
                    done_ok = rc == "0"
                    self.btn.configure(state="normal",
                                       text="Done ✓" if done_ok else "Retry")
                    self.status.configure(
                        text="finished" if done_ok else f"failed (exit {rc})",
                        fg=OKC if done_ok else "#f0524d")
                else:
                    self._write(line)
        except queue.Empty:
            pass
        self.after(80, self._drain_log)

    def _write(self, text) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")


if __name__ == "__main__":
    Installer().mainloop()
