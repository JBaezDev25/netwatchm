"""
NetWatchM Windows GUI Installer
Double-click to install — auto-elevates to Administrator.

Build (from repo root on Windows):
    pip install pyinstaller
    pyinstaller netwachmInstall/installer.spec --clean --noconfirm

Output: dist/netwatchm-setup.exe
"""

import sys
import os
import subprocess
import threading
import shutil
import ctypes
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

APP_VERSION  = "0.2.22"
GITHUB_ZIP   = "https://github.com/al4nbr3/netwatchm/archive/refs/heads/master.zip"
PROGRAMDATA  = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
DATA_DIR     = PROGRAMDATA / "netwatchm"
VERSION_FILE = DATA_DIR / "version.txt"
CONFIG_FILE  = DATA_DIR / "netwatchm.yaml"

# ── Auto-elevate to Administrator ─────────────────────────────────────────────
def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not _is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
    )
    sys.exit(0)

# ── Colours ───────────────────────────────────────────────────────────────────
BG       = "#1c1c1c"
BG_LOG   = "#0c0c0c"
FG_WHITE = "#ffffff"
FG_GREEN = "#4ec94e"
FG_BLUE  = "#58a6ff"
FG_YELLOW = "#e3b341"
FG_RED   = "#f85149"
FG_SILVER = "#aaaaaa"


class InstallerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"NetWatchM Installer  v{APP_VERSION}")
        self.geometry("520x470")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._build_ui()
        self.after(100, self._check_existing)

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        tk.Label(self, text=f"NetWatchM  {APP_VERSION}",
                 font=("Segoe UI", 14, "bold"), bg=BG, fg=FG_WHITE
                 ).place(x=20, y=14)
        tk.Label(self, text="Network Monitoring and Threat Detection  —  by al4nbr3",
                 font=("Segoe UI", 9), bg=BG, fg=FG_SILVER
                 ).place(x=22, y=46)

        sep = tk.Frame(self, bg="#444444", height=1)
        sep.place(x=20, y=70, width=460)

        self._step_var = tk.StringVar(value="Initializing...")
        self._step_lbl = tk.Label(self, textvariable=self._step_var,
                                  font=("Segoe UI", 9, "bold"), bg=BG, fg=FG_BLUE)
        self._step_lbl.place(x=20, y=80)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("g.Horizontal.TProgressbar",
                        troughcolor="#2a2a2a", background=FG_GREEN, bordercolor=BG)
        self._bar = ttk.Progressbar(self, style="g.Horizontal.TProgressbar",
                                    length=460, mode="determinate")
        self._bar.place(x=20, y=104)

        self._log = tk.Text(self, width=62, height=15,
                            font=("Consolas", 8), bg=BG_LOG, fg=FG_GREEN,
                            relief="flat", state="disabled", wrap="word")
        self._log.place(x=20, y=132)
        self._log.tag_config("ok",   foreground=FG_GREEN)
        self._log.tag_config("warn", foreground=FG_YELLOW)
        self._log.tag_config("err",  foreground=FG_RED)
        self._log.tag_config("step", foreground=FG_BLUE)

        self._close_btn = tk.Button(self, text="Please wait...", state="disabled",
                                    bg="#0078d4", fg=FG_WHITE, relief="flat",
                                    font=("Segoe UI", 9), command=self.destroy)
        self._close_btn.place(x=390, y=415, width=90, height=28)

    # ── UI helpers ────────────────────────────────────────────────────────────
    def _log_msg(self, text, tag="ok"):
        self._log.configure(state="normal")
        self._log.insert("end", text + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _set_step(self, text, pct):
        self._step_var.set(text)
        self._step_lbl.configure(fg=FG_BLUE)
        self._bar["value"] = pct
        self._log_msg(f"\n--- {text} ---", "step")

    def _finish(self, ok=True):
        if ok:
            self._step_var.set("Installation complete!")
            self._step_lbl.configure(fg=FG_GREEN)
            self._close_btn.configure(text="Close", state="normal")
            messagebox.showinfo(
                "Installation Complete",
                f"NetWatchM {APP_VERSION} installed successfully!\n\n"
                f"Dashboard:  https://localhost:8765/events.html\n"
                f"Config:     {CONFIG_FILE}\n\n"
                "A shortcut has been placed on your Desktop."
            )
        else:
            self._step_var.set("Installation failed")
            self._step_lbl.configure(fg=FG_RED)
            self._close_btn.configure(text="Close", state="normal")

    # ── Version detection ─────────────────────────────────────────────────────
    def _check_existing(self):
        if VERSION_FILE.exists():
            installed = VERSION_FILE.read_text().strip()
            label = ("already installed" if installed == APP_VERSION
                     else f"v{installed} is installed")
            ans = messagebox.askyesnocancel(
                "NetWatchM Already Installed",
                f"NetWatchM {label}.\n\n"
                f"  [Yes]    Upgrade / Reinstall to {APP_VERSION}\n"
                f"  [No]     Uninstall\n"
                f"  [Cancel] Exit"
            )
            if ans is None:
                self.destroy()
                return
            if ans is False:
                threading.Thread(target=self._run_uninstall, daemon=True).start()
                return
        threading.Thread(target=self._run_install, daemon=True).start()

    # ── subprocess helper ─────────────────────────────────────────────────────
    def _run_cmd(self, *args, cwd=None):
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=cwd
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self.after(0, self._log_msg, f"  {line}")
        proc.wait()
        return proc.returncode

    def _winget(self, pkg_id, display_name):
        self.after(0, self._log_msg, f"Installing {display_name} via winget...", "warn")
        rc = self._run_cmd("winget", "install", "--id", pkg_id, "--silent",
                           "--accept-package-agreements", "--accept-source-agreements")
        if rc != 0:
            raise RuntimeError(f"winget failed to install {display_name}. "
                               "Install it manually and re-run.")

    # ── Install ───────────────────────────────────────────────────────────────
    def _run_install(self):
        try:
            self._do_install()
            self.after(0, self._finish, True)
        except Exception as exc:
            self.after(0, self._log_msg, f"[ERR] {exc}", "err")
            self.after(0, messagebox.showerror, "Installation Error", str(exc))
            self.after(0, self._finish, False)

    def _do_install(self):
        import urllib.request, zipfile, tempfile

        # ── Download source ───────────────────────────────────────────────────
        self.after(0, self._set_step, "Downloading NetWatchM source...", 5)
        tmp_dir  = Path(tempfile.mkdtemp(prefix="netwatchm_install_"))
        zip_path = tmp_dir / "netwatchm.zip"

        self.after(0, self._log_msg, f"Downloading {GITHUB_ZIP} ...")
        try:
            urllib.request.urlretrieve(GITHUB_ZIP, zip_path)
        except Exception as e:
            raise RuntimeError(f"Download failed: {e}\nCheck your internet connection.")
        self.after(0, self._log_msg, "Download complete")

        self.after(0, self._log_msg, "Extracting...")
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp_dir)
        # GitHub zips extract to <repo>-<branch>/ subfolder
        extracted = next(p for p in tmp_dir.iterdir()
                         if p.is_dir() and p.name.startswith("netwatchm"))
        repo_root = extracted
        self.after(0, self._log_msg, f"Source ready: {repo_root}")

        self._install_from(repo_root, tmp_dir)

    def _install_from(self, repo_root: Path, tmp_dir: Path):
        import shutil as _shutil

        # ── Preflight ─────────────────────────────────────────────────────────
        self.after(0, self._set_step, "Running preflight checks...", 15)

        if not shutil.which("python"):
            self._winget("Python.Python.3.12", "Python 3.12")
        py_ver = subprocess.check_output(["python", "--version"],
                                         stderr=subprocess.STDOUT, text=True).strip()
        self.after(0, self._log_msg, f"{py_ver} OK")

        if not shutil.which("tshark"):
            self._winget("Wireshark.Wireshark", "Wireshark (tshark)")
        if shutil.which("tshark"):
            self.after(0, self._log_msg, f"tshark: {shutil.which('tshark')}")
        else:
            self.after(0, self._log_msg,
                       "tshark not in PATH — add Wireshark bin dir manually", "warn")

        # ── Python package ────────────────────────────────────────────────────
        self.after(0, self._set_step,
                   "Installing NetWatchM and dependencies (may take a few minutes)...", 30)
        self.after(0, self._log_msg, "Window may pause briefly during download...")

        # Add Defender exclusion for pip cache to prevent AV blocking downloads
        pip_cache = Path(os.environ.get("LOCALAPPDATA", "")) / "pip" / "cache"
        tmp_path = Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
        for excl in [str(pip_cache), str(tmp_path)]:
            subprocess.run(
                ["powershell", "-Command", f'Add-MpPreference -ExclusionPath "{excl}"'],
                capture_output=True
            )

        # impacket is excluded from Windows install — flagged by Windows Defender.
        # It is only used for SMB forensics (Linux feature). Install as forensics extra if needed.
        rc = self._run_cmd("pip", "install", ".[windows]", "--quiet",
                           cwd=str(repo_root))
        if rc != 0:
            raise RuntimeError("pip install failed.")
        self.after(0, self._log_msg, "netwatchm installed")

        # ── Config ────────────────────────────────────────────────────────────
        self.after(0, self._set_step, "Setting up configuration...", 58)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not CONFIG_FILE.exists():
            shutil.copy(repo_root / "netwatchm.yaml.example", CONFIG_FILE)
            self.after(0, self._log_msg, f"Config created: {CONFIG_FILE}")
        else:
            self.after(0, self._log_msg, "Config already exists — not overwriting")

        # ── Monitor service ───────────────────────────────────────────────────
        self.after(0, self._set_step, "Installing monitor service...", 67)
        rc = self._run_cmd("python", "-m", "netwatchm",
                           "--config", str(CONFIG_FILE), "--install-service",
                           cwd=str(repo_root))
        if rc != 0:
            self.after(0, self._log_msg,
                       "Service install warning (may already exist)", "warn")
        else:
            self.after(0, self._log_msg, "Monitor service installed")

        # ── Web server ────────────────────────────────────────────────────────
        self.after(0, self._set_step, "Installing web server...", 76)
        server_dst = DATA_DIR / "netwatchm-server.py"
        shutil.copy(repo_root / "netwatchm_server.py", server_dst)
        self.after(0, self._log_msg, f"Server script: {server_dst}")

        # TLS certificate
        if not (DATA_DIR / "server.crt").exists() and shutil.which("openssl"):
            self._run_cmd("openssl", "req", "-x509", "-newkey", "rsa:2048",
                          "-keyout", str(DATA_DIR / "server.key"),
                          "-out",    str(DATA_DIR / "server.crt"),
                          "-days", "3650", "-nodes",
                          "-subj", "/CN=localhost/O=NetWatchM")
            self.after(0, self._log_msg, "TLS certificate generated")
        elif not shutil.which("openssl"):
            self.after(0, self._log_msg,
                       "openssl not found — copy server.crt/server.key manually", "warn")

        # Register web server (NSSM → Scheduled Task fallback)
        python_exe = shutil.which("python") or "python"
        nssm = shutil.which("nssm")
        if not nssm:
            self.after(0, self._log_msg, "NSSM not found — trying winget...", "warn")
            subprocess.run(
                ["winget", "install", "--id", "NSSM.NSSM", "--silent",
                 "--accept-package-agreements", "--accept-source-agreements"],
                capture_output=True
            )
            nssm = shutil.which("nssm")

        if nssm:
            subprocess.run([nssm, "install", "netwatchm-web",
                            python_exe, str(server_dst)], capture_output=True)
            subprocess.run([nssm, "set", "netwatchm-web",
                            "DisplayName", "NetWatchM Web Server"], capture_output=True)
            subprocess.run([nssm, "set", "netwatchm-web",
                            "Start", "SERVICE_AUTO_START"], capture_output=True)
            subprocess.run(["sc", "start", "netwatchm-web"], capture_output=True)
            self.after(0, self._log_msg, "netwatchm-web service registered (NSSM)")
        else:
            subprocess.run([
                "schtasks", "/create", "/tn", "netwatchm-web",
                "/tr", f'"{python_exe}" "{server_dst}"',
                "/sc", "onstart", "/ru", "SYSTEM", "/f"
            ], capture_output=True)
            subprocess.run(["schtasks", "/run", "/tn", "netwatchm-web"],
                           capture_output=True)
            self.after(0, self._log_msg,
                       "netwatchm-web registered as Scheduled Task", "warn")

        # ── Defender exclusion ────────────────────────────────────────────────
        self.after(0, self._set_step, "Adding Windows Defender exclusion...", 88)
        subprocess.run(
            ["powershell", "-Command",
             f'Add-MpPreference -ExclusionPath "{DATA_DIR}"'],
            capture_output=True
        )
        self.after(0, self._log_msg, f"Defender exclusion: {DATA_DIR}")

        # ── Shortcuts ─────────────────────────────────────────────────────────
        self.after(0, self._set_step, "Creating shortcuts...", 94)
        url_content = "[InternetShortcut]\r\nURL=https://localhost:8765/events.html\r\nIconIndex=0\r\n"
        public = Path(os.environ.get("PUBLIC", r"C:\Users\Public"))
        try:
            (public / "Desktop" / "NetWatchM Dashboard.url").write_text(url_content)
            self.after(0, self._log_msg, "Desktop shortcut created")
        except Exception as e:
            self.after(0, self._log_msg, f"Desktop shortcut failed: {e}", "warn")

        start_menu = PROGRAMDATA / "Microsoft" / "Windows" / "Start Menu" / \
                     "Programs" / "NetWatchM"
        try:
            start_menu.mkdir(parents=True, exist_ok=True)
            (start_menu / "NetWatchM Dashboard.url").write_text(url_content)
            self.after(0, self._log_msg, "Start Menu shortcut created")
        except Exception as e:
            self.after(0, self._log_msg, f"Start Menu shortcut failed: {e}", "warn")

        # ── Save version ──────────────────────────────────────────────────────
        VERSION_FILE.write_text(APP_VERSION)
        self.after(0, self._log_msg, f"Version recorded: {APP_VERSION}")

        # ── Cleanup temp files ────────────────────────────────────────────────
        try:
            _shutil.rmtree(tmp_dir, ignore_errors=True)
            self.after(0, self._log_msg, "Temp files cleaned up")
        except Exception:
            pass

        self.after(0, self._set_step, "Installation complete!", 100)

    # ── Uninstall ─────────────────────────────────────────────────────────────
    def _run_uninstall(self):
        try:
            self.after(0, self._set_step, "Uninstalling NetWatchM...", 10)
            for svc in ["netwatchm", "netwatchm-web"]:
                subprocess.run(["sc", "stop",   svc], capture_output=True)
                subprocess.run(["sc", "delete", svc], capture_output=True)
            subprocess.run(["schtasks", "/delete", "/tn", "netwatchm-web", "/f"],
                           capture_output=True)
            subprocess.run(["uv", "tool", "uninstall", "netwatchm"],
                           capture_output=True)
            public = Path(os.environ.get("PUBLIC", r"C:\Users\Public"))
            shortcut = public / "Desktop" / "NetWatchM Dashboard.url"
            shortcut.unlink(missing_ok=True)
            start_menu = PROGRAMDATA / "Microsoft" / "Windows" / "Start Menu" / \
                         "Programs" / "NetWatchM"
            shutil.rmtree(start_menu, ignore_errors=True)
            VERSION_FILE.unlink(missing_ok=True)

            self.after(0, self._log_msg,
                       f"NetWatchM removed. Config/data left at {DATA_DIR}")
            self.after(0, self._bar.__setitem__, "value", 100)
            self.after(0, self._step_var.set, "Uninstall complete")
            self.after(0, self._close_btn.configure, {"text": "Close", "state": "normal"})
            self.after(0, messagebox.showinfo, "Uninstall Complete",
                       f"NetWatchM has been removed.\n\n"
                       f"Config and data remain at:\n{DATA_DIR}\n\n"
                       "Delete manually if desired.")
        except Exception as exc:
            self.after(0, self._log_msg, f"[ERR] {exc}", "err")
            self.after(0, self._finish, False)


if __name__ == "__main__":
    app = InstallerApp()
    app.mainloop()
