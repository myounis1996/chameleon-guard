"""
Chameleon -- Hardware Identity Guard.

A desktop app that sits between other apps and the OS functions that reveal your
hardware identity. Pick (or one-click generate) an identity profile, launch an
app "protected", and every call it makes to read a machine id, MAC, volume
serial, SMBIOS serial/UUID, hostname, etc. is logged and answered with the
profile's fake value instead. Detaching restores the truth -- your real machine
is never modified.

UI is HTML/CSS/JS rendered in a WebView2 window via pywebview.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

import webview

from engine.profiles import ProfileStore
from engine.interceptor import GuardEngine
from engine.identity_files import IdentityFileManager, known_targets as id_known_targets

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
AGENT = BASE / "engine" / "agent.js"


# --------------------------------------------------------------------------- #
# Elevation
#
# Attaching to an already-running or elevated process needs Administrator
# rights, so we ask for them up front rather than failing later. The relaunch
# hands the child a sentinel flag; seeing that flag disables any further
# elevation attempt, which makes a relaunch loop impossible. (An env var cannot
# do this job -- ShellExecuteW does not propagate one to the new process.)
# --------------------------------------------------------------------------- #
ELEVATED_FLAG = "--elevated"        # sentinel: "you are the relaunched child"
NO_ELEVATE_FLAG = "--no-elevate"    # developer opt-out
NO_ELEVATE_ENV = "CHAMELEON_NO_ELEVATE"


def _is_admin() -> bool:
    """True when this process holds an elevated administrator token."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


#: Resolved once at import and reused everywhere -- the UI reads it as
#: ``live.admin``. Re-querying per API call would be pointless: a process's
#: token never gains elevation while it runs.
IS_ADMIN = _is_admin()


def _elevation_opt_out() -> bool:
    """Developer escape hatch: env var or command-line flag."""
    if os.environ.get(NO_ELEVATE_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return NO_ELEVATE_FLAG in sys.argv[1:]


def _relaunch_as_admin() -> bool:
    """Ask UAC to start a second, elevated copy of this app.

    Returns True only when Windows accepted the request -- the caller must then
    exit and let the elevated copy take over. Returns False when the user
    answered "No" or the shell refused, in which case we keep running
    unelevated: launching an app *through* the guard still works, only
    attaching to an already-running one does not.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller one-file build: sys.executable *is* the app.
        argv = list(sys.argv[1:])
    else:
        # Running from source: the interpreter needs the script path first.
        argv = [str(Path(__file__).resolve())] + list(sys.argv[1:])
    argv.append(ELEVATED_FLAG)
    params = subprocess.list2cmdline(argv)   # Windows-correct quoting
    try:
        shell32 = ctypes.windll.shell32
        # HINSTANCE is pointer-sized; without this the result is truncated.
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        rc = shell32.ShellExecuteW(None, "runas", sys.executable, params, str(BASE), 1)
        return int(rc or 0) > 32             # <= 32 means declined or failed
    except Exception:
        return False


def ensure_elevated() -> bool:
    """Elevate before the window exists. True => this instance should quit.

    A no-op when we are already elevated, when the developer opted out, or when
    the ``--elevated`` sentinel says we *are* the relaunched child. Never
    raises and never exits on failure -- an unelevated Chameleon is degraded,
    not broken, and the UI surfaces that via ``live.admin``.
    """
    if IS_ADMIN or os.name != "nt":
        return False
    if ELEVATED_FLAG in sys.argv[1:]:        # loop guard -- one attempt, ever
        return False
    if _elevation_opt_out():
        return False
    return _relaunch_as_admin()


def discover_launch_targets() -> list[dict]:
    """Find installed apps we know how to launch (VS Code family, etc.)."""
    lad = Path(os.environ.get("LOCALAPPDATA", ""))
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pfx = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    candidates = [
        ("Visual Studio Code",          [lad / "Programs/Microsoft VS Code/Code.exe", pf / "Microsoft VS Code/Code.exe"]),
        ("Visual Studio Code Insiders", [lad / "Programs/Microsoft VS Code Insiders/Code - Insiders.exe"]),
        ("Cursor",                      [lad / "Programs/cursor/Cursor.exe"]),
        ("VSCodium",                    [lad / "Programs/VSCodium/VSCodium.exe", pf / "VSCodium/VSCodium.exe"]),
        ("Windsurf",                    [lad / "Programs/Windsurf/Windsurf.exe"]),
    ]
    out = []
    for name, paths in candidates:
        found = next((p for p in paths if p.exists()), None)
        out.append({"name": name, "path": str(found) if found else "", "installed": bool(found)})
    return out


# Verify self-test probes. Each is a single PowerShell command line (run under
# the guard) that prints KEY=value lines, so one spawned process can prove
# several identifiers at once. They are split by management stack: the classic
# Win32 / WMI APIs, and the newer MI/CIM stack behind Get-CimInstance,
# Get-PhysicalDisk and Get-NetAdapter.
PROBE_WIN32_WMI = (
    "$ErrorActionPreference='SilentlyContinue';"
    "'HOSTAPI=' + [Environment]::MachineName;"
    "'BIOS=' + (Get-WmiObject Win32_BIOS).SerialNumber;"
    "'MAC=' + (Get-WmiObject Win32_NetworkAdapterConfiguration |"
    " Where-Object {$_.MACAddress} | Select-Object -First 1).MACAddress;"
    "'DISK=' + (Get-WmiObject Win32_DiskDrive | Select-Object -First 1).SerialNumber"
)

PROBE_MI_CIM = (
    "$ErrorActionPreference='SilentlyContinue';"
    "'BOARD=' + (Get-CimInstance Win32_BaseBoard).SerialNumber;"
    "'UUID=' + (Get-CimInstance Win32_ComputerSystemProduct).UUID;"
    "'HOST=' + (Get-CimInstance Win32_ComputerSystem).Name;"
    "'PDISK=' + (Get-CimInstance -Namespace root/Microsoft/Windows/Storage"
    " -ClassName MSFT_PhysicalDisk | Select-Object -First 1).SerialNumber;"
    "'CMAC=' + (Get-CimInstance -Namespace root/StandardCimv2"
    " -ClassName MSFT_NetAdapter | Where-Object {$_.NetworkAddresses} |"
    " Select-Object -First 1).NetworkAddresses[0];"
    "'VOLNUM=' + (Get-CimInstance Win32_Volume |"
    " Where-Object {$_.SerialNumber} | Select-Object -First 1).SerialNumber"
)


# Known AI coding CLIs. Launched through a guarded shell so child-gating catches
# the node/python/reg helpers they spawn.
KNOWN_AI_CLIS = [
    {"id": "codex",        "name": "OpenAI Codex CLI",   "cmd": "codex",        "probe": ["codex", "codex.cmd"]},
    {"id": "claude",       "name": "Claude Code",         "cmd": "claude",       "probe": ["claude", "claude.cmd"]},
    {"id": "copilot",      "name": "GitHub Copilot CLI",  "cmd": "copilot",      "probe": ["copilot", "copilot.cmd"]},
    {"id": "gh-copilot",   "name": "GitHub Copilot (gh)", "cmd": "gh copilot",   "probe": ["gh", "gh.exe"]},
    {"id": "gemini",       "name": "Google Gemini CLI",   "cmd": "gemini",       "probe": ["gemini", "gemini.cmd"]},
    {"id": "aider",        "name": "Aider",               "cmd": "aider",        "probe": ["aider", "aider.exe"]},
    {"id": "cursor-agent", "name": "Cursor Agent CLI",    "cmd": "cursor-agent", "probe": ["cursor-agent", "cursor-agent.cmd"]},
    {"id": "qwen",         "name": "Qwen Code CLI",       "cmd": "qwen",         "probe": ["qwen", "qwen.cmd"]},
    {"id": "opencode",     "name": "opencode",            "cmd": "opencode",     "probe": ["opencode", "opencode.cmd"]},
    {"id": "amazon-q",     "name": "Amazon Q CLI",        "cmd": "q",            "probe": ["q", "q.exe"]},
]


def discover_cli_agents() -> list[dict]:
    out = []
    for a in KNOWN_AI_CLIS:
        found = next((shutil.which(p) for p in a["probe"] if shutil.which(p)), None)
        out.append({"id": a["id"], "name": a["name"], "cmd": a["cmd"],
                    "path": found or "", "installed": bool(found)})
    return out


class Api:
    def __init__(self):
        self.store = ProfileStore(DATA)
        self.idfiles = IdentityFileManager(DATA / "backups")
        self.engine = GuardEngine(AGENT, config_provider=self._active_config)
        self._window = None
        # resume the auto-attach watcher if it was left enabled
        if self.store.get_watcher_enabled() and self.store.get_active_id():
            try:
                self.engine.start_watcher(self.store.get_watch_list())
            except Exception:
                pass

    # -------------------------------------------------- internal
    def _active_config(self):
        aid = self.store.get_active_id()
        if not aid:
            return None
        cfg = self.store.runtime_config(aid)
        if cfg:
            cfg["wmi"] = self.store.get_wmi()
        return cfg

    def _active_summary(self):
        aid = self.store.get_active_id()
        prof = self.store.get(aid) if aid else None
        return {
            "active_id": aid,
            "active_name": prof["name"] if prof else None,
            "enabled": self.store.get_enabled(),
            "wmi": self.store.get_wmi(),
            "admin": IS_ADMIN,
        }

    # -------------------------------------------------- profiles
    def list_profiles(self):
        return {"profiles": self.store.list(), **self._active_summary()}

    def get_profile(self, pid):
        return self.store.get(pid)

    def create_profile(self, name=None):
        prof = self.store.create(name or None)
        # if nothing is active yet, make the new one active for convenience
        if not self.store.get_active_id():
            self.store.set_active_id(prof["id"])
        return {"ok": True, "profile": prof, **self._active_summary()}

    def rename_profile(self, pid, name):
        p = self.store.rename(pid, name)
        return {"ok": bool(p), "profile": p}

    def delete_profile(self, pid):
        ok = self.store.delete(pid)
        return {"ok": ok, **self._active_summary()}

    def regenerate_profile(self, pid, keep_name=True):
        """Roll a brand-new identity, optionally under the same name/id slot."""
        old = self.store.get(pid)
        if not old:
            return {"ok": False, "error": "not found"}
        from engine.profiles import generate_identity
        fresh = generate_identity(name=old["name"] if keep_name else None)
        fresh["id"] = old["id"]  # keep the slot so 'active' stays valid
        self.store.save(fresh)
        if self.store.get_active_id() == pid and self.store.get_enabled():
            cfg = self._active_config()
            if cfg:
                self.engine.update_config(cfg)
        return {"ok": True, "profile": fresh}

    def activate_profile(self, pid):
        if not self.store.get(pid):
            return {"ok": False, "error": "not found"}
        self.store.set_active_id(pid)
        cfg = self._active_config()
        if cfg and self.store.get_enabled():
            self.engine.update_config(cfg)   # live-swap on all running agents
        return {"ok": True, **self._active_summary()}

    # -------------------------------------------------- engine control
    def set_enabled(self, flag):
        flag = bool(flag)
        self.store.set_enabled(flag)
        if not flag:
            self.engine.stop_all()
            self.engine.stop_watcher()
            self.store.set_watcher_enabled(False)
        return {"ok": True, **self._active_summary()}

    def set_wmi_coverage(self, flag):
        self.store.set_wmi(bool(flag))
        return {"ok": True, **self._active_summary()}

    # -------------------------------------------------- verify self-test
    def verify_profile(self):
        aid = self.store.get_active_id()
        prof = self.store.get(aid) if aid else None
        if not prof:
            return {"ok": False, "error": "Select or create an identity first."}
        win = os.environ.get("WINDIR", r"C:\Windows")
        ps = rf"{win}\System32\WindowsPowerShell\v1.0\powershell.exe"

        def cap(prog, args, wait=5.0):
            try:
                return self.engine.run_and_capture(prog, args, wait)
            except Exception as e:
                return f"__ERR__:{e}"

        vser = prof["volume_serial"] & 0xFFFFFFFF
        volfmt = f"{vser:08X}"[:4] + "-" + f"{vser:08X}"[4:]

        # Two batched probes, one per management stack, so every identifier is
        # proven on the API an app would really use. Batching keeps the whole
        # self-test down to four spawned processes.
        wmi_out = cap(ps, ["-NoProfile", "-Command", PROBE_WIN32_WMI], 25.0)
        cim_out = cap(ps, ["-NoProfile", "-Command", PROBE_MI_CIM], 35.0)

        checks = [
            self._vcheck("MachineGuid (registry)", prof["machine_guid"], "Windows API",
                cap(rf"{win}\System32\reg.exe", ["QUERY", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])),
            self._vcheck("Volume serial", volfmt, "Windows API",
                cap(rf"{win}\System32\cmd.exe", ["/c", "vol", "C:"])),
            self._vline("Hostname", prof["computer_name"], "Windows API", wmi_out, "HOSTAPI"),
            self._vline("BIOS serial", prof["bios_serial"], "WMI", wmi_out, "BIOS"),
            self._vline("MAC address", prof["mac_str"], "WMI", wmi_out, "MAC"),
            self._vline("Disk serial", prof["disk_serial"], "WMI", wmi_out, "DISK"),
            self._vline("Baseboard serial", prof["baseboard_serial"], "MI / CIM", cim_out, "BOARD"),
            self._vline("System UUID", prof["system_uuid"], "MI / CIM", cim_out, "UUID"),
            self._vline("Hostname", prof["computer_name"], "MI / CIM", cim_out, "HOST"),
            self._vline("Physical disk serial", prof["disk_serial"], "MI / CIM", cim_out, "PDISK"),
            self._vline("Net adapter MAC", prof["mac_str"].replace(":", ""), "MI / CIM", cim_out, "CMAC"),
            self._vline("Volume serial (numeric)", str(vser), "MI / CIM", cim_out, "VOLNUM"),
        ]
        return {"ok": True, "checks": checks, "wmi": self.store.get_wmi(),
                "passed": sum(c["pass"] for c in checks), "total": len(checks)}

    def _vcheck(self, name, expected, group, out):
        """Pass if the expected value appears anywhere in a tool's output."""
        err = out.startswith("__ERR__")
        ok = (not err) and (expected.lower() in out.lower())
        return {"name": name, "expected": expected, "group": group, "pass": bool(ok),
                "error": out[8:] if err else None,
                "snippet": " ".join(out.split())[:90]}

    def _vline(self, name, expected, group, out, key):
        """Pass if the batched probe's 'KEY=value' line is exactly the fake value."""
        if out.startswith("__ERR__"):
            return {"name": name, "expected": expected, "group": group, "pass": False,
                    "error": out[8:], "snippet": ""}
        got = ""
        for line in out.splitlines():
            line = line.strip()
            if line.upper().startswith(key.upper() + "="):
                got = line.split("=", 1)[1].strip()
                break
        return {"name": name, "expected": expected, "group": group,
                "pass": bool(got) and got.lower() == expected.lower(),
                "error": None, "snippet": got[:90] or "(no value returned)"}

    # -------------------------------------------------- auto-attach watcher
    def get_watch_config(self):
        return {"enabled": self.store.get_watcher_enabled(),
                "running": self.engine.watcher_running(),
                "names": self.store.get_watch_list()}

    def set_watch_list(self, names):
        self.store.set_watch_list(names or [])
        if self.store.get_watcher_enabled():
            self.engine.start_watcher(self.store.get_watch_list())
        return {"ok": True, **self.get_watch_config()}

    def set_watcher(self, flag):
        flag = bool(flag)
        if flag and not self.store.get_active_id():
            return {"ok": False, "error": "Select an identity first."}
        self.store.set_watcher_enabled(flag)
        if flag:
            self.store.set_enabled(True)
            self.engine.start_watcher(self.store.get_watch_list())
        else:
            self.engine.stop_watcher()
        return {"ok": True, **self.get_watch_config()}

    def get_live(self):
        data = self.engine.live()
        data.update(self._active_summary())
        return data

    def reset_stats(self):
        self.engine.reset_stats()
        return {"ok": True}

    # -------------------------------------------------- targets / launching
    def list_targets(self):
        launch = discover_launch_targets()
        # annotate with running pids
        running = {}
        try:
            for p in self.engine.device.enumerate_processes():
                running.setdefault(p.name.lower(), []).append(p.pid)
        except Exception:
            pass
        for t in launch:
            base = os.path.basename(t["path"]).lower() if t["path"] else ""
            t["running"] = running.get(base, [])
        return {"targets": launch, "cli_agents": discover_cli_agents(),
                "identity_files": self.idfiles.status(), "watch": self.get_watch_config(),
                **self._active_summary()}

    def list_processes(self):
        out = []
        try:
            for p in self.engine.device.enumerate_processes():
                out.append({"pid": p.pid, "name": p.name})
        except Exception:
            pass
        out.sort(key=lambda x: x["name"].lower())
        return out

    def launch_target(self, path, args=None):
        if not self.store.get_active_id():
            return {"ok": False, "error": "Select or create an identity first."}
        if not path or not Path(path).exists():
            return {"ok": False, "error": "Executable not found."}
        self.store.set_enabled(True)
        try:
            pid = self.engine.spawn(path, args or [])
            return {"ok": True, "pid": pid}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def launch_command(self, command):
        """Launch an arbitrary command line under the guard (for CLI tools like
        codex / copilot). We go through cmd.exe so PATH resolution works and
        child-gating instruments the node/reg children it spawns."""
        if not self.store.get_active_id():
            return {"ok": False, "error": "Select or create an identity first."}
        if not command or not command.strip():
            return {"ok": False, "error": "Empty command."}
        self.store.set_enabled(True)
        comspec = os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
        try:
            pid = self.engine.spawn(comspec, ["/k", command])
            return {"ok": True, "pid": pid}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def launch_cli(self, agent_id):
        agent = next((a for a in discover_cli_agents() if a["id"] == agent_id), None)
        if not agent:
            return {"ok": False, "error": "unknown agent"}
        return self.launch_command(agent["cmd"])

    def attach_process(self, pid):
        if not self.store.get_active_id():
            return {"ok": False, "error": "Select or create an identity first."}
        self.store.set_enabled(True)
        try:
            ok = self.engine.attach(int(pid))
            return {"ok": ok}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def stop_session(self, pid):
        self.engine.stop(int(pid))
        return {"ok": True}

    def browse_exe(self):
        try:
            res = self._window.create_file_dialog(
                webview.OPEN_DIALOG, allow_multiple=False,
                file_types=("Executable (*.exe)", "All files (*.*)"))
            if res:
                return {"ok": True, "path": res[0] if isinstance(res, (list, tuple)) else res}
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": False}

    # -------------------------------------------------- identity files
    def apply_identity_files(self, target_ids=None):
        aid = self.store.get_active_id()
        prof = self.store.get(aid) if aid else None
        if not prof:
            return {"ok": False, "error": "Select an identity first."}
        ids = prof["vscode"]
        targets = target_ids or [t["id"] for t in self.idfiles.status() if t["exists"]]
        results = [self.idfiles.apply(t, ids) for t in targets]
        return {"ok": True, "results": results, "status": self.idfiles.status()}

    def restore_identity_files(self, target_ids=None):
        targets = target_ids or [t["id"] for t in self.idfiles.status() if t["patched"]]
        results = [self.idfiles.restore(t) for t in targets]
        return {"ok": True, "results": results, "status": self.idfiles.status()}

    def open_data_folder(self):
        try:
            os.startfile(str(DATA))  # noqa: S606 (Windows explorer)
        except Exception:
            pass
        return {"ok": True}


def main():
    # Administrator rights first: without them we cannot attach to apps that
    # are already running. If the UAC prompt is declined we simply carry on
    # unelevated instead of dying.
    if ensure_elevated():
        return   # the elevated copy takes over; this instance is done
    DATA.mkdir(parents=True, exist_ok=True)
    api = Api()
    window = webview.create_window(
        "Chameleon — Hardware Identity Guard",
        url=str(BASE / "ui" / "index.html"),
        js_api=api,
        width=1200, height=800, min_size=(960, 640),
        background_color="#0b0f14",
    )
    api._window = window
    webview.start(debug=False)


if __name__ == "__main__":
    main()
