"""
Frida-based interception engine.

Launches a target app (or attaches to a running one), injects agent.js into it
and every relevant child process (child-gating catches the reg.exe that
node-machine-id shells out to), routes the agent's reports into aggregated live
stats, and can swap the served profile on the fly.

Detaching restores the real behavior instantly -- nothing on the machine is
modified.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

import frida


# Child processes worth instrumenting. Everything else spawned by the target is
# resumed but left un-hooked, to avoid the overhead of injecting into Electron's
# many GPU/crashpad helpers that never read machine identifiers.
INSTRUMENT_CHILDREN = {
    "reg.exe", "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
    "wmic.exe", "node.exe", "code.exe", "code - insiders.exe",
    "vscodium.exe", "cursor.exe", "msedgewebview2.exe", "python.exe",
}


class GuardEngine:
    def __init__(self, agent_path: Path, config_provider: Callable[[], Optional[dict]]):
        self.agent_template = Path(agent_path).read_text(encoding="utf-8")
        self.config_provider = config_provider
        self.device = frida.get_local_device()

        self._lock = threading.RLock()
        self._sessions: dict[int, dict] = {}   # pid -> session info
        self._script_refs: dict[int, object] = {}
        self._session_refs: dict[int, object] = {}
        self._name_cache: dict[int, str] = {}

        # aggregated stats
        self._total = 0
        self._by_api: dict[str, int] = {}
        self._by_key: dict[str, int] = {}
        self._by_app: dict[str, int] = {}
        self._recent = deque(maxlen=250)
        self._errors = deque(maxlen=50)

        self._child_q: "queue.Queue" = queue.Queue()
        self._worker = threading.Thread(target=self._child_worker, daemon=True)
        self._worker.start()

        # auto-attach watcher
        self._watch_names: set = set()
        self._watch_stop = threading.Event()
        self._watcher_thread = None
        self._watch_seen: set = set()

        self.device.on("child-added", self._on_child_added)

    # ---------------------------------------------------------------- names
    def _proc_name(self, pid: int, hint: Optional[str] = None) -> str:
        if hint:
            self._name_cache[pid] = hint
            return hint
        if pid in self._name_cache:
            return self._name_cache[pid]
        try:
            for p in self.device.enumerate_processes():
                self._name_cache[p.pid] = p.name
        except Exception:
            pass
        return self._name_cache.get(pid, f"pid {pid}")

    # ----------------------------------------------------------- injection
    def _agent_source(self) -> str:
        cfg = self.config_provider()
        if not cfg:
            raise RuntimeError("No active profile selected.")
        return self.agent_template.replace("__CONFIG__", json.dumps(cfg), 1)

    def _instrument(self, pid: int, name_hint: Optional[str] = None) -> bool:
        """Attach, enable child-gating, inject the agent. Returns True on success."""
        name = self._proc_name(pid, name_hint)
        try:
            session = self.device.attach(pid)
        except Exception as e:
            self._log_error(pid, name, f"attach failed: {e}")
            return False
        try:
            session.enable_child_gating()
        except Exception:
            pass

        try:
            script = session.create_script(self._agent_source())
        except Exception as e:
            self._log_error(pid, name, f"script build failed: {e}")
            return False

        script.on("message", lambda message, data, _pid=pid: self._on_message(_pid, message, data))
        session.on("detached", lambda reason, *a, _pid=pid: self._on_detached(_pid, reason))

        try:
            script.load()
        except Exception as e:
            self._log_error(pid, name, f"inject failed: {e}")
            return False

        with self._lock:
            self._session_refs[pid] = session
            self._script_refs[pid] = script
            self._sessions[pid] = {
                "pid": pid, "name": name, "hooked": [], "calls": 0,
                "since": time.time(), "status": "active", "child": name_hint is not None,
            }
        return True

    def spawn(self, program: str, argv: Optional[list] = None) -> int:
        """Launch a program suspended, instrument it, then resume."""
        args = [program] + (argv or [])
        pid = self.device.spawn(args)
        name = os.path.basename(program)
        ok = self._instrument(pid, name_hint=name)
        try:
            self.device.resume(pid)
        except Exception:
            pass
        if not ok:
            raise RuntimeError(f"Spawned {name} (pid {pid}) but injection failed; it is running unprotected.")
        return pid

    def attach(self, pid: int) -> bool:
        return self._instrument(int(pid))

    def _on_child_added(self, child):
        # This runs on Frida's reactor thread. Blocking Frida calls here
        # (attach / create_script / load) would deadlock the reactor, so we
        # only enqueue; a worker thread does the instrument + resume.
        name = None
        try:
            if getattr(child, "path", None):
                name = os.path.basename(child.path)
        except Exception:
            pass
        self._child_q.put((child.pid, name))

    def _child_worker(self):
        while True:
            pid, name = self._child_q.get()
            try:
                if not name:
                    name = self._proc_name(pid)
                # Instrument known identity-reading children (and any we can't
                # name, to be safe); everything else is just resumed.
                if name is None or name.lower() in INSTRUMENT_CHILDREN:
                    self._instrument(pid, name_hint=name)
            except Exception as e:
                self._log_error(pid, name or "?", f"child instrument error: {e}")
            finally:
                try:
                    self.device.resume(pid)
                except Exception:
                    pass

    # --------------------------------------------------------------- events
    def _on_message(self, pid: int, message: dict, data):
        try:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                ptype = payload.get("type")
                if ptype == "ready":
                    with self._lock:
                        if pid in self._sessions:
                            self._sessions[pid]["hooked"] = payload.get("hooked", [])
                elif ptype == "call":
                    self._record_call(pid, payload)
            elif message.get("type") == "error":
                self._log_error(pid, self._proc_name(pid),
                                message.get("description", "script error"))
        except Exception:
            pass

    def _record_call(self, pid: int, payload: dict):
        with self._lock:
            self._total += 1
            api = payload.get("api", "?")
            key = payload.get("key", "?")
            self._by_api[api] = self._by_api.get(api, 0) + 1
            self._by_key[key] = self._by_key.get(key, 0) + 1
            name = self._sessions.get(pid, {}).get("name", self._proc_name(pid))
            self._by_app[name] = self._by_app.get(name, 0) + 1
            if pid in self._sessions:
                self._sessions[pid]["calls"] += 1
            self._recent.appendleft({
                "ts": time.time(), "pid": pid, "app": name,
                "api": api, "key": key,
                "real": payload.get("real"), "served": payload.get("served"),
            })

    def _on_detached(self, pid: int, reason):
        with self._lock:
            if pid in self._sessions:
                self._sessions[pid]["status"] = "ended"
            self._script_refs.pop(pid, None)
            self._session_refs.pop(pid, None)

    def _log_error(self, pid, name, msg):
        with self._lock:
            self._errors.appendleft({"ts": time.time(), "pid": pid, "app": name, "msg": str(msg)})

    # ------------------------------------------------------------- control
    def update_config(self, cfg: dict):
        """Push a new served profile to every live agent, no re-injection."""
        with self._lock:
            scripts = list(self._script_refs.values())
        for s in scripts:
            try:
                s.post({"type": "config", "config": cfg})
            except Exception:
                pass

    def stop(self, pid: int):
        with self._lock:
            session = self._session_refs.pop(pid, None)
            self._script_refs.pop(pid, None)
            if pid in self._sessions:
                self._sessions[pid]["status"] = "stopped"
        if session:
            try:
                session.detach()
            except Exception:
                pass

    def stop_all(self):
        with self._lock:
            pids = list(self._session_refs.keys())
        for pid in pids:
            self.stop(pid)

    # ------------------------------------------------- verify (capture)
    def run_and_capture(self, program: str, args: list = None, timeout: float = 5.0) -> str:
        """Spawn a leaf tool under the agent, capture its stdout, return it.

        Used by the profile self-test. Kept separate from the live sessions/stats
        so a verify run doesn't pollute the monitor.
        """
        if not self.config_provider():
            raise RuntimeError("No active profile selected.")
        argv = [program] + (args or [])
        box = {"pid": None, "buf": bytearray()}

        def on_output(pid, fd, data):
            if data and pid == box["pid"]:
                box["buf"].extend(bytes(data))

        self.device.on("output", on_output)
        session = None
        done = threading.Event()
        try:
            pid = self.device.spawn(argv, stdio="pipe")
            box["pid"] = pid
            session = self.device.attach(pid)
            session.on("detached", lambda *a: done.set())
            try:
                script = session.create_script(self._agent_source())
                script.load()
            except Exception:
                pass
            self.device.resume(pid)
            done.wait(timeout)         # returns as soon as the tool exits
            time.sleep(0.2)            # small grace for final stdout to flush
            return bytes(box["buf"]).decode("utf-8", "replace")
        finally:
            try:
                self.device.kill(box["pid"])
            except Exception:
                pass
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
            try:
                self.device.off("output", on_output)
            except Exception:
                pass

    # ------------------------------------------------- auto-attach watcher
    def start_watcher(self, names):
        self._watch_names = set(n.lower() for n in names)
        self._watch_seen.clear()
        if self._watcher_thread and self._watcher_thread.is_alive():
            return
        self._watch_stop.clear()
        self._watcher_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._watcher_thread.start()

    def stop_watcher(self):
        self._watch_stop.set()
        self._watcher_thread = None

    def watcher_running(self) -> bool:
        return bool(self._watcher_thread and self._watcher_thread.is_alive())

    def _watch_loop(self):
        me = os.getpid()
        while not self._watch_stop.is_set():
            try:
                if self.config_provider():           # only when an identity is active
                    with self._lock:
                        active = set(self._sessions.keys())
                    for p in self.device.enumerate_processes():
                        if p.pid == me or p.pid in self._watch_seen or p.pid in active:
                            continue
                        if p.name.lower() in self._watch_names:
                            self._watch_seen.add(p.pid)
                            try:
                                self._instrument(p.pid, name_hint=p.name)
                            except Exception as e:
                                self._log_error(p.pid, p.name, f"watch attach: {e}")
            except Exception:
                pass
            self._watch_stop.wait(2.0)

    # ---------------------------------------------------------------- read
    def live(self) -> dict:
        with self._lock:
            active_sessions = [s for s in self._sessions.values() if s["status"] == "active"]
            return {
                "total": self._total,
                "by_api": dict(self._by_api),
                "by_key": dict(self._by_key),
                "by_app": dict(self._by_app),
                "recent": list(self._recent)[:120],
                "errors": list(self._errors)[:20],
                "sessions": list(self._sessions.values()),
                "active_session_count": len(active_sessions),
            }

    def reset_stats(self):
        with self._lock:
            self._total = 0
            self._by_api.clear()
            self._by_key.clear()
            self._by_app.clear()
            self._recent.clear()
