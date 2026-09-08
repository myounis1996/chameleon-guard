"""
Identity-file layer.

Some apps cache their device identity in a file rather than re-reading it from
the OS each time. VS Code (and its forks, plus GitHub Copilot which rides on VS
Code's telemetry ids) is the prime example: the ids live in

    %APPDATA%\\<App>\\User\\globalStorage\\storage.json

as telemetry.machineId / telemetry.macMachineId / telemetry.devDeviceId /
telemetry.sqmId.

For those we back the file up once, write the active profile's ids, and can
restore the original at any time. This is fully reversible.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Optional


def _appdata() -> Path:
    import os
    return Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming")))


# id -> (display name, storage.json path)
def known_targets() -> dict[str, dict]:
    ad = _appdata()
    defs = {
        "vscode":          ("Visual Studio Code",          ad / "Code" / "User" / "globalStorage" / "storage.json"),
        "vscode-insiders": ("Visual Studio Code Insiders",  ad / "Code - Insiders" / "User" / "globalStorage" / "storage.json"),
        "vscodium":        ("VSCodium",                     ad / "VSCodium" / "User" / "globalStorage" / "storage.json"),
        "cursor":          ("Cursor",                       ad / "Cursor" / "User" / "globalStorage" / "storage.json"),
    }
    return {k: {"id": k, "name": n, "path": str(p)} for k, (n, p) in defs.items()}


TELEMETRY_KEYS = ("telemetry.machineId", "telemetry.macMachineId",
                  "telemetry.devDeviceId", "telemetry.sqmId")


class IdentityFileManager:
    def __init__(self, backup_dir: Path):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _backup_path(self, target_id: str) -> Path:
        return self.backup_dir / f"{target_id}.storage.json.bak"

    def status(self) -> list[dict]:
        out = []
        for t in known_targets().values():
            p = Path(t["path"])
            patched = False
            current = {}
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    current = {k: data.get(k) for k in TELEMETRY_KEYS if k in data}
                    patched = self._backup_path(t["id"]).exists()
                except Exception:
                    pass
            out.append({
                "id": t["id"], "name": t["name"], "path": t["path"],
                "exists": p.exists(), "patched": patched, "current": current,
            })
        return out

    def apply(self, target_id: str, vscode_ids: dict) -> dict:
        targets = known_targets()
        if target_id not in targets:
            return {"id": target_id, "ok": False, "error": "unknown target"}
        p = Path(targets[target_id]["path"])
        if not p.exists():
            return {"id": target_id, "ok": False, "error": "not installed / no storage.json"}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            return {"id": target_id, "ok": False, "error": f"unreadable: {e}"}

        # one-time backup of the pristine file
        bak = self._backup_path(target_id)
        if not bak.exists():
            try:
                shutil.copy2(p, bak)
            except Exception as e:
                return {"id": target_id, "ok": False, "error": f"backup failed: {e}"}

        data["telemetry.machineId"] = vscode_ids["machineId"]
        data["telemetry.macMachineId"] = vscode_ids["macMachineId"]
        data["telemetry.devDeviceId"] = vscode_ids["devDeviceId"]
        data["telemetry.sqmId"] = vscode_ids["sqmId"]
        try:
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            return {"id": target_id, "ok": False, "error": f"write failed: {e}"}
        return {"id": target_id, "ok": True}

    def restore(self, target_id: str) -> dict:
        bak = self._backup_path(target_id)
        targets = known_targets()
        if target_id not in targets:
            return {"id": target_id, "ok": False, "error": "unknown target"}
        if not bak.exists():
            return {"id": target_id, "ok": False, "error": "no backup to restore"}
        p = Path(targets[target_id]["path"])
        try:
            shutil.copy2(bak, p)
            bak.unlink()
        except Exception as e:
            return {"id": target_id, "ok": False, "error": f"restore failed: {e}"}
        return {"id": target_id, "ok": True}
