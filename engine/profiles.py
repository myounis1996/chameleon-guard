"""
Profile store + identity generator for Chameleon.

A *profile* is a self-consistent set of fake hardware identifiers derived from a
single random seed. Deriving everything from one seed means the values look like
they belong to one real machine (same style of hostname, a MAC with a real
vendor OUI, a volume serial in range, etc.) and that a profile is perfectly
reproducible from its seed.

Nothing here touches the real machine. Profiles are just JSON on disk; the
interception engine reads the active profile and serves its values to hooked
apps.
"""
from __future__ import annotations

import json
import os
import random
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


# Real, common vendor OUIs (first 3 MAC bytes). Using a real OUI makes a spoofed
# MAC look like ordinary consumer hardware rather than an obviously fake or
# locally-administered address.
_VENDOR_OUIS = [
    ("Dell",            (0x00, 0x14, 0x22)),
    ("Intel",           (0x3C, 0x97, 0x0E)),
    ("Intel",           (0x00, 0x1B, 0x21)),
    ("ASUSTek",         (0x1C, 0x87, 0x2C)),
    ("Hewlett-Packard", (0x3C, 0xD9, 0x2B)),
    ("Lenovo",          (0x54, 0xEE, 0x75)),
    ("Micro-Star",      (0x00, 0x21, 0x85)),
    ("Realtek",         (0x52, 0x54, 0x00)),
    ("Gigabyte",        (0x1C, 0x1B, 0x0D)),
    ("Apple",           (0xA4, 0x5E, 0x60)),
]

_BIOS_VENDORS = [
    ("American Megatrends Inc.", "AMI"),
    ("Dell Inc.", "DELL"),
    ("LENOVO", "LENOVO"),
    ("Insyde Corp.", "INSYDE"),
    ("Phoenix Technologies LTD", "PHNX"),
]

_SYSTEM_MANUFACTURERS = [
    ("Dell Inc.", ["OptiPlex 7090", "Latitude 5420", "XPS 15 9500"]),
    ("LENOVO", ["20U9S0S200", "21CB0089US"]),
    ("ASUS", ["ROG STRIX B550-F", "TUF GAMING X570"]),
    ("Micro-Star International Co., Ltd.", ["MS-7C56", "MS-7B86"]),
    ("Hewlett-Packard", ["HP EliteBook 840 G8", "HP ProDesk 600 G6"]),
]


def _rand_hex(rng: random.Random, n: int, upper: bool = True) -> str:
    s = "".join(rng.choice("0123456789ABCDEF") for _ in range(n))
    return s if upper else s.lower()


def _guid(rng: random.Random, braces: bool = False, upper: bool = False) -> str:
    # Build a v4-style GUID deterministically from the RNG.
    b = bytearray(rng.getrandbits(8) for _ in range(16))
    b[6] = (b[6] & 0x0F) | 0x40  # version 4
    b[8] = (b[8] & 0x3F) | 0x80  # variant
    u = uuid.UUID(bytes=bytes(b))
    s = str(u)
    if upper:
        s = s.upper()
    return "{" + s + "}" if braces else s


def _windows_product_id(rng: random.Random) -> str:
    # Format: NNNNN-NNN-NNNNNNN-NNNNN
    d = lambda n: "".join(rng.choice("0123456789") for _ in range(n))
    return f"{d(5)}-{d(3)}-{d(7)}-{d(5)}"


def _computer_name(rng: random.Random) -> str:
    # Windows default style: DESKTOP-XXXXXXX / LAPTOP-XXXXXXX
    prefix = rng.choice(["DESKTOP", "LAPTOP", "WIN", "PC"])
    tail = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(7))
    return f"{prefix}-{tail}"


def _mac(rng: random.Random) -> list[int]:
    _, oui = rng.choice(_VENDOR_OUIS)
    return list(oui) + [rng.randint(0, 255) for _ in range(3)]


def _processor_id(rng: random.Random) -> str:
    # 16 hex chars, like WMI Win32_Processor.ProcessorId
    return _rand_hex(rng, 16, upper=True)


def generate_identity(name: Optional[str] = None, seed: Optional[int] = None) -> dict:
    """Generate a fresh, internally consistent fake identity."""
    if seed is None:
        seed = random.getrandbits(64)
    rng = random.Random(seed)

    manufacturer, models = rng.choice(_SYSTEM_MANUFACTURERS)
    model = rng.choice(models)
    bios_vendor, bios_tag = rng.choice(_BIOS_VENDORS)

    mac = _mac(rng)
    mac_str = ":".join(f"{b:02X}" for b in mac)

    bios_serial = f"{bios_tag}{_rand_hex(rng, 7)}"
    baseboard_serial = _rand_hex(rng, 12)
    chassis_serial = _rand_hex(rng, 10)
    system_serial = f"{bios_tag[:2]}{_rand_hex(rng, 8)}"
    system_uuid = _guid(rng, braces=False, upper=True)

    ident = {
        "id": str(uuid.uuid4()),
        "name": name or f"Identity-{_rand_hex(rng, 4)}",
        "seed": seed,
        "created": time.time(),
        # --- OS / registry identifiers ---
        "machine_guid": _guid(rng, braces=False, upper=False),        # HKLM\...\Cryptography\MachineGuid
        "sqm_machine_id": _guid(rng, braces=True, upper=True),        # HKLM\...\SQMClient\MachineId
        "product_id": _windows_product_id(rng),                       # HKLM\...\CurrentVersion\ProductId
        "sus_client_id": _guid(rng, braces=False, upper=False),       # HKLM\...\WindowsUpdate\SusClientId
        "hw_profile_guid": _guid(rng, braces=True, upper=True),       # IDConfigDB\Hardware Profiles\0001
        "build_guid": _guid(rng, braces=False, upper=False),          # CurrentVersion\BuildGUID
        "computer_name": _computer_name(rng),
        # --- Firmware / SMBIOS ---
        "system_manufacturer": manufacturer,
        "system_model": model,
        "system_uuid": system_uuid,                                   # SMBIOS Type 1 UUID
        "system_serial": system_serial,
        "bios_vendor": bios_vendor,
        "bios_serial": bios_serial,
        "baseboard_serial": baseboard_serial,
        "chassis_serial": chassis_serial,
        "processor_id": _processor_id(rng),
        # --- Storage / network ---
        "volume_serial": rng.randint(0x10000000, 0xFFFFFFFF),         # NTFS volume serial (uint32)
        "disk_serial": "".join(rng.choice("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(16)),
        "mac": mac,
        "mac_str": mac_str,
        # --- App-level telemetry IDs (VS Code family / Copilot in VS Code) ---
        "vscode": {
            "machineId": _rand_hex(rng, 64, upper=False),             # telemetry.machineId (sha256 hex)
            "macMachineId": _rand_hex(rng, 64, upper=False),          # telemetry.macMachineId
            "devDeviceId": _guid(rng, braces=False, upper=False),     # telemetry.devDeviceId (uuid)
            "sqmId": _guid(rng, braces=True, upper=True),             # telemetry.sqmId ({GUID})
        },
    }
    return ident


class ProfileStore:
    """CRUD over profile JSON files plus the notion of an 'active' profile."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.profiles_dir = self.data_dir / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.data_dir / "state.json"

    # -- state (active id + engine enabled flag) --
    def _read_state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {"active_id": None, "enabled": False}

    def _write_state(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def get_active_id(self) -> Optional[str]:
        return self._read_state().get("active_id")

    def set_active_id(self, pid: Optional[str]) -> None:
        st = self._read_state()
        st["active_id"] = pid
        self._write_state(st)

    def get_enabled(self) -> bool:
        return bool(self._read_state().get("enabled"))

    def set_enabled(self, val: bool) -> None:
        st = self._read_state()
        st["enabled"] = bool(val)
        self._write_state(st)

    def get_wmi(self) -> bool:
        v = self._read_state().get("wmi_coverage")
        return True if v is None else bool(v)   # default ON

    def set_wmi(self, val: bool) -> None:
        st = self._read_state()
        st["wmi_coverage"] = bool(val)
        self._write_state(st)

    # -- profiles --
    def _path(self, pid: str) -> Path:
        return self.profiles_dir / f"{pid}.json"

    def list(self) -> list[dict]:
        out = []
        for f in sorted(self.profiles_dir.glob("*.json")):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                continue
        out.sort(key=lambda p: p.get("created", 0))
        return out

    def get(self, pid: str) -> Optional[dict]:
        p = self._path(pid)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def create(self, name: Optional[str] = None) -> dict:
        ident = generate_identity(name=name)
        self._path(ident["id"]).write_text(json.dumps(ident, indent=2), encoding="utf-8")
        return ident

    def save(self, ident: dict) -> None:
        self._path(ident["id"]).write_text(json.dumps(ident, indent=2), encoding="utf-8")

    def rename(self, pid: str, name: str) -> Optional[dict]:
        ident = self.get(pid)
        if not ident:
            return None
        ident["name"] = name
        self.save(ident)
        return ident

    def delete(self, pid: str) -> bool:
        p = self._path(pid)
        if p.exists():
            p.unlink()
            if self.get_active_id() == pid:
                self.set_active_id(None)
            return True
        return False

    def runtime_config(self, pid: str) -> Optional[dict]:
        """The subset the Frida agent needs, in the shape agent.js expects."""
        ident = self.get(pid)
        if not ident:
            return None
        return {
            "profileId": ident["id"],
            "profileName": ident["name"],
            "machineGuid": ident["machine_guid"],
            "sqmMachineId": ident["sqm_machine_id"],
            "productId": ident["product_id"],
            "computerName": ident["computer_name"],
            "mac": ident["mac"],
            "volumeSerial": ident["volume_serial"],
            "systemUuid": ident["system_uuid"],
            "biosSerial": ident["bios_serial"],
            "baseboardSerial": ident["baseboard_serial"],
            "chassisSerial": ident["chassis_serial"],
            "systemSerial": ident["system_serial"],
            "processorId": ident["processor_id"],
            "diskSerial": ident.get("disk_serial", ident["baseboard_serial"]),
            "susClientId": ident.get("sus_client_id", ident["machine_guid"]),
            "hwProfileGuid": ident.get("hw_profile_guid", "{" + ident["system_uuid"] + "}"),
            "buildGuid": ident.get("build_guid", ident["machine_guid"]),
        }
