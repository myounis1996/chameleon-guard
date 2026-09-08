# 🦎 Chameleon — Hardware Identity Guard

Chameleon sits **between an app and the Windows functions that reveal your
hardware identity**. When you launch an app "protected", a lightweight Frida
agent is injected into it (and the helper processes it spawns, like `reg.exe`).
Every time the app asks Windows for a machine id, MAC, volume serial, SMBIOS
serial/UUID, or hostname, the call is **logged and answered with a fake value**
from your active *identity profile*.

This is aimed at the new wave of desktop AI apps (Codex, Copilot, Cursor, VS
Code, …) that fingerprint your device. Instead of changing your real machine
(which breaks activation and is irreversible), Chameleon just *lies to the apps
you choose* — and stops lying the moment you detach.

> **Your real machine is never modified.** Nothing is written to your registry
> or firmware. Detach (or toggle Protection off) and apps instantly see the
> real values again.

---

## Screenshots

**Identities** — each profile is a self-consistent set of fake hardware IDs; one click generates a fresh one, one click activates it.

![Identities](docs/identities.png)

**Live Monitor** — every hardware-ID call a protected app makes, in real time, with the real value it asked for and the value served back.

![Live Monitor](docs/monitor.png)

## Why interception instead of a "HWID changer"

Most HWID spoofers permanently rewrite registry keys or use a kernel driver to
patch firmware — machine-wide, risky, and hard to undo. Chameleon takes the
approach you actually want for privacy from *specific apps*:

* **Per-app** — you see exactly which app asked for which identifier.
* **Reversible by design** — hooks live only inside the target process.
* **No machine damage** — real IDs, licenses and activation are untouched.
* **Covers "firmware" too** — hooking `GetSystemFirmwareTable` means the app
  receives a fake BIOS/board serial even though the real firmware is unchanged.

---

## What gets intercepted

| Identifier | Windows function(s) hooked | Verified |
|---|---|---|
| **MachineGuid**, SQMClient MachineId, ProductId | `RegQueryValueEx`, `RegGetValue`, `RegEnumValue` | ✅ |
| **SMBIOS** system/board/chassis serial, system UUID, CPU id | `GetSystemFirmwareTable('RSMB')` | ✅ |
| **MAC** addresses | `GetAdaptersAddresses`, `GetAdaptersInfo` | ✅ |
| **Volume serial** | `GetVolumeInformation(W/A)`, `…ByHandleW` | ✅ |
| **Hostname** | `GetComputerName(W/A)` | ✅ |
| **WMI** serials / UUID / ProcessorId / MAC / hostname | client-side COM: `IWbemClassObject::Get` + property-enum `Next` | ✅ |

The `reg.exe` child process that `node-machine-id` (used by VS Code / Electron
apps) shells out to is caught automatically via Frida **child-gating**.

### WMI coverage
`WmiPrvSE.exe` (the WMI provider host) runs as NETWORK SERVICE and refuses
injection, so WMI is intercepted **client-side**: a protected app's WMI results
are unmarshaled into its own process and read via COM, which is hooked. This
covers the classic WMI stack — `wmic.exe`, .NET `System.Management`, PowerShell
`Get-WmiObject`, and Node libs that shell out to `wmic` (e.g. `systeminformation`).
Verified: `wmic bios/csproduct/cpu/baseboard/computersystem` and `Get-WmiObject`
all return the profile's values. Toggle it in the **Launch & Attach** tab
(applies to the next launch).

### AI CLI agents
The Launch tab auto-detects known AI coding CLIs on `PATH` — Codex, Claude Code,
GitHub Copilot (`copilot` / `gh copilot`), Gemini, Aider, Cursor Agent, Qwen,
opencode, Amazon Q — and launches them in a guarded shell so child-gating
instruments the node/python/reg helpers they spawn.

### Identity Files (complementary layer)
Some apps cache their id in a file instead of re-reading it. VS Code, its forks
(Insiders / VSCodium / Cursor) and Copilot-in-VS-Code keep telemetry ids in
`%APPDATA%\<App>\User\globalStorage\storage.json`
(`telemetry.machineId` / `macMachineId` / `devDeviceId` / `sqmId`). The
**Identity Files** tab backs that file up and writes your active profile's ids
into it, reversibly.

---

## Honest limitations

* **MI / CIM stack not rewritten.** `Get-CimInstance` (and apps using the newer
  MI API / `mi.dll`) use a different path than classic WMI and are not
  intercepted. Classic WMI (`wmic`, .NET `System.Management`, `Get-WmiObject`)
  **is** covered.
* **Hostname vs. local RPC.** Hostname is spoofed via `GetComputerName` and in
  WMI results, but **not** `GetComputerNameEx` — local RPC/DCOM binds to the WMI
  host through it, so spoofing it there breaks WMI (crashes .NET). The WMI hook
  redirects a client's fake-host connection back to local so `wmic` still works.
* **Run as Administrator** to attach to already-running processes and to
  instrument elevated targets.
* **Anti-tamper / EDR.** Frida injects into the target; hardened apps or
  aggressive AV/EDR may detect or block it. The mainstream AI/editor apps do
  not.
* Rotating ids can sign you out of apps or affect licenses tied to hardware.
  This tool is for protecting your own privacy on your own machine.

---

## Install & run

Already set up on this machine (Python 3.12, Frida, pywebview, WebView2 runtime).

```bat
run.bat
```

or

```bat
python app.py
```

Fresh machine:

```bat
pip install -r requirements.txt
:: install the Microsoft Edge WebView2 runtime if missing
python app.py
```

### Usage (minimal clicks)
1. **Identities** tab → **＋ New Identity** (generates a full, consistent fake
   machine in one click; the first one auto-activates).
2. **Launch & Attach** tab → **Launch protected** on a detected app, or paste an
   `.exe` path / a CLI command (e.g. `codex`), or attach to a running process.
3. **Live Monitor** tab → watch every intercepted call, real → served, per app
   and per function.
4. Toggle **Protection** off (top-right) to detach everything and restore real
   values.

---

## Project layout

```
hw_profile/
├─ app.py                    # pywebview window + JS API bridge + app discovery
├─ run.bat                   # launcher
├─ requirements.txt
├─ engine/
│  ├─ profiles.py            # identity generator + profile store
│  ├─ agent.js               # Frida agent: the hooks (injected into targets)
│  ├─ interceptor.py         # spawn/attach, child-gating, live stats
│  └─ identity_files.py      # VS Code family storage.json backup/patch/restore
├─ ui/
│  ├─ index.html  styles.css  app.js
└─ data/                     # profiles/, backups/, state.json  (created at runtime)
```

## Building the release .exe

A single self-contained `dist\Chameleon.exe` (~52 MB), dead modules excluded and
compiled with `--optimize 2`:

```bat
pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name Chameleon ^
  --add-data "ui;ui" --add-data "engine/agent.js;engine" ^
  --collect-all frida --collect-all pythonnet --collect-all clr_loader --collect-all webview ^
  --exclude-module tkinter --exclude-module PyQt5 --exclude-module PyQt6 ^
  --exclude-module PySide2 --exclude-module PySide6 --exclude-module PIL ^
  --exclude-module numpy --exclude-module pandas --exclude-module scipy ^
  --exclude-module matplotlib --exclude-module IPython --exclude-module pytest ^
  --exclude-module notebook --exclude-module sqlite3 ^
  --exclude-module webview.platforms.gtk --exclude-module webview.platforms.qt ^
  --exclude-module webview.platforms.cocoa --exclude-module webview.platforms.android ^
  --optimize 2 app.py
```

**On the size:** the weight is Frida's native core (`_frida.pyd` is ~112 MB
uncompressed; PyInstaller's zlib brings the whole app to ~52 MB). UPX is
intentionally **not** used — it can corrupt Frida's embedded agent and makes
antivirus false-positives far more likely.

**Two notes for distribution:**
- The WebView2 **runtime** must be present on the target machine (it is on
  Windows 11 and up-to-date Windows 10/Server; otherwise ship the Evergreen
  bootstrapper).
- Because it bundles Frida and injects into other processes, some antivirus /
  EDR may flag the exe. Run as Administrator.

## License

[MIT](LICENSE) (c) mohayo
