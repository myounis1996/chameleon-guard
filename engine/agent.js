/*
 * Chameleon Frida agent.
 *
 * Injected into a target app (and, via child-gating, its child processes such
 * as reg.exe). It hooks the Windows functions that return hardware / machine
 * identifiers, reports every call back to the Python host, and rewrites the
 * returned value to the active profile's fake value.
 *
 * Design rules:
 *   - Every hook body is wrapped so a failure NEVER propagates into the target.
 *   - We only ever rewrite an OUTPUT buffer in place, never resize it, so we
 *     cannot corrupt the caller's memory.
 *   - Nothing is persisted. Detaching the agent restores real behavior.
 */
'use strict';

let CONFIG = __CONFIG__;               // replaced by the Python host at injection
const hooked = [];                     // names of successfully installed hooks

/* ------------------------------------------------------------------ utils */

function report(api, key, real, served) {
  try {
    send({
      type: 'call',
      api: api,
      key: key,
      real: (real === undefined ? null : real),
      served: (served === undefined ? null : served),
    });
  } catch (e) { /* ignore */ }
}

function resolve(mod, name) {
  // Frida 17 removed the static Module.findExportByName(mod, name). Use the
  // per-module instance API, then fall back to a global export search.
  try {
    const m = Process.findModuleByName(mod);
    if (m) { const p = m.findExportByName(name); if (p) return p; }
  } catch (e) {}
  try {
    const m = Module.load(mod);            // force-load (e.g. iphlpapi) then look up
    if (m) { const p = m.findExportByName(name); if (p) return p; }
  } catch (e) {}
  try {
    if (Module.findGlobalExportByName) { const p = Module.findGlobalExportByName(name); if (p) return p; }
  } catch (e) {}
  // very old Frida fallback
  try {
    if (Module.findExportByName) { const p = Module.findExportByName(mod, name); if (p) return p; }
  } catch (e) {}
  return null;
}

const attachedAddrs = new Set();
function hook(mod, name, callbacks) {
  const p = resolve(mod, name);
  if (!p) return false;
  const key = p.toString();
  if (attachedAddrs.has(key)) return true;   // same address via another module alias
  try {
    Interceptor.attach(p, callbacks);
    attachedAddrs.add(key);
    hooked.push(name);
    return true;
  } catch (e) {
    return false;
  }
}

/* --------------------------------------------------------- registry paths */

const ROOTS = {
  '0x80000000': 'hkcr',
  '0x80000001': 'hkcu',
  '0x80000002': 'hklm',
  '0x80000003': 'hku',
  '0x80000005': 'hkcc',
};
const handlePaths = {};   // HKEY (string) -> lowercased full path

function rootName(hkey) {
  try {
    const key = '0x' + hkey.toUInt32().toString(16).toUpperCase().replace('0X', '');
    // normalize e.g. 0x80000002
    const norm = '0x' + (hkey.toUInt32() >>> 0).toString(16);
    if (ROOTS[norm]) return ROOTS[norm];
  } catch (e) {}
  const s = handlePaths[hkey.toString()];
  return s || null;
}

function pathFor(hkey) {
  const norm = (function () {
    try { return '0x' + (hkey.toUInt32() >>> 0).toString(16); } catch (e) { return null; }
  })();
  if (norm && ROOTS[norm]) return ROOTS[norm];
  return handlePaths[hkey.toString()] || null;
}

function trackOpen(parentHkey, subKeyPtr, phkResultPtr, wide) {
  try {
    if (phkResultPtr.isNull()) return;
    const parent = pathFor(parentHkey);
    let sub = '';
    try { sub = wide ? subKeyPtr.readUtf16String() : subKeyPtr.readAnsiString(); } catch (e) { sub = ''; }
    const full = ((parent || '?') + '\\' + (sub || '')).toLowerCase();
    const newH = phkResultPtr.readPointer().toString();
    handlePaths[newH] = full;
  } catch (e) {}
}

// Which fake value (if any) should be served for a given key path + value name?
function matchValue(pathLower, valueLower) {
  if (!pathLower || !valueLower) return null;
  if (pathLower.indexOf('microsoft\\cryptography') !== -1 && valueLower === 'machineguid')
    return { key: 'MachineGuid', val: CONFIG.machineGuid };
  if (pathLower.indexOf('microsoft\\sqmclient') !== -1 && valueLower === 'machineid')
    return { key: 'SQMClient.MachineId', val: CONFIG.sqmMachineId };
  if (pathLower.indexOf('windows nt\\currentversion') !== -1 && valueLower === 'productid')
    return { key: 'ProductId', val: CONFIG.productId };
  if (pathLower.indexOf('windows nt\\currentversion') !== -1 && valueLower === 'computername')
    return { key: 'ComputerName', val: CONFIG.computerName };
  if (pathLower.indexOf('currentversion\\windowsupdate') !== -1 && valueLower === 'susclientid')
    return { key: 'SusClientId', val: CONFIG.susClientId };
  if (pathLower.indexOf('idconfigdb\\hardware profiles') !== -1 && valueLower === 'hwprofileguid')
    return { key: 'HwProfileGuid', val: CONFIG.hwProfileGuid };
  if (pathLower.indexOf('windows nt\\currentversion') !== -1 && valueLower === 'buildguid')
    return { key: 'BuildGUID', val: CONFIG.buildGuid };
  return null;
}

// Write a REG_SZ string (wide or ansi) into an output buffer, in place only.
function writeRegString(lpData, lpcbData, lpType, avail, value, wide) {
  const needed = wide ? (value.length + 1) * 2 : (value.length + 1);
  if (!lpData.isNull()) {
    if (avail >= needed) {
      if (wide) lpData.writeUtf16String(value);
      else lpData.writeAnsiString(value);
      if (!lpcbData.isNull()) lpcbData.writeU32(needed);
      if (!lpType.isNull()) lpType.writeU32(1); // REG_SZ
      return true;
    }
    return false;
  }
  // size query
  if (!lpcbData.isNull()) lpcbData.writeU32(needed);
  return false;
}

/* -------------------------------------------------------- registry hooks */

function installRegistryHooks() {
  ['RegOpenKeyExW', 'RegOpenKeyExA'].forEach(function (name) {
    const wide = name.endsWith('W');
    hook('advapi32.dll', name, {
      onEnter: function (a) { this.parent = a[0]; this.sub = a[1]; this.phk = a[4]; this.wide = wide; },
      onLeave: function (r) { if (r.toInt32() === 0) trackOpen(this.parent, this.sub, this.phk, this.wide); },
    });
  });
  ['RegCreateKeyExW', 'RegCreateKeyExA'].forEach(function (name) {
    const wide = name.endsWith('W');
    hook('advapi32.dll', name, {
      onEnter: function (a) { this.parent = a[0]; this.sub = a[1]; this.phk = a[7]; this.wide = wide; },
      onLeave: function (r) { if (r.toInt32() === 0) trackOpen(this.parent, this.sub, this.phk, this.wide); },
    });
  });

  ['RegQueryValueExW', 'RegQueryValueExA'].forEach(function (name) {
    const wide = name.endsWith('W');
    hook('advapi32.dll', name, {
      onEnter: function (a) {
        this.wide = wide;
        this.path = pathFor(a[0]);
        try { this.vname = (wide ? a[1].readUtf16String() : a[1].readAnsiString()) || ''; }
        catch (e) { this.vname = ''; }
        this.lpType = a[3];
        this.lpData = a[4];
        this.lpcb = a[5];
        this.avail = 0;
        try { if (!this.lpcb.isNull()) this.avail = this.lpcb.readU32(); } catch (e) {}
      },
      onLeave: function (r) {
        const code = r.toInt32();
        if (code !== 0 && code !== 234 /*ERROR_MORE_DATA*/) return;
        const m = matchValue((this.path || '').toLowerCase(), this.vname.toLowerCase());
        if (!m) return;
        let real = null;
        try { if (!this.lpData.isNull()) real = this.wide ? this.lpData.readUtf16String() : this.lpData.readAnsiString(); } catch (e) {}
        const ok = writeRegString(this.lpData, this.lpcb, this.lpType, this.avail, m.val, this.wide);
        if (ok || this.lpData.isNull()) report(this.wide ? 'RegQueryValueExW' : 'RegQueryValueExA', m.key, real, m.val);
      },
    });
  });

  ['RegGetValueW', 'RegGetValueA'].forEach(function (name) {
    const wide = name.endsWith('W');
    hook('advapi32.dll', name, {
      onEnter: function (a) {
        this.wide = wide;
        const root = pathFor(a[0]) || '';
        let sub = '', val = '';
        try { sub = (wide ? a[1].readUtf16String() : a[1].readAnsiString()) || ''; } catch (e) {}
        try { val = (wide ? a[2].readUtf16String() : a[2].readAnsiString()) || ''; } catch (e) {}
        this.path = (root + '\\' + sub);
        this.vname = val;
        this.lpType = a[4];
        this.lpData = a[5];
        this.lpcb = a[6];
        this.avail = 0;
        try { if (!this.lpcb.isNull()) this.avail = this.lpcb.readU32(); } catch (e) {}
      },
      onLeave: function (r) {
        const code = r.toInt32();
        if (code !== 0 && code !== 234) return;
        const m = matchValue((this.path || '').toLowerCase(), (this.vname || '').toLowerCase());
        if (!m) return;
        let real = null;
        try { if (!this.lpData.isNull()) real = this.wide ? this.lpData.readUtf16String() : this.lpData.readAnsiString(); } catch (e) {}
        const ok = writeRegString(this.lpData, this.lpcb, this.lpType, this.avail, m.val, this.wide);
        if (ok || this.lpData.isNull()) report(this.wide ? 'RegGetValueW' : 'RegGetValueA', m.key, real, m.val);
      },
    });
  });

  // Enumeration path (reg.exe "REG QUERY key" without /v enumerates values).
  hook('advapi32.dll', 'RegEnumValueW', {
    onEnter: function (a) {
      this.path = pathFor(a[0]);
      this.lpName = a[2];
      this.lpType = a[5];
      this.lpData = a[6];
      this.lpcb = a[7];
      this.avail = 0;
      try { if (!this.lpcb.isNull()) this.avail = this.lpcb.readU32(); } catch (e) {}
    },
    onLeave: function (r) {
      if (r.toInt32() !== 0) return;
      let vname = '';
      try { vname = this.lpName.readUtf16String() || ''; } catch (e) {}
      const m = matchValue((this.path || '').toLowerCase(), vname.toLowerCase());
      if (!m) return;
      let real = null;
      try { if (!this.lpData.isNull()) real = this.lpData.readUtf16String(); } catch (e) {}
      const ok = writeRegString(this.lpData, this.lpcb, this.lpType, this.avail, m.val, true);
      if (ok || this.lpData.isNull()) report('RegEnumValueW', m.key, real, m.val);
    },
  });
}

/* ------------------------------------------------------------ SMBIOS */

function writeSmbiosUuid(ptr, g) {
  try {
    g = g.replace(/[{}\-]/g, '');
    if (g.length !== 32) return;
    const b = [];
    for (let i = 0; i < 16; i++) b.push(parseInt(g.substr(i * 2, 2), 16));
    // SMBIOS stores the first three fields little-endian.
    const out = [b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
                 b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]];
    ptr.writeByteArray(out);
  } catch (e) {}
}

function setSmbiosString(buffer, strings, wantIndex, val) {
  if (!wantIndex) return false;
  for (let i = 0; i < strings.length; i++) {
    const s = strings[i];
    if (s.index === wantIndex) {
      const bytes = [];
      for (let j = 0; j < s.len; j++) {
        bytes.push(j < val.length ? (val.charCodeAt(j) & 0x7F) : 0x30); // pad with '0'
      }
      try { buffer.add(s.off).writeByteArray(bytes); } catch (e) {}
      return true;
    }
  }
  return false;
}

function patchSmbios(buffer, totalLen) {
  const length = buffer.add(4).readU32();
  let p = 8;
  const limit = 8 + Math.min(length, totalLen);
  let changed = false;

  while (p + 4 <= limit) {
    const type = buffer.add(p).readU8();
    const flen = buffer.add(p + 1).readU8();
    if (flen < 4) break;

    // collect the string-set that follows the formatted area
    let q = p + flen;
    const strings = [];
    if (buffer.add(q).readU8() === 0 && buffer.add(q + 1).readU8() === 0) {
      q += 2;
    } else {
      let idx = 1;
      while (q < limit) {
        const s0 = q;
        while (q < limit && buffer.add(q).readU8() !== 0) q++;
        strings.push({ index: idx, off: s0, len: q - s0 });
        idx++;
        q++; // skip terminator
        if (q < limit && buffer.add(q).readU8() === 0) { q++; break; }
      }
    }

    try {
      if (type === 1) { // System Information
        if (flen > 0x07) changed |= setSmbiosString(buffer, strings, buffer.add(p + 0x07).readU8(), CONFIG.systemSerial);
        if (flen >= 0x18) { writeSmbiosUuid(buffer.add(p + 0x08), CONFIG.systemUuid); changed = true; }
      } else if (type === 2) { // Baseboard
        if (flen > 0x07) changed |= setSmbiosString(buffer, strings, buffer.add(p + 0x07).readU8(), CONFIG.baseboardSerial);
      } else if (type === 3) { // Chassis
        if (flen > 0x07) changed |= setSmbiosString(buffer, strings, buffer.add(p + 0x07).readU8(), CONFIG.chassisSerial);
      } else if (type === 0) { // BIOS
        // BIOS serial isn't a standard field; nothing identity-bearing to change.
      } else if (type === 4) { // Processor
        if (flen >= 0x10) {
          // ProcessorID is 8 bytes at offset 0x08
          const pid = CONFIG.processorId.replace(/[^0-9a-fA-F]/g, '').padEnd(16, '0').substr(0, 16);
          const bytes = [];
          for (let k = 0; k < 8; k++) bytes.push(parseInt(pid.substr(k * 2, 2), 16));
          try { buffer.add(p + 0x08).writeByteArray(bytes); changed = true; } catch (e) {}
        }
        if (flen > 0x20) changed |= setSmbiosString(buffer, strings, buffer.add(p + 0x20).readU8(), CONFIG.systemSerial);
      }
    } catch (e) {}

    p = q;
    if (type === 127) break; // end-of-table
  }
  return changed;
}

function installFirmwareHook() {
  hook('kernel32.dll', 'GetSystemFirmwareTable', {
    onEnter: function (a) {
      this.provider = a[0].toUInt32() >>> 0;
      this.buffer = a[2];
      this.size = a[3].toUInt32() >>> 0;
    },
    onLeave: function (r) {
      const written = r.toUInt32() >>> 0;
      if (this.provider !== 0x52534D42) return;      // 'RSMB'
      if (this.buffer.isNull() || written === 0 || written > this.size) return;
      try {
        const changed = patchSmbios(this.buffer, written);
        if (changed) report('GetSystemFirmwareTable', 'SMBIOS', '(real firmware)',
                            CONFIG.systemSerial + ' / ' + CONFIG.baseboardSerial);
      } catch (e) {}
    },
  });
}

/* ------------------------------------------------------- network (MAC) */

function installMacHooks() {
  hook('iphlpapi.dll', 'GetAdaptersInfo', {
    onEnter: function (a) { this.p = a[0]; },
    onLeave: function (r) {
      if (r.toInt32() !== 0 || this.p.isNull()) return;
      let node = this.p, guard = 0, real = null;
      while (!node.isNull() && guard < 64) {
        try {
          const alen = node.add(404).readU32();
          if (alen >= 6) {
            if (real === null) { try { real = Array.prototype.map.call(node.add(408).readByteArray(6) ? new Uint8Array(node.add(408).readByteArray(6)) : [], function (x) { return ('0' + x.toString(16)).slice(-2); }).join(':'); } catch (e) {} }
            node.add(408).writeByteArray(CONFIG.mac.slice(0, 6));
          }
          node = node.readPointer();
        } catch (e) { break; }
        guard++;
      }
      report('GetAdaptersInfo', 'MAC', real, macStr());
    },
  });

  hook('iphlpapi.dll', 'GetAdaptersAddresses', {
    onEnter: function (a) { this.p = a[3]; },
    onLeave: function (r) {
      if (r.toInt32() !== 0 || this.p.isNull()) return;
      let node = this.p, guard = 0, real = null;
      while (!node.isNull() && guard < 64) {
        try {
          const plen = node.add(88).readU32();
          if (plen >= 6) {
            if (real === null) { try { real = fmtMac(new Uint8Array(node.add(80).readByteArray(6))); } catch (e) {} }
            node.add(80).writeByteArray(CONFIG.mac.slice(0, 6));
          }
          node = node.add(8).readPointer();
        } catch (e) { break; }
        guard++;
      }
      report('GetAdaptersAddresses', 'MAC', real, macStr());
    },
  });
}

function fmtMac(u8) {
  return Array.prototype.map.call(u8, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(':').toUpperCase();
}
function macStr() {
  return CONFIG.mac.map(function (x) { return ('0' + (x & 0xff).toString(16)).slice(-2); }).join(':').toUpperCase();
}

/* -------------------------------------------------- volume serial */

function installVolumeHooks() {
  ['GetVolumeInformationW', 'GetVolumeInformationA'].forEach(function (name) {
    hook('kernel32.dll', name, {
      onEnter: function (a) { this.pSerial = a[3]; },
      onLeave: function (r) {
        if (r.toInt32() === 0 || this.pSerial.isNull()) return;
        let real = null;
        try { real = this.pSerial.readU32(); } catch (e) {}
        try { this.pSerial.writeU32(CONFIG.volumeSerial >>> 0); } catch (e) { return; }
        report(name, 'VolumeSerial',
               real === null ? null : fmtSerial(real), fmtSerial(CONFIG.volumeSerial));
      },
    });
  });
  hook('kernel32.dll', 'GetVolumeInformationByHandleW', {
    onEnter: function (a) { this.pSerial = a[3]; },
    onLeave: function (r) {
      if (r.toInt32() === 0 || this.pSerial.isNull()) return;
      let real = null;
      try { real = this.pSerial.readU32(); } catch (e) {}
      try { this.pSerial.writeU32(CONFIG.volumeSerial >>> 0); } catch (e) { return; }
      report('GetVolumeInformationByHandleW', 'VolumeSerial',
             real === null ? null : fmtSerial(real), fmtSerial(CONFIG.volumeSerial));
    },
  });
}
function fmtSerial(v) {
  const h = ((v >>> 0).toString(16).toUpperCase()).padStart(8, '0');
  return h.substr(0, 4) + '-' + h.substr(4, 4);
}

/* -------------------------------------------------- computer name */

function installComputerNameHooks() {
  hook('kernel32.dll', 'GetComputerNameW', {
    onEnter: function (a) { this.buf = a[0]; this.pSize = a[1]; try { this.cap = this.pSize.readU32(); } catch (e) { this.cap = 0; } },
    onLeave: function (r) {
      if (r.toInt32() === 0 || this.buf.isNull()) return;
      let real = null; try { real = this.buf.readUtf16String(); } catch (e) {}
      const name = CONFIG.computerName;
      if (name.length + 1 > this.cap) return;
      try { this.buf.writeUtf16String(name); if (!this.pSize.isNull()) this.pSize.writeU32(name.length); } catch (e) { return; }
      report('GetComputerNameW', 'ComputerName', real, name);
    },
  });
  hook('kernel32.dll', 'GetComputerNameA', {
    onEnter: function (a) { this.buf = a[0]; this.pSize = a[1]; try { this.cap = this.pSize.readU32(); } catch (e) { this.cap = 0; } },
    onLeave: function (r) {
      if (r.toInt32() === 0 || this.buf.isNull()) return;
      let real = null; try { real = this.buf.readAnsiString(); } catch (e) {}
      const name = CONFIG.computerName;
      if (name.length + 1 > this.cap) return;
      try { this.buf.writeAnsiString(name); if (!this.pSize.isNull()) this.pSize.writeU32(name.length); } catch (e) { return; }
      report('GetComputerNameA', 'ComputerName', real, name);
    },
  });
  // GetComputerNameEx is also used by local RPC/COM to bind to the WMI host, and
  // spoofing it *there* breaks WMI/DCOM. So we hook it but only rewrite when the
  // immediate caller is NOT a system RPC/COM/WMI module: real application reads
  // get the fake name, while RPC/WMI internals keep seeing the real one.
  const SYS_CALLERS = {
    'rpcrt4.dll': 1, 'combase.dll': 1, 'ole32.dll': 1, 'rpcss.dll': 1, 'sspicli.dll': 1,
    'secur32.dll': 1, 'wkscli.dll': 1, 'netutils.dll': 1, 'sechost.dll': 1,
    'wbemprox.dll': 1, 'wbemcomn.dll': 1, 'fastprox.dll': 1, 'wbemsvc.dll': 1, 'wbemcore.dll': 1,
  };
  const HOST_FORMATS = { 0: 1, 1: 1, 4: 1, 5: 1 };
  function callerModule(ret) {
    try { const m = Process.findModuleByAddress(ret); return m ? m.name.toLowerCase() : null; }
    catch (e) { return null; }
  }
  ['GetComputerNameExW', 'GetComputerNameExA'].forEach(function (name) {
    const wide = name.endsWith('W');
    hook('kernel32.dll', name, {
      onEnter: function (a) {
        this.nameType = a[0].toInt32();
        this.buf = a[1]; this.pSize = a[2];
        this.ret = this.returnAddress;
        try { this.cap = this.pSize.readU32(); } catch (e) { this.cap = 0; }
      },
      onLeave: function (r) {
        if (r.toInt32() === 0 || this.buf.isNull()) return;
        if (!HOST_FORMATS[this.nameType]) return;
        const cm = callerModule(this.ret);
        if (cm && SYS_CALLERS[cm]) return;         // leave RPC/COM/WMI internals alone
        let real = null;
        try { real = wide ? this.buf.readUtf16String() : this.buf.readAnsiString(); } catch (e) {}
        const val = CONFIG.computerName;
        if (val.length + 1 > this.cap) return;
        try {
          if (wide) this.buf.writeUtf16String(val); else this.buf.writeAnsiString(val);
          if (!this.pSize.isNull()) this.pSize.writeU32(val.length);
        } catch (e) { return; }
        report(name, 'ComputerName', real, val);
      },
    });
  });
}

/* --------------------------------------------- disk serial (IOCTL) */

function overwriteAsciiInPlace(ptr, maxLen, val) {
  const bytes = [];
  for (let i = 0; i < maxLen; i++) bytes.push(i < val.length ? (val.charCodeAt(i) & 0x7F) : 0x30);
  try { ptr.writeByteArray(bytes); } catch (e) {}
}

function installDiskHooks() {
  const IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
  ['kernel32.dll', 'kernelbase.dll'].forEach(function (mod) {
    hook(mod, 'DeviceIoControl', {
      onEnter: function (a) {
        this.ioctl = a[1].toUInt32() >>> 0;
        this.outBuf = a[4];
        this.outSize = a[5].toUInt32() >>> 0;
      },
      onLeave: function (r) {
        if (this.ioctl !== IOCTL_STORAGE_QUERY_PROPERTY) return;
        if (r.toInt32() === 0 || this.outBuf.isNull()) return;
        try {
          // STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset is at byte offset 24
          const off = this.outBuf.add(24).readU32();
          if (off === 0 || off === 0xffffffff || off >= this.outSize) return;
          const sp = this.outBuf.add(off);
          let real = null;
          try { real = sp.readAnsiString(); } catch (e) {}
          if (!real || real.length === 0) return;
          overwriteAsciiInPlace(sp, real.length, CONFIG.diskSerial);
          report('DeviceIoControl', 'DiskSerial', real.trim(), CONFIG.diskSerial);
        } catch (e) {}
      },
    });
  });
}

/* -------------------------- WMI + MI/CIM (client-side COM hooks) */
// WmiPrvSE.exe can't be injected reliably (it runs as NETWORK SERVICE), so both
// management stacks are intercepted *in the client*:
//
//   * Classic WMI  -- wmic.exe, .NET System.Management, Get-WmiObject, Node libs
//     that shell out to wmic. The app calls IWbemServices::ExecQuery /
//     CreateInstanceEnum / GetObject and reads properties off the returned
//     IWbemClassObject.
//   * MI / CIM     -- Get-CimInstance, Get-PhysicalDisk, Get-NetAdapter and any
//     app on the newer MI API (mi.dll). Locally, mi.dll does NOT invent its own
//     transport: it loads wmidcom.dll, which is an ordinary DCOM WMI client
//     (CLSID_WbemLocator -> IWbemLocator::ConnectServer -> IWbemServices) that
//     uses the *asynchronous* entry points and receives results through an
//     IWbemObjectSink. Results are unmarshaled into the app's own process as
//     IWbemClassObject, exactly like classic WMI, and wmidcom then reads them
//     with IWbemClassObject::Get/Next to build each MI_Instance.
//
// So both stacks funnel through the same two COM methods, and hooking those --
// plus the async sinks that deliver MI's objects -- covers them together. This
// deliberately avoids hooking mi.dll's own function tables, whose in-memory
// layout is build-specific; every interface used here is frozen COM ABI.

const PTR = Process.pointerSize;
const CLSID_WbemLocator = [0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11,
                           0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24];
const VT_BSTR = 8;
const VT_ARRAY = 0x2000;
// Win32_Volume.SerialNumber is a uint32 rather than a string; WMI hands those
// back as VT_I4/VT_UI4 (and occasionally VT_INT/VT_UINT).
const VT_NUMERIC = { 3: 1, 19: 1, 22: 1, 23: 1 };
const vtSeen = new Set();      // hooked vtable-method addresses (dedupe)
const guardTids = new Set();   // threads currently inside our own COM call
let OLE = null;
let CLASS_BSTR = null;         // cached BSTR("__CLASS")
let REAL_HOST = null;          // real machine name, captured before we hook it

function ole() {
  if (OLE) return OLE;
  const a = resolve('oleaut32.dll', 'SysAllocString');
  const f = resolve('oleaut32.dll', 'SysFreeString');
  const c = resolve('oleaut32.dll', 'VariantClear');
  OLE = {
    alloc: a ? new NativeFunction(a, 'pointer', ['pointer']) : null,
    free: f ? new NativeFunction(f, 'void', ['pointer']) : null,
    clear: c ? new NativeFunction(c, 'int', ['pointer']) : null,
  };
  return OLE;
}

function bstr(s) {
  const o = ole();
  return o.alloc ? o.alloc(Memory.allocUtf16String(s)) : null;
}

function guidEq(p, bytes) {
  try {
    const b = new Uint8Array(p.readByteArray(16));
    for (let i = 0; i < 16; i++) if (b[i] !== bytes[i]) return false;
    return true;
  } catch (e) { return false; }
}

/* -- the real machine name, read once before installComputerNameHooks runs -- */

function captureRealHost() {
  try {
    const p = resolve('kernel32.dll', 'GetComputerNameW');
    if (!p) return;
    const fn = new NativeFunction(p, 'int', ['pointer', 'pointer']);
    const buf = Memory.alloc(128);
    const cch = Memory.alloc(4);
    cch.writeU32(64);
    if (fn(buf, cch)) REAL_HOST = buf.readUtf16String();
  } catch (e) {}
}

function replaceCI(s, find, repl) {
  if (!s || !find) return s;
  const ls = s.toLowerCase(), lf = find.toLowerCase();
  let out = '', i = 0;
  for (;;) {
    const j = ls.indexOf(lf, i);
    if (j < 0) return out + s.slice(i);
    out += s.slice(i, j) + repl;
    i = j + lf.length;
  }
}

// real host -> fake host, for values flowing out to the app.
function hostOut(s) {
  if (!s || !REAL_HOST || !CONFIG.computerName) return s;
  return replaceCI(s, REAL_HOST, CONFIG.computerName);
}
// fake host -> real host, for object paths / queries flowing back into WMI.
function hostIn(s) {
  if (!s || !CONFIG.computerName) return s;
  return replaceCI(s, CONFIG.computerName, REAL_HOST || '.');
}
function isRealHost(s) {
  return !!(s && REAL_HOST && s.toLowerCase() === REAL_HOST.toLowerCase());
}

/* ------------------------------------------------- value formatting */

function macColon() {
  return CONFIG.mac.slice(0, 6).map(function (x) {
    return ('0' + (x & 0xff).toString(16)).slice(-2);
  }).join(':').toUpperCase();
}
// "AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF". These property
// names are also used by CIM classes for values that are not MAC addresses.
function looksLikeMac(s) {
  if (typeof s !== 'string') return false;
  if (s.length !== 12 && s.length !== 17) return false;
  return /^[0-9A-Fa-f]{12}$/.test(s.split(':').join('').split('-').join(''));
}
// Mimic however the real value was punctuated: "AA:BB:..", "AA-BB-..", "AABB..".
function macLike(real) {
  const h = macColon().split(':');
  if (typeof real === 'string') {
    if (real.indexOf(':') >= 0) return h.join(':');
    if (real.indexOf('-') >= 0) return h.join('-');
    if (/^[0-9A-Fa-f]{12}$/.test(real)) return h.join('');
  }
  return h.join(':');
}
function volPlain() {
  return ((CONFIG.volumeSerial >>> 0).toString(16).toUpperCase()).padStart(8, '0');
}

// Stable per-profile pseudonym for an opaque hardware id (MSFT_PhysicalDisk
// UniqueId is an EUI/NAA string, one per disk). Deriving it from the real value
// keeps two disks distinct instead of collapsing them onto one id.
function h32(s, seed) {
  let h = seed >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i) & 0xff;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return ('00000000' + h.toString(16).toUpperCase()).slice(-8);
}
function pseudoHex(real) {
  const salt = (CONFIG.machineGuid || CONFIG.profileId || '') + '|' + real;
  return h32(salt, 0x811c9dc5) + h32(salt, 0x01000193);
}
function fakeUniqueId(real) {
  if (!real) return null;
  const m = /^([A-Za-z]+\.)(.+)$/.exec(real);       // "eui.<hex>", "naa.<hex>"
  if (m) return m[1] + pseudoHex(real).substr(0, Math.min(m[2].length, 16));
  if (/^[0-9A-Fa-f]{8,}$/.test(real)) return pseudoHex(real).substr(0, Math.min(real.length, 16));
  return CONFIG.diskSerial;
}

/* ------------------------------------------------- property mapping */

// Fast pre-filter: only these property names can ever be rewritten, so the vast
// majority of property reads cost one lookup and nothing else.
const SENSITIVE = {
  'uuid': 1, 'processorid': 1, 'identifyingnumber': 1, 'serialnumber': 1,
  'macaddress': 1, 'permanentaddress': 1, 'networkaddresses': 1,
  'volumeserialnumber': 1,
  'dnshostname': 1, 'name': 1, 'caption': 1, 'csname': 1, 'pscomputername': 1,
  'uniqueid': 1, 'objectid': 1, '__server': 1, '__path': 1,
};

// Only 'serialnumber' and 'uniqueid' actually need the object's class; the rest
// are decided from the property name and the real value alone.
function serialForClass(cls) {
  if (cls.indexOf('baseboard') >= 0 || cls.indexOf('_card') >= 0) return CONFIG.baseboardSerial;
  if (cls.indexOf('enclosure') >= 0 || cls.indexOf('chassis') >= 0) return CONFIG.chassisSerial;
  if (cls.indexOf('disk') >= 0 || cls.indexOf('physicalmedia') >= 0 ||
      cls.indexOf('storage') >= 0 || cls.indexOf('volume') >= 0) return CONFIG.diskSerial;
  return CONFIG.biosSerial;                       // BIOS, and anything unknown
}

function wmiValueFor(prop, obj, real) {
  switch (prop) {
    case 'uuid': return CONFIG.systemUuid;
    case 'processorid': return CONFIG.processorId;
    case 'identifyingnumber': return CONFIG.systemSerial;
    case 'volumeserialnumber': return volPlain();
    case 'dnshostname': return CONFIG.computerName;
    case '__server': return CONFIG.computerName;
    // MACAddress (Win32_*), PermanentAddress / NetworkAddresses[] (MSFT_NetAdapter,
    // which is what Get-NetAdapter reads). Shape-checked, because CIM classes
    // also use these names for things that are not MACs.
    case 'macaddress':
    case 'permanentaddress':
    case 'networkaddresses':
      return looksLikeMac(real) ? macLike(real) : null;
    // Any property whose value *is* the machine name: Win32_ComputerSystem.Name
    // and .Caption, Win32_OperatingSystem.CSName, ... This deliberately leaves
    // Win32_ComputerSystemProduct.Name (the model) alone.
    case 'name':
    case 'caption':
    case 'csname':
    case 'pscomputername': {
      if (isRealHost(real)) return CONFIG.computerName;
      if (REAL_HOST) return null;                 // known host, not a match
      const cls = classOf(obj) || '';             // fallback if capture failed
      if (prop === 'csname' && cls.indexOf('operatingsystem') >= 0) return CONFIG.computerName;
      if (prop !== 'csname' && cls.indexOf('computersystem') >= 0 &&
          cls.indexOf('product') < 0) return CONFIG.computerName;
      return null;
    }
    // Object paths carry "\\<host>\root\..."; rewrite only the host part.
    case '__path':
    case 'objectid': {
      const s = hostOut(real);
      return (s && s !== real) ? s : null;
    }
    case 'serialnumber': return serialForClass(classOf(obj) || '');
    case 'uniqueid': {
      const cls = classOf(obj) || '';
      if (cls.indexOf('disk') < 0 && cls.indexOf('physicalmedia') < 0) return null;
      return fakeUniqueId(real);
    }
    default: return null;
  }
}

/* --------------------------------------------------- COM plumbing */

function hookVtableMethod(obj, index, label, cbs) {
  try {
    const fn = obj.readPointer().add(index * PTR).readPointer();
    const k = fn.toString();
    if (vtSeen.has(k)) return;
    vtSeen.add(k);
    Interceptor.attach(fn, cbs);
    hooked.push(label);
  } catch (e) {}
}

// IWbemClassObject::Get, used both to serve the app and (re-entrantly, under a
// guard) to ask an object for its own __CLASS.
function classOf(obj) {
  const tid = Process.getCurrentThreadId();
  try {
    const fn = obj.readPointer().add(4 * PTR).readPointer();
    if (fn.isNull()) return null;
    if (!CLASS_BSTR) CLASS_BSTR = bstr('__CLASS');
    if (!CLASS_BSTR) return null;
    const nf = new NativeFunction(fn, 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer']);
    const v = Memory.alloc(24);
    v.writeByteArray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    guardTids.add(tid);
    const hr = nf(obj, CLASS_BSTR, 0, v, ptr(0), ptr(0));
    guardTids.delete(tid);
    let cls = null;
    if (hr === 0 && v.readU16() === VT_BSTR) {
      const b = v.add(8).readPointer();
      if (!b.isNull()) cls = b.readUtf16String();
    }
    if (ole().clear) ole().clear(v);
    return cls ? cls.toLowerCase() : null;
  } catch (e) { guardTids.delete(tid); return null; }
}

// Swap a BSTR held in a VARIANT/SAFEARRAY slot. The caller owns the string and
// will SysFreeString it, so ownership stays correct.
function swapBstr(slot, val) {
  const o = ole();
  if (!o.alloc) return false;
  const nb = o.alloc(Memory.allocUtf16String(val));
  if (nb.isNull()) return false;
  const old = slot.readPointer();
  slot.writePointer(nb);
  if (!old.isNull() && o.free) o.free(old);
  return true;
}

function rewriteVariant(pVal, prop, self, label) {
  try {
    if (!prop || pVal.isNull()) return;
    const p = prop.toLowerCase();
    if (!SENSITIVE[p]) return;
    const vt = pVal.readU16();

    if (vt === VT_BSTR) {
      const slot = pVal.add(8);
      const cur = slot.readPointer();
      const real = cur.isNull() ? null : cur.readUtf16String();
      const val = wmiValueFor(p, self, real);
      if (val === null || val === real) return;
      if (!swapBstr(slot, val)) return;
      report(label, prop, real, val);
      return;
    }

    if (VT_NUMERIC[vt]) {
      // The only numeric identifier WMI/CIM exposes is the volume serial.
      if (p !== 'serialnumber') return;
      if ((classOf(self) || '').indexOf('volume') < 0) return;
      const slot = pVal.add(8);
      const real = slot.readU32() >>> 0;
      const val = CONFIG.volumeSerial >>> 0;
      if (real === val) return;
      slot.writeU32(val);
      report(label, prop, fmtSerial(real), fmtSerial(val));
      return;
    }

    if (vt === (VT_BSTR | VT_ARRAY)) {             // string[] properties
      const sa = pVal.add(8).readPointer();
      if (sa.isNull() || sa.readU16() !== 1) return;   // 1-dimensional only
      const data = sa.add(16).readPointer();
      const n = sa.add(24).readU32();
      if (data.isNull() || n > 4096) return;
      for (let i = 0; i < n; i++) {
        const slot = data.add(i * PTR);
        const cur = slot.readPointer();
        const real = cur.isNull() ? null : cur.readUtf16String();
        const val = wmiValueFor(p, self, real);
        if (val === null || val === real) continue;
        if (swapBstr(slot, val)) report(label, prop, real, val);
      }
    }
  } catch (e) {}
}

// mi.dll's local transport is wmidcom.dll, and miutils.dll is the helper that
// turns each IWbemClassObject into an MI_Instance -- so a read coming from
// either is a CIM/MI read rather than a classic WMI one. Only computed when
// we are about to rewrite, so it costs nothing on ordinary property reads.
const MI_MODULES = { 'miutils.dll': 1, 'wmidcom.dll': 1, 'mi.dll': 1 };

function stackTag(ret) {
  try {
    const m = Process.findModuleByAddress(ret);
    if (m && MI_MODULES[m.name.toLowerCase()]) return 'MI/CIM';
  } catch (e) {}
  return 'WMI';
}

function registerObject(obj) {
  try {
    if (obj.isNull()) return;
    // Path A: app reads a named property -> IWbemClassObject::Get (idx 4)
    hookVtableMethod(obj, 4, 'IWbemClassObject::Get', {
      onEnter: function (a) { this.self = a[0]; this.pName = a[1]; this.pVal = a[3]; this.ret = this.returnAddress; },
      onLeave: function (r) {
        if (r.toInt32() !== 0) return;
        if (guardTids.has(Process.getCurrentThreadId())) return;
        let prop = null;
        try { prop = this.pName.readUtf16String(); } catch (e) {}
        if (!prop || !SENSITIVE[prop.toLowerCase()]) return;
        rewriteVariant(this.pVal, prop, this.self, stackTag(this.ret) + '::Get');
      },
    });
    // Path B: app enumerates properties -> IWbemClassObject::Next (idx 9),
    // returning each property's name (*strName) and value (*pVal). This is how
    // wmic.exe reads values and how wmidcom builds an MI_Instance.
    hookVtableMethod(obj, 9, 'IWbemClassObject::Next(prop)', {
      onEnter: function (a) { this.self = a[0]; this.pName = a[2]; this.pVal = a[3]; this.ret = this.returnAddress; },
      onLeave: function (r) {
        if (r.toInt32() !== 0) return;
        if (guardTids.has(Process.getCurrentThreadId())) return;
        let prop = null;
        try { const b = this.pName.readPointer(); if (!b.isNull()) prop = b.readUtf16String(); } catch (e) {}
        if (!prop || !SENSITIVE[prop.toLowerCase()]) return;
        rewriteVariant(this.pVal, prop, this.self, stackTag(this.ret) + '::Enum');
      },
    });
  } catch (e) {}
}

// Async results (the path MI/CIM uses) arrive as IWbemObjectSink::Indicate(
// LONG count, IWbemClassObject** objs). Hook on ENTER so the object hooks are
// in place before the sink reads anything.
function hookSink(p) {
  try {
    if (p.isNull()) return;
    hookVtableMethod(p, 3, 'IWbemObjectSink::Indicate', {
      onEnter: function (a) {
        try {
          const n = a[1].toInt32();
          const arr = a[2];
          if (arr.isNull() || n <= 0 || n > 4096) return;
          for (let i = 0; i < n; i++) {
            const o = arr.add(i * PTR).readPointer();
            if (!o.isNull()) { registerObject(o); break; }
          }
        } catch (e) {}
      },
    });
  } catch (e) {}
}

// An app that read the fake hostname may hand it back to WMI as a server name,
// object path or query filter. Swap it for the real one on the way in so the
// call still resolves, then release our temporary string on return.
function deFakeArg(state, a, idx) {
  try {
    const p = a[idx];
    if (p.isNull() || !CONFIG.computerName) return;
    const s = p.readUtf16String();
    if (!s || s.toLowerCase().indexOf(CONFIG.computerName.toLowerCase()) < 0) return;
    const nb = bstr(hostIn(s));
    if (!nb || nb.isNull()) return;
    a[idx] = nb;
    state.tmpBstr = nb;
  } catch (e) {}
}
function freeTmp(state) {
  try { if (state.tmpBstr && ole().free) ole().free(state.tmpBstr); } catch (e) {}
  state.tmpBstr = null;
}

function installWmiClientHooks() {
  if (!CONFIG.wmi) return;

  const nextCbs = {                    // IEnumWbemClassObject::Next
    onEnter: function (a) { this.ap = a[3]; this.pnum = a[4]; },
    onLeave: function (r) {
      try {
        if (this.ap.isNull() || this.pnum.isNull()) return;
        const n = this.pnum.readU32();     // only the returned count is valid
        for (let i = 0; i < n; i++) {
          const o = this.ap.add(i * PTR).readPointer();
          if (!o.isNull()) registerObject(o);
        }
      } catch (e) {}
    },
  };

  // -- synchronous entry points (classic WMI) --
  const execQueryCbs = {
    onEnter: function (a) { this.pp = a[5]; deFakeArg(this, a, 2); },
    onLeave: function (r) {
      freeTmp(this);
      if (r.toInt32() === 0) { try { hookVtableMethod(this.pp.readPointer(), 4, 'IEnumWbemClassObject::Next', nextCbs); } catch (e) {} }
    },
  };
  const createEnumCbs = {
    onEnter: function (a) { this.pp = a[4]; },
    onLeave: function (r) { if (r.toInt32() === 0) { try { hookVtableMethod(this.pp.readPointer(), 4, 'IEnumWbemClassObject::Next', nextCbs); } catch (e) {} } },
  };
  const getObjectCbs = {
    onEnter: function (a) { this.pp = a[4]; deFakeArg(this, a, 1); },
    onLeave: function (r) {
      freeTmp(this);
      if (r.toInt32() === 0) { try { registerObject(this.pp.readPointer()); } catch (e) {} }
    },
  };

  // -- asynchronous entry points (the ones mi.dll/wmidcom drives) --
  const execQueryAsyncCbs = {
    onEnter: function (a) { deFakeArg(this, a, 2); hookSink(a[5]); },
    onLeave: function () { freeTmp(this); },
  };
  const createEnumAsyncCbs = {
    onEnter: function (a) { hookSink(a[4]); },
  };
  const getObjectAsyncCbs = {
    onEnter: function (a) { deFakeArg(this, a, 1); hookSink(a[4]); },
    onLeave: function () { freeTmp(this); },
  };

  const connectCbs = {
    onEnter: function (a) {
      this.pp = a[8];
      // A client that read the fake hostname may try to connect to
      // \\<fake>\root\cimv2, which isn't reachable -- point it back at the real
      // machine while the app still sees the fake name everywhere else.
      deFakeArg(this, a, 1);
    },
    onLeave: function (r) {
      freeTmp(this);
      if (r.toInt32() !== 0) return;
      try {
        const svc = this.pp.readPointer();
        hookVtableMethod(svc, 6,  'IWbemServices::GetObject', getObjectCbs);
        hookVtableMethod(svc, 7,  'IWbemServices::GetObjectAsync', getObjectAsyncCbs);
        hookVtableMethod(svc, 18, 'IWbemServices::CreateInstanceEnum', createEnumCbs);
        hookVtableMethod(svc, 19, 'IWbemServices::CreateInstanceEnumAsync', createEnumAsyncCbs);
        hookVtableMethod(svc, 20, 'IWbemServices::ExecQuery', execQueryCbs);
        hookVtableMethod(svc, 21, 'IWbemServices::ExecQueryAsync', execQueryAsyncCbs);
      } catch (e) {}
    },
  };

  const cci = resolve('combase.dll', 'CoCreateInstance') || resolve('ole32.dll', 'CoCreateInstance');
  if (cci) {
    Interceptor.attach(cci, {
      onEnter: function (a) { this.rclsid = a[0]; this.ppv = a[4]; },
      onLeave: function (r) {
        if (r.toInt32() !== 0) return;
        if (!guidEq(this.rclsid, CLSID_WbemLocator)) return;
        try { hookVtableMethod(this.ppv.readPointer(), 3, 'IWbemLocator::ConnectServer', connectCbs); } catch (e) {}
      },
    });
    hooked.push('CoCreateInstance(WbemLocator)');
  }
}

/* ------------------------------------------------------------ boot */

function main() {
  // Read the real machine name first: installComputerNameHooks() is about to
  // make every later read of it return the profile's fake name, and the WMI /
  // MI layer needs the real one to recognise (and repair) host references.
  try { captureRealHost(); } catch (e) {}

  try { installRegistryHooks(); } catch (e) {}
  try { installFirmwareHook(); } catch (e) {}
  try { installMacHooks(); } catch (e) {}
  try { installVolumeHooks(); } catch (e) {}
  try { installComputerNameHooks(); } catch (e) {}
  try { installDiskHooks(); } catch (e) {}
  try { installWmiClientHooks(); } catch (e) {}

  send({ type: 'ready', pid: Process.id, hooked: hooked, profile: CONFIG.profileName });
}

// allow the host to swap the served profile live, without re-injecting
function listen(msg) {
  try {
    if (msg && msg.type === 'config' && msg.config) CONFIG = msg.config;
  } catch (e) {}
  recv('config', listen);
}
recv('config', listen);

main();
