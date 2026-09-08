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

function hook(mod, name, callbacks) {
  const p = resolve(mod, name);
  if (!p) return false;
  try {
    Interceptor.attach(p, callbacks);
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
  // NOTE: We deliberately do NOT hook GetComputerNameEx*. Local RPC/COM builds
  // the binding to the WMI host (\\<name>\root\cimv2) via GetComputerNameEx, so
  // spoofing it there breaks WMI/DCOM entirely ("Invalid access to memory
  // location"). Apps still get a spoofed name via GetComputerName (above) and,
  // for WMI consumers, via Win32_ComputerSystem.Name in the WMI hook below.
}

/* ------------------------------------------ WMI (client-side COM hooks) */
// WmiPrvSE.exe can't be injected reliably (it runs as NETWORK SERVICE), so we
// intercept WMI *in the client*: when the app runs a query, result objects are
// unmarshaled into its own process and it reads properties via
// IWbemClassObject::Get. We walk the COM chain from CoCreateInstance(WbemLocator)
// to reach that Get and rewrite sensitive property values in place. Covers the
// classic WMI stack (wmic.exe, .NET System.Management, Get-WmiObject, Node libs
// that shell out to wmic). The newer MI/CIM stack (Get-CimInstance) is separate.

const PTR = Process.pointerSize;
const CLSID_WbemLocator = [0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11,
                           0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24];
const vtSeen = new Set();      // hooked vtable-method addresses (dedupe)
const classMap = {};           // IWbemClassObject ptr -> lowercased __CLASS
let wmiGuard = false;          // suppress our own Get hook during __CLASS lookup
let OLE = null;

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

function guidEq(p, bytes) {
  try {
    const b = new Uint8Array(p.readByteArray(16));
    for (let i = 0; i < 16; i++) if (b[i] !== bytes[i]) return false;
    return true;
  } catch (e) { return false; }
}

function macColon() {
  return CONFIG.mac.map(function (x) { return ('0' + (x & 0xff).toString(16)).slice(-2); }).join(':').toUpperCase();
}
function volPlain() {
  return ((CONFIG.volumeSerial >>> 0).toString(16).toUpperCase()).padStart(8, '0');
}

function wmiValueFor(prop, cls) {
  prop = (prop || '').toLowerCase();
  cls = (cls || '').toLowerCase();
  switch (prop) {
    case 'uuid': return CONFIG.systemUuid;
    case 'processorid': return CONFIG.processorId;
    case 'macaddress': return macColon();
    case 'identifyingnumber': return CONFIG.systemSerial;
    case 'volumeserialnumber': return volPlain();
    case 'serialnumber':
      if (cls.indexOf('baseboard') >= 0) return CONFIG.baseboardSerial;
      if (cls.indexOf('enclosure') >= 0 || cls.indexOf('chassis') >= 0) return CONFIG.chassisSerial;
      if (cls.indexOf('diskdrive') >= 0 || cls.indexOf('physicalmedia') >= 0) return CONFIG.diskSerial;
      return CONFIG.biosSerial;
    case 'dnshostname': return CONFIG.computerName;
    case 'name': return cls.indexOf('computersystem') >= 0 ? CONFIG.computerName : null;
    case 'csname': return cls.indexOf('operatingsystem') >= 0 ? CONFIG.computerName : null;
    default: return null;
  }
}

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

function getFnPtr(obj) {
  try { return obj.readPointer().add(4 * PTR).readPointer(); } catch (e) { return null; }
}

function classOf(obj) {
  try {
    const o = ole();
    const gfn = getFnPtr(obj);
    if (!o.alloc || !gfn) return null;
    const nf = new NativeFunction(gfn, 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer']);
    const name = o.alloc(Memory.allocUtf16String('__CLASS'));
    const v = Memory.alloc(24);
    v.writeByteArray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    wmiGuard = true;
    const hr = nf(obj, name, 0, v, ptr(0), ptr(0));
    wmiGuard = false;
    let cls = null;
    if (hr === 0 && v.readU16() === 8) {         // VT_BSTR
      const bstr = v.add(8).readPointer();
      if (!bstr.isNull()) cls = bstr.readUtf16String();
    }
    if (o.clear) o.clear(v);
    if (o.free) o.free(name);
    return cls;
  } catch (e) { wmiGuard = false; return null; }
}

function rewriteVariant(pVal, prop, self, label) {
  try {
    if (!prop || pVal.isNull()) return;
    const cls = classMap[self.toString()] || '';
    const val = wmiValueFor(prop, cls);
    if (val === null) return;
    if (pVal.readU16() !== 8) return;              // only rewrite string (BSTR) values
    const o = ole();
    if (!o.alloc) return;
    const oldb = pVal.add(8).readPointer();
    pVal.add(8).writePointer(o.alloc(Memory.allocUtf16String(val)));
    if (!oldb.isNull() && o.free) o.free(oldb);
    report(label, prop + (cls ? ' (' + cls + ')' : ''), null, val);
  } catch (e) {}
}

function registerObject(obj) {
  try {
    if (obj.isNull()) return;
    // Path A: app reads a named property directly -> IWbemClassObject::Get (idx 4)
    hookVtableMethod(obj, 4, 'IWbemClassObject::Get', {
      onEnter: function (a) { this.self = a[0]; this.pName = a[1]; this.pVal = a[3]; },
      onLeave: function (r) {
        if (wmiGuard || r.toInt32() !== 0) return;
        let prop = null;
        try { prop = this.pName.readUtf16String(); } catch (e) {}
        rewriteVariant(this.pVal, prop, this.self, 'WMI::Get');
      },
    });
    // Path B: app enumerates properties -> IWbemClassObject::Next (idx 9),
    // which returns each property's name (*strName) and value (*pVal). This is
    // how wmic.exe reads values.
    hookVtableMethod(obj, 9, 'IWbemClassObject::Next(prop)', {
      onEnter: function (a) { this.self = a[0]; this.pName = a[2]; this.pVal = a[3]; },
      onLeave: function (r) {
        if (wmiGuard || r.toInt32() !== 0) return;
        let prop = null;
        try { const b = this.pName.readPointer(); if (!b.isNull()) prop = b.readUtf16String(); } catch (e) {}
        rewriteVariant(this.pVal, prop, this.self, 'WMI::Enum');
      },
    });
    const cls = classOf(obj);
    if (cls) classMap[obj.toString()] = cls.toLowerCase();
  } catch (e) {}
}

function installWmiClientHooks() {
  if (!CONFIG.wmi) return;

  const nextCbs = {
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
  const execQueryCbs = {
    onEnter: function (a) { this.pp = a[5]; },
    onLeave: function (r) { if (r.toInt32() === 0) { try { hookVtableMethod(this.pp.readPointer(), 4, 'IEnumWbemClassObject::Next', nextCbs); } catch (e) {} } },
  };
  const createEnumCbs = {
    onEnter: function (a) { this.pp = a[4]; },
    onLeave: function (r) { if (r.toInt32() === 0) { try { hookVtableMethod(this.pp.readPointer(), 4, 'IEnumWbemClassObject::Next', nextCbs); } catch (e) {} } },
  };
  const getObjectCbs = {
    onEnter: function (a) { this.pp = a[4]; },
    onLeave: function (r) { if (r.toInt32() === 0) { try { registerObject(this.pp.readPointer()); } catch (e) {} } },
  };
  const connectCbs = {
    onEnter: function (a) {
      this.pp = a[8];
      // A WMI client (e.g. wmic) reads the hostname via GetComputerName -- which
      // we spoof -- then connects to \\<host>\root\cimv2. The fake host isn't
      // reachable, so redirect the connection target back to "." (local) while
      // still letting the app *read* the fake name and fake results.
      try {
        const res = a[1];
        if (!res.isNull() && CONFIG.computerName) {
          const str = res.readUtf16String();
          if (str && str.toUpperCase().indexOf(CONFIG.computerName.toUpperCase()) !== -1) {
            let fixed = str.split(CONFIG.computerName).join('.');
            fixed = fixed.split(CONFIG.computerName.toUpperCase()).join('.');
            const o = ole();
            if (o.alloc) a[1] = o.alloc(Memory.allocUtf16String(fixed));
          }
        }
      } catch (e) {}
    },
    onLeave: function (r) {
      if (r.toInt32() !== 0) return;
      try {
        const svc = this.pp.readPointer();
        hookVtableMethod(svc, 20, 'IWbemServices::ExecQuery', execQueryCbs);
        hookVtableMethod(svc, 18, 'IWbemServices::CreateInstanceEnum', createEnumCbs);
        hookVtableMethod(svc, 6, 'IWbemServices::GetObject', getObjectCbs);
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
  try { installRegistryHooks(); } catch (e) {}
  try { installFirmwareHook(); } catch (e) {}
  try { installMacHooks(); } catch (e) {}
  try { installVolumeHooks(); } catch (e) {}
  try { installComputerNameHooks(); } catch (e) {}
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
