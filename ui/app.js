"use strict";

let api = null;
let state = { activeId: null, enabled: false, profiles: [], view: "identities", live: null };

/* --------------------------------------------------------------- helpers */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show " + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.className = "toast " + kind; }, 2600);
}
function copy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    toast("Copied", "ok");
  } catch (e) { /* ignore */ }
}
function fmtVol(n) {
  const h = ((n >>> 0) >>> 0).toString(16).toUpperCase().padStart(8, "0");
  return h.slice(0, 4) + "-" + h.slice(4);
}
function ago(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function shorten(s, n = 22) { s = String(s == null ? "—" : s); return s.length > n ? s.slice(0, n) + "…" : s; }

/* ------------------------------------------------------------ tabs / view */
function switchView(name) {
  state.view = name;
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  if (name === "launch") { loadTargets(); refreshProcs(); }
  if (name === "files") loadFiles();
  // paint the conditional panels straight away instead of waiting for the next poll
  if (name === "monitor") renderErrors(state.live);
  if (name === "launch") renderElevation(state.live);
}

/* --------------------------------------------------------------- header */
function renderHeader() {
  const chip = $("#activeChip");
  chip.classList.toggle("on", !!state.activeId);
  $("#activeChipName").textContent = state.activeName || "No identity";
  $("#masterToggle").checked = !!state.enabled;
}

/* ---------------------------------------------------------- identities */
async function loadProfiles() {
  const r = await api.list_profiles();
  state.profiles = r.profiles || [];
  state.activeId = r.active_id;
  state.activeName = r.active_name;
  state.enabled = r.enabled;
  renderHeader();
  renderIdentities();
}

function idField(k, v, copyable = true) {
  return `<div class="idrow"><span class="k">${esc(k)}</span>
    <span class="v" ${copyable ? `data-copy="${esc(v)}"` : ""}>${esc(v)}</span></div>`;
}

function renderIdentities() {
  const wrap = $("#identityCards");
  if (!state.profiles.length) {
    wrap.innerHTML = `<div class="panel empty" style="grid-column:1/-1">No identities yet. Click “＋ New Identity” to generate one.</div>`;
    return;
  }
  wrap.innerHTML = state.profiles.map((p) => {
    const active = p.id === state.activeId;
    return `<div class="card ${active ? "active" : ""}" data-id="${p.id}">
      <div class="card-head">
        <input class="card-name" value="${esc(p.name)}" data-rename="${p.id}" spellcheck="false"/>
        <span class="pill ${active ? "active" : "idle"}">${active ? "Active" : "Idle"}</span>
      </div>
      ${idField("Machine GUID", p.machine_guid)}
      ${idField("Hostname", p.computer_name)}
      ${idField("MAC", p.mac_str)}
      ${idField("Volume", fmtVol(p.volume_serial))}
      ${idField("System UUID", p.system_uuid)}
      ${idField("BIOS serial", p.bios_serial)}
      <div class="card-actions">
        ${active ? "" : `<button class="btn sm primary" data-act="activate" data-id="${p.id}">Activate</button>`}
        <button class="btn sm" data-act="regen" data-id="${p.id}">Regenerate</button>
        <button class="btn sm danger" data-act="delete" data-id="${p.id}">Delete</button>
      </div>
    </div>`;
  }).join("");
}

/* ------------------------------------------------------------- monitor */
function renderMonitor(live) {
  const tiles = [
    { n: live.total || 0, l: "Calls intercepted", grad: true },
    { n: live.active_session_count || 0, l: "Active sessions" },
    { n: Object.keys(live.by_api || {}).length, l: "Functions hit" },
    { n: Object.keys(live.by_app || {}).length, l: "Distinct apps" },
  ];
  $("#statRow").innerHTML = tiles.map((t) =>
    `<div class="tile"><div class="n ${t.grad ? "grad" : ""}">${t.n}</div><div class="l">${t.l}</div></div>`).join("");

  $("#byApi").innerHTML = barlist(live.by_api);
  $("#byApp").innerHTML = barlist(live.by_app);

  const rows = (live.recent || []);
  $("#feedEmpty").style.display = rows.length ? "none" : "block";
  $("#feedBody").innerHTML = rows.map((e) => `<tr>
      <td class="mono">${ago(e.ts)}</td>
      <td class="app">${esc(e.app)}</td>
      <td class="fn">${esc(e.api)}</td>
      <td><span class="kchip">${esc(e.key)}</span></td>
      <td class="swap"><span class="real">${esc(shorten(e.real, 26))}</span><span class="arrow">→</span><span class="served">${esc(shorten(e.served, 26))}</span></td>
    </tr>`).join("");
}
function barlist(obj) {
  const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!entries.length) return `<div class="empty">Nothing yet.</div>`;
  const max = Math.max(...entries.map((e) => e[1]));
  return entries.map(([k, v]) =>
    `<div class="bar"><span class="name" title="${esc(k)}">${esc(k)}</span>
      <span class="track"><span class="fill" style="width:${Math.round((v / max) * 100)}%"></span></span>
      <span class="num">${v}</span></div>`).join("");
}

/* -------------------------------------------------------- engine errors */
/* Failures reported by the engine (attach denied, injection failed, …).
   Renders nothing at all while live.errors is empty. */
function renderErrors(live) {
  const panel = $("#errPanel");
  if (!panel) return;
  const errs = (live && live.errors) || [];
  if (!errs.length) { panel.innerHTML = ""; panel.hidden = true; return; }
  const rows = errs.map((e) => `<div class="erow">
      <span class="ets">${e.ts ? ago(e.ts) : "—"}</span>
      <span class="eapp" title="${esc(e.app)}">${esc(e.app || "—")}${e.pid ? `<span class="epid">pid ${esc(e.pid)}</span>` : ""}</span>
      <span class="emsg">${esc(e.msg)}</span>
    </div>`).join("");
  panel.innerHTML = `<div class="panel-title bad">Engine errors <span class="badge">${errs.length}</span></div>
    <div class="elist">${rows}</div>${elevationHint(live)}`;
  panel.hidden = false;
}

/* One-line version of the elevation notice, shown only when we know we are not elevated. */
function elevationHint(live) {
  if (!live || live.admin !== false) return "";
  return `<div class="enote">Chameleon is not running as Administrator, so Windows refuses to attach to apps that are already running. Launch the app from the “Launch &amp; Attach” tab instead, or restart Chameleon as Administrator.</div>`;
}

/* ------------------------------------------------------------- sessions */
function renderSessions(live) {
  const list = $("#sessionList");
  const s = (live.sessions || []).slice().reverse();
  if (!s.length) { list.innerHTML = `<div class="empty">No protected sessions. Launch or attach an app above.</div>`; return; }
  list.innerHTML = s.map((x) => `<div class="session-item ${x.status === "active" ? "active-s" : ""}">
    <div style="display:flex;align-items:center;gap:10px">
      <span class="stat-dot ${x.status === "active" ? "" : "ended"}"></span>
      <div class="meta"><span class="name">${esc(x.name)}</span>
      <span class="sub">pid ${x.pid} · ${x.calls} calls · ${x.hooked.length} hooks · ${x.status}</span></div>
    </div>
    ${x.status === "active" ? `<button class="btn sm ghost" data-stop="${x.pid}">Detach</button>` : ""}
  </div>`).join("");
}

/* Elevation notice on the Launch & Attach tab. Hidden unless live.admin === false,
   so an unknown/missing admin flag changes nothing. */
function renderElevation(live) {
  const box = $("#elevNotice");
  if (!box) return;
  if (!live || live.admin !== false) { box.innerHTML = ""; box.hidden = true; return; }
  box.innerHTML = `<div class="panel-title warn">Not running as Administrator</div>
    <p class="muted">Attaching to an app that is <strong>already running</strong> is unavailable — Windows will not let Chameleon open another process for injection without elevation, so “Attach” and the auto-attach watcher fail.</p>
    <p class="muted" style="margin-top:6px">Launching an app <strong>through Chameleon</strong> still works and is fully protected. To attach to running apps, close Chameleon and start it again with <strong>Run as administrator</strong>.</p>`;
  box.hidden = false;
}

/* ------------------------------------------------------- launch/attach */
async function loadTargets() {
  const r = await api.list_targets();
  const wt = $("#wmiToggle");
  if (wt) wt.checked = !!r.wmi;

  const w = r.watch || {};
  const wtoggle = $("#watchToggle");
  if (wtoggle) wtoggle.checked = !!w.enabled;
  const wnames = $("#watchNames");
  if (wnames && document.activeElement !== wnames) wnames.value = (w.names || []).join(", ");

  // AI CLI agents
  const cli = $("#cliCards");
  if (cli) {
    cli.innerHTML = (r.cli_agents || []).map((a) => `<div class="card">
      <div class="card-head"><div class="card-name" style="width:auto">${esc(a.name)}</div>
        <span class="pill ${a.installed ? "active" : "idle"}">${a.installed ? "Installed" : "Not found"}</span></div>
      <div class="idrow"><span class="k">Command</span><span class="v cli-badge">${esc(a.cmd)}</span></div>
      <div class="card-actions">
        <button class="btn sm primary" data-launchcli="${esc(a.id)}" ${a.installed ? "" : "disabled"}>Launch protected</button>
      </div></div>`).join("") || `<div class="empty">No known AI CLIs found on PATH.</div>`;
  }

  const wrap = $("#targetCards");
  wrap.innerHTML = (r.targets || []).map((t) => {
    const running = (t.running || []).length;
    return `<div class="card">
      <div class="card-head"><div class="card-name" style="width:auto">${esc(t.name)}</div>
        <span class="pill ${t.installed ? "active" : "idle"}">${t.installed ? "Installed" : "Not found"}</span></div>
      <div class="idrow"><span class="k">Path</span><span class="v" title="${esc(t.path)}">${esc(shorten(t.path, 34) || "—")}</span></div>
      <div class="idrow"><span class="k">Running</span><span class="v">${running ? running + " process(es)" : "no"}</span></div>
      <div class="card-actions">
        <button class="btn sm primary" data-launch="${esc(t.path)}" ${t.installed ? "" : "disabled"}>Launch protected</button>
        ${running ? `<button class="btn sm" data-attach="${t.running[0]}">Attach running</button>` : ""}
      </div></div>`;
  }).join("");
}

let allProcs = [];
async function refreshProcs() {
  allProcs = await api.list_processes();
  renderProcs();
}
function renderProcs() {
  const q = ($("#procSearch").value || "").toLowerCase();
  const list = allProcs.filter((p) => !q || p.name.toLowerCase().includes(q)).slice(0, 200);
  $("#procList").innerHTML = list.map((p) =>
    `<div class="proc-item"><div class="meta"><span class="name">${esc(p.name)}</span><span class="pid">pid ${p.pid}</span></div>
      <button class="btn sm" data-attach="${p.pid}">Attach</button></div>`).join("")
    || `<div class="empty">No matches.</div>`;
}

/* --------------------------------------------------------------- files */
async function loadFiles() {
  const r = await api.list_targets();
  renderFiles(r.identity_files || []);
}
function renderFiles(items) {
  $("#fileTargets").innerHTML = items.map((t) => {
    let tag = t.exists
      ? (t.patched ? `<span class="status-tag ok">Spoofed</span>` : `<span class="status-tag no">Original</span>`)
      : `<span class="status-tag warn">Not installed</span>`;
    const cur = t.current && t.current["telemetry.devDeviceId"]
      ? `<span class="fpath">devDeviceId: ${esc(t.current["telemetry.devDeviceId"])}</span>` : "";
    return `<div class="ftrow">
      <div class="fmeta"><div class="fname">${esc(t.name)}</div>
        <div class="fpath">${esc(t.path)}</div>${cur}</div>
      <div style="display:flex;gap:10px;align-items:center">${tag}
        ${t.exists && t.patched ? `<button class="btn sm ghost" data-restore="${t.id}">Restore</button>` : ""}
        ${t.exists && !t.patched ? `<button class="btn sm" data-applyone="${t.id}">Apply</button>` : ""}
      </div></div>`;
  }).join("");
}

/* --------------------------------------------------------------- verify */
function renderVerify(r) {
  const groups = [];
  r.checks.forEach((c) => {
    const g = c.group || "";
    const last = groups[groups.length - 1];
    if (last && last.name === g) last.rows.push(c);
    else groups.push({ name: g, rows: [c] });
  });
  const html = groups.map((g) => {
    const passed = g.rows.filter((c) => c.pass).length;
    const rows = g.rows.map((c) => `<div class="vrow ${c.pass ? "ok" : "bad"}">
      <span class="vmark">${c.pass ? "✓" : "✗"}</span>
      <span class="vname">${esc(c.name)}</span>
      <span class="vval">${c.pass ? esc(c.expected)
        : esc(c.error ? ("error: " + c.error) : ("real value leaked — " + c.snippet))}</span></div>`).join("");
    return `<div class="vgroup"><span>${esc(g.name)}</span>
      <span class="vgcount ${passed === g.rows.length ? "ok" : "bad"}">${passed}/${g.rows.length}</span></div>` + rows;
  }).join("");
  const all = r.passed === r.total;
  const hint = (!all && r.wmi === false)
    ? ` <span class="muted">— WMI / CIM coverage is off; turn it on in Launch &amp; Attach and re-run.</span>` : "";
  $("#verifyResults").innerHTML =
    `<div class="vsum">${r.passed}/${r.total} identifiers served the fake value${all ? " — fully covered ✅" : ""}${hint}</div>` + html;
}

/* -------------------------------------------------------------- polling */
async function pollLive() {
  if (!api) return;
  try {
    const live = await api.get_live();
    state.live = live;
    state.enabled = live.enabled;
    state.activeId = live.active_id;
    state.activeName = live.active_name;
    renderHeader();

    const active = live.active_session_count || 0;
    $("#tabSessions").textContent = active;
    const ms = $("#masterState"), mh = $("#masterHint");
    if (!live.enabled) { ms.textContent = "Protection off"; mh.textContent = "toggle on, then launch an app"; }
    else if (active > 0) { ms.textContent = `Protecting ${active} app${active > 1 ? "s" : ""}`; mh.textContent = `${live.total} calls served`; }
    else { ms.textContent = "Armed"; mh.textContent = "launch or attach an app"; }

    if (state.view === "monitor") { renderMonitor(live); renderErrors(live); }
    if (state.view === "launch") { renderSessions(live); renderElevation(live); }
  } catch (e) { /* window closing */ }
}

/* --------------------------------------------------------------- events */
function wire() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => switchView(t.dataset.view)));

  $("#masterToggle").addEventListener("change", async (e) => {
    const r = await api.set_enabled(e.target.checked);
    state.enabled = r.enabled;
    toast(r.enabled ? "Protection armed" : "Protection off — all apps detached", r.enabled ? "ok" : "");
  });

  $("#btnNewIdentity").addEventListener("click", async () => {
    const r = await api.create_profile(null);
    if (r.ok) { toast("New identity generated", "ok"); await loadProfiles(); }
  });

  $("#btnResetStats").addEventListener("click", async () => { await api.reset_stats(); toast("Stats reset"); });

  $("#wmiToggle").addEventListener("change", async (e) => {
    await api.set_wmi_coverage(e.target.checked);
    toast(e.target.checked ? "WMI / CIM coverage on (applies to next launch)" : "WMI / CIM coverage off", "ok");
  });

  $("#btnVerify").addEventListener("click", async () => {
    $("#verifyPanel").hidden = false;
    $("#verifyResults").innerHTML = `<div class="vsum">Running self-test — launching probe tools under the guard…</div>`;
    const r = await api.verify_profile();
    if (!r.ok) { $("#verifyResults").innerHTML = `<div class="vsum">${esc(r.error)}</div>`; return; }
    renderVerify(r);
    toast(`${r.passed}/${r.total} identifiers covered`, r.passed === r.total ? "ok" : "err");
  });

  $("#watchToggle").addEventListener("change", async (e) => {
    const r = await api.set_watcher(e.target.checked);
    if (!r.ok) { toast(r.error, "err"); e.target.checked = false; }
    else toast(e.target.checked ? "Auto-attach watcher on" : "Auto-attach off", "ok");
  });
  $("#btnSaveWatch").addEventListener("click", async () => {
    const names = $("#watchNames").value.split(",").map((s) => s.trim()).filter(Boolean);
    const r = await api.set_watch_list(names);
    $("#watchNames").value = (r.names || []).join(", ");
    toast("Watch list saved", "ok");
  });

  // delegated clicks
  document.addEventListener("click", async (e) => {
    const el = e.target.closest("[data-act],[data-copy],[data-launch],[data-launchcli],[data-attach],[data-stop],[data-restore],[data-applyone]");
    if (!el) return;

    if (el.dataset.copy !== undefined) return copy(el.dataset.copy);

    if (el.dataset.act) {
      const id = el.dataset.id, act = el.dataset.act;
      if (act === "activate") { await api.activate_profile(id); toast("Identity activated", "ok"); await loadProfiles(); }
      if (act === "regen") { await api.regenerate_profile(id, true); toast("Rolled a fresh identity", "ok"); await loadProfiles(); }
      if (act === "delete") {
        if (confirm("Delete this identity?")) { await api.delete_profile(id); toast("Deleted"); await loadProfiles(); }
      }
      return;
    }
    if (el.dataset.launch !== undefined) {
      const r = await api.launch_target(el.dataset.launch, []);
      toast(r.ok ? "Launched under guard" : r.error, r.ok ? "ok" : "err");
      return;
    }
    if (el.dataset.launchcli !== undefined) {
      const r = await api.launch_cli(el.dataset.launchcli);
      toast(r.ok ? "AI CLI launched in guarded shell" : r.error, r.ok ? "ok" : "err");
      return;
    }
    if (el.dataset.attach !== undefined) {
      const r = await api.attach_process(parseInt(el.dataset.attach, 10));
      toast(r.ok ? "Attached" : (r.error || "Attach failed"), r.ok ? "ok" : "err");
      return;
    }
    if (el.dataset.stop !== undefined) { await api.stop_session(parseInt(el.dataset.stop, 10)); toast("Detached"); return; }
    if (el.dataset.restore !== undefined) { const r = await api.restore_identity_files([el.dataset.restore]); toast("Restored original", "ok"); loadFiles(); return; }
    if (el.dataset.applyone !== undefined) { const r = await api.apply_identity_files([el.dataset.applyone]); toast(r.ok ? "Identity written" : "Failed", r.ok ? "ok" : "err"); loadFiles(); return; }
  });

  // rename on blur/enter
  document.addEventListener("keydown", (e) => {
    if (e.target.dataset && e.target.dataset.rename && e.key === "Enter") e.target.blur();
  });
  document.addEventListener("blur", async (e) => {
    if (e.target.dataset && e.target.dataset.rename) {
      await api.rename_profile(e.target.dataset.rename, e.target.value.trim() || "Unnamed");
    }
  }, true);

  $("#btnBrowse").addEventListener("click", async () => {
    const r = await api.browse_exe();
    if (r && r.ok) $("#customExe").value = r.path;
  });
  $("#btnLaunchExe").addEventListener("click", async () => {
    const r = await api.launch_target($("#customExe").value.trim(), []);
    toast(r.ok ? "Launched under guard" : r.error, r.ok ? "ok" : "err");
  });
  $("#btnLaunchCmd").addEventListener("click", async () => {
    const r = await api.launch_command($("#customCmd").value.trim());
    toast(r.ok ? "Command launched in guarded shell" : r.error, r.ok ? "ok" : "err");
  });
  $("#btnRefreshProcs").addEventListener("click", refreshProcs);
  $("#procSearch").addEventListener("input", renderProcs);

  $("#btnApplyFiles").addEventListener("click", async () => {
    const r = await api.apply_identity_files(null);
    toast(r.ok ? "Active identity written to installed apps" : "Failed", r.ok ? "ok" : "err");
    loadFiles();
  });
  $("#btnRestoreFiles").addEventListener("click", async () => {
    await api.restore_identity_files(null); toast("Originals restored", "ok"); loadFiles();
  });
}

/* ----------------------------------------------------------------- help */
function renderHelp() {
  $("#helpBody").innerHTML = `
    <p>Chameleon puts itself <strong>between an app and the Windows functions that reveal your hardware identity</strong>. When you launch an app “protected”, a lightweight agent is injected into it (and the helper processes it spawns, like <code>reg.exe</code>). Each time the app asks Windows for a machine id, the call is logged and answered with your active identity's fake value.</p>
    <div class="note ok"><strong>Your real machine is never modified.</strong> Nothing is written to your registry or firmware. Detaching (toggle Protection off, or “Detach”) makes apps see the real values again instantly.</div>
    <h3>What gets intercepted (in-process)</h3>
    <ul>
      <li><code>RegQueryValueEx / RegGetValue / RegEnumValue</code> → <strong>MachineGuid</strong>, SQMClient MachineId, ProductId</li>
      <li><code>GetSystemFirmwareTable('RSMB')</code> → <strong>SMBIOS</strong> system/board/chassis serials + system UUID + CPU id</li>
      <li><code>GetAdaptersAddresses / GetAdaptersInfo</code> → <strong>MAC</strong> addresses</li>
      <li><code>GetVolumeInformation</code> → <strong>volume serial</strong></li>
      <li><code>GetComputerName</code> → <strong>hostname</strong></li>
      <li><code>DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)</code> → <strong>physical disk serial</strong></li>
      <li><strong>WMI</strong> (client-side COM): <code>Win32_BIOS</code>, <code>ComputerSystemProduct</code>, <code>BaseBoard</code>, <code>SystemEnclosure</code>, <code>Processor</code>, <code>DiskDrive</code>, <code>NetworkAdapter(Configuration)</code>, <code>LogicalDisk</code>, <code>Volume</code>, <code>ComputerSystem</code> → serials, UUID, ProcessorId, MAC, volume serial, hostname</li>
      <li><strong>MI / CIM</strong> (same COM layer, async sinks): <code>Get-CimInstance</code>, <code>Get-PhysicalDisk</code>, <code>Get-Disk</code>, <code>Get-NetAdapter</code> and anything else on <code>mi.dll</code> → the same identifiers, plus <code>MSFT_PhysicalDisk</code> serial/UniqueId and <code>MSFT_NetAdapter</code> addresses</li>
    </ul>
    <h3>Identity Files</h3>
    <p>Some apps cache their id in a file instead of re-reading it. VS Code, its forks, and Copilot-in-VS-Code keep telemetry ids in <code>storage.json</code>. The Identity Files tab backs that file up and writes your active identity's ids into it, reversibly.</p>
    <h3>WMI &amp; MI / CIM coverage</h3>
    <p>The WMI provider host (<code>WmiPrvSE.exe</code>) runs as NETWORK SERVICE and can't be injected reliably, so both management stacks are intercepted <strong>client-side</strong> instead: when a protected app runs a query, the results are unmarshaled into its own process and read via COM, which is hooked.</p>
    <p>That single hook point covers <strong>both</strong> stacks, because locally <code>mi.dll</code> does not invent its own transport — it loads <code>wmidcom.dll</code>, an ordinary DCOM WMI client that uses the <em>asynchronous</em> entry points and receives objects through an <code>IWbemObjectSink</code>. So <code>wmic</code>, .NET <code>System.Management</code>, <code>Get-WmiObject</code> <em>and</em> <code>Get-CimInstance</code>, <code>Get-PhysicalDisk</code>, <code>Get-NetAdapter</code> all end up reading the same rewritten objects. Toggle it in the Launch tab (applies to the next launch).</p>
    <h3>Honest limitations</h3>
    <div class="note">MI over <strong>WSMan</strong> (an explicit <code>New-CimSession</code> to a host name, rather than the default local session) leaves the machine and isn't intercepted. Per-adapter GUIDs (<code>Win32_NetworkAdapter.GUID</code>, <code>MSFT_NetAdapter.InterfaceGuid</code>) are left alone — they key the networking stack, and rewriting them breaks it. Hostname is spoofed via <code>GetComputerName</code>, <code>GetComputerNameEx</code> (caller-guarded so local RPC/DCOM keeps working) and both management stacks. Firmware read via <code>GetSystemFirmwareTable</code> is covered in-process.</div>
    <p class="muted">This tool is for protecting your own privacy on your own machine. Rotating ids can log you out of apps or affect software licenses tied to hardware.</p>`;
}

/* ---------------------------------------------------------------- boot */
window.addEventListener("pywebviewready", async () => {
  api = window.pywebview.api;
  wire();
  renderHelp();
  await loadProfiles();
  await pollLive();
  setInterval(pollLive, 900);
});
