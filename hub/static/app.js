// term — minimal SPA. No frameworks. No cookies. No localStorage.
//
// State that survives a page reload lives in the URL fragment:
//   #m:sid,m:sid,...
// where `m` is a machine id and `sid` is a tmux session id.
//
// Auth state (bearer token) lives only in the `token` module-level
// variable; a refresh forces re-auth via passkey.

'use strict';

// ----- low-level helpers -----------------------------------------------------

const $ = (sel) => document.querySelector(sel);

function b64uToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function bytesToB64NoPad(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=+$/, '');
}

function showMsg(el, text, ok = false) {
  el.textContent = text;
  el.classList.toggle('ok', !!ok);
}

// ----- WebAuthn glue (webauthn-rs JSON <-> WebAuthn API) ---------------------

function prepCreateOptions(ccr) {
  const pk = JSON.parse(JSON.stringify(ccr.publicKey));
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  if (pk.excludeCredentials) {
    pk.excludeCredentials = pk.excludeCredentials.map(c =>
      Object.assign({}, c, { id: b64uToBuf(c.id) }));
  }
  return pk;
}
function prepGetOptions(rcr) {
  const pk = JSON.parse(JSON.stringify(rcr.publicKey));
  pk.challenge = b64uToBuf(pk.challenge);
  if (pk.allowCredentials) {
    pk.allowCredentials = pk.allowCredentials.map(c =>
      Object.assign({}, c, { id: b64uToBuf(c.id) }));
  }
  return pk;
}
function credentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
    },
  };
}
function assertionToJSON(cred) {
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
  };
}

// ----- frame protocol --------------------------------------------------------
//
// 9-byte header: [stream_id:u32 BE][type:u8][len:u32 BE][payload:len]
// Browser always uses stream_id = 0 (the WS itself is the demux); the hub
// injects the real stream_id when forwarding to the agent, and strips it
// back to 0 on the way back.

const HEADER_LEN   = 9;
const FRAME_DATA               = 0;
const FRAME_RESIZE             = 1;
const FRAME_OPEN               = 2;
const FRAME_PASTE_BEGIN        = 7;
const FRAME_PASTE_CHUNK        = 8;
const FRAME_PASTE_END          = 9;
const FRAME_PASTE_REJECT       = 10;
const FRAME_DOWNLOAD_BEGIN     = 11;
const FRAME_DOWNLOAD_CHUNK     = 12;
const FRAME_DOWNLOAD_END       = 13;
const FRAME_ACQUIRE_CONTROL    = 14;
const FRAME_RELEASE_CONTROL    = 15;
const FRAME_TAKE_CONTROL       = 16;
const FRAME_CONTROLLER_CHANGED = 17;

// Mirror the constants in common/src/frame.rs.
const MAX_PASTE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024 - 1; // 4 GiB - 1
const MAX_PASTE_CHUNK_BYTES = 1024 * 1024;                // 1 MiB
const MAX_PASTE_NAME_LEN    = 255;
const PASTE_STATUS_OK     = 0;
const PASTE_STATUS_CANCEL = 1;
const DOWNLOAD_STATUS_OK     = 0;
const DOWNLOAD_STATUS_CANCEL = 1;
// Per-tab cap on concurrent downloads in flight — matches the
// agent-side MAX_INFLIGHT_DOWNLOADS.
const MAX_INFLIGHT_DOWNLOADS = 16;
// Per-download memory cap on the browser side. The wire protocol
// allows up to 4 GiB per file, but until we wire up streaming-to-disk
// (File System Access API) the JS heap has to hold the whole Blob,
// which can OOM the tab. 256 MiB is the practical safe ceiling.
const MAX_DOWNLOAD_TOTAL_BYTES = 256 * 1024 * 1024;

const PASTE_REJECT_REASONS = [
  'too many concurrent pastes',
  'agent could not create temp file',
  'paste size mismatch',
  'agent failed to write file',
  'duplicate paste id',
  'paste batch exceeds 4 GiB',
];
function pasteRejectMessage(reason) {
  return PASTE_REJECT_REASONS[reason] || `unknown reason ${reason}`;
}

function encodeFrame(type, payload) {
  const len = payload.length;
  const buf = new Uint8Array(HEADER_LEN + len);
  // stream_id = 0
  buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 0;
  buf[4] = type;
  buf[5] = (len >>> 24) & 0xff;
  buf[6] = (len >>> 16) & 0xff;
  buf[7] = (len >>>  8) & 0xff;
  buf[8] =  len         & 0xff;
  buf.set(payload, HEADER_LEN);
  return buf;
}
function encodeData(bytes) { return encodeFrame(FRAME_DATA, bytes); }
function encodeResize(rows, cols) {
  const p = new Uint8Array(4);
  p[0] = (rows >>> 8) & 0xff; p[1] = rows & 0xff;
  p[2] = (cols >>> 8) & 0xff; p[3] = cols & 0xff;
  return encodeFrame(FRAME_RESIZE, p);
}
function encodeOpen(sessionId, rows, cols) {
  // Wire: [session_id UTF-8][rows:u16 BE][cols:u16 BE]
  const idBytes = new TextEncoder().encode(sessionId);
  const payload = new Uint8Array(idBytes.length + 4);
  payload.set(idBytes, 0);
  payload[idBytes.length    ] = (rows >>> 8) & 0xff;
  payload[idBytes.length + 1] =  rows        & 0xff;
  payload[idBytes.length + 2] = (cols >>> 8) & 0xff;
  payload[idBytes.length + 3] =  cols        & 0xff;
  return encodeFrame(FRAME_OPEN, payload);
}
function encodeControlOnly(type) {
  // AcquireControl / ReleaseControl / TakeControl — zero-payload.
  return encodeFrame(type, new Uint8Array(0));
}

function writeU32BE(buf, off, n) {
  buf[off    ] = (n >>> 24) & 0xff;
  buf[off + 1] = (n >>> 16) & 0xff;
  buf[off + 2] = (n >>>  8) & 0xff;
  buf[off + 3] =  n         & 0xff;
}
function writeU64BE(buf, off, n) {
  // n may exceed 2^32; split via BigInt to stay exact across the full
  // 4 GiB range.
  const big = BigInt(n);
  const hi = Number((big >> 32n) & 0xffffffffn);
  const lo = Number(big & 0xffffffffn);
  writeU32BE(buf, off,     hi);
  writeU32BE(buf, off + 4, lo);
}

function encodePasteBegin(pasteId, totalSize, groupId, groupSize, name) {
  // payload: [paste_id:u32][total_size:u64][group_id:u32]
  //          [group_size:u32][name_len:u8][name utf8]
  const nameBytes = new TextEncoder().encode(name).slice(0, MAX_PASTE_NAME_LEN);
  const payload = new Uint8Array(4 + 8 + 4 + 4 + 1 + nameBytes.length);
  writeU32BE(payload, 0,  pasteId);
  writeU64BE(payload, 4,  totalSize);
  writeU32BE(payload, 12, groupId);
  writeU32BE(payload, 16, groupSize);
  payload[20] = nameBytes.length;
  payload.set(nameBytes, 21);
  return encodeFrame(FRAME_PASTE_BEGIN, payload);
}
function encodePasteChunk(pasteId, bytes) {
  // payload: [paste_id:u32][bytes]
  const payload = new Uint8Array(4 + bytes.length);
  writeU32BE(payload, 0, pasteId);
  payload.set(bytes, 4);
  return encodeFrame(FRAME_PASTE_CHUNK, payload);
}
function encodePasteEnd(pasteId, status) {
  // payload: [paste_id:u32][status:u8]
  const payload = new Uint8Array(5);
  writeU32BE(payload, 0, pasteId);
  payload[4] = status;
  return encodeFrame(FRAME_PASTE_END, payload);
}
function parseFrame(view) {
  if (view.byteLength < HEADER_LEN) return null;
  // stream_id at [0..4] is always 0 from the hub; ignore.
  const type = view[4];
  const len  = ((view[5] << 24) | (view[6] << 16) | (view[7] << 8) | view[8]) >>> 0;
  if (view.byteLength !== HEADER_LEN + len) return null;
  return { type, payload: view.subarray(HEADER_LEN) };
}

// ----- URL fragment <-> tabs -------------------------------------------------

const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MACHINE_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

function parseFragment() {
  const raw = location.hash.replace(/^#/, '');
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean).map(pair => {
    const ix = pair.indexOf(':');
    if (ix < 0) return null;
    const m = pair.slice(0, ix), s = pair.slice(ix + 1);
    if (!MACHINE_ID_RE.test(m) || !SESSION_ID_RE.test(s)) return null;
    return { machineId: m, sessionId: s };
  }).filter(Boolean);
}
function writeFragment(tabs) {
  const frag = tabs.map(t => `${t.machineId}:${t.sessionId}`).join(',');
  const next = frag ? '#' + frag : '';
  if (location.hash !== next) {
    // Use replaceState so refreshes are reproducible but we don't pile up
    // history entries every time a tab opens or closes.
    history.replaceState(null, '', location.pathname + location.search + next);
  }
}
function newSessionId() {
  // 8 hex chars from window.crypto.
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ----- application state -----------------------------------------------------

let token = null;        // bearer token (in-memory only)
let machines = [];       // [{id, label, address}]
const machinesById = new Map();
let tabs = [];           // [{ machineId, sessionId, term, fit, ws, paneEl, tabEl, statusEl }]
let activeTabIdx = -1;

// ----- auth flow -------------------------------------------------------------

async function doLogin() {
  const startRes = await fetch('/webauthn/login/start', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  if (!startRes.ok) throw new Error(`login/start ${startRes.status}: ${await startRes.text()}`);
  const { nonce, rcr } = await startRes.json();

  const pk = prepGetOptions(rcr);
  const cred = await navigator.credentials.get({ publicKey: pk });
  if (!cred) throw new Error('navigator.credentials.get returned null');

  const finishRes = await fetch('/webauthn/login/finish', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce, response: assertionToJSON(cred) }),
  });
  if (!finishRes.ok) throw new Error(`login/finish ${finishRes.status}: ${await finishRes.text()}`);
  const { token: tok } = await finishRes.json();
  token = tok;
}

async function doRegister(label) {
  const startRes = await fetch('/webauthn/register/start', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  if (!startRes.ok) throw new Error(`register/start ${startRes.status}: ${await startRes.text()}`);
  const { ccr, envelope, rp_id, ttl_secs } = await startRes.json();

  const pk = prepCreateOptions(ccr);
  const cred = await navigator.credentials.create({ publicKey: pk });
  if (!cred) throw new Error('navigator.credentials.create returned null');

  const paste = {
    envelope,
    response: credentialToJSON(cred),
    label: label || null,
  };
  const json = JSON.stringify(paste);
  const blob = bytesToB64NoPad(new TextEncoder().encode(json));
  return { blob, rpId: rp_id, ttlSecs: ttl_secs };
}

// ----- bootstrap -------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  bindAuthUi();
  // Page always starts on the auth screen — no auth state survives refresh.
  showScreen('auth');
});

function showScreen(which) {
  $('#loading').hidden = true;
  $('#auth-screen').hidden = which !== 'auth';
  $('#app').hidden = which !== 'app';
}

function bindAuthUi() {
  $('#login-btn').addEventListener('click', async () => {
    const msg = $('#login-msg'); showMsg(msg, '');
    try {
      await doLogin();
      await enterApp();
    } catch (e) {
      console.error(e);
      showMsg(msg, e.message || String(e));
    }
  });

  $('#register-btn').addEventListener('click', async () => {
    const msg = $('#register-msg'); showMsg(msg, '');
    const label = $('#label-input').value.trim();
    try {
      const { blob, rpId, ttlSecs } = await doRegister(label);
      const ta = $('#blob-output');
      ta.hidden = false; ta.value = blob; ta.select();
      const ins = $('#blob-instructions');
      ins.hidden = false;
      ins.textContent =
        `# valid for ${Math.round(ttlSecs/60)} minutes (rp_id=${rpId})\n` +
        `# on the hub host, run:\n\n` +
        `hub-admin add-passkey '${blob}'`;
      showMsg(msg, 'blob ready — copy and paste on the hub host', true);
    } catch (e) {
      console.error(e);
      showMsg(msg, e.message || String(e));
    }
  });
}

// ----- main app --------------------------------------------------------------

async function enterApp() {
  const res = await fetch('/api/machines', {
    headers: { 'authorization': 'Bearer ' + token }
  });
  if (!res.ok) throw new Error(`/api/machines ${res.status}`);
  const data = await res.json();
  machines = data.machines || [];
  machinesById.clear();
  for (const m of machines) machinesById.set(m.id, m);

  renderMachines();
  bindAppUi();
  showScreen('app');

  // Reattach tabs from URL fragment.
  const want = parseFragment();
  for (const t of want) {
    if (machinesById.has(t.machineId)) {
      openTab(t.machineId, t.sessionId, /*activate*/ false);
    }
  }
  if (tabs.length > 0) activateTab(0);
  window.addEventListener('resize', onResize);
  bindSearchUi();
}

function bindAppUi() {
  $('#logout-btn').addEventListener('click', async () => {
    try {
      await fetch('/api/logout', {
        method: 'POST', headers: { 'authorization': 'Bearer ' + token }
      });
    } catch (_) { /* ignore */ }
    // Close everything and reload to auth screen.
    for (const t of tabs.slice()) closeTab(t, /*persist*/ false);
    token = null;
    location.hash = '';
    location.reload();
  });
}

function renderMachines() {
  const ul = $('#machines');
  ul.innerHTML = '';
  for (const m of machines) {
    const li = document.createElement('li');
    const row = document.createElement('div');
    row.className = 'machine-row';
    const label = document.createElement('span');
    label.className = 'label'; label.textContent = m.label;
    const id = document.createElement('span');
    id.className = 'id'; id.textContent = m.id;
    const sessionsBtn = document.createElement('button');
    sessionsBtn.className = 'sessions-toggle';
    sessionsBtn.type = 'button';
    sessionsBtn.title = 'list / kill running sessions on this agent';
    sessionsBtn.textContent = 'sessions ▾';
    const add = document.createElement('button');
    add.className = 'new'; add.type = 'button'; add.title = 'new tab';
    add.textContent = '+';
    row.appendChild(label);
    row.appendChild(id);
    row.appendChild(sessionsBtn);
    row.appendChild(add);
    const panel = document.createElement('div');
    panel.className = 'sessions-panel';
    panel.hidden = true;
    li.appendChild(row);
    li.appendChild(panel);
    row.addEventListener('click', (ev) => {
      if (ev.target === add || ev.target === sessionsBtn) return;
      openTab(m.id, newSessionId(), /*activate*/ true);
    });
    add.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openTab(m.id, newSessionId(), /*activate*/ true);
    });
    sessionsBtn.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      panel.hidden = !panel.hidden;
      sessionsBtn.textContent = panel.hidden ? 'sessions ▾' : 'sessions ▴';
      if (!panel.hidden) await refreshSessionsPanel(m.id, panel);
    });
    ul.appendChild(li);
  }
}

/// Fetch the agent's session list via the new admin API and render it
/// in `panel`. Each entry shows id + attached count + idle time + a
/// kill button. Refreshes on its own after a kill so the user sees
/// the entry disappear.
async function refreshSessionsPanel(machineId, panel) {
  panel.innerHTML = '<div class="sessions-status">loading…</div>';
  let data;
  try {
    const res = await fetch(`/api/machines/${encodeURIComponent(machineId)}/sessions`, {
      headers: { 'authorization': 'Bearer ' + token },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      panel.innerHTML = `<div class="sessions-status err">error ${res.status}: ${text}</div>`;
      return;
    }
    data = await res.json();
  } catch (e) {
    panel.innerHTML = `<div class="sessions-status err">fetch failed: ${e}</div>`;
    return;
  }
  if (!data.sessions || data.sessions.length === 0) {
    panel.innerHTML = '<div class="sessions-status">no live sessions</div>';
    return;
  }
  panel.innerHTML = '';
  const list = document.createElement('ul');
  list.className = 'sessions-list';
  for (const s of data.sessions) {
    const row = document.createElement('li');
    const idSpan = document.createElement('span');
    idSpan.className = 'sid'; idSpan.textContent = s.id;
    const meta = document.createElement('span');
    meta.className = 'meta';
    const ctrl = s.has_controller ? '●' : '○';
    const idle = formatIdle(s.idle_secs);
    meta.textContent = `${ctrl} ${s.attached} attached · idle ${idle}`;
    const kill = document.createElement('button');
    kill.className = 'sess-kill';
    kill.type = 'button';
    kill.textContent = '× kill';
    kill.title = `kill session ${s.id}`;
    kill.addEventListener('click', async () => {
      if (!confirm(`Kill session "${s.id}" on ${machineId}? Any attached tabs will see the shell exit.`)) return;
      kill.disabled = true;
      try {
        const res = await fetch(
          `/api/machines/${encodeURIComponent(machineId)}/sessions/${encodeURIComponent(s.id)}`,
          { method: 'DELETE', headers: { 'authorization': 'Bearer ' + token } },
        );
        if (!res.ok) {
          flash(`kill failed: ${res.status}`);
        }
      } catch (e) {
        flash(`kill error: ${e}`);
      } finally {
        await refreshSessionsPanel(machineId, panel);
      }
    });
    row.appendChild(idSpan);
    row.appendChild(meta);
    row.appendChild(kill);
    list.appendChild(row);
  }
  panel.appendChild(list);
}

function formatIdle(secs) {
  if (secs < 60)     return `${secs}s`;
  if (secs < 3600)   return `${Math.floor(secs / 60)}m`;
  if (secs < 86400)  return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

function openTab(machineId, sessionId, activate) {
  const machine = machinesById.get(machineId);
  if (!machine) return;
  // Deduplicate: if we already have this (machine, session), focus it.
  const existing = tabs.findIndex(t => t.machineId === machineId && t.sessionId === sessionId);
  if (existing >= 0) {
    if (activate) activateTab(existing);
    return;
  }

  const term = new Terminal({
    fontFamily: 'ui-monospace, "JetBrains Mono", "Cascadia Code", Menlo, Consolas, monospace',
    fontSize: 13,
    lineHeight: 1.0,
    letterSpacing: 0,
    cursorBlink: true,
    cursorStyle: 'block',
    cursorInactiveStyle: 'outline',
    convertEol: false,
    scrollback: 10000,
    fastScrollModifier: 'shift',
    fastScrollSensitivity: 5,
    scrollSensitivity: 1,
    minimumContrastRatio: 4.5,
    drawBoldTextInBrightColors: false,
    wordSeparator: ' ()[]{}\'",;:`',
    // xterm 6.0 moved overviewRulerWidth into the overviewRuler object.
    // Reserve a slim gutter so the search addon's match markers can be
    // painted on the scrollbar.
    overviewRuler: { width: 14 },
    windowOptions: { setWinSizeChars: true },
    theme: {
      // Catppuccin Mocha.
      background: '#0b0e14', foreground: '#cdd6f4',
      cursor: '#f5e0dc', cursorAccent: '#1e1e2e',
      selectionBackground: '#414559', selectionForeground: undefined,
      black: '#45475a',  red: '#f38ba8', green: '#a6e3a1',  yellow: '#f9e2af',
      blue: '#89b4fa',   magenta: '#f5c2e7', cyan: '#94e2d5', white: '#bac2de',
      brightBlack: '#585b70', brightRed: '#f38ba8', brightGreen: '#a6e3a1',
      brightYellow: '#f9e2af', brightBlue: '#89b4fa', brightMagenta: '#f5c2e7',
      brightCyan: '#94e2d5',   brightWhite: '#a6adc8',
    },
    allowProposedApi: true,
  });
  // Let the browser handle Ctrl/Cmd-V and Ctrl/Cmd-Shift-V so the
  // native `paste` event fires (capture-phase listener on paneEl then
  // forwards images as PasteBegin/Chunk/End, or lets xterm.js bubble-
  // phase handle text paste). Without this xterm.js eats the keystroke
  // and forwards it to the shell as literal `^V` — meaning Ctrl-V
  // never reaches our paste handler at all.
  //
  // Trade-off: vim users who relied on Ctrl-V for "quoted-insert" must
  // now use Ctrl-Q. Acceptable for a web terminal where paste is the
  // dominant use case.
  term.attachCustomKeyEventHandler((ev) => {
    if (ev.type === 'keydown'
        && (ev.ctrlKey || ev.metaKey)
        && (ev.key === 'v' || ev.key === 'V')) {
      return false;
    }
    return true;
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  // Wide-character widths (emoji, CJK). Must activate the version.
  term.loadAddon(new Unicode11Addon.Unicode11Addon());
  term.unicode.activeVersion = '11';
  // Ctrl/Cmd-click URLs.
  term.loadAddon(new WebLinksAddon.WebLinksAddon());
  // Ctrl-F search (UI wired below).
  const search = new SearchAddon.SearchAddon();
  term.loadAddon(search);
  // Inline images: sixel + iTerm2 protocol (chafa, kitty +icat, imgcat …).
  term.loadAddon(new ImageAddon.ImageAddon());
  // Snapshot the terminal state (incl. scrollback) for sharing / debugging.
  // Bound to Ctrl-Shift-S below; copies the buffer to the clipboard.
  const serialize = new SerializeAddon.SerializeAddon();
  term.loadAddon(serialize);
  // OSC 52 clipboard: lets `tmux save-buffer -|xclip -i -sel c`-style
  // tricks and vim's `+y/+p go through the browser's clipboard.
  term.loadAddon(new ClipboardAddon.ClipboardAddon());

  const paneEl = document.createElement('div');
  paneEl.className = 'term-pane';
  paneEl.hidden = true;
  $('#terminal-container').appendChild(paneEl);
  term.open(paneEl);

  // Transfer panel: floats over the bottom-right of this pane and
  // shows one row per in-flight paste / download. Hidden when empty.
  // Populated by setTransfer / updateTransfer / clearTransfer.
  const transfersEl = document.createElement('div');
  transfersEl.className = 'transfers';
  transfersEl.hidden = true;
  paneEl.appendChild(transfersEl);

  // Hints overlay: shown on first activation. Three tips for new
  // users (paste, drag-drop, term-dl). Dismissable via the × button;
  // dismissal is per-tab and per-page-load (no localStorage).
  const hintsEl = document.createElement('div');
  hintsEl.className = 'hints';
  hintsEl.hidden = true;
  hintsEl.innerHTML = `
    <button type="button" class="hints-close" title="dismiss">×</button>
    <div class="hint"><span class="hint-key">drag</span> drop files anywhere in the terminal to upload</div>
    <div class="hint"><span class="hint-key">Ctrl-V</span> paste files or text from the clipboard</div>
    <div class="hint"><span class="hint-key">term-dl</span> &lt;path&gt; — download a file from this host</div>
  `;
  paneEl.appendChild(hintsEl);

  // WebGL renderer: 5–10× faster than the DOM renderer. Must be loaded
  // *after* term.open() so the element exists. Fall back to DOM if the
  // GPU context is lost or unavailable.
  try {
    const webgl = new WebglAddon.WebglAddon();
    webgl.onContextLoss(() => { try { webgl.dispose(); } catch (_) {} });
    term.loadAddon(webgl);
  } catch (e) {
    console.warn('WebGL renderer unavailable; using DOM renderer', e);
  }

  // Windows-Terminal / PuTTY clipboard flow:
  //   - selection auto-copies to the system clipboard (writeText is
  //     allowed because the surrounding mouseup is a user gesture).
  //   - right-click pastes from the system clipboard. Falls back
  //     silently if the user denies clipboard-read.
  //
  // Paste + contextmenu handlers that need access to `tab.ws` (for
  // image paste) are installed in `attachClipboardHandlers(tab)` below,
  // after the tab object exists.
  paneEl.addEventListener('mouseup', () => {
    const sel = term.getSelection();
    if (!sel) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(sel).catch(() => {});
    }
  });

  // Tab strip element.
  const tabEl = document.createElement('button');
  tabEl.type = 'button';
  tabEl.className = 'tab';
  const status = document.createElement('span');
  status.className = 'status connecting';
  const name = document.createElement('span');
  name.className = 'name';
  name.textContent = `${machine.label} · ${sessionId}`;
  // Controller pill: shows "● controlling — Release" when this tab is
  // controller, "👁 viewing — Take control" when not, and "no
  // controller — Acquire" when nobody controls. Wired by
  // handleControllerChanged below.
  const ctrlPill = document.createElement('span');
  ctrlPill.className = 'ctrl-pill';
  ctrlPill.hidden = true;
  const ctrlLabel = document.createElement('span');
  ctrlLabel.className = 'ctrl-label';
  const ctrlBtn = document.createElement('button');
  ctrlBtn.type = 'button';
  ctrlBtn.className = 'ctrl-btn';
  ctrlPill.appendChild(ctrlLabel);
  ctrlPill.appendChild(ctrlBtn);
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'close'; close.textContent = '×'; close.title = 'close';
  tabEl.appendChild(status);
  tabEl.appendChild(name);
  tabEl.appendChild(ctrlPill);
  tabEl.appendChild(close);
  $('#tab-bar').appendChild(tabEl);

  const tab = {
    machineId, sessionId, term, fit, search, serialize, paneEl, tabEl, statusEl: status,
    transfersEl, hintsEl,
    _transfers: new Map(),
    _hintsDismissed: false,
    ctrlPill, ctrlLabel, ctrlBtn,
    controllerStatus: 0, // CONTROLLER_STATUS_NONE
    ws: null, dataDisposable: null, resizeDisposable: null,
    closing: false, reconnectAttempt: 0, reconnectTimer: 0,
  };
  tabs.push(tab);
  writeFragment(tabs);

  hintsEl.querySelector('.hints-close').addEventListener('click', (ev) => {
    ev.stopPropagation();
    tab._hintsDismissed = true;
    hintsEl.hidden = true;
  });

  attachClipboardHandlers(tab);

  // Wire the controller-pill button: behavior depends on current
  // status. Stops propagation so it doesn't also activate the tab.
  ctrlBtn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) return;
    switch (tab.controllerStatus) {
      case 0: tab.ws.send(encodeControlOnly(FRAME_ACQUIRE_CONTROL)); break;
      case 1: tab.ws.send(encodeControlOnly(FRAME_RELEASE_CONTROL)); break;
      case 2: tab.ws.send(encodeControlOnly(FRAME_TAKE_CONTROL));    break;
    }
  });

  tabEl.addEventListener('click', (ev) => {
    if (ev.target === close) return;
    activateTab(tabs.indexOf(tab));
  });
  close.addEventListener('click', (ev) => {
    ev.stopPropagation();
    closeTab(tab, /*persist*/ true);
  });

  connectTab(tab);

  if (activate) activateTab(tabs.indexOf(tab));
}

// ----- transfer progress overlay --------------------------------------------
//
// Per-tab floating panel that lists one row per in-flight transfer
// (paste = browser→agent, download = agent→browser) with a progress
// bar. Auto-hides when empty. Drives off the existing paste-send loop
// (sendPasteFile, sendPasteFiles) and the download-receive handlers
// (onDownloadBegin/Chunk/End).

function setTransfer(tab, key, info) {
  tab._transfers.set(key, info);
  renderTransfers(tab);
}
function updateTransfer(tab, key, done) {
  const t = tab._transfers.get(key);
  if (!t) return;
  t.done = done;
  renderTransfers(tab);
}
function clearTransfer(tab, key) {
  if (tab._transfers.delete(key)) renderTransfers(tab);
}
function renderTransfers(tab) {
  const panel = tab.transfersEl;
  if (!panel) return;
  if (tab._transfers.size === 0) {
    panel.hidden = true;
    panel.textContent = '';
    return;
  }
  // Rebuild from scratch — sets are small (a few rows) and this avoids
  // tracking per-row DOM nodes.
  panel.textContent = '';
  for (const [, t] of tab._transfers) {
    const row = document.createElement('div');
    row.className = 'transfer';
    const pct = t.total > 0 ? Math.min(100, (t.done * 100 / t.total)) : 0;
    const dir = document.createElement('span');
    dir.className = 'dir';
    dir.textContent = t.kind === 'paste' ? '↑' : '↓';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = t.name;
    name.title = t.name;
    const bar = document.createElement('div');
    bar.className = 'bar';
    const fill = document.createElement('div');
    fill.className = 'bar-fill';
    fill.style.width = pct.toFixed(1) + '%';
    bar.appendChild(fill);
    const bytes = document.createElement('span');
    bytes.className = 'bytes';
    bytes.textContent = `${humanBytes(t.done)} / ${humanBytes(t.total)}`;
    row.appendChild(dir);
    row.appendChild(name);
    row.appendChild(bar);
    row.appendChild(bytes);
    panel.appendChild(row);
  }
  panel.hidden = false;
}
function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

// ----- clipboard / paste / drag-and-drop glue --------------------------------
//
// Pasting (Ctrl-V, right-click) or dragging a file onto the terminal pane
// streams the bytes to the agent as a chunked PasteBegin/Chunk*/End
// sequence. The agent saves each file under its paste dir, then injects
// the absolute path(s) into the PTY as a bracketed-paste block. This
// mirrors iTerm2's "Paste Selection as File" — gives CLI agents running
// inside the remote shell (Copilot CLI, Claude Code, …) something they
// can read off disk.
//
// Multi-file paste sends N PasteBegins in parallel (different paste_ids);
// the agent coalesces their finished paths into a single space-separated
// bracketed-paste block when they land close in time.
//
// Text paste continues to flow through xterm.js's normal path.

// Sanitize a browser-supplied filename: take the last path component,
// restrict to [A-Za-z0-9._-], strip leading dots/dashes, truncate to
// 200 chars. The agent re-sanitizes; this is just for a sensible hint
// over the wire and a less-surprising flash() label.
function sanitizePasteName(name) {
  if (!name) return '';
  // Browsers don't expose directory paths on File.name, but be defensive
  // about backslashes and slashes anyway.
  let s = name.replace(/^.*[\\/]/, '');
  s = s.replace(/[^A-Za-z0-9._-]/g, '_');
  s = s.replace(/^[.\-]+/, '');
  return s.slice(0, 200);
}

function defaultNameForBlob(blob) {
  if (blob && blob.name && blob.name.length) return blob.name;
  const ext = ({
    'image/png':  'png',
    'image/jpeg': 'jpg',
    'image/gif':  'gif',
    'image/webp': 'webp',
    'image/bmp':  'bmp',
    'application/pdf': 'pdf',
    'text/plain': 'txt',
  })[blob && blob.type] || 'bin';
  return `paste.${ext}`;
}

// Per-tab paste_id allocator. paste_ids only need to be unique among
// the tab's in-flight pastes; we just monotonically increment.
function nextPasteId(tab) {
  tab._nextPasteId = ((tab._nextPasteId || 0) + 1) >>> 0;
  if (tab._nextPasteId === 0) tab._nextPasteId = 1; // skip 0 (cosmetic)
  return tab._nextPasteId;
}

// Per-tab group_id allocator. Each "paste action" (one Ctrl-V, one
// right-click, one drag-and-drop) gets a fresh group_id; all N files
// in that action share it, so the agent injects all N paths in one
// bracketed-paste block once the last file completes.
function nextGroupId(tab) {
  tab._nextGroupId = ((tab._nextGroupId || 0) + 1) >>> 0;
  if (tab._nextGroupId === 0) tab._nextGroupId = 1;
  return tab._nextGroupId;
}

// Block until the WebSocket's send buffer drops below `lowMark`, so a
// fast file slice doesn't outrun a slow link and blow up RAM.
async function waitForDrain(ws, lowMark) {
  while (ws.bufferedAmount > lowMark) {
    if (ws.readyState !== WebSocket.OPEN) return;
    await new Promise((r) => setTimeout(r, 20));
  }
}

// Stream a Blob/File as PasteBegin → PasteChunk×N → PasteEnd. Returns
// true on success (End sent OK), false on any failure (End cancelled).
async function sendPasteFile(tab, blob, groupId, groupSize) {
  const size = blob.size;
  if (size > MAX_PASTE_TOTAL_BYTES) {
    flash(`file too large (${(size / 1024 / 1024 / 1024).toFixed(2)} GiB > 4 GiB)`);
    return false;
  }
  if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) {
    flash('terminal disconnected; paste not sent');
    return false;
  }
  // If the group has already been rejected by the agent, bail without
  // sending any more chunks for it. (sendPasteFiles will skip the rest.)
  if (tab._abortedGroups && tab._abortedGroups.has(groupId)) {
    return false;
  }
  const name = sanitizePasteName(defaultNameForBlob(blob));
  const pasteId = nextPasteId(tab);
  // Track paste_id → group_id so the WS receiver can mark the whole
  // group aborted when a PasteReject arrives.
  if (!tab._pasteToGroup) tab._pasteToGroup = new Map();
  tab._pasteToGroup.set(pasteId, groupId);
  // High-water mark for browser-side outgoing buffer: 16 chunks.
  // waitForDrain() yields until we drop below this.
  const SEND_HIGH_WATER = 16 * MAX_PASTE_CHUNK_BYTES;

  try {
    tab.ws.send(encodePasteBegin(pasteId, size, groupId, groupSize, name));
    const transferKey = `p:${pasteId}`;
    setTransfer(tab, transferKey, {
      kind: 'paste', name, done: 0, total: size, groupId,
    });

    const big = size > MAX_PASTE_CHUNK_BYTES;
    if (big) flash(`uploading ${name} (${(size / 1024 / 1024).toFixed(1)} MiB)…`);

    // Slice the blob and ship chunk-by-chunk. Blob.slice() doesn't
    // materialize anything; only the active chunk is read into a JS
    // ArrayBuffer at any time.
    let offset = 0;
    while (offset < size) {
      if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) {
        flash('terminal disconnected mid-paste');
        clearTransfer(tab, transferKey);
        return false;
      }
      // Agent rejected this paste mid-stream — stop wasting bytes.
      if (tab._abortedPastes && tab._abortedPastes.has(pasteId)) {
        clearTransfer(tab, transferKey);
        return false;
      }
      // Backpressure: don't read+send the next chunk until the WS has
      // drained the previous ones. waitForDrain bails out if the socket
      // closes during the wait.
      if (tab.ws.bufferedAmount > SEND_HIGH_WATER) {
        await waitForDrain(tab.ws, SEND_HIGH_WATER / 2);
        if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) {
          flash('terminal disconnected mid-paste');
          clearTransfer(tab, transferKey);
          return false;
        }
      }
      const end = Math.min(offset + MAX_PASTE_CHUNK_BYTES, size);
      const slice = blob.slice(offset, end);
      const buf = new Uint8Array(await slice.arrayBuffer());
      // Re-check after the await.
      if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) {
        flash('terminal disconnected mid-paste');
        clearTransfer(tab, transferKey);
        return false;
      }
      if (tab._abortedPastes && tab._abortedPastes.has(pasteId)) {
        clearTransfer(tab, transferKey);
        return false;
      }
      tab.ws.send(encodePasteChunk(pasteId, buf));
      offset = end;
      updateTransfer(tab, transferKey, offset);
    }
    tab.ws.send(encodePasteEnd(pasteId, PASTE_STATUS_OK));
    clearTransfer(tab, transferKey);
    if (big) flash(`uploaded ${name}`);
    return true;
  } catch (e) {
    console.warn('sendPasteFile', e);
    flash(`paste failed: ${name}`);
    try {
      if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
        tab.ws.send(encodePasteEnd(pasteId, PASTE_STATUS_CANCEL));
      }
    } catch (_) {}
    clearTransfer(tab, `p:${pasteId}`);
    return false;
  } finally {
    if (tab._pasteToGroup) tab._pasteToGroup.delete(pasteId);
    if (tab._abortedPastes) tab._abortedPastes.delete(pasteId);
  }
}

// Send a list of File objects (any type) in order as one paste group,
// so the agent injects all the paths in a single bracketed-paste
// block once the last one finishes uploading.
async function sendPasteFiles(tab, files) {
  const fs = (files || []).filter(Boolean);
  if (fs.length === 0) return;
  // Enforce the aggregate per-paste-action cap up front. Agent will
  // reject this anyway via PasteReject if we lie, but it's nicer UX
  // to fail fast before we start uploading the first file.
  const totalSize = fs.reduce((a, f) => a + (f.size || 0), 0);
  if (totalSize > MAX_PASTE_TOTAL_BYTES) {
    flash(`paste batch too large (${(totalSize / 1024 / 1024 / 1024).toFixed(2)} GiB > 4 GiB)`);
    return;
  }
  const groupId = nextGroupId(tab);
  for (const f of fs) {
    // If a previous file in this group hit a PasteReject, stop
    // dispatching new ones — the agent has already discarded the
    // already-uploaded siblings.
    if (tab._abortedGroups && tab._abortedGroups.has(groupId)) break;
    await sendPasteFile(tab, f, groupId, fs.length);
  }
  if (tab._abortedGroups) tab._abortedGroups.delete(groupId);
}

// ----- downloads (agent → browser, via term-dl) ------------------------------
//
// The agent ships a file as DownloadBegin → DownloadChunk × N →
// DownloadEnd. We buffer chunks per download_id and, on End(ok), trigger
// a save via a programmatic `<a download>` click. End(cancel) discards
// the buffer and flashes a message.

function readU32BE(buf, off) {
  return ((buf[off] << 24) | (buf[off + 1] << 16) |
          (buf[off + 2] <<  8) |  buf[off + 3]) >>> 0;
}
function readU64BENumber(buf, off) {
  // Accurate across the full 4 GiB range using BigInt; clamp back to a
  // Number for ergonomic use. Beyond 2^53 we'd lose precision, but
  // total_size is capped at 4 GiB so we're safe.
  const hi = BigInt(readU32BE(buf, off));
  const lo = BigInt(readU32BE(buf, off + 4));
  return Number((hi << 32n) | lo);
}

function handleDownloadBegin(tab, payload) {
  if (payload.length < 13) return;
  const downloadId = readU32BE(payload, 0);
  const totalSize  = readU64BENumber(payload, 4);
  const nameLen    = payload[12];
  if (payload.length !== 13 + nameLen) return;
  const name = new TextDecoder('utf-8', { fatal: false })
    .decode(payload.subarray(13, 13 + nameLen)) || 'download';

  if (totalSize > MAX_DOWNLOAD_TOTAL_BYTES) {
    flash(`download "${name}" too large (${(totalSize / 1024 / 1024).toFixed(0)} MiB; cap 256 MiB)`);
    return;
  }

  if (!tab._downloads) tab._downloads = new Map();
  if (tab._downloads.size >= MAX_INFLIGHT_DOWNLOADS) {
    flash(`too many downloads in flight; dropping "${name}"`);
    return;
  }
  if (tab._downloads.has(downloadId)) {
    // Agent shouldn't reuse a download_id while one is in flight, but
    // be defensive and reject quietly.
    return;
  }
  tab._downloads.set(downloadId, { name, totalSize, received: 0, chunks: [] });
  setTransfer(tab, `d:${downloadId}`, {
    kind: 'download', name, done: 0, total: totalSize,
  });
  if (totalSize > MAX_PASTE_CHUNK_BYTES) {
    flash(`downloading ${name} (${(totalSize / 1024 / 1024).toFixed(1)} MiB)…`);
  }
}

function handleDownloadChunk(tab, payload) {
  if (payload.length < 4 || !tab._downloads) return;
  const downloadId = readU32BE(payload, 0);
  const dl = tab._downloads.get(downloadId);
  if (!dl) return;
  const chunk = payload.subarray(4);
  if (dl.received + chunk.length > dl.totalSize) {
    // Agent overran its own declaration. Drop the download to avoid
    // saving a too-large file (the agent will also have logged this).
    tab._downloads.delete(downloadId);
    clearTransfer(tab, `d:${downloadId}`);
    flash(`download "${dl.name}" overran declared size; discarded`);
    return;
  }
  // Copy out of the WS buffer (which the browser may reuse) into an
  // owned Uint8Array.
  dl.chunks.push(new Uint8Array(chunk));
  dl.received += chunk.length;
  updateTransfer(tab, `d:${downloadId}`, dl.received);
}

function handleDownloadEnd(tab, payload) {
  if (payload.length !== 5 || !tab._downloads) return;
  const downloadId = readU32BE(payload, 0);
  const status     = payload[4];
  const dl = tab._downloads.get(downloadId);
  if (!dl) return;
  tab._downloads.delete(downloadId);
  clearTransfer(tab, `d:${downloadId}`);

  if (status === DOWNLOAD_STATUS_CANCEL) {
    flash(`download "${dl.name}" cancelled`);
    return;
  }
  if (dl.received !== dl.totalSize) {
    flash(`download "${dl.name}" truncated (${dl.received}/${dl.totalSize})`);
    return;
  }
  saveBlob(new Blob(dl.chunks), dl.name);
  flash(`downloaded ${dl.name}`);
}

/// Update the controller pill in the tab strip based on the
/// per-receiver status byte the agent sent us.
/// status = 0 (NONE) | 1 (SELF) | 2 (OTHER).
function handleControllerChanged(tab, status) {
  tab.controllerStatus = status;
  if (!tab.ctrlPill) return;
  tab.ctrlPill.hidden = false;
  tab.ctrlPill.classList.remove('controlling', 'viewing', 'no-controller');
  switch (status) {
    case 1: // SELF
      tab.ctrlPill.classList.add('controlling');
      tab.ctrlLabel.textContent = '● controlling';
      tab.ctrlBtn.textContent = 'release';
      tab.ctrlBtn.title = 'release control of this session';
      break;
    case 2: // OTHER
      tab.ctrlPill.classList.add('viewing');
      tab.ctrlLabel.textContent = '👁 viewing';
      tab.ctrlBtn.textContent = 'take';
      tab.ctrlBtn.title = 'take control (the current controller becomes a viewer)';
      break;
    default: // NONE
      tab.ctrlPill.classList.add('no-controller');
      tab.ctrlLabel.textContent = '— no controller';
      tab.ctrlBtn.textContent = 'acquire';
      tab.ctrlBtn.title = 'become the controller for this session';
      break;
  }
}

/// Programmatic save via a hidden <a download>. URL.createObjectURL is
/// per-document so we revoke after the click to avoid leaking the blob.
function saveBlob(blob, suggestedName) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = suggestedName;
  a.rel = 'noopener';
  // Some browsers won't initiate the download for a detached anchor.
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Small timeout so the browser starts the download before we
  // invalidate the URL.
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
}

function attachClipboardHandlers(tab) {
  const { paneEl, term } = tab;

  // Right-click is reserved for "paste from clipboard". xterm.js, when
  // an inner app (tmux, vim) enables mouse reporting, encodes button-2
  // mousedown/up as CSI sequences and writes them to the helper
  // textarea — which we then forward as Data, which tmux interprets as
  // "right-click on pane → show menu". Swallowing the raw mouse events
  // at the capture phase keeps xterm.js from ever seeing them, so the
  // PTY only ever observes the `contextmenu`-triggered paste below.
  const swallowRightButton = (ev) => {
    if (ev.button !== 2) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
  };
  paneEl.addEventListener('mousedown', swallowRightButton, { capture: true });
  paneEl.addEventListener('mouseup',   swallowRightButton, { capture: true });

  // Capture-phase paste handler. xterm.js attaches its own paste
  // handler on the helper textarea in the bubble phase; calling
  // stopImmediatePropagation() here suppresses that text-paste fallback
  // when we've already intercepted file items.
  paneEl.addEventListener('paste', (ev) => {
    const items = ev.clipboardData && ev.clipboardData.items;
    if (!items) return;
    const files = [];
    for (const it of items) {
      if (it.kind !== 'file') continue;
      const f = it.getAsFile();
      if (f) files.push(f);
    }
    if (files.length === 0) return; // text paste — let xterm.js handle.
    ev.preventDefault();
    ev.stopImmediatePropagation();
    sendPasteFiles(tab, files);
  }, { capture: true });

  // Right-click paste. Try clipboard.read() so we can detect files
  // (images especially); fall back to readText() if the permission is
  // denied or the API is unavailable (older Safari etc).
  paneEl.addEventListener('contextmenu', async (ev) => {
    ev.preventDefault();
    if (!navigator.clipboard) return;
    if (navigator.clipboard.read) {
      try {
        const items = await navigator.clipboard.read();
        // Collect any image-like items as Files; ClipboardItem doesn't
        // expose a filename, so we synthesize one from the MIME type.
        const blobs = [];
        for (const item of items) {
          for (const type of item.types) {
            if (!type.startsWith('image/') && type !== 'application/pdf') continue;
            try {
              const blob = await item.getType(type);
              // Convert to a File-ish so sendPasteFile can name it.
              blob.name = defaultNameForBlob({ type, name: '' });
              blobs.push(blob);
              break; // one type per ClipboardItem
            } catch (_) {}
          }
        }
        if (blobs.length > 0) { await sendPasteFiles(tab, blobs); return; }
        // No files; try text.
        for (const item of items) {
          if (item.types.includes('text/plain')) {
            const blob = await item.getType('text/plain');
            const text = await blob.text();
            if (text) term.paste(text);
            return;
          }
        }
        return;
      } catch (_) { /* permission denied; fall through to readText */ }
    }
    if (navigator.clipboard.readText) {
      try {
        const text = await navigator.clipboard.readText();
        if (text) term.paste(text);
      } catch (_) { /* permission denied or no clipboard */ }
    }
  });

  // Drag-and-drop: dropping files onto the terminal pane sends them
  // through the same path. Browser default is to navigate to the file,
  // so preventDefault on both dragover (to allow drop) and drop.
  paneEl.addEventListener('dragover', (ev) => {
    if (ev.dataTransfer && Array.from(ev.dataTransfer.items || []).some((it) => it.kind === 'file')) {
      ev.preventDefault();
      ev.dataTransfer.dropEffect = 'copy';
    }
  });
  paneEl.addEventListener('drop', (ev) => {
    if (!ev.dataTransfer || !ev.dataTransfer.files || ev.dataTransfer.files.length === 0) return;
    ev.preventDefault();
    sendPasteFiles(tab, Array.from(ev.dataTransfer.files));
  });
}

function connectTab(tab) {
  if (tab.closing) return;
  if (tab.reconnectTimer) { clearTimeout(tab.reconnectTimer); tab.reconnectTimer = 0; }

  const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/term/${encodeURIComponent(tab.machineId)}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl, ['bearer.' + token]);
  } catch (e) {
    setStatus(tab, 'error');
    scheduleReconnect(tab);
    return;
  }
  ws.binaryType = 'arraybuffer';
  tab.ws = ws;
  setStatus(tab, 'connecting');

  ws.addEventListener('open', () => {
    tab.reconnectAttempt = 0;
    setStatus(tab, 'ok');
    // First frame: Open(session_id, initial_size) — agent attaches to
    // (or spawns) the session with this geometry, so a fresh PTY comes
    // up at the right size instead of the 24×80 placeholder.
    let { fit } = tab;
    // The fit addon needs the pane visible to compute size; if this
    // tab isn't the active one yet, fit may report nothing. Fall back
    // to (24, 80) — Resize will fix it as soon as the tab is shown.
    try { fit.fit(); } catch (_) {}
    const rows = (tab.term && tab.term.rows) ? tab.term.rows : 24;
    const cols = (tab.term && tab.term.cols) ? tab.term.cols : 80;
    ws.send(encodeOpen(tab.sessionId, rows, cols));
    sendResizeIfReady(tab);
    tab.dataDisposable = tab.term.onData((str) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(encodeData(new TextEncoder().encode(str)));
    });
    tab.resizeDisposable = tab.term.onResize(({ rows, cols }) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(encodeResize(rows, cols));
    });
  });
  ws.addEventListener('message', (ev) => {
    const view = new Uint8Array(ev.data);
    const f = parseFrame(view);
    if (!f) return;
    if (f.type === FRAME_DATA) {
      tab.term.write(f.payload);
    } else if (f.type === FRAME_PASTE_REJECT && f.payload.length === 5) {
      const pasteId = ((f.payload[0] << 24) | (f.payload[1] << 16) |
                       (f.payload[2] <<  8) |  f.payload[3]) >>> 0;
      const reason  = f.payload[4];
      // Mark this paste_id (and its whole group) as aborted so any
      // in-flight chunk loop bails on its next pre-send check. The
      // agent has already discarded its tempfile + the group's
      // already-finished siblings.
      if (!tab._abortedPastes) tab._abortedPastes = new Set();
      tab._abortedPastes.add(pasteId);
      const gid = tab._pasteToGroup && tab._pasteToGroup.get(pasteId);
      if (gid != null) {
        if (!tab._abortedGroups) tab._abortedGroups = new Set();
        tab._abortedGroups.add(gid);
      }
      flash(`paste rejected: ${pasteRejectMessage(reason)}`);
    } else if (f.type === FRAME_DOWNLOAD_BEGIN) {
      handleDownloadBegin(tab, f.payload);
    } else if (f.type === FRAME_DOWNLOAD_CHUNK) {
      handleDownloadChunk(tab, f.payload);
    } else if (f.type === FRAME_DOWNLOAD_END) {
      handleDownloadEnd(tab, f.payload);
    } else if (f.type === FRAME_CONTROLLER_CHANGED && f.payload.length === 1) {
      // status: 0 = no controller, 1 = SELF, 2 = OTHER. Agent does
      // the mapping per-stream so the browser doesn't have to know its
      // own (hub-allocated) sid.
      handleControllerChanged(tab, f.payload[0]);
    }
    // Other frame types coming from hub are not currently used in this
    // direction; ignore.
  });
  ws.addEventListener('close', () => {
    if (tab.dataDisposable)   { tab.dataDisposable.dispose();   tab.dataDisposable = null; }
    if (tab.resizeDisposable) { tab.resizeDisposable.dispose(); tab.resizeDisposable = null; }
    tab.ws = null;
    if (!tab.closing) {
      setStatus(tab, 'connecting');
      scheduleReconnect(tab);
    }
  });
  ws.addEventListener('error', () => {
    // The close event will follow and do the reconnect.
    setStatus(tab, 'error');
  });
}

function scheduleReconnect(tab) {
  if (tab.closing) return;
  tab.reconnectAttempt = (tab.reconnectAttempt || 0) + 1;
  // 500ms, 1s, 2s, 4s, 8s, 16s, capped at 30s; with jitter to avoid
  // thundering-herd when many tabs reconnect at once.
  const base = Math.min(500 * Math.pow(2, tab.reconnectAttempt - 1), 30_000);
  const delay = Math.floor(base * (0.7 + Math.random() * 0.6));
  tab.reconnectTimer = setTimeout(() => connectTab(tab), delay);
}

function sendResizeIfReady(tab) {
  if (!tab.paneEl.isConnected || tab.paneEl.hidden) return;
  try { tab.fit.fit(); } catch (_) { return; }
  if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
    tab.ws.send(encodeResize(tab.term.rows, tab.term.cols));
  }
}

function setStatus(tab, kind) {
  tab.statusEl.className = 'status ' + (kind || '');
}

function activateTab(idx) {
  if (idx < 0 || idx >= tabs.length) return;
  activeTabIdx = idx;
  tabs.forEach((t, i) => {
    const on = i === idx;
    t.paneEl.hidden = !on;
    t.tabEl.classList.toggle('active', on);
  });
  const t = tabs[idx];
  // First-activation hints overlay. Skip if already dismissed.
  if (!t._hintsDismissed && !t._hintsShown) {
    t._hintsShown = true;
    t.hintsEl.hidden = false;
    // Auto-dismiss after 12 seconds so it doesn't linger forever
    // for users who never explicitly close it.
    setTimeout(() => {
      if (!t._hintsDismissed) { t._hintsDismissed = true; t.hintsEl.hidden = true; }
    }, 12000);
  }
  // Refit once visible.
  requestAnimationFrame(() => {
    sendResizeIfReady(t);
    t.term.focus();
  });
}

function closeTab(tab, persist) {
  const idx = tabs.indexOf(tab); if (idx < 0) return;
  tab.closing = true;
  if (tab.reconnectTimer) { clearTimeout(tab.reconnectTimer); tab.reconnectTimer = 0; }
  try { tab.ws && tab.ws.close(); } catch (_) {}
  try { tab.term.dispose(); } catch (_) {}
  try { tab.paneEl.remove(); } catch (_) {}
  try { tab.tabEl.remove(); } catch (_) {}
  tabs.splice(idx, 1);
  if (persist) writeFragment(tabs);
  if (tabs.length === 0) { activeTabIdx = -1; return; }
  const next = Math.min(idx, tabs.length - 1);
  activateTab(next);
}

let resizeRaf = 0;
function onResize() {
  if (resizeRaf) cancelAnimationFrame(resizeRaf);
  resizeRaf = requestAnimationFrame(() => {
    resizeRaf = 0;
    if (activeTabIdx >= 0) sendResizeIfReady(tabs[activeTabIdx]);
  });
}

// ----- search bar (Ctrl-F / Cmd-F) -------------------------------------------

function bindSearchUi() {
  const bar    = $('#search-bar');
  const input  = $('#search-input');
  const count  = $('#search-count');
  const opts   = { decorations: { matchOverviewRuler: '#f9e2af',
                                  activeMatchColorOverviewRuler: '#f5e0dc',
                                  matchBackground: '#414559',
                                  activeMatchBackground: '#fab387' } };

  function active() { return activeTabIdx >= 0 ? tabs[activeTabIdx] : null; }

  function open() {
    if (!active()) return;
    bar.hidden = false;
    input.focus();
    input.select();
  }
  function close() {
    bar.hidden = true;
    const t = active();
    if (t) { try { t.search.clearDecorations(); } catch (_) {} t.term.focus(); }
    count.textContent = '';
  }
  function find(next) {
    const t = active();
    if (!t || !input.value) return;
    const fn = next ? 'findNext' : 'findPrevious';
    try { t.search[fn](input.value, opts); } catch (_) {}
  }

  // Ctrl-F (Cmd-F on Mac). Also intercept Ctrl-Shift-F as "find again".
  window.addEventListener('keydown', (ev) => {
    const mod = ev.ctrlKey || ev.metaKey;
    if (mod && (ev.key === 'f' || ev.key === 'F')) {
      // Allow the browser's native find inside form inputs; otherwise
      // hijack for terminal search.
      if (document.activeElement && document.activeElement.tagName === 'INPUT') return;
      ev.preventDefault();
      open();
    } else if (mod && ev.shiftKey && (ev.key === 'S' || ev.key === 's')) {
      // Ctrl-Shift-S: copy a serialized snapshot of the active tab's
      // buffer (incl. scrollback + colors as ANSI) to the clipboard.
      const t = active();
      if (!t || !t.serialize) return;
      ev.preventDefault();
      try {
        const text = t.serialize.serialize();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            () => flash('snapshot copied'),
            () => flash('snapshot copy failed'),
          );
        }
      } catch (_) {}
    } else if (ev.key === 'Escape' && !bar.hidden) {
      ev.preventDefault();
      close();
    }
  });
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); find(!ev.shiftKey); }
    else if (ev.key === 'Escape') { ev.preventDefault(); close(); }
  });
  input.addEventListener('input', () => find(true));
}

// ----- transient toast --------------------------------------------------------

function flash(text) {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = text;
  el.classList.add('show');
  clearTimeout(flash._t);
  flash._t = setTimeout(() => el.classList.remove('show'), 1200);
}
