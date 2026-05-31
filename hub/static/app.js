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

const FRAME_DATA   = 0;
const FRAME_RESIZE = 1;
const FRAME_OPEN   = 2;

function encodeFrame(type, payload) {
  const len = payload.length;
  const buf = new Uint8Array(5 + len);
  buf[0] = type;
  buf[1] = (len >>> 24) & 0xff;
  buf[2] = (len >>> 16) & 0xff;
  buf[3] = (len >>> 8)  & 0xff;
  buf[4] =  len         & 0xff;
  buf.set(payload, 5);
  return buf;
}
function encodeData(bytes) { return encodeFrame(FRAME_DATA, bytes); }
function encodeResize(rows, cols) {
  const p = new Uint8Array(4);
  p[0] = (rows >>> 8) & 0xff; p[1] = rows & 0xff;
  p[2] = (cols >>> 8) & 0xff; p[3] = cols & 0xff;
  return encodeFrame(FRAME_RESIZE, p);
}
function encodeOpen(sessionId) {
  return encodeFrame(FRAME_OPEN, new TextEncoder().encode(sessionId));
}
function parseFrame(view) {
  if (view.byteLength < 5) return null;
  const type = view[0];
  const len = (view[1] << 24) | (view[2] << 16) | (view[3] << 8) | view[4];
  if (view.byteLength !== 5 + len) return null;
  return { type, payload: view.subarray(5) };
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
    const label = document.createElement('span');
    label.className = 'label'; label.textContent = m.label;
    const id = document.createElement('span');
    id.className = 'id'; id.textContent = m.id;
    const add = document.createElement('button');
    add.className = 'new'; add.type = 'button'; add.title = 'new tab';
    add.textContent = '+';
    li.appendChild(label);
    li.appendChild(id);
    li.appendChild(add);
    li.addEventListener('click', (ev) => {
      if (ev.target === add) return;
      openTab(m.id, newSessionId(), /*activate*/ true);
    });
    add.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openTab(m.id, newSessionId(), /*activate*/ true);
    });
    ul.appendChild(li);
  }
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
    fontFamily: 'ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace',
    fontSize: 13,
    cursorBlink: true,
    convertEol: false,
    theme: {
      background: '#0b0e14', foreground: '#cdd6f4', cursor: '#cdd6f4',
      selectionBackground: '#414559',
    },
    allowProposedApi: true,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);

  const paneEl = document.createElement('div');
  paneEl.className = 'term-pane';
  paneEl.hidden = true;
  $('#terminal-container').appendChild(paneEl);
  term.open(paneEl);

  // Tab strip element.
  const tabEl = document.createElement('button');
  tabEl.type = 'button';
  tabEl.className = 'tab';
  const status = document.createElement('span');
  status.className = 'status connecting';
  const name = document.createElement('span');
  name.className = 'name';
  name.textContent = `${machine.label} · ${sessionId}`;
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'close'; close.textContent = '×'; close.title = 'close';
  tabEl.appendChild(status);
  tabEl.appendChild(name);
  tabEl.appendChild(close);
  $('#tab-bar').appendChild(tabEl);

  const tab = {
    machineId, sessionId, term, fit, paneEl, tabEl, statusEl: status,
    ws: null, dataDisposable: null, resizeDisposable: null,
  };
  tabs.push(tab);
  writeFragment(tabs);

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

function connectTab(tab) {
  const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/term/${encodeURIComponent(tab.machineId)}`;
  const ws = new WebSocket(wsUrl, ['bearer.' + token]);
  ws.binaryType = 'arraybuffer';
  tab.ws = ws;
  setStatus(tab, 'connecting');

  ws.addEventListener('open', () => {
    setStatus(tab, 'ok');
    // First frame: Open(session_id).
    ws.send(encodeOpen(tab.sessionId));
    // Then send initial size (fit will recompute lazily after activation).
    sendResizeIfReady(tab);
    // Hook xterm input -> data frames.
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
    }
    // Hub never sends resize/open to browser; ignore everything else.
  });
  ws.addEventListener('close', () => {
    setStatus(tab, 'error');
    if (tab.dataDisposable) { tab.dataDisposable.dispose(); tab.dataDisposable = null; }
    if (tab.resizeDisposable) { tab.resizeDisposable.dispose(); tab.resizeDisposable = null; }
  });
  ws.addEventListener('error', () => setStatus(tab, 'error'));
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
  // Refit once visible.
  requestAnimationFrame(() => {
    sendResizeIfReady(t);
    t.term.focus();
  });
}

function closeTab(tab, persist) {
  const idx = tabs.indexOf(tab); if (idx < 0) return;
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
