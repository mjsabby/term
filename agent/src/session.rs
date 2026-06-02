//! In-agent session manager: replaces tmux for session persistence,
//! multi-attach, scrollback replay, and the single-active-controller
//! model.
//!
//! ## Model
//!
//! A `Session` owns one PTY + one shell process. Many `Stream`s
//! (browser tabs) may attach to it; one of them is the *controller*
//! (the only one whose input/resize actually reaches the PTY) and the
//! rest are *viewers*. On controller transition the PTY is resized to
//! the new controller's geometry.
//!
//! Sessions outlive their streams: when the last attached stream
//! detaches, the session is kept alive until either (a) the shell
//! exits, or (b) the idle-TTL sweeper drops it (default 24 h).
//!
//! ## Output fan-out
//!
//! Each Session has a single PTY reader task that:
//!   1. feeds bytes through an [`OscScanner`] (consumes our private
//!      `5111;` OSCs; forwards every other OSC verbatim),
//!   2. appends the to-forward bytes into the scrollback ring,
//!   3. broadcasts the bytes via a `tokio::sync::broadcast` channel.
//!
//! Per-stream tasks subscribe to that broadcast. On new attach, the
//! current scrollback snapshot is replayed as the new subscriber's
//! first batch of Data so the browser doesn't see an empty terminal.
//!
//! Backpressure: a slow subscriber that falls behind by more than
//! `BROADCAST_CAP` events receives `RecvError::Lagged(n)`. We log and
//! continue — the slow browser will see a gap rather than blocking the
//! shared PTY reader.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};

use term_common::frame::{
    DOWNLOAD_STATUS_CANCEL, DOWNLOAD_STATUS_OK, MAX_PASTE_CHUNK_BYTES,
    MAX_PASTE_TOTAL_BYTES, CONTROLLER_NONE_STREAM_ID,
};
use term_common::osc::OscScanner;

/// 8 MiB byte ring of recent PTY output. Replayed on attach. Used as
/// the default when `agent.toml` doesn't override
/// `limits.scrollback_cap_bytes`.
pub const DEFAULT_SCROLLBACK_CAP_BYTES: usize = 8 * 1024 * 1024;
/// Default idle TTL — sessions with no attached client this long are
/// dropped by the sweeper. Used as the default when `agent.toml`
/// doesn't override `limits.idle_ttl_secs`.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Broadcast channel capacity (events). With ~16 KiB PTY reads, ~1024
/// events ≈ 16 MiB worst-case buffer per slow subscriber.
const BROADCAST_CAP: usize = 1024;

pub type SessionId = String;
pub type StreamId  = u32;

/// One event broadcast from a Session to every attached stream.
#[derive(Clone)]
pub enum SessionEvent {
    /// PTY output bytes (OSC-scanned; safe to forward verbatim as Data).
    Data(Arc<Vec<u8>>),
    /// The session's controller changed. `controller` = new controller
    /// stream_id, or `CONTROLLER_NONE_STREAM_ID` (0) if no one
    /// currently controls.
    ControllerChanged { controller: StreamId },
    /// Begin a download (agent → browser). Same on all attached streams.
    DownloadBegin { id: u32, total_size: u64, name: String },
    /// One chunk of a download. `bytes` is Arc'd so the broadcast
    /// doesn't deep-copy the payload per subscriber.
    DownloadChunk { id: u32, bytes: Arc<Vec<u8>> },
    /// Finalize a download (0 = ok, 1 = cancel).
    DownloadEnd { id: u32, status: u8 },
    /// The shell exited; the Session is being torn down. Subscribers
    /// should send Close on their stream and drop their subscription.
    Closed,
}

/// Bounded byte FIFO (drain on overflow). Used for scrollback.
pub struct ByteRing {
    buf: VecDeque<u8>,
    cap: usize,
}

impl ByteRing {
    pub fn new(cap: usize) -> Self {
        // Pre-allocate a sane lower bound (1 MiB if cap >= 1 MiB) so
        // we don't realloc on every push during steady-state.
        let prealloc = cap.min(1024 * 1024);
        ByteRing { buf: VecDeque::with_capacity(prealloc), cap }
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
        if self.buf.len() > self.cap {
            let excess = self.buf.len() - self.cap;
            self.buf.drain(..excess);
        }
    }

    /// Snapshot current contents as one contiguous Vec. Caller chunks
    /// at MAX_DATA_LEN if needed.
    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize { self.buf.len() }
}

pub struct Session {
    pub id:           SessionId,
    #[allow(dead_code)]
    pub created_at:   Instant,
    /// Per-session unguessable token. Set as `TERM_DL_TOKEN` in the
    /// spawned shell's env; `term-dl` echoes it in every download OSC.
    /// Without this, any PTY output containing
    /// `ESC ] 5111 ; dl ; <path> BEL` would trigger a download —
    /// `cat /etc/motd` on a hostile host could exfiltrate files.
    pub dl_token:     String,
    /// How to inject pasted file paths into the shell when a paste
    /// completes. Derived from the configured `shell` at spawn time.
    pub paste_style:  PasteStyle,
    broadcast_tx:     broadcast::Sender<SessionEvent>,
    pty:              crate::pty::AsyncPty,
    inner:            Mutex<SessionInner>,
    next_download_id: AtomicU32,
}

/// How `inject_paste_paths` (in `main.rs`) formats pasted file paths
/// before typing them into the PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteStyle {
    /// `\x1b[200~ p1 p2 ... pn \x1b[201~`. Works with shells that
    /// understand bracketed paste mode: bash/zsh/fish via readline,
    /// PSReadLine in pwsh ≥ 7.2, vim, less, …
    Bracketed,
    /// Space-separated, with paths containing spaces quoted with `"…"`.
    /// Used for `cmd.exe` because it interprets the bracketed-paste
    /// markers as literal `^[[200~` text instead of consuming them.
    Plain,
}

impl PasteStyle {
    /// Derive a paste style from the configured `shell` knob (raw
    /// argv string from `agent.toml`).
    pub fn from_shell(shell: &str) -> Self {
        let prog = std::path::Path::new(
            shell.split_whitespace().next().unwrap_or(""),
        )
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
        // cmd.exe (with or without .exe suffix, case-insensitive
        // because Windows file system is mostly case-insensitive).
        if prog.eq_ignore_ascii_case("cmd.exe") || prog.eq_ignore_ascii_case("cmd") {
            PasteStyle::Plain
        } else {
            PasteStyle::Bracketed
        }
    }
}

struct SessionInner {
    controller:       Option<StreamId>,
    /// Current PTY geometry (== controller's last-reported size).
    last_size:        (u16, u16),
    /// Stream_id → last-reported geometry. Honored only when this
    /// stream is the controller.
    attached:         HashMap<StreamId, (u16, u16)>,
    scrollback:       ByteRing,
    last_attached_at: Instant,
    exited:           bool,
}

/// Result of an attach: the broadcast subscription, the scrollback to
/// replay before live data starts, and whether this stream became
/// the controller (so the per-stream task can immediately forward a
/// `ControllerChanged(self_sid)` to its browser).
pub struct AttachResult {
    pub event_rx:        broadcast::Receiver<SessionEvent>,
    pub scrollback:      Vec<u8>,
    pub became_controller: bool,
    pub current_controller: Option<StreamId>,
}

impl Session {
    /// Spawn the configured shell in a fresh PTY (no tmux wrapper)
    /// via the cross-platform [`crate::pty::AsyncPty`]. Replaces
    /// `tmux new-session -A -s <id> -- <shell>`.
    ///
    /// `scrollback_cap` bounds the per-session scrollback ring; set
    /// via `agent.toml`'s `limits.scrollback_cap_bytes`.
    pub fn spawn(
        id: SessionId,
        shell: &str,
        initial_size: (u16, u16),
        scrollback_cap: usize,
    ) -> Result<Arc<Self>> {
        let (program, args) = crate::pty::split_shell(shell);
        let (rows, cols) = initial_size;
        // 16 random bytes → 22 base64url-no-pad chars. ~128 bits of
        // entropy; an attacker who can only print bytes into the PTY
        // can't guess this in any practical time.
        let dl_token = {
            let mut buf = [0u8; 16];
            term_common::random::fill(&mut buf);
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
        };
        // systemd service units inherit no TERM and no locale. Set a
        // terminfo-capable TERM, advertise truecolor, pick a UTF-8
        // locale. Same env we used to pass to tmux. Plus the
        // per-session download token (see Session::dl_token).
        let env: Vec<(&str, &str)> = vec![
            ("TERM",           "xterm-256color"),
            ("COLORTERM",      "truecolor"),
            ("LANG",           "C.UTF-8"),
            ("LC_ALL",         "C.UTF-8"),
            ("TERM_DL_TOKEN",  dl_token.as_str()),
        ];
        let pty = crate::pty::AsyncPty::spawn(&program, &args, &env, rows, cols)
            .with_context(|| format!("spawn {program}"))?;

        let (tx, _rx0) = broadcast::channel(BROADCAST_CAP);

        let session = Arc::new(Session {
            id:               id.clone(),
            created_at:       Instant::now(),
            dl_token,
            paste_style:      PasteStyle::from_shell(shell),
            broadcast_tx:     tx.clone(),
            pty,
            next_download_id: AtomicU32::new(1),
            inner:            Mutex::new(SessionInner {
                controller:       None,
                last_size:        initial_size,
                attached:         HashMap::new(),
                scrollback:       ByteRing::new(scrollback_cap),
                last_attached_at: Instant::now(),
                exited:           false,
            }),
        });

        // PTY reader task — per session, NOT per stream. The AsyncPty
        // bridge thread has already moved bytes off the blocking
        // handle into `out_rx`; we just drain, OSC-scan, broadcast.
        let session_for_reader = session.clone();
        let session_id_for_log = id;
        tokio::spawn(async move {
            let mut osc = OscScanner::new();
            loop {
                let chunk = {
                    let mut rx = session_for_reader.pty.out_rx.lock().await;
                    rx.recv().await
                };
                let buf = match chunk {
                    Some(b) => b,
                    None    => break, // shell exited / bridge closed
                };
                let (fwd, captured) = osc.feed(&buf);
                if !fwd.is_empty() {
                    let chunk = Arc::new(fwd);
                    session_for_reader.inner.lock().await.scrollback.extend(&chunk);
                    let _ = session_for_reader.broadcast_tx.send(SessionEvent::Data(chunk));
                }
                for payload in captured {
                    match parse_dl_osc(&payload) {
                        Some((token, path)) => {
                            // Token gate: refuse downloads whose token
                            // doesn't match this session's. Defeats the
                            // "hostile printf in PTY output" attack;
                            // only term-dl invocations from inside the
                            // attached shell get TERM_DL_TOKEN.
                            if !ct_eq_str(&token, &session_for_reader.dl_token) {
                                warn!(
                                    session = %session_id_for_log,
                                    "rejecting dl OSC: token mismatch (hostile PTY output?)",
                                );
                                continue;
                            }
                            let s = session_for_reader.clone();
                            let session_id_for_log = session_id_for_log.clone();
                            tokio::spawn(async move {
                                let id = s.next_download_id.fetch_add(1, Ordering::Relaxed);
                                if let Err(e) = stream_download(&s, id, &path).await {
                                    warn!(
                                        session = %session_id_for_log,
                                        download_id = id,
                                        path = %path.display(),
                                        error = %e,
                                        "download failed",
                                    );
                                    let _ = s.broadcast_tx.send(SessionEvent::DownloadEnd {
                                        id, status: DOWNLOAD_STATUS_CANCEL,
                                    });
                                    let line = format!(
                                        "\rterm-dl: {}: {e}\r\n",
                                        path.display(),
                                    );
                                    let _ = s.write_internal(line.as_bytes()).await;
                                }
                            });
                        }
                        None => {
                            warn!(session=%session_id_for_log,
                                  payload=?String::from_utf8_lossy(&payload),
                                  "ignoring unknown app OSC");
                        }
                    }
                }
            }
            // Shell exited (bridge closed). Mark + notify.
            info!(session=%session_id_for_log, "shell exited; closing session");
            session_for_reader.inner.lock().await.exited = true;
            let _ = session_for_reader.broadcast_tx.send(SessionEvent::Closed);
        });

        Ok(session)
    }

    /// Add this stream to the attached set. If the session had no
    /// controller, this stream becomes controller and the PTY is
    /// resized to its geometry.
    pub async fn attach(self: &Arc<Self>, sid: StreamId, size: (u16, u16)) -> AttachResult {
        let event_rx = self.broadcast_tx.subscribe();
        let mut inner = self.inner.lock().await;
        let scrollback = inner.scrollback.snapshot();
        inner.attached.insert(sid, size);
        inner.last_attached_at = Instant::now();

        let became_controller = inner.controller.is_none();
        if became_controller {
            inner.controller = Some(sid);
            inner.last_size = size;
        }
        let current_controller = inner.controller;
        drop(inner);

        if became_controller {
            let _ = self.pty.resize(size.0, size.1).await;
            let _ = self.broadcast_tx.send(
                SessionEvent::ControllerChanged { controller: sid });
        }

        AttachResult { event_rx, scrollback, became_controller, current_controller }
    }

    pub async fn detach(self: &Arc<Self>, sid: StreamId) {
        let was_controller = {
            let mut inner = self.inner.lock().await;
            inner.attached.remove(&sid);
            inner.last_attached_at = Instant::now();
            let was = inner.controller == Some(sid);
            if was { inner.controller = None; }
            was
        };
        if was_controller {
            let _ = self.broadcast_tx.send(
                SessionEvent::ControllerChanged { controller: CONTROLLER_NONE_STREAM_ID });
        }
    }

    /// Write input to the PTY, but only from the controller. Viewer
    /// input is silently dropped (the browser UI gates it too, this is
    /// belt-and-braces).
    pub async fn write_input_from(&self, sid: StreamId, bytes: &[u8]) {
        if self.inner.lock().await.controller != Some(sid) { return; }
        let _ = self.pty.in_tx.send(bytes.to_vec()).await;
    }

    /// Direct PTY write (bypasses controller check). Used for
    /// agent-internal injections — bracketed-paste path strings on
    /// PasteEnd, term-dl error lines, etc.
    pub async fn write_internal(&self, bytes: &[u8]) -> std::io::Result<()> {
        // The bridge channel only fails when the writer thread has
        // exited, which only happens after the shell process dies.
        // Map that to a BrokenPipe so callers can log gracefully.
        self.pty.in_tx.send(bytes.to_vec())
            .await
            .map_err(|_| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pty writer thread has exited",
            ))
    }

    pub async fn resize_for(&self, sid: StreamId, rows: u16, cols: u16) {
        let do_resize = {
            let mut inner = self.inner.lock().await;
            inner.attached.insert(sid, (rows, cols));
            if inner.controller != Some(sid) { false } else {
                inner.last_size = (rows, cols);
                true
            }
        };
        if do_resize {
            let _ = self.pty.resize(rows, cols).await;
        }
    }

    /// Attempt to become controller. Succeeds only when the session has
    /// no current controller. Returns `true` on success.
    pub async fn acquire_control(self: &Arc<Self>, sid: StreamId) -> bool {
        let (success, new_size) = {
            let mut inner = self.inner.lock().await;
            if !inner.attached.contains_key(&sid) { return false; }
            if inner.controller.is_some() { return false; }
            inner.controller = Some(sid);
            let size = *inner.attached.get(&sid).unwrap();
            inner.last_size = size;
            (true, size)
        };
        let _ = self.pty.resize(new_size.0, new_size.1).await;
        let _ = self.broadcast_tx.send(SessionEvent::ControllerChanged { controller: sid });
        success
    }

    /// Voluntarily release control. Only the current controller can.
    pub async fn release_control(self: &Arc<Self>, sid: StreamId) -> bool {
        let success = {
            let mut inner = self.inner.lock().await;
            if inner.controller != Some(sid) { return false; }
            inner.controller = None;
            true
        };
        let _ = self.broadcast_tx.send(
            SessionEvent::ControllerChanged { controller: CONTROLLER_NONE_STREAM_ID });
        success
    }

    /// Force preemption: caller becomes controller, prior controller
    /// stays attached as viewer.
    pub async fn take_control(self: &Arc<Self>, sid: StreamId) -> bool {
        let new_size = {
            let mut inner = self.inner.lock().await;
            if !inner.attached.contains_key(&sid) { return false; }
            inner.controller = Some(sid);
            let size = *inner.attached.get(&sid).unwrap();
            inner.last_size = size;
            size
        };
        let _ = self.pty.resize(new_size.0, new_size.1).await;
        let _ = self.broadcast_tx.send(SessionEvent::ControllerChanged { controller: sid });
        true
    }

    #[allow(dead_code)]
    pub async fn controller(&self) -> Option<StreamId> {
        self.inner.lock().await.controller
    }

    /// True iff `sid` currently holds the control lease. Used to gate
    /// input-injecting actions (keystrokes, resize, paste) to the one
    /// stream allowed to drive the shared PTY.
    pub async fn is_controller(&self, sid: StreamId) -> bool {
        self.inner.lock().await.controller == Some(sid)
    }

    #[allow(dead_code)]
    pub async fn last_attached_at(&self) -> Instant {
        self.inner.lock().await.last_attached_at
    }

    #[allow(dead_code)]
    pub async fn attached_count(&self) -> usize {
        self.inner.lock().await.attached.len()
    }

    pub async fn exited(&self) -> bool {
        self.inner.lock().await.exited
    }

    /// Force the shell to exit. Used by KillSession + idle-TTL drop.
    pub async fn kill(&self) {
        self.pty.kill().await;
    }
}

/// Constant-time compare for the per-session download token. Both
/// operands are fixed-length base64url tokens, so the early length
/// check leaks nothing useful; the byte loop avoids a short-circuit
/// timing signal on the secret.
fn ct_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse a `5111;` OSC payload. We recognise:
///
///   `dl;<token>;<path>`     — request a download of `<path>`. The
///                              token must match the session's
///                              `TERM_DL_TOKEN` (caller checks).
///
/// Returns `Some((token, path))` if the OSC asked for a download,
/// `None` otherwise. The token is borrowed from the input; the path
/// is the remainder after the second `;` (so paths may legally
/// contain `;`).
fn parse_dl_osc(payload: &[u8]) -> Option<(String, PathBuf)> {
    let semi1 = payload.iter().position(|&b| b == b';')?;
    let cmd = &payload[..semi1];
    if cmd != b"dl" { return None; }
    let rest = &payload[semi1 + 1..];
    let semi2 = rest.iter().position(|&b| b == b';')?;
    let token = std::str::from_utf8(&rest[..semi2]).ok()?.to_owned();
    let path  = std::str::from_utf8(&rest[semi2 + 1..]).ok()?;
    Some((token, PathBuf::from(path)))
}

/// Registry of all live sessions on this agent. Look up or spawn on
/// `Open(session_id, initial_size)`; sweep idle/exited entries via
/// `gc_pass`.
pub struct SessionManager {
    pub shell: String,
    /// Resolved resource limits (from `agent.toml`'s `[limits]` table
    /// plus defaults). The agent's per-stream task reads the
    /// `max_pending_*` knobs from here; the session manager itself
    /// uses `idle_ttl` and `scrollback_cap_bytes`.
    pub limits: crate::Limits,
    map: Mutex<HashMap<SessionId, Arc<Session>>>,
}

impl SessionManager {
    pub fn new(shell: String, limits: crate::Limits) -> Arc<Self> {
        Arc::new(SessionManager {
            shell,
            limits,
            map: Mutex::new(HashMap::new()),
        })
    }

    /// Lookup an existing session or spawn a fresh one.
    pub async fn lookup_or_spawn(
        &self,
        id: &SessionId,
        initial_size: (u16, u16),
    ) -> Result<Arc<Session>> {
        let mut map = self.map.lock().await;
        if let Some(s) = map.get(id) {
            if !s.exited().await {
                return Ok(s.clone());
            }
            // Stale (shell exited but not yet GC'd) — replace.
            map.remove(id);
        }
        // Cap the number of live shells one agent will spawn. Attaching
        // to an *existing* session is always allowed (handled above, so
        // reconnects keep working at the cap); only brand-new sessions
        // are gated. Without this, a client could open unbounded tabs
        // with fresh session ids and fork-bomb the host.
        if map.len() >= self.limits.max_sessions {
            bail!(
                "session limit reached ({} live sessions on this host); \
                 close an existing tab first",
                self.limits.max_sessions,
            );
        }
        let s = Session::spawn(
            id.clone(), &self.shell, initial_size, self.limits.scrollback_cap_bytes,
        )?;
        map.insert(id.clone(), s.clone());
        info!(session = %id, shell = %self.shell, "session spawned");
        Ok(s)
    }

    #[allow(dead_code)]
    pub async fn list(&self) -> Vec<Arc<Session>> {
        self.map.lock().await.values().cloned().collect()
    }

    #[allow(dead_code)]
    pub async fn remove(&self, id: &SessionId) -> Option<Arc<Session>> {
        self.map.lock().await.remove(id)
    }

    /// One pass: drop any session that has exited OR whose idle time
    /// since last detach exceeds `limits.idle_ttl`.
    pub async fn gc_pass(&self) {
        let now = Instant::now();
        let to_drop: Vec<(SessionId, Arc<Session>)> = {
            let map = self.map.lock().await;
            let mut drops = Vec::new();
            for (id, s) in map.iter() {
                let inner = s.inner.lock().await;
                let idle  = now.saturating_duration_since(inner.last_attached_at);
                let detached = inner.attached.is_empty();
                let exited = inner.exited;
                if exited || (detached && idle > self.limits.idle_ttl) {
                    drops.push((id.clone(), s.clone()));
                }
            }
            drops
        };
        if to_drop.is_empty() { return; }
        let mut map = self.map.lock().await;
        for (id, s) in to_drop {
            map.remove(&id);
            drop(map); // release before .kill().await
            info!(session = %id, "session gc'd");
            s.kill().await;
            map = self.map.lock().await; // reacquire for next iteration
        }
    }
}

/// Stream `path` from disk and broadcast as DownloadBegin/Chunk/End.
/// All attached browser streams receive the events; each forwards to
/// its own writer with its own sid. Bails on file errors.
async fn stream_download(session: &Arc<Session>, id: u32, path: &Path) -> Result<()> {
    let mut file = fs::File::open(path).await
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = file.metadata().await
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let total_size = meta.len();
    if total_size > MAX_PASTE_TOTAL_BYTES {
        bail!("{} is {} bytes; over 4 GiB cap", path.display(), total_size);
    }
    let name = path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download")
        .to_owned();

    info!(session = %session.id, download_id = id, name = %name, total_size,
          "download begin");

    let _ = session.broadcast_tx.send(SessionEvent::DownloadBegin {
        id, total_size, name: name.clone(),
    });

    let mut buf = vec![0u8; MAX_PASTE_CHUNK_BYTES as usize];
    let mut sent: u64 = 0;
    loop {
        let n = file.read(&mut buf).await
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 { break; }
        if sent.saturating_add(n as u64) > total_size {
            bail!("{} grew during read: declared {total_size}, would send {}",
                path.display(), sent + n as u64);
        }
        sent = sent.saturating_add(n as u64);
        let _ = session.broadcast_tx.send(SessionEvent::DownloadChunk {
            id, bytes: Arc::new(buf[..n].to_vec()),
        });
    }
    if sent != total_size {
        bail!("{} shrank during read: declared {total_size}, sent {sent}",
            path.display());
    }
    let _ = session.broadcast_tx.send(SessionEvent::DownloadEnd {
        id, status: DOWNLOAD_STATUS_OK,
    });
    info!(session = %session.id, download_id = id, "download committed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_drains_on_overflow() {
        let mut r = ByteRing::new(8);
        r.extend(b"abcd");
        r.extend(b"efghij");
        assert_eq!(r.len(), 8);
        assert_eq!(r.snapshot(), b"cdefghij");
    }

    #[test]
    fn ring_handles_single_huge_push() {
        let mut r = ByteRing::new(4);
        r.extend(b"0123456789");
        assert_eq!(r.len(), 4);
        assert_eq!(r.snapshot(), b"6789");
    }

    #[test]
    fn parse_dl_osc_extracts_token_and_path() {
        assert_eq!(
            parse_dl_osc(b"dl;TOK123;/tmp/foo"),
            Some(("TOK123".into(), PathBuf::from("/tmp/foo"))),
        );
        // Empty token is structurally valid (caller's check rejects it).
        assert_eq!(
            parse_dl_osc(b"dl;;/tmp/foo"),
            Some((String::new(), PathBuf::from("/tmp/foo"))),
        );
        // Paths may legally contain ';' — we split only on the first
        // two semicolons.
        assert_eq!(
            parse_dl_osc(b"dl;TOK;/tmp/a;b;c"),
            Some(("TOK".into(), PathBuf::from("/tmp/a;b;c"))),
        );
        assert_eq!(parse_dl_osc(b"xx;TOK;/tmp/foo"), None);
        assert_eq!(parse_dl_osc(b"nosemicolon"), None);
        assert_eq!(parse_dl_osc(b"dl;onlyonesemi"), None);
    }

    #[test]
    fn paste_style_picks_plain_for_cmd_exe() {
        assert_eq!(PasteStyle::from_shell("cmd.exe"), PasteStyle::Plain);
        assert_eq!(PasteStyle::from_shell("CMD.EXE"), PasteStyle::Plain);
        // Plain `cmd` (no .exe) — rare but accept it.
        assert_eq!(PasteStyle::from_shell("cmd /K prompt $G"), PasteStyle::Plain);
        // Full Windows path. `Path::file_name` only treats `\` as a
        // separator on Windows, so the basename-extraction assertion
        // only makes sense there.
        #[cfg(windows)]
        assert_eq!(
            PasteStyle::from_shell(r"C:\Windows\System32\cmd.exe /Q"),
            PasteStyle::Plain,
        );
    }

    #[test]
    fn paste_style_picks_bracketed_for_real_shells() {
        for s in [
            "/bin/bash",
            "/bin/bash -l",
            "/usr/bin/zsh",
            "fish",
            "powershell.exe -NoLogo",
            "pwsh.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            "",  // empty falls through to bracketed too
        ] {
            assert_eq!(
                PasteStyle::from_shell(s),
                PasteStyle::Bracketed,
                "shell {s:?} should be bracketed",
            );
        }
    }

    // ---- integration tests over a real shell + session lifecycle ----
    //
    // These spawn `/bin/sh` so they're cfg(unix). On Windows they
    // silently no-op (`return;` once we detect /bin/sh is missing).

    /// Drain `event_rx` for up to `dur`, returning everything seen.
    /// Stops early once an `is_done` predicate returns true on the
    /// accumulated event vector.
    #[cfg(unix)]
    async fn drain_events_until<F>(
        rx: &mut tokio::sync::broadcast::Receiver<SessionEvent>,
        dur: Duration,
        is_done: F,
    ) -> Vec<SessionEvent>
    where F: Fn(&[SessionEvent]) -> bool
    {
        let deadline = Instant::now() + dur;
        let mut out = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { break; }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(ev)) => {
                    out.push(ev);
                    if is_done(&out) { break; }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        out
    }

    /// Return the concatenation of all `Data` event payloads in `evs`.
    #[cfg(unix)]
    fn collect_data(evs: &[SessionEvent]) -> Vec<u8> {
        let mut out = Vec::new();
        for ev in evs {
            if let SessionEvent::Data(b) = ev { out.extend_from_slice(b); }
        }
        out
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_attach_writes_and_reads() {
        // Spawn a real shell, write a command, read echo back.
        if !std::path::Path::new("/bin/sh").exists() { return; }
        let session = Session::spawn(
            "test-attach".into(),
            "/bin/sh",
            (24, 80),
            crate::session::DEFAULT_SCROLLBACK_CAP_BYTES,
        ).expect("spawn");

        let mut attach = session.attach(1, (24, 80)).await;
        assert!(attach.became_controller);

        // Write "echo TEST_NEEDLE\n" (controller writes are honored).
        session.write_input_from(1, b"echo TEST_NEEDLE\n").await;

        let evs = drain_events_until(&mut attach.event_rx, Duration::from_secs(3), |evs| {
            let data = collect_data(evs);
            data.windows(11).any(|w| w == b"TEST_NEEDLE")
        }).await;
        let data = collect_data(&evs);
        assert!(
            data.windows(11).any(|w| w == b"TEST_NEEDLE"),
            "expected TEST_NEEDLE in PTY output, got {:?}",
            String::from_utf8_lossy(&data),
        );

        // Exit the shell so the session cleans up.
        session.write_input_from(1, b"exit\n").await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_dl_token_mismatch_silently_drops() {
        // Spawn a real shell. Inject an OSC with the wrong dl token
        // and confirm no DownloadBegin event fires.
        if !std::path::Path::new("/bin/sh").exists() { return; }

        // Create a real file the download could read if it weren't
        // gated by the token.
        let tmp = std::env::temp_dir().join(format!(
            "term-agent-dl-test-{}", std::process::id(),
        ));
        std::fs::write(&tmp, b"file-contents-for-test").expect("write tmp");

        let session = Session::spawn(
            "test-token".into(),
            "/bin/sh",
            (24, 80),
            crate::session::DEFAULT_SCROLLBACK_CAP_BYTES,
        ).expect("spawn");
        let mut attach = session.attach(1, (24, 80)).await;

        // Print the OSC with a WRONG token via printf inside the shell.
        // Use printf %b to emit literal ESC bytes.
        let path_str = tmp.to_str().unwrap();
        let osc_wrong = format!(
            "printf '\\033]5111;dl;WRONG_TOKEN;{path}\\07'\n",
            path = path_str,
        );
        session.write_input_from(1, osc_wrong.as_bytes()).await;

        let evs = drain_events_until(&mut attach.event_rx, Duration::from_secs(2), |evs| {
            evs.iter().any(|e| matches!(e, SessionEvent::DownloadBegin { .. }))
        }).await;
        let saw_dl = evs.iter().any(|e| matches!(e, SessionEvent::DownloadBegin { .. }));
        assert!(!saw_dl, "wrong-token OSC must NOT trigger a DownloadBegin");

        // Now do it with the CORRECT token: capture the session's
        // token first, then inject a matching OSC.
        let good_token = session.dl_token.clone();
        let osc_ok = format!(
            "printf '\\033]5111;dl;{tok};{path}\\07'\n",
            tok = good_token,
            path = path_str,
        );
        session.write_input_from(1, osc_ok.as_bytes()).await;

        let evs2 = drain_events_until(&mut attach.event_rx, Duration::from_secs(2), |evs| {
            evs.iter().any(|e| matches!(e, SessionEvent::DownloadEnd { .. }))
        }).await;
        let saw_begin = evs2.iter().any(|e| matches!(e, SessionEvent::DownloadBegin { .. }));
        let saw_end   = evs2.iter().any(|e| matches!(
            e, SessionEvent::DownloadEnd { status, .. } if *status == DOWNLOAD_STATUS_OK
        ));
        assert!(saw_begin, "correct-token OSC must trigger DownloadBegin");
        assert!(saw_end,   "correct-token OSC must finish with DownloadEnd(OK)");

        let _ = std::fs::remove_file(&tmp);
        session.write_input_from(1, b"exit\n").await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reattach_replays_scrollback() {
        if !std::path::Path::new("/bin/sh").exists() { return; }
        let session = Session::spawn(
            "test-replay".into(),
            "/bin/sh",
            (24, 80),
            crate::session::DEFAULT_SCROLLBACK_CAP_BYTES,
        ).expect("spawn");

        // First attach + write something the shell echoes.
        let mut attach1 = session.attach(1, (24, 80)).await;
        session.write_input_from(1, b"echo REPLAY_NEEDLE\n").await;
        let _ = drain_events_until(&mut attach1.event_rx, Duration::from_secs(2), |evs| {
            collect_data(evs).windows(13).any(|w| w == b"REPLAY_NEEDLE")
        }).await;
        // Detach the first stream.
        session.detach(1).await;

        // Second attach: scrollback should contain REPLAY_NEEDLE.
        let attach2 = session.attach(2, (24, 80)).await;
        assert!(
            attach2.scrollback.windows(13).any(|w| w == b"REPLAY_NEEDLE"),
            "expected scrollback to replay the prior echo; got {:?}",
            String::from_utf8_lossy(&attach2.scrollback),
        );

        session.write_input_from(2, b"exit\n").await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_manager_respects_custom_idle_ttl() {
        // We don't actually wait the TTL out — just verify the field
        // is plumbed through.
        let limits = crate::Limits {
            scrollback_cap_bytes: 64 * 1024,
            idle_ttl: Duration::from_millis(50),
            max_pending_pastes_per_stream: 4,
            max_pending_groups_per_stream: 4,
            max_sessions: 8,
        };
        let mgr = SessionManager::new("/bin/sh".into(), limits);
        assert_eq!(mgr.limits.idle_ttl, Duration::from_millis(50));
        assert_eq!(mgr.limits.scrollback_cap_bytes, 64 * 1024);
        assert_eq!(mgr.limits.max_pending_pastes_per_stream, 4);
        assert_eq!(mgr.limits.max_pending_groups_per_stream, 4);
        assert_eq!(mgr.limits.max_sessions, 8);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_manager_enforces_max_sessions() {
        if !std::path::Path::new("/bin/sh").exists() { return; }
        let limits = crate::Limits {
            scrollback_cap_bytes: 64 * 1024,
            idle_ttl: Duration::from_secs(3600),
            max_pending_pastes_per_stream: 4,
            max_pending_groups_per_stream: 4,
            max_sessions: 2,
        };
        let mgr = SessionManager::new("/bin/sh".into(), limits);

        // Two distinct sessions spawn fine.
        let s1 = mgr.lookup_or_spawn(&"cap-a".into(), (24, 80)).await.expect("first spawn");
        let _s2 = mgr.lookup_or_spawn(&"cap-b".into(), (24, 80)).await.expect("second spawn");

        // A third *new* session id is refused at the cap.
        assert!(
            mgr.lookup_or_spawn(&"cap-c".into(), (24, 80)).await.is_err(),
            "third distinct session must be rejected at the cap",
        );

        // Re-attaching to an existing session is still allowed at the cap.
        let s1_again = mgr.lookup_or_spawn(&"cap-a".into(), (24, 80)).await
            .expect("reattach to existing session must succeed at the cap");
        assert!(Arc::ptr_eq(&s1, &s1_again));

        // Cleanup.
        for id in ["cap-a", "cap-b"] {
            if let Some(s) = mgr.remove(&id.into()).await { s.kill().await; }
        }
    }
}
