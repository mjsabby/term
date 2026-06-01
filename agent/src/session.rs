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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

use term_common::frame::{
    DOWNLOAD_STATUS_CANCEL, DOWNLOAD_STATUS_OK, MAX_PASTE_CHUNK_BYTES,
    MAX_PASTE_TOTAL_BYTES, CONTROLLER_NONE_STREAM_ID,
};
use term_common::osc::OscScanner;

/// 8 MiB byte ring of recent PTY output. Replayed on attach.
pub const SCROLLBACK_CAP_BYTES: usize = 8 * 1024 * 1024;
/// Default idle TTL — sessions with no attached client this long are
/// dropped by the sweeper.
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
    broadcast_tx:     broadcast::Sender<SessionEvent>,
    pty_w:            Mutex<pty_process::OwnedWritePty>,
    child:            Mutex<tokio::process::Child>,
    inner:            Mutex<SessionInner>,
    next_download_id: AtomicU32,
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
    /// Spawn `$SHELL` in a fresh PTY, no tmux wrapper. Replaces
    /// `tmux new-session -A -s <id> -- <shell>`.
    pub fn spawn(id: SessionId, shell: &str, initial_size: (u16, u16)) -> Result<Arc<Self>> {
        let (pty, pts) = pty_process::open().context("pty_process::open")?;
        let (rows, cols) = initial_size;
        pty.resize(pty_process::Size::new(rows, cols)).context("initial resize")?;
        // systemd service units inherit no TERM and no locale. Set a
        // terminfo-capable TERM, advertise truecolor, pick a UTF-8
        // locale. Same env we used to pass to tmux.
        let child = pty_process::Command::new(shell)
            .env("TERM",      "xterm-256color")
            .env("COLORTERM", "truecolor")
            .env("LANG",      "C.UTF-8")
            .env("LC_ALL",    "C.UTF-8")
            .spawn(pts)
            .with_context(|| format!("spawn {shell}"))?;

        let (mut pty_r, pty_w) = pty.into_split();
        let (tx, _rx0) = broadcast::channel(BROADCAST_CAP);

        let session = Arc::new(Session {
            id:               id.clone(),
            created_at:       Instant::now(),
            broadcast_tx:     tx.clone(),
            pty_w:            Mutex::new(pty_w),
            child:            Mutex::new(child),
            next_download_id: AtomicU32::new(1),
            inner:            Mutex::new(SessionInner {
                controller:       None,
                last_size:        initial_size,
                attached:         HashMap::new(),
                scrollback:       ByteRing::new(SCROLLBACK_CAP_BYTES),
                last_attached_at: Instant::now(),
                exited:           false,
            }),
        });

        // PTY reader task — per session, NOT per stream. Reads PTY,
        // OSC-scans, dispatches 5111;dl; OSCs as DownloadRequest events,
        // forwards the rest as Data events + scrollback appends.
        let session_for_reader = session.clone();
        let session_id_for_log = id;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut osc = OscScanner::new();
            loop {
                let n = match pty_r.read(&mut buf).await {
                    Ok(0)  => break, // shell exited
                    Ok(n)  => n,
                    Err(e) => { debug!(session=%session_id_for_log, error=%e, "pty read"); break; }
                };
                let (fwd, captured) = osc.feed(&buf[..n]);
                if !fwd.is_empty() {
                    let chunk = Arc::new(fwd);
                    session_for_reader.inner.lock().await.scrollback.extend(&chunk);
                    let _ = session_for_reader.broadcast_tx.send(SessionEvent::Data(chunk));
                }
                for payload in captured {
                    if let Some(path) = parse_dl_osc(&payload) {
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
                    } else {
                        warn!(session=%session_id_for_log,
                              payload=?String::from_utf8_lossy(&payload),
                              "ignoring unknown app OSC");
                    }
                }
            }
            // Shell exited (read returned 0 or errored).
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
            let _ = self.pty_w.lock().await
                .resize(pty_process::Size::new(size.0, size.1));
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
        let _ = self.pty_w.lock().await.write_all(bytes).await;
    }

    /// Direct PTY write (bypasses controller check). Used for
    /// agent-internal injections — bracketed-paste path strings on
    /// PasteEnd, term-dl error lines, etc.
    pub async fn write_internal(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.pty_w.lock().await.write_all(bytes).await
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
            let _ = self.pty_w.lock().await.resize(pty_process::Size::new(rows, cols));
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
        let _ = self.pty_w.lock().await.resize(pty_process::Size::new(new_size.0, new_size.1));
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
        let _ = self.pty_w.lock().await.resize(pty_process::Size::new(new_size.0, new_size.1));
        let _ = self.broadcast_tx.send(SessionEvent::ControllerChanged { controller: sid });
        true
    }

    #[allow(dead_code)]
    pub async fn controller(&self) -> Option<StreamId> {
        self.inner.lock().await.controller
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
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

/// Parse a `5111;` OSC payload — currently only `dl;<utf-8 path>` is
/// recognised. Returns `Some(path)` if the OSC asked for a download,
/// `None` otherwise.
fn parse_dl_osc(payload: &[u8]) -> Option<PathBuf> {
    let semi = payload.iter().position(|&b| b == b';')?;
    let cmd = &payload[..semi];
    let arg = &payload[semi + 1..];
    if cmd != b"dl" { return None; }
    let s = std::str::from_utf8(arg).ok()?;
    Some(PathBuf::from(s))
}

/// Registry of all live sessions on this agent. Look up or spawn on
/// `Open(session_id, initial_size)`; sweep idle/exited entries via
/// `gc_pass`.
pub struct SessionManager {
    pub shell: String,
    pub idle_ttl: Duration,
    map: Mutex<HashMap<SessionId, Arc<Session>>>,
}

impl SessionManager {
    pub fn new(shell: String) -> Arc<Self> {
        Arc::new(SessionManager {
            shell,
            idle_ttl: DEFAULT_IDLE_TTL,
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
        let s = Session::spawn(id.clone(), &self.shell, initial_size)?;
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
    /// since last detach exceeds `idle_ttl`.
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
                if exited || (detached && idle > self.idle_ttl) {
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
    fn parse_dl_osc_extracts_path() {
        assert_eq!(parse_dl_osc(b"dl;/tmp/foo"), Some(PathBuf::from("/tmp/foo")));
        assert_eq!(parse_dl_osc(b"dl;"), Some(PathBuf::from("")));
        assert_eq!(parse_dl_osc(b"xx;/tmp/foo"), None);
        assert_eq!(parse_dl_osc(b"nosemicolon"), None);
    }
}
