//! Agent multiplexer.
//!
//! One persistent connection per agent carries any number of session
//! streams. Frames on stream 0 are control (`Hello`, `Ping`, `Pong`);
//! all other stream IDs are data streams allocated by the hub when a
//! browser opens a terminal tab.
//!
//! ## Lifecycle
//!
//! 1. Acceptor accepts TCP; in ACME mode it wraps with rustls and
//!    presents the same cert as the browser-facing listener.
//! 2. [`handle_connection`] reads the agent's `Hello` frame, validates
//!    the PSK against the configured machine, registers an [`AgentLink`]
//!    in `AppState.agents`, then runs the read/write pump until either
//!    side closes.
//! 3. [`AgentLink::open_stream`] returns a [`StreamHandle`] that the WS
//!    proxy uses to send/receive frames for one tab. Dropping the handle
//!    sends a `Close` frame and removes the stream from the registry.
//!
//! On agent disconnect, every `StreamHandle.recv()` returns `None` so
//! every browser WS handler cleanly tears down. The browser auto-reconnects
//! once a new agent link is installed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use term_common::frame::{
    Body, Frame, FrameError, FrameType, HelloPayload, HEADER_LEN, HELLO_VERSION,
};
use term_common::prio::{prio_channel, PrioTx};

use crate::config::{is_valid_machine_id, HubConfig};
use crate::state::AppState;

// --- writer queue budgets (bytes, per agent connection) -------------------
//
// hi: small control/interactive frames (Data, Resize, Open, Close, Ping,
//     Pong, Hello, PasteReject). All ≤ 64 KiB; 4 MiB headroom is far
//     more than any realistic backlog of these.
// lo: paste chunks (PasteBegin/PasteChunk/PasteEnd). PasteChunk is up to
//     1 MiB; 16 MiB total lets ~16 chunks queue before the WS reader
//     pauses, which TCP-backpressures the browser. Old item-based cap
//     (256 items × 1 MiB) was 256 MiB worst case.
const HUB_WRITER_HI_BYTES: usize =  4 * 1024 * 1024;
const HUB_WRITER_LO_BYTES: usize = 16 * 1024 * 1024;
const STREAM_CHAN_CAP:   usize    = 64;
const HELLO_DEADLINE:    Duration = Duration::from_secs(10);
const IDLE_DEADLINE:     Duration = Duration::from_secs(90);

/// Handle the hub keeps for one connected agent.
pub struct AgentLink {
    writer:         PrioTx,
    next_stream_id: AtomicU32,
    streams:        Mutex<HashMap<u32, mpsc::Sender<Body>>>,
    /// Fired when the link is evicted from the agents map (e.g. by a
    /// fresh connection from the same machine_id). The connection's
    /// reader loop selects on this notification and exits.
    notify_close:   tokio::sync::Notify,
}

/// Send half of a mux stream, held by the browser→agent task.
pub struct StreamSink {
    pub id: u32,
    link:    Arc<AgentLink>,
    _guard:  Arc<StreamGuard>,
}

/// Receive half of a mux stream, held by the agent→browser task.
pub struct StreamSource {
    rx:      mpsc::Receiver<Body>,
    _guard:  Arc<StreamGuard>,
}

/// Both halves of a stream share this guard. When the last `Arc` to it
/// is dropped, we remove the stream from the registry and send `Close`.
struct StreamGuard {
    id:   u32,
    link: Arc<AgentLink>,
}

impl AgentLink {
    pub async fn open_stream(self: &Arc<Self>) -> (StreamSink, StreamSource) {
        let id = loop {
            let c = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
            if c != 0 { break c; }
        };
        let (tx, rx) = mpsc::channel(STREAM_CHAN_CAP);
        self.streams.lock().await.insert(id, tx);
        let guard = Arc::new(StreamGuard { id, link: self.clone() });
        (
            StreamSink   { id, link: self.clone(), _guard: guard.clone() },
            StreamSource { rx,                     _guard: guard          },
        )
    }

    async fn send_frame(&self, f: Frame) -> Result<(), ()> {
        // Route bulk paste chunks through `lo` so they never wedge
        // interactive Data/Resize/Ping/etc behind 1 MiB chunks. The new
        // PasteReject (agent → browser) is small and time-sensitive →
        // hi.
        let ty = f.ty();
        let half = match ty {
            FrameType::PasteBegin | FrameType::PasteChunk | FrameType::PasteEnd => &self.writer.lo,
            _ => &self.writer.hi,
        };
        half.send(f.encode()).await.map_err(|_| ())
    }
}

impl StreamSink {
    pub async fn send(&self, body: Body) -> Result<(), ()> {
        self.link.send_frame(Frame { stream_id: self.id, body }).await
    }
}

impl StreamSource {
    pub async fn recv(&mut self) -> Option<Body> { self.rx.recv().await }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let link = self.link.clone();
        let id   = self.id;
        tokio::spawn(async move {
            link.streams.lock().await.remove(&id);
            let _ = link.send_frame(Frame::close(id)).await;
        });
    }
}

/// Constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

fn decode_psk(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let s = s.trim();
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
        return Ok(v);
    }
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.as_bytes())
}

/// Run the hello/auth/pump loop for one agent connection. Returns when
/// the agent disconnects or any protocol error occurs.
pub async fn handle_connection<R, W>(
    state: AppState,
    mut reader: R,
    mut writer: W,
    peer: String,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // ---- hello + auth -----------------------------------------------------
    let hello_frame = timeout(HELLO_DEADLINE, read_frame(&mut reader))
        .await
        .map_err(|_| anyhow!("hello timeout from {peer}"))?
        .context("read hello")?
        .ok_or_else(|| anyhow!("eof before hello"))?;

    let hello: HelloPayload = match (hello_frame.stream_id, &hello_frame.body) {
        (0, Body::Hello(b)) => serde_json::from_slice(b).context("parse hello json")?,
        _ => bail!("first frame must be Hello on stream 0"),
    };
    if hello.version != HELLO_VERSION {
        bail!("hello version mismatch: agent={} hub={}", hello.version, HELLO_VERSION);
    }
    if !is_valid_machine_id(&hello.machine_id) {
        bail!("invalid machine_id in hello");
    }

    let machine = state
        .cfg
        .machines
        .iter()
        .find(|m| m.id == hello.machine_id)
        .ok_or_else(|| anyhow!("unknown machine_id: {}", hello.machine_id))?
        .clone();

    let claimed  = decode_psk(&hello.psk_b64).context("decode claimed psk")?;
    let expected = decode_psk(&machine.psk).context("decode configured psk")?;
    if !ct_eq(&claimed, &expected) {
        bail!("psk mismatch for machine {}", hello.machine_id);
    }
    if expected.len() < 16 {
        warn!(machine = %hello.machine_id, "configured PSK is shorter than 16 bytes");
    }

    info!(machine = %hello.machine_id, peer = %peer, "agent registered");

    // ---- link + writer ----------------------------------------------------
    let (write_tx, mut write_rx) = prio_channel(HUB_WRITER_HI_BYTES, HUB_WRITER_LO_BYTES);
    let link = Arc::new(AgentLink {
        writer:         write_tx.clone(),
        next_stream_id: AtomicU32::new(1),
        streams:        Mutex::new(HashMap::new()),
        notify_close:   tokio::sync::Notify::new(),
    });

    // Atomically replace any prior link for this machine. If we evict an
    // old link, tell its reader/writer to bail so its TCP gets torn down
    // and the (probably still-alive) old agent reconnects fresh.
    {
        let mut map = state.agents.lock().await;
        if let Some(old) = map.insert(hello.machine_id.clone(), link.clone()) {
            warn!(machine = %hello.machine_id, "replacing existing agent link");
            // notify_waiters wakes both the old reader's select! and its
            // writer task's select! simultaneously.
            old.notify_close.notify_waiters();
            drop(old);
        }
    }

    let machine_id = hello.machine_id.clone();

    // Writer task. Exits on either:
    //   (a) write_rx returns None (all senders dropped), or
    //   (b) notify_close fires (eviction). Important: AgentLink holds a
    //       writer-clone, and any in-flight StreamSink also holds one
    //       transitively, so without (b) we'd deadlock here on eviction
    //       until every browser tab for this agent closes.
    let link_for_writer = link.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            let evict = link_for_writer.notify_close.notified();
            tokio::pin!(evict);
            tokio::select! {
                biased;
                _ = &mut evict => break,
                msg = write_rx.recv() => match msg {
                    Some(bytes) => {
                        if writer.write_all(&bytes).await.is_err() { break; }
                    }
                    None => break,
                }
            }
        }
        let _ = writer.shutdown().await;
    });

    // Reader loop.
    let link_for_read = link.clone();
    let read_result: anyhow::Result<()> = async {
        loop {
            let evict = link_for_read.notify_close.notified();
            tokio::pin!(evict);
            let f_opt = tokio::select! {
                biased;
                _ = &mut evict => {
                    bail!("evicted by newer connection for same machine_id");
                }
                r = timeout(IDLE_DEADLINE, read_frame(&mut reader)) => {
                    match r {
                        Ok(Ok(Some(f))) => Some(f),
                        Ok(Ok(None))    => return Ok(()),
                        Ok(Err(e))      => return Err(e.into()),
                        Err(_)          => bail!("idle timeout (>{IDLE_DEADLINE:?})"),
                    }
                }
            };
            let f = match f_opt { Some(f) => f, None => return Ok(()) };
            match (f.stream_id, f.body) {
                (0, Body::Ping(p))  => { let _ = link_for_read.send_frame(Frame::pong(p)).await; }
                (0, Body::Pong(_))  => { /* track RTT later */ }
                (0, Body::Hello(_)) => bail!("hello after registration"),
                (0, _)              => bail!("unexpected control frame"),
                (sid, body)         => {
                    let tx = {
                        let map = link_for_read.streams.lock().await;
                        map.get(&sid).cloned()
                    };
                    match tx {
                        Some(tx) => { let _ = tx.send(body).await; }
                        None     => debug!(sid, "frame for unknown stream; agent should send Close"),
                    }
                }
            }
        }
    }
    .await;

    // ---- teardown ---------------------------------------------------------
    {
        let mut map = state.agents.lock().await;
        if let Some(cur) = map.get(&machine_id) {
            if Arc::ptr_eq(cur, &link) {
                map.remove(&machine_id);
            }
        }
    }
    // Drop per-stream senders so any WS handler reading from
    // StreamSource sees EOF and tears down its own state.
    link.streams.lock().await.clear();
    // Make sure the writer task is unblocked even if a StreamSink
    // (held by some still-running WS handler) is keeping a writer clone
    // alive transitively.
    link.notify_close.notify_waiters();
    drop(link);          // our local Arc
    drop(link_for_read); // reader's Arc
    drop(write_tx);      // our local sender
    let _ = writer_task.await;

    if let Err(e) = read_result {
        warn!(machine = %machine_id, peer = %peer, error = %e, "agent connection ended with error");
    } else {
        info!(machine = %machine_id, peer = %peer, "agent disconnected");
    }
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, FrameError> {
    let mut hdr = [0u8; HEADER_LEN];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let stream_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let ty_byte   = hdr[4];
    let len       = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
    let (ty, len) = Frame::validate_header(stream_id, ty_byte, len)?;
    let mut payload = vec![0u8; len as usize];
    if len > 0 { r.read_exact(&mut payload).await?; }
    Frame::from_payload(stream_id, ty, payload).map(Some)
}

/// Acceptor task for the agent listener. Loops accepting TCP; if a
/// `TlsAcceptor` is provided, wraps each accepted socket and spawns
/// `handle_connection` over the TLS stream, else over the raw TCP.
pub async fn run_acceptor(
    state: AppState,
    cfg: Arc<HubConfig>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&cfg.agent_bind)
        .await
        .with_context(|| format!("bind agent_bind {}", cfg.agent_bind))?;
    info!(
        "agent listener up on {} ({})",
        cfg.agent_bind,
        if tls.is_some() { "TLS" } else { "plain TCP" },
    );

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!(error = %e, "agent accept error"); continue; }
        };
        let _ = sock.set_nodelay(true);
        let state = state.clone();
        let tls = tls.clone();
        let peer = peer.to_string();
        tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                if let Some(acceptor) = tls {
                    let tls = acceptor.accept(sock).await.context("tls accept")?;
                    let (r, w) = tokio::io::split(tls);
                    handle_connection(state, r, w, peer).await
                } else {
                    let (r, w) = sock.into_split();
                    handle_connection(state, r, w, peer).await
                }
            }
            .await;
            if let Err(e) = result { warn!(error = %e, "agent connection failed"); }
        });
    }
}
