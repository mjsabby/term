//! Agent multiplexer.
//!
//! One persistent connection per agent carries any number of session
//! streams. Frames on stream 0 are control (`Hello`, `Ping`, `Pong`);
//! all other stream IDs are data streams allocated by the hub when a
//! browser opens a terminal tab.
//!
//! ## Lifecycle
//!
//! 1. Acceptor accepts TCP and wraps with rustls. The rustls config
//!    plugs in [`crate::client_verifier::AgentClientVerifier`], so
//!    any handshake without a valid + allowed client cert tears down
//!    the TCP connection BEFORE we ever reach this module.
//! 2. After a successful handshake, the acceptor extracts the leaf
//!    cert's SAN URN and calls [`handle_connection`] with the
//!    already-authenticated `machine_id`.
//! 3. [`handle_connection`] reads the agent's `Hello` frame for
//!    version negotiation, registers an [`AgentLink`] in
//!    `AppState.agents`, then runs the read/write pump until either
//!    side closes.
//! 4. [`AgentLink::open_stream`] returns a [`StreamHandle`] that the
//!    WS proxy uses to send/receive frames for one tab. Dropping the
//!    handle sends a `Close` frame and removes the stream from the
//!    registry.
//!
//! On agent disconnect, every `StreamHandle.recv()` returns `None` so
//! every browser WS handler cleanly tears down. The browser auto-reconnects
//! once a new agent link is installed.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use term_common::agent_pki::ca::extract_machine_id_from_san;
use term_common::frame::{Body, Frame, FrameType, HELLO_VERSION, HelloPayload, KILL_STATUS_OK};
use term_common::prio::{PrioTx, prio_channel};
use term_common::transport::{ByteStreamRecv, ByteStreamSend, FrameRecv, FrameSend};

use crate::config::HubConfig;
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
const HUB_WRITER_HI_BYTES: usize = 4 * 1024 * 1024;
const HUB_WRITER_LO_BYTES: usize = 16 * 1024 * 1024;
const STREAM_CHAN_CAP: usize = 64;
/// Hard cap on concurrent mux streams the hub will open against a single
/// agent. Bounds per-agent task / memory growth from a client that opens
/// an unbounded number of tabs or WebSockets. Generous enough for normal
/// multi-tab use; the agent's own `limits.max_sessions` caps the costlier
/// shell-spawn side.
pub const MAX_STREAMS_PER_AGENT: usize = 256;
const HELLO_DEADLINE: Duration = Duration::from_secs(10);
const IDLE_DEADLINE: Duration = Duration::from_secs(90);
/// Wait this long for a session-admin RPC response from the agent
/// before failing the HTTP call back to the browser.
const RPC_DEADLINE: Duration = Duration::from_secs(5);

/// JSON shape the agent sends in a `SessionList` response and the hub
/// re-serialises for the browser admin panel.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionInfo {
    pub id: String,
    /// Seconds since this session was last attached or detached.
    pub idle_secs: u64,
    /// Number of browser tabs currently attached.
    pub attached: usize,
    /// Whether there is a current controller (any one of the attached
    /// streams).
    pub has_controller: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfoEnvelope {
    pub sessions: Vec<SessionInfo>,
}

/// Handle the hub keeps for one connected agent.
pub struct AgentLink {
    /// Echo of the agent's machine_id (from its Hello frame). Cached
    /// here so /metrics can label time-series without re-locking.
    pub machine_id: String,
    writer: PrioTx,
    next_stream_id: AtomicU32,
    streams: Mutex<HashMap<u32, mpsc::Sender<Body>>>,
    /// Fired when the link is evicted from the agents map (e.g. by a
    /// fresh connection from the same machine_id). The connection's
    /// reader loop selects on this notification and exits.
    notify_close: tokio::sync::Notify,
    /// Per-link RPC plumbing: each ListSessions / KillSession call
    /// allocates a fresh `request_id`, parks an oneshot here, and
    /// awaits. The reader loop fires the oneshot when the matching
    /// SessionList / KillSessionAck comes back.
    next_request_id: AtomicU32,
    pending_rpcs: Mutex<HashMap<u32, oneshot::Sender<Body>>>,

    // ---- /metrics counters ----
    /// Bytes read from the agent socket (full wire frames, header
    /// + payload). Incremented after each successful read_frame.
    pub bytes_in: AtomicU64,
    /// Bytes written toward the agent socket. Incremented after
    /// `send_frame` queues the encoded bytes.
    pub bytes_out: AtomicU64,
    /// Total frames seen on the reader side.
    pub frames_in: AtomicU64,
    /// Total frames queued on the writer side.
    pub frames_out: AtomicU64,
}

/// Send half of a mux stream, held by the browser→agent task.
pub struct StreamSink {
    pub id: u32,
    link: Arc<AgentLink>,
    _guard: Arc<StreamGuard>,
}

/// Receive half of a mux stream, held by the agent→browser task.
pub struct StreamSource {
    rx: mpsc::Receiver<Body>,
    _guard: Arc<StreamGuard>,
}

/// Both halves of a stream share this guard. When the last `Arc` to it
/// is dropped, we remove the stream from the registry and send `Close`.
struct StreamGuard {
    id: u32,
    link: Arc<AgentLink>,
}

impl AgentLink {
    pub async fn open_stream(self: &Arc<Self>) -> (StreamSink, StreamSource) {
        let id = loop {
            let c = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
            if c != 0 {
                break c;
            }
        };
        let (tx, rx) = mpsc::channel(STREAM_CHAN_CAP);
        self.streams.lock().await.insert(id, tx);
        let guard = Arc::new(StreamGuard {
            id,
            link: self.clone(),
        });
        (
            StreamSink {
                id,
                link: self.clone(),
                _guard: guard.clone(),
            },
            StreamSource { rx, _guard: guard },
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
        let encoded = f.encode();
        let n = encoded.len() as u64;
        half.send(encoded).await.map_err(|_| ())?;
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
        self.frames_out.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Number of mux streams currently open against this agent.
    /// Used by /metrics. Cheap: just a HashMap len under a Mutex.
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Ask the agent for the current session list. Times out after
    /// `RPC_DEADLINE`; returns an `Err` if the agent doesn't respond
    /// or has gone away.
    pub async fn list_sessions(self: &Arc<Self>) -> anyhow::Result<Vec<SessionInfo>> {
        let body = self.rpc(Frame::list_sessions).await?;
        match body {
            Body::SessionList { json, .. } => {
                let env: SessionInfoEnvelope =
                    serde_json::from_slice(&json).context("decode SessionList JSON")?;
                Ok(env.sessions)
            }
            other => bail!("unexpected RPC response: {:?}", other.kind()),
        }
    }

    /// Ask the agent to kill `session_id`. Returns `Ok(true)` if the
    /// session was found and killed, `Ok(false)` if not found.
    pub async fn kill_session(self: &Arc<Self>, session_id: &str) -> anyhow::Result<bool> {
        let body = self
            .rpc(|rid| Frame::kill_session(rid, session_id.to_owned()))
            .await?;
        match body {
            Body::KillSessionAck { status, .. } => Ok(status == KILL_STATUS_OK),
            other => bail!("unexpected RPC response: {:?}", other.kind()),
        }
    }

    /// Generic request/response over stream 0. `build` constructs the
    /// request frame from the allocated `request_id`. Used by
    /// `list_sessions` and `kill_session`.
    async fn rpc<F>(self: &Arc<Self>, build: F) -> anyhow::Result<Body>
    where
        F: FnOnce(u32) -> Frame,
    {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_rpcs.lock().await.insert(request_id, tx);
        let send_result = self.send_frame(build(request_id)).await;
        if send_result.is_err() {
            // Clean up the entry we just inserted; nobody will fire it.
            self.pending_rpcs.lock().await.remove(&request_id);
            bail!("agent link writer closed");
        }
        let body = match timeout(RPC_DEADLINE, rx).await {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => {
                self.pending_rpcs.lock().await.remove(&request_id);
                bail!("agent dropped before responding");
            }
            Err(_) => {
                self.pending_rpcs.lock().await.remove(&request_id);
                bail!("agent did not respond within {RPC_DEADLINE:?}");
            }
        };
        Ok(body)
    }
}

/// Helper for the `unexpected RPC response` log line: stringifies the
/// body variant name without dumping payload bytes.
trait BodyKind {
    fn kind(&self) -> &'static str;
}
impl BodyKind for Body {
    fn kind(&self) -> &'static str {
        match self {
            Body::Data(_) => "Data",
            Body::Resize { .. } => "Resize",
            Body::Open { .. } => "Open",
            Body::Close => "Close",
            Body::Ping(_) => "Ping",
            Body::Pong(_) => "Pong",
            Body::Hello(_) => "Hello",
            Body::PasteBegin { .. } => "PasteBegin",
            Body::PasteChunk { .. } => "PasteChunk",
            Body::PasteEnd { .. } => "PasteEnd",
            Body::PasteReject { .. } => "PasteReject",
            Body::DownloadBegin { .. } => "DownloadBegin",
            Body::DownloadChunk { .. } => "DownloadChunk",
            Body::DownloadEnd { .. } => "DownloadEnd",
            Body::AcquireControl => "AcquireControl",
            Body::ReleaseControl => "ReleaseControl",
            Body::TakeControl => "TakeControl",
            Body::ControllerChanged { .. } => "ControllerChanged",
            Body::ListSessions { .. } => "ListSessions",
            Body::SessionList { .. } => "SessionList",
            Body::KillSession { .. } => "KillSession",
            Body::KillSessionAck { .. } => "KillSessionAck",
        }
    }
}

impl StreamSink {
    pub async fn send(&self, body: Body) -> Result<(), ()> {
        self.link
            .send_frame(Frame {
                stream_id: self.id,
                body,
            })
            .await
    }
}

impl StreamSource {
    pub async fn recv(&mut self) -> Option<Body> {
        self.rx.recv().await
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let link = self.link.clone();
        let id = self.id;
        tokio::spawn(async move {
            link.streams.lock().await.remove(&id);
            let _ = link.send_frame(Frame::close(id)).await;
        });
    }
}

/// Run the hello/auth/pump loop for one agent connection. Returns when
/// the agent disconnects or any protocol error occurs.
///
/// `machine_id` is the already-authenticated identity (cert SAN URN
/// on the raw mTLS path, X-Agent-Cert SAN on the WSS-perimeter path).
/// This function does NOT do any cert validation of its own — it
/// trusts the caller to have already torn down any unauthenticated
/// connection at the TLS layer (raw path) or at the HTTP-upgrade
/// layer (WSS path).
pub async fn handle_connection<FR, FW>(
    state: AppState,
    mut reader: FR,
    mut writer: FW,
    machine_id: String,
    peer: String,
) -> anyhow::Result<()>
where
    FR: FrameRecv + Send,
    FW: FrameSend + Send + 'static,
{
    // ---- hello (version handshake only) -----------------------------------
    let (hello_frame, hello_bytes_in) = timeout(HELLO_DEADLINE, reader.recv())
        .await
        .map_err(|_| anyhow!("hello timeout from {peer}"))?
        .context("read hello")?
        .ok_or_else(|| anyhow!("eof before hello"))?;

    let hello: HelloPayload = match (hello_frame.stream_id, &hello_frame.body) {
        (0, Body::Hello(b)) => serde_json::from_slice(b).context("parse hello json")?,
        _ => bail!("first frame must be Hello on stream 0"),
    };
    if hello.version != HELLO_VERSION {
        bail!(
            "hello version mismatch: agent={} hub={} (this hub requires mTLS-era agents; \
             re-issue the agent cert with `hub-admin issue-cert` and reinstall)",
            hello.version,
            HELLO_VERSION
        );
    }
    // Sanity-check that the cert-derived id resembles a configured
    // machine. If `[[machines]]` omits this id the agent still runs
    // (the cert was issued by us so it's trusted), but the browser
    // sidebar won't list it — warn so the operator notices the gap.
    if !state.cfg.machines.iter().any(|m| m.id == machine_id) {
        warn!(
            machine = %machine_id,
            "agent presented a valid cert but no matching [[machines]] entry in hub.toml; \
             add one to surface this machine in the SPA"
        );
    }

    info!(machine = %machine_id, peer = %peer, "agent registered");

    // ---- link + writer ----------------------------------------------------
    let (write_tx, mut write_rx) = prio_channel(HUB_WRITER_HI_BYTES, HUB_WRITER_LO_BYTES);
    let link = Arc::new(AgentLink {
        machine_id: machine_id.clone(),
        writer: write_tx.clone(),
        next_stream_id: AtomicU32::new(1),
        streams: Mutex::new(HashMap::new()),
        notify_close: tokio::sync::Notify::new(),
        next_request_id: AtomicU32::new(1),
        pending_rpcs: Mutex::new(HashMap::new()),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        frames_in: AtomicU64::new(0),
        frames_out: AtomicU64::new(0),
    });

    // The hello frame counts toward bytes_in too.
    link.bytes_in.fetch_add(hello_bytes_in, Ordering::Relaxed);
    link.frames_in.fetch_add(1, Ordering::Relaxed);

    // Atomically replace any prior link for this machine. If we evict an
    // old link, tell its reader/writer to bail so its TCP gets torn down
    // and the (probably still-alive) old agent reconnects fresh.
    {
        let mut map = state.agents.lock().await;
        if let Some(old) = map.insert(machine_id.clone(), link.clone()) {
            warn!(machine = %machine_id, "replacing existing agent link");
            // notify_waiters wakes both the old reader's select! and its
            // writer task's select! simultaneously.
            old.notify_close.notify_waiters();
            drop(old);
        }
    }

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
                        if writer.send(bytes).await.is_err() { break; }
                    }
                    None => break,
                }
            }
        }
        writer.close().await;
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
                r = timeout(IDLE_DEADLINE, reader.recv()) => {
                    match r {
                        Ok(Ok(Some((f, bytes)))) => {
                            link_for_read.bytes_in.fetch_add(bytes, Ordering::Relaxed);
                            link_for_read.frames_in.fetch_add(1, Ordering::Relaxed);
                            Some(f)
                        }
                        Ok(Ok(None))    => return Ok(()),
                        Ok(Err(e))      => return Err(e.into()),
                        Err(_)          => bail!("idle timeout (>{IDLE_DEADLINE:?})"),
                    }
                }
            };
            let f = match f_opt {
                Some(f) => f,
                None => return Ok(()),
            };
            match (f.stream_id, f.body) {
                (0, Body::Ping(p)) => {
                    let _ = link_for_read.send_frame(Frame::pong(p)).await;
                }
                (0, Body::Pong(_)) => { /* track RTT later */ }
                (0, Body::Hello(_)) => bail!("hello after registration"),
                // Admin RPC responses: route back to the parked oneshot.
                (0, body @ (Body::SessionList { .. } | Body::KillSessionAck { .. })) => {
                    let request_id = match &body {
                        Body::SessionList { request_id, .. } => *request_id,
                        Body::KillSessionAck { request_id, .. } => *request_id,
                        _ => unreachable!(),
                    };
                    let tx = link_for_read.pending_rpcs.lock().await.remove(&request_id);
                    if let Some(tx) = tx {
                        let _ = tx.send(body);
                    } else {
                        debug!(request_id, "RPC response with no waiter; dropping");
                    }
                }
                (0, _) => bail!("unexpected control frame"),
                (sid, body) => {
                    let tx = {
                        let map = link_for_read.streams.lock().await;
                        map.get(&sid).cloned()
                    };
                    match tx {
                        Some(tx) => {
                            let _ = tx.send(body).await;
                        }
                        None => debug!(sid, "frame for unknown stream; agent should send Close"),
                    }
                }
            }
        }
    }
    .await;

    // ---- teardown ---------------------------------------------------------
    {
        let mut map = state.agents.lock().await;
        if let Some(cur) = map.get(&machine_id)
            && Arc::ptr_eq(cur, &link)
        {
            map.remove(&machine_id);
        }
    }
    // Drop per-stream senders so any WS handler reading from
    // StreamSource sees EOF and tears down its own state.
    link.streams.lock().await.clear();
    // Make sure the writer task is unblocked even if a StreamSink
    // (held by some still-running WS handler) is keeping a writer clone
    // alive transitively.
    link.notify_close.notify_waiters();
    drop(link); // our local Arc
    drop(link_for_read); // reader's Arc
    drop(write_tx); // our local sender
    let _ = writer_task.await;

    if let Err(e) = read_result {
        warn!(machine = %machine_id, peer = %peer, error = %e, "agent connection ended with error");
    } else {
        info!(machine = %machine_id, peer = %peer, "agent disconnected");
    }
    Ok(())
}

/// Acceptor task for the agent listener. Always TLS (mTLS, with a
/// custom client-cert verifier passed in); never accepts plain TCP
/// because the auth scheme requires a client cert. After a successful
/// handshake we pull the leaf cert's SAN URN as the agent's
/// authenticated identity and pass it into `handle_connection`.
pub async fn run_acceptor(
    state: AppState,
    cfg: Arc<HubConfig>,
    tls: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&cfg.agent_bind)
        .await
        .with_context(|| format!("bind agent_bind {}", cfg.agent_bind))?;
    info!("agent listener up on {} (mTLS)", cfg.agent_bind);

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "agent accept error");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let state = state.clone();
        let acceptor = tls.clone();
        let peer = peer.to_string();
        tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                // The TLS handshake itself runs our AgentClientVerifier,
                // so we get here only if chain + fingerprint + SAN are
                // valid. We still need the SAN URN for `handle_connection`.
                let tls = acceptor.accept(sock).await.context("tls accept")?;
                let machine_id = peer_machine_id(&tls)
                    .context("extract machine_id from authenticated peer cert")?;
                let (r, w) = tokio::io::split(tls);
                handle_connection(
                    state,
                    ByteStreamRecv(r),
                    ByteStreamSend(w),
                    machine_id,
                    peer,
                )
                .await
            }
            .await;
            if let Err(e) = result {
                warn!(error = %e, "agent connection failed");
            }
        });
    }
}

/// Pull the leaf cert from a freshly-accepted rustls server stream
/// and extract its SAN URN. The TLS handshake has already validated
/// the cert against our `AgentClientVerifier`, so this MUST succeed —
/// any error here would mean rustls accepted a connection without a
/// peer cert despite the verifier being `client_auth_mandatory()`.
fn peer_machine_id(tls: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<String> {
    let (_io, sess) = tls.get_ref();
    let certs = sess
        .peer_certificates()
        .ok_or_else(|| anyhow!("no peer certificates on authenticated TLS stream"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("peer cert chain is empty"))?;
    extract_machine_id_from_san(leaf.as_ref())
}
