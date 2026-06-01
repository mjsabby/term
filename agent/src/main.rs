//! term-agent (push mode)
//!
//! Dials the hub on `hub` (host:port), authenticates with PSK in a
//! `Hello` frame, then runs the multiplex demuxer. Each `Open` frame on
//! a new stream attaches to (or spawns) a [`session::Session`] whose
//! stdout flows back as `Data` frames on the same stream. Reconnects
//! with exponential backoff on any failure.

mod session;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use term_common::frame::{
    Body, Frame, FrameError, FrameType, HelloPayload, HEADER_LEN, HELLO_VERSION,
    CONTROLLER_STATUS_NONE, CONTROLLER_STATUS_OTHER, CONTROLLER_STATUS_SELF,
    MAX_DATA_LEN, MAX_PASTE_TOTAL_BYTES, PASTE_REJECT_DUPLICATE_PASTE,
    PASTE_REJECT_GROUP_OVERSIZE, PASTE_REJECT_OPEN_FAILED, PASTE_REJECT_REGISTRY_FULL,
    PASTE_REJECT_SIZE_MISMATCH, PASTE_REJECT_WRITE_FAILED, PASTE_STATUS_CANCEL,
};
use term_common::prio::{item_prio_channel, prio_channel, ItemPrioRx, ItemPrioTx, PrioTx};

#[derive(Debug, Deserialize)]
struct AgentConfig {
    /// "host:port" of the hub's agent_bind.
    hub: String,
    /// Machine id presented in the Hello frame; must match a `[[machines]]`
    /// entry on the hub.
    machine_id: String,
    /// Pre-shared key (base64-encoded 32 random bytes) matching hub config.
    psk: String,
    /// "on" (default) or "off". Must match hub's tls mode.
    #[serde(default = "default_tls")]
    tls: String,
    /// SNI / cert-verification target. Defaults to the host part of `hub`.
    #[serde(default)]
    server_name: Option<String>,
    /// Shell program spawned in a fresh PTY by the in-agent session
    /// manager. Defaults to $SHELL or /bin/sh.
    #[serde(default)]
    shell: Option<String>,
    /// **Deprecated, ignored as of Phase 4.2** — the agent now manages
    /// sessions in-process and no longer wraps in tmux. Kept here so
    /// old `agent.toml` files still parse.
    #[serde(default, rename = "tmux")]
    _legacy_tmux: Option<String>,
}
fn default_tls() -> String { "on".into() }

const WRITE_HI_BYTES:    usize    = 4 * 1024 * 1024;
const WRITE_LO_BYTES:    usize    = 16 * 1024 * 1024;
/// Per-stream hi-priority queue (Data, Resize, Close). Keystrokes are
/// tiny so 8 items ≈ a few KiB.
const STREAM_HI_CAP:     usize    = 8;
/// Per-stream lo-priority queue (PasteBegin/Chunk/End). PasteChunk
/// holds up to 1 MiB; 8 items ≈ 8 MiB worst case per active paste
/// stream. Old item-based queue of 64 was 64 MiB worst case.
const STREAM_LO_CAP:     usize    = 8;
const PING_INTERVAL:     Duration = Duration::from_secs(30);
const IDLE_DEADLINE:     Duration = Duration::from_secs(90);
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX:     Duration = Duration::from_secs(60);
/// A connection that lasted at least this long is considered "healthy"
/// — a clean close after this is treated as a normal disconnect (fast
/// reset of backoff). Anything shorter is treated as a likely rejection
/// (the hub `bail!`s during hello on auth / version / unknown
/// machine_id and just shuts the socket — the agent sees a clean EOF
/// with no error frame, so we cannot distinguish the two by the
/// returned `Result` alone). Without this guard, a misconfigured agent
/// reconnects ~4x/second forever and spams both logs.
const HEALTHY_SESSION:   Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Crypto provider for rustls (no default with default-features=off).
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install rustls crypto provider"))?;

    let cfg_path = std::env::var("TERM_AGENT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/term-agent/agent.toml"));
    let cfg: AgentConfig = {
        let s = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("reading {}", cfg_path.display()))?;
        toml::from_str(&s).with_context(|| format!("parsing {}", cfg_path.display()))?
    };

    let shell = cfg.shell.clone()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".into());

    let server_name = cfg.server_name.clone().unwrap_or_else(|| {
        cfg.hub.split(':').next().unwrap_or("").to_string()
    });

    let tls_on = match cfg.tls.as_str() {
        "on"  | "true"  => true,
        "off" | "false" => false,
        other => bail!("invalid tls = {other:?}; use \"on\" or \"off\""),
    };

    let resolved = Arc::new(ResolvedConfig {
        hub: cfg.hub,
        machine_id: cfg.machine_id,
        psk: cfg.psk,
        tls_on,
        server_name,
        shell,
    });

    info!(
        "term-agent: hub={} machine_id={} tls={} server_name={} shell={}",
        resolved.hub, resolved.machine_id, if resolved.tls_on { "on" } else { "off" },
        resolved.server_name, resolved.shell,
    );

    let tls_connector = if resolved.tls_on { Some(build_tls_connector()?) } else { None };

    let mut backoff = RECONNECT_INITIAL;
    loop {
        let started = std::time::Instant::now();
        let result = run_once(resolved.clone(), tls_connector.clone()).await;
        let lasted = started.elapsed();
        match result {
            Ok(()) if lasted >= HEALTHY_SESSION => {
                info!("hub closed connection cleanly after {:?}; reconnecting", lasted);
                backoff = RECONNECT_INITIAL;
                sleep(Duration::from_millis(250)).await;
            }
            Ok(()) => {
                warn!(
                    "hub closed connection cleanly after only {:?} (likely rejection); backoff {:?}",
                    lasted, backoff
                );
                sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
            Err(e) => {
                warn!(error = %e, "connection failed; backoff {:?}", backoff);
                sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        }
    }
}

struct ResolvedConfig {
    hub: String,
    machine_id: String,
    psk: String,
    tls_on: bool,
    server_name: String,
    shell: String,
}

fn build_tls_connector() -> Result<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

async fn run_once(
    cfg: Arc<ResolvedConfig>,
    tls: Option<tokio_rustls::TlsConnector>,
) -> Result<()> {
    debug!("dialing {}", cfg.hub);
    let tcp = TcpStream::connect(&cfg.hub)
        .await
        .with_context(|| format!("dial {}", cfg.hub))?;
    tcp.set_nodelay(true).ok();

    if let Some(connector) = tls {
        let sn = ServerName::try_from(cfg.server_name.clone())
            .context("server_name must be a valid DNS name")?;
        let tls_stream = connector
            .connect(sn, tcp)
            .await
            .context("tls handshake")?;
        let (r, w) = tokio::io::split(tls_stream);
        run_session(cfg, r, w).await
    } else {
        let (r, w) = tcp.into_split();
        run_session(cfg, r, w).await
    }
}

async fn run_session<R, W>(
    cfg: Arc<ResolvedConfig>,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Build writer mpsc + spawn writer task.
    //
    // The agent → hub writer is split into hi/lo priority halves so a
    // long download (1 MiB DownloadChunk frames) can't queue ahead of
    // interactive PTY Data or control frames. Routing is by frame type
    // — see `send_frame_to_hub`. Byte budgets mirror the hub side.
    let (write_tx, mut write_rx) = prio_channel(WRITE_HI_BYTES, WRITE_LO_BYTES);
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = write_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() { break; }
        }
        let _ = writer.shutdown().await;
    });

    // Send Hello.
    let hello = HelloPayload {
        version: HELLO_VERSION,
        machine_id: cfg.machine_id.clone(),
        psk_b64: cfg.psk.clone(),
    };
    let hello_bytes = serde_json::to_vec(&hello).context("serialize hello")?;
    send_frame_to_hub(&write_tx, Frame::hello(hello_bytes))
        .await
        .map_err(|_| anyhow!("writer closed before hello"))?;

    // In-agent session manager: drops tmux, owns PTYs + scrollback +
    // controller state across browser tab lifecycle.
    let sessions = session::SessionManager::new(cfg.shell.clone());

    // Idle/exit sweeper: periodically drops sessions whose shells have
    // exited OR which have been detached longer than IDLE_TTL.
    let gc_sessions = sessions.clone();
    let gc_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            gc_sessions.gc_pass().await;
        }
    });

    // Per-stream registry. Each stream gets a priority channel so
    // interactive Data/Resize never sit behind 1 MiB PasteChunks.
    let streams: Arc<Mutex<HashMap<u32, ItemPrioTx<Body>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Pinger.
    let ping_writer = write_tx.clone();
    let pinger = tokio::spawn(async move {
        let mut tick = tokio::time::interval(PING_INTERVAL);
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if send_frame_to_hub(&ping_writer, Frame::ping(vec![])).await.is_err() { return; }
        }
    });

    // Reader loop. Returns on any unrecoverable error.
    let read_result: Result<()> = async {
        loop {
            let f = match timeout(IDLE_DEADLINE, read_frame(&mut reader)).await {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None))    => return Ok(()),
                Ok(Err(e))      => return Err(e.into()),
                Err(_)          => bail!("idle timeout (>{IDLE_DEADLINE:?})"),
            };
            match (f.stream_id, f.body) {
                (0, Body::Ping(p))  => { let _ = send_frame_to_hub(&write_tx, Frame::pong(p)).await; }
                (0, Body::Pong(_))  => {}
                (0, Body::Hello(_)) => bail!("hub sent hello (protocol error)"),
                (0, _)              => bail!("unexpected control-stream frame"),
                (sid, Body::Open { session_id, initial_size }) => {
                    // Spawn a per-stream task that attaches to (or
                    // spawns) the session and pumps frames.
                    let (s_tx, s_rx) = item_prio_channel::<Body>(STREAM_HI_CAP, STREAM_LO_CAP);
                    streams.lock().await.insert(sid, s_tx);
                    let sessions = sessions.clone();
                    let writer = write_tx.clone();
                    let streams = streams.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_session_stream(
                            sessions, sid, session_id.clone(), initial_size, s_rx, writer.clone()
                        ).await {
                            warn!(stream_id = sid, session = %session_id, error = %e, "session ended with error");
                        }
                        // Best-effort: tell hub the stream is done and
                        // remove ourselves from the registry.
                        let _ = send_frame_to_hub(&writer, Frame::close(sid)).await;
                        streams.lock().await.remove(&sid);
                    });
                }
                (sid, body) => {
                    // Route by body type: bulk paste chunks go through
                    // the lo channel; everything else (Data, Resize,
                    // Close) takes the hi channel so keystrokes are
                    // never blocked by an in-flight large paste.
                    let half_lo = matches!(body,
                        Body::PasteBegin { .. } |
                        Body::PasteChunk { .. } |
                        Body::PasteEnd   { .. });
                    let tx = { streams.lock().await.get(&sid).cloned() };
                    if let Some(tx) = tx {
                        let ch = if half_lo { &tx.lo } else { &tx.hi };
                        let _ = ch.send(body).await;
                    } else {
                        debug!(sid, "frame for unknown stream; ignoring");
                    }
                }
            }
        }
    }
    .await;

    // Tear down everything for this connection.
    streams.lock().await.clear(); // drops all per-stream txes -> sessions terminate
    pinger.abort();
    gc_task.abort();
    drop(write_tx);
    let _ = writer_task.await;

    read_result
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

/// Maximum number of in-flight paste uploads for one mux stream. Bounds
/// concurrent tempfile descriptors a malicious browser can hold open.
const MAX_PENDING_PASTES: usize = 32;
/// Maximum number of distinct in-flight paste *groups* for one stream.
/// Each group can hold up to `MAX_PENDING_PASTES` files; this caps
/// total registry-side memory.
const MAX_PENDING_GROUPS: usize = 32;

/// One paste that is mid-transfer. Lives inside the per-stream task.
struct PendingPaste {
    file:       fs::File,
    path:       PathBuf,
    total_size: u64,
    written:    u64,
    group_id:   u32,
}

/// One paste group that is mid-transfer: the set of `group_size` files
/// the browser is currently uploading as one logical paste action.
/// Finished paths are buffered here until all `group_size` pastes
/// complete, then injected into the PTY in one bracketed-paste block.
struct PendingGroup {
    group_size:     u32,
    finished:       Vec<PathBuf>,
    /// Sum of `total_size` declared by every PasteBegin in this group.
    /// Bounded by `MAX_PASTE_TOTAL_BYTES`: a single paste action cannot
    /// claim more than 4 GiB of aggregate file bytes, even split across
    /// many files.
    total_declared: u64,
}

/// Per-stream task: attach to the session, replay scrollback, pump
/// frames in both directions. The PTY, OSC scanner, scrollback, and
/// download stream all live inside the shared [`session::Session`] —
/// this function only handles wire-side concerns (paste uploads,
/// controller frames, broadcast → writer fan-out for THIS stream's
/// sid).
async fn run_session_stream(
    sessions: Arc<session::SessionManager>,
    sid: u32,
    session_id: String,
    initial_size: (u16, u16),
    mut rx: ItemPrioRx<Body>,
    writer: PrioTx,
) -> Result<()> {
    // Look up or spawn the underlying session.
    let session = sessions.lookup_or_spawn(&session_id, initial_size).await?;
    let attach = session.attach(sid, initial_size).await;
    info!(stream_id = sid, session = %session_id,
          became_controller = attach.became_controller,
          "attached to session");

    // Replay scrollback as Data frames before live output resumes. Cap
    // each frame at MAX_DATA_LEN so the wire is well-formed.
    for chunk in attach.scrollback.chunks(MAX_DATA_LEN as usize) {
        send_frame_to_hub(&writer, Frame::data(sid, chunk.to_vec()))
            .await
            .map_err(|_| anyhow!("writer closed during scrollback replay"))?;
    }
    // Tell this browser who the current controller is, in *its own*
    // reference frame (it doesn't know its hub-allocated sid).
    let initial_status = match attach.current_controller {
        None      => CONTROLLER_STATUS_NONE,
        Some(c) if c == sid => CONTROLLER_STATUS_SELF,
        _         => CONTROLLER_STATUS_OTHER,
    };
    let _ = send_frame_to_hub(&writer, Frame::controller_changed(sid, initial_status)).await;

    // Per-stream paste state (PasteBegin/Chunk/End handlers buffer
    // chunks here; on PasteEnd the path is typed into the shared PTY
    // via session.write_internal()).
    let pending_pastes: Arc<tokio::sync::Mutex<HashMap<u32, PendingPaste>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let pending_groups: Arc<tokio::sync::Mutex<HashMap<u32, PendingGroup>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Outbound: forward broadcast events from the session to our writer.
    let outbound = {
        let writer = writer.clone();
        let mut event_rx = attach.event_rx;
        async move {
            loop {
                use session::SessionEvent::*;
                match event_rx.recv().await {
                    Ok(Data(bytes)) => {
                        for chunk in bytes.chunks(MAX_DATA_LEN as usize) {
                            if send_frame_to_hub(&writer, Frame::data(sid, chunk.to_vec()))
                                .await.is_err()
                            { return; }
                        }
                    }
                    Ok(ControllerChanged { controller }) => {
                        let status = if controller == term_common::frame::CONTROLLER_NONE_STREAM_ID {
                            CONTROLLER_STATUS_NONE
                        } else if controller == sid {
                            CONTROLLER_STATUS_SELF
                        } else {
                            CONTROLLER_STATUS_OTHER
                        };
                        if send_frame_to_hub(&writer,
                            Frame::controller_changed(sid, status)).await.is_err()
                        { return; }
                    }
                    Ok(DownloadBegin { id, total_size, name }) => {
                        if send_frame_to_hub(&writer,
                            Frame::download_begin(sid, id, total_size, name)).await.is_err()
                        { return; }
                    }
                    Ok(DownloadChunk { id, bytes }) => {
                        if send_frame_to_hub(&writer,
                            Frame::download_chunk(sid, id, bytes.as_ref().clone()))
                            .await.is_err()
                        { return; }
                    }
                    Ok(DownloadEnd { id, status }) => {
                        if send_frame_to_hub(&writer,
                            Frame::download_end(sid, id, status)).await.is_err()
                        { return; }
                    }
                    Ok(Closed) => {
                        let _ = send_frame_to_hub(&writer, Frame::close(sid)).await;
                        return;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(stream_id = sid, lagged = n, "broadcast lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    };

    // Inbound: forward rx frames to the session.
    let inbound = {
        let session = session.clone();
        let pending_pastes = pending_pastes.clone();
        let pending_groups = pending_groups.clone();
        let writer = writer.clone();
        async move {
            while let Some(body) = rx.recv().await {
                match body {
                    Body::Data(b) => session.write_input_from(sid, &b).await,
                    Body::Resize { rows, cols } => session.resize_for(sid, rows, cols).await,
                    Body::AcquireControl => { session.acquire_control(sid).await; }
                    Body::ReleaseControl => { session.release_control(sid).await; }
                    Body::TakeControl    => { session.take_control(sid).await; }
                    Body::PasteBegin { paste_id, total_size, group_id, group_size, name } => {
                        handle_paste_begin(
                            sid, paste_id, total_size, group_id, group_size, name,
                            &pending_pastes, &pending_groups, &writer,
                        ).await;
                    }
                    Body::PasteChunk { paste_id, bytes } => {
                        handle_paste_chunk(sid, paste_id, &bytes, &pending_pastes, &writer).await;
                    }
                    Body::PasteEnd { paste_id, status } => {
                        handle_paste_end(
                            sid, paste_id, status,
                            &pending_pastes, &pending_groups, &session, &writer,
                        ).await;
                    }
                    Body::Close => break,
                    _ => debug!("ignored body on session stream"),
                }
            }
        }
    };

    tokio::select! {
        _ = outbound => {}
        _ = inbound  => {}
    }

    // Detach (releases controller slot if we held it; broadcasts
    // ControllerChanged(none) to the remaining viewers).
    session.detach(sid).await;

    // Clean up any in-flight pastes for this stream.
    {
        let mut pp = pending_pastes.lock().await;
        for (_, p) in pp.drain() {
            let _ = fs::remove_file(&p.path).await;
        }
    }
    {
        let mut pg = pending_groups.lock().await;
        for (_, g) in pg.drain() {
            for path in g.finished {
                let _ = fs::remove_file(&path).await;
            }
        }
    }

    Ok(())
}

/// Send a frame to the hub via the priority writer, routing by frame
/// type: bulk DownloadChunks go through `lo` so they never queue ahead
/// of interactive PTY Data or control frames. Everything else (Data,
/// Resize, Open, Close, Ping, Pong, Hello, PasteReject, DownloadBegin,
/// DownloadEnd) takes the `hi` channel. Mirrors the hub-side dispatch
/// in `hub/src/agent_link.rs::AgentLink::send_frame`.
async fn send_frame_to_hub(w: &PrioTx, f: Frame) -> Result<(), Vec<u8>> {
    let half = match f.ty() {
        FrameType::DownloadChunk => &w.lo,
        _                        => &w.hi,
    };
    half.send(f.encode()).await
}

/// Send a PasteReject(paste_id, reason) frame back to the hub on this
/// stream. Best-effort: silent failure on a closed writer is fine
/// because the stream is dying anyway.
async fn send_paste_reject(
    writer: &PrioTx,
    sid: u32,
    paste_id: u32,
    reason: u8,
) {
    let _ = send_frame_to_hub(writer, Frame::paste_reject(sid, paste_id, reason)).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_paste_begin(
    sid: u32,
    paste_id: u32,
    total_size: u64,
    group_id: u32,
    group_size: u32,
    name: String,
    pending_pastes: &tokio::sync::Mutex<HashMap<u32, PendingPaste>>,
    pending_groups: &tokio::sync::Mutex<HashMap<u32, PendingGroup>>,
    writer: &PrioTx,
) {
    let mut pp = pending_pastes.lock().await;
    if pp.len() >= MAX_PENDING_PASTES {
        warn!(stream_id = sid, paste_id, "too many concurrent pastes; rejecting");
        drop(pp);
        send_paste_reject(writer, sid, paste_id, PASTE_REJECT_REGISTRY_FULL).await;
        return;
    }
    if pp.contains_key(&paste_id) {
        warn!(stream_id = sid, paste_id, "duplicate paste_id; rejecting");
        drop(pp);
        send_paste_reject(writer, sid, paste_id, PASTE_REJECT_DUPLICATE_PASTE).await;
        return;
    }
    // Reserve / extend the group slot, enforcing the per-group
    // aggregate cap. If the group already exists and adding total_size
    // would push past MAX_PASTE_TOTAL_BYTES, reject this Begin and
    // cancel the whole group.
    {
        let mut pg = pending_groups.lock().await;
        if let Some(g) = pg.get_mut(&group_id) {
            if g.total_declared.saturating_add(total_size) > MAX_PASTE_TOTAL_BYTES {
                warn!(
                    stream_id = sid, paste_id, group_id,
                    declared = g.total_declared, adding = total_size,
                    "group aggregate would exceed 4 GiB; rejecting and cancelling group"
                );
                let to_drop = pg.remove(&group_id).unwrap().finished;
                drop(pg);
                drop(pp);
                for path in to_drop { let _ = fs::remove_file(&path).await; }
                send_paste_reject(writer, sid, paste_id, PASTE_REJECT_GROUP_OVERSIZE).await;
                return;
            }
            g.total_declared = g.total_declared.saturating_add(total_size);
        } else {
            if pg.len() >= MAX_PENDING_GROUPS {
                warn!(stream_id = sid, group_id, "too many concurrent paste groups; rejecting begin");
                drop(pg);
                drop(pp);
                send_paste_reject(writer, sid, paste_id, PASTE_REJECT_REGISTRY_FULL).await;
                return;
            }
            if total_size > MAX_PASTE_TOTAL_BYTES {
                warn!(stream_id = sid, paste_id, total_size, "single file exceeds 4 GiB; rejecting");
                drop(pg);
                drop(pp);
                send_paste_reject(writer, sid, paste_id, PASTE_REJECT_GROUP_OVERSIZE).await;
                return;
            }
            pg.insert(group_id, PendingGroup {
                group_size,
                finished: Vec::new(),
                total_declared: total_size,
            });
        }
    }
    match open_paste_file(&name).await {
        Ok((file, path)) => {
            info!(
                stream_id = sid, paste_id,
                name = %name, total_size, group_id, group_size,
                path = %path.display(),
                "paste begin"
            );
            pp.insert(paste_id, PendingPaste {
                file, path, total_size, written: 0, group_id,
            });
        }
        Err(e) => {
            warn!(error = %e, "paste begin: open file failed");
            // Roll back the group bookkeeping we just did.
            {
                let mut pg = pending_groups.lock().await;
                if let Some(g) = pg.get_mut(&group_id) {
                    g.total_declared = g.total_declared.saturating_sub(total_size);
                }
            }
            drop(pp);
            send_paste_reject(writer, sid, paste_id, PASTE_REJECT_OPEN_FAILED).await;
        }
    }
}

async fn handle_paste_chunk(
    sid: u32,
    paste_id: u32,
    bytes: &[u8],
    pending_pastes: &tokio::sync::Mutex<HashMap<u32, PendingPaste>>,
    writer: &PrioTx,
) {
    let mut pp = pending_pastes.lock().await;
    let Some(p) = pp.get_mut(&paste_id) else {
        debug!(stream_id = sid, paste_id, "chunk for unknown paste_id");
        return;
    };
    if p.written.saturating_add(bytes.len() as u64) > p.total_size {
        warn!(stream_id = sid, paste_id, "chunk exceeds total_size; cancelling paste");
        if let Some(p) = pp.remove(&paste_id) {
            drop(pp);
            let _ = fs::remove_file(&p.path).await;
            send_paste_reject(writer, sid, paste_id, PASTE_REJECT_SIZE_MISMATCH).await;
        }
        return;
    }
    if let Err(e) = p.file.write_all(bytes).await {
        warn!(error = %e, "chunk write failed; cancelling paste");
        if let Some(p) = pp.remove(&paste_id) {
            drop(pp);
            let _ = fs::remove_file(&p.path).await;
            send_paste_reject(writer, sid, paste_id, PASTE_REJECT_WRITE_FAILED).await;
        }
        return;
    }
    p.written += bytes.len() as u64;
}

#[allow(clippy::too_many_arguments)]
async fn handle_paste_end(
    sid: u32,
    paste_id: u32,
    status: u8,
    pending_pastes: &tokio::sync::Mutex<HashMap<u32, PendingPaste>>,
    pending_groups: &tokio::sync::Mutex<HashMap<u32, PendingGroup>>,
    session: &Arc<session::Session>,
    writer: &PrioTx,
) {
    let mut pp = pending_pastes.lock().await;
    let Some(mut p) = pp.remove(&paste_id) else {
        debug!(stream_id = sid, paste_id, "end for unknown paste_id");
        return;
    };
    let group_id = p.group_id;
    drop(pp); // release before any await

    if status == PASTE_STATUS_CANCEL {
        let _ = fs::remove_file(&p.path).await;
        info!(stream_id = sid, paste_id, "paste cancelled");
        // Cancel implicitly drops the whole group: the browser is
        // unlikely to commit some files while cancelling others, and
        // even if it does, we'd rather inject nothing than a partial
        // batch. Wipe whatever already-finished paths this group had.
        let removed = pending_groups.lock().await.remove(&group_id);
        if let Some(g) = removed {
            for path in g.finished {
                let _ = fs::remove_file(&path).await;
            }
        }
        return;
    }
    // PASTE_STATUS_OK
    if p.written != p.total_size {
        warn!(
            stream_id = sid, paste_id,
            written = p.written, expected = p.total_size,
            "paste size mismatch; dropping"
        );
        let _ = fs::remove_file(&p.path).await;
        send_paste_reject(writer, sid, paste_id, PASTE_REJECT_SIZE_MISMATCH).await;
        // Treat as group cancel for the same reason as above.
        let removed = pending_groups.lock().await.remove(&group_id);
        if let Some(g) = removed {
            for path in g.finished {
                let _ = fs::remove_file(&path).await;
            }
        }
        return;
    }
    if let Err(e) = p.file.flush().await {
        warn!(error = %e, "paste flush failed");
    }
    drop(p.file);
    info!(stream_id = sid, paste_id, path = %p.path.display(), "paste committed");

    // Stage this path into its group; if the group is now full, drain
    // and inject in one bracketed-paste block.
    let to_inject: Option<Vec<PathBuf>> = {
        let mut pg = pending_groups.lock().await;
        if let Some(g) = pg.get_mut(&group_id) {
            g.finished.push(p.path);
            if g.finished.len() as u32 >= g.group_size {
                let g = pg.remove(&group_id).unwrap();
                Some(g.finished)
            } else {
                None
            }
        } else {
            // Shouldn't happen — handle_paste_begin would have created
            // the group. Be conservative and inject this one path
            // standalone rather than leaking it.
            Some(vec![p.path])
        }
    };

    if let Some(paths) = to_inject {
        inject_paste_paths(sid, paths, session).await;
    }
}

/// Build a single bracketed-paste sequence
/// `ESC[200~ p1 p2 ... pn ESC[201~` and write it to the shared PTY via
/// the Session, so all attached viewers see the typed paths. Shells /
/// readline / vim treat the lot as literal text and do not execute it.
/// Trailing space lets the user keep typing without a gap.
async fn inject_paste_paths(
    sid: u32,
    paths: Vec<PathBuf>,
    session: &Arc<session::Session>,
) {
    let cap: usize = paths.iter().map(|p| p.as_os_str().len() + 1).sum::<usize>() + 16;
    let mut seq = Vec::with_capacity(cap);
    seq.extend_from_slice(b"\x1b[200~");
    for (i, p) in paths.iter().enumerate() {
        if i > 0 { seq.push(b' '); }
        seq.extend_from_slice(p.as_os_str().as_encoded_bytes());
    }
    seq.extend_from_slice(b" \x1b[201~");
    if let Err(e) = session.write_internal(&seq).await {
        warn!(stream_id = sid, error = %e, "pty write of pasted paths failed");
    }
}


/// Returns the path used for pasted screenshots (does NOT create it; use
/// [`ensure_paste_dir`]).
///
/// We prefer `$XDG_RUNTIME_DIR/term-agent/paste` because systemd sets it
/// on a per-uid tmpfs that is wiped on session/service exit. When the
/// service runs as a system user (no XDG_RUNTIME_DIR), fall back to
/// `/tmp/term-agent-<euid>/paste`.
fn paste_root() -> &'static Path {
    static PASTE_ROOT: OnceLock<PathBuf> = OnceLock::new();
    PASTE_ROOT.get_or_init(|| {
        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
            PathBuf::from(rt).join("term-agent").join("paste")
        } else {
            // SAFETY: geteuid() is documented as always successful.
            let uid = unsafe { libc::geteuid() };
            PathBuf::from(format!("/tmp/term-agent-{uid}")).join("paste")
        }
    })
}

/// Create the paste dir (and its parent) idempotently with 0700, and
/// best-effort sweep any pasted files older than 1 hour. Returns an
/// error if the directory cannot be created or its permissions cannot
/// be enforced — better to fail the paste than to silently leak files
/// into a world-readable location.
///
/// The hot path runs this every paste because `save_paste_file` cannot
/// assume the dir survived since the previous call (PrivateTmp, manual
/// wipes, etc). Cost on the steady-state happy path is one stat + one
/// chmod syscall, which is negligible compared to writing megabytes of
/// image bytes.
async fn ensure_paste_dir() -> Result<&'static Path> {
    let dir = paste_root();

    // For the /tmp/term-agent-<uid> fallback the parent path component
    // (/tmp/term-agent-<uid>) is owned by us; refuse to follow a symlink
    // there so a hostile local user who pre-creates the path cannot
    // redirect our writes. XDG_RUNTIME_DIR is per-uid and tmpfs-backed,
    // so the same defense is not necessary on that path.
    if let Some(parent) = dir.parent() {
        match std::fs::symlink_metadata(parent) {
            Ok(md) if md.file_type().is_symlink() => {
                bail!("paste parent {} is a symlink; refusing", parent.display());
            }
            Ok(md) if !md.file_type().is_dir() => {
                bail!("paste parent {} exists and is not a directory", parent.display());
            }
            _ => {} // missing-or-dir: fine, create_dir_all will handle it
        }
    }

    fs::create_dir_all(dir).await
        .with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Re-apply perms unconditionally (umask may have left them looser,
    // or the dir may have been recreated by something else with 0755).
    fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;

    // Best-effort: prune any pasted files older than 1 hour. Runs once
    // per save, but a single readdir/<N stats> is cheap and bounds long-
    // term accumulation without needing a background sweeper task.
    sweep_old_paste_files(dir).await;

    Ok(dir)
}

async fn sweep_old_paste_files(dir: &Path) {
    const TTL: Duration = Duration::from_secs(60 * 60);
    let mut rd = match fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let now = SystemTime::now();
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            _ => return,
        };
        let name = entry.file_name();
        let name_s = match name.to_str() {
            Some(s) if s.starts_with("term-paste-") => s.to_owned(),
            _ => continue,
        };
        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !md.is_file() { continue; }
        let mtime = match md.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if now.duration_since(mtime).map(|d| d > TTL).unwrap_or(false) {
            let _ = fs::remove_file(dir.join(name_s)).await;
        }
    }
}

/// Sanitize a browser-supplied filename into something safe to drop in
/// the agent's paste dir and type into the PTY: take the basename only
/// (defeats `../foo` traversal), restrict to `[A-Za-z0-9._-]`, strip
/// leading dots/dashes, truncate to 200 bytes. Empty input or input
/// that collapses to nothing yields a generated `term-paste-<nanos>`
/// name with no extension.
fn sanitize_paste_name(input: &str) -> String {
    // file_name() strips any directory components and returns the last
    // component, so `../etc/passwd`, `/etc/passwd`, and `foo/bar.png`
    // all return their basename. Trailing slashes return None.
    let basename = std::path::Path::new(input)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let cleaned: String = basename.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            c
        } else {
            '_'
        })
        .collect();
    // Don't allow leading '.' (hidden file) or '-' (looks like a CLI
    // flag if pasted into a `cat`/`rm` invocation).
    let trimmed = cleaned.trim_start_matches(['.', '-']);
    let truncated: String = trimmed.chars().take(200).collect();
    if truncated.is_empty() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        format!("term-paste-{nanos:016x}")
    } else {
        truncated
    }
}

/// Split `"file.tar.gz"` into `("file.tar", "gz")`; `"foo"` into
/// `("foo", "")`; `".hidden"` into `(".hidden", "")`.
fn split_ext(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, ext),
        _ => (name, ""),
    }
}

/// Open a fresh paste tempfile keyed off the (sanitized) `name`. Tries
/// `<name>` first, then `<stem>-1.<ext>`, `<stem>-2.<ext>`, ... up to
/// 1024 attempts; finally falls back to a nanos-suffixed name. The file
/// is opened with `O_EXCL | O_CREAT | O_WRONLY` at mode 0600.
async fn open_paste_file(name: &str) -> Result<(fs::File, PathBuf)> {
    let dir = ensure_paste_dir().await?;
    let base = sanitize_paste_name(name);
    let (stem, ext) = split_ext(&base);
    let stem = stem.to_owned();
    let ext = ext.to_owned();

    for i in 0..1024 {
        let candidate = if i == 0 {
            base.clone()
        } else if ext.is_empty() {
            format!("{stem}-{i}")
        } else {
            format!("{stem}-{i}.{ext}")
        };
        let path = dir.join(&candidate);

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);

        match opts.open(&path).await {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(anyhow!("creating {}: {e}", path.display())),
        }
    }
    // Fallback: nanos suffix essentially guarantees uniqueness.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let candidate = if ext.is_empty() {
        format!("{stem}-{nanos:016x}")
    } else {
        format!("{stem}-{nanos:016x}.{ext}")
    };
    let path = dir.join(&candidate);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let f = opts.open(&path).await
        .with_context(|| format!("creating fallback paste file {}", path.display()))?;
    Ok((f, path))
}
