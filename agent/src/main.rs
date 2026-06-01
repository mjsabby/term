//! term-agent (push mode)
//!
//! Dials the hub on `hub` (host:port), authenticates with PSK in a
//! `Hello` frame, then runs the multiplex demuxer. Each `Open` frame on
//! a new stream spawns a tmux+PTY task whose stdout flows back as
//! `Data` frames on the same stream. Reconnects with exponential
//! backoff on any failure.

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
    DOWNLOAD_STATUS_OK, MAX_PASTE_CHUNK_BYTES, MAX_PASTE_TOTAL_BYTES,
    PASTE_REJECT_DUPLICATE_PASTE, PASTE_REJECT_GROUP_OVERSIZE, PASTE_REJECT_OPEN_FAILED,
    PASTE_REJECT_REGISTRY_FULL, PASTE_REJECT_SIZE_MISMATCH, PASTE_REJECT_WRITE_FAILED,
    PASTE_STATUS_CANCEL,
};
use term_common::osc::OscScanner;
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
    /// Shell program inside tmux. Defaults to $SHELL or /bin/sh.
    #[serde(default)]
    shell: Option<String>,
    /// tmux binary path.
    #[serde(default = "default_tmux")]
    tmux: String,
}
fn default_tls() -> String { "on".into() }
fn default_tmux() -> String { "tmux".into() }

const WRITE_HI_BYTES:    usize    = 4 * 1024 * 1024;
const WRITE_LO_BYTES:    usize    = 16 * 1024 * 1024;
/// Per-stream hi-priority queue (Data, Resize, Close). Keystrokes are
/// tiny so 8 items ≈ a few KiB.
const STREAM_HI_CAP:     usize    = 8;
/// Per-stream lo-priority queue (PasteBegin/Chunk/End). PasteChunk
/// holds up to 1 MiB; 8 items ≈ 8 MiB worst case per active paste
/// stream. Old item-based queue of 64 was 64 MiB worst case.
const STREAM_LO_CAP:     usize    = 8;
/// Max concurrent in-flight downloads per mux stream. Each download
/// task holds an open fd + a 1 MiB read buffer.
const MAX_INFLIGHT_DOWNLOADS: usize = 16;
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
        tmux: cfg.tmux,
    });

    info!(
        "term-agent: hub={} machine_id={} tls={} server_name={} tmux={} shell={}",
        resolved.hub, resolved.machine_id, if resolved.tls_on { "on" } else { "off" },
        resolved.server_name, resolved.tmux, resolved.shell,
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
    tmux: String,
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
                (sid, Body::Open(session_id)) => {
                    // Spawn a per-session task.
                    let (s_tx, s_rx) = item_prio_channel::<Body>(STREAM_HI_CAP, STREAM_LO_CAP);
                    streams.lock().await.insert(sid, s_tx);
                    let cfg = cfg.clone();
                    let writer = write_tx.clone();
                    let streams = streams.clone();
                    tokio::spawn(async move {
                        if let Err(e) = run_session_stream(cfg, sid, session_id.clone(), s_rx, writer.clone()).await {
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

/// Spawn tmux+PTY and pump data both ways for one stream.
async fn run_session_stream(
    cfg: Arc<ResolvedConfig>,
    sid: u32,
    session_id: String,
    mut rx: ItemPrioRx<Body>,
    writer: PrioTx,
) -> Result<()> {
    let (pty, pts) = pty_process::open().context("pty_process::open")?;
    pty.resize(pty_process::Size::new(24, 80)).context("initial resize")?;
    // systemd service units inherit no TERM and no locale. Set a
    // terminfo-capable TERM so tmux starts, advertise truecolor so
    // modern TUIs (nvim, bat, eza, …) light up, and pick a UTF-8 locale
    // so glibc-based programs render non-ASCII correctly. xterm.js is
    // xterm-compatible and supports 24-bit color via COLORTERM=truecolor.
    let mut child = pty_process::Command::new(&cfg.tmux)
        .env("TERM",      "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("LANG",      "C.UTF-8")
        .env("LC_ALL",    "C.UTF-8")
        .args(["new-session", "-A", "-s", &session_id, "--", &cfg.shell])
        .spawn(pts)
        .context("spawn tmux")?;

    let (mut pty_r, pty_w) = pty.into_split();
    info!(stream_id = sid, session = %session_id, "tmux session started");

    // pty_w is shared between the rx-driven control loop and the
    // group-flush path; tokio::sync::Mutex is held across .await on
    // writes, so std::sync::Mutex won't do.
    let pty_w = Arc::new(tokio::sync::Mutex::new(pty_w));

    // Paste registries live in Arcs so that, no matter which arm of the
    // tokio::select! finishes first, the post-select cleanup runs over
    // the same maps and can unlink any tempfiles for in-flight pastes.
    let pending_pastes: Arc<tokio::sync::Mutex<HashMap<u32, PendingPaste>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let pending_groups: Arc<tokio::sync::Mutex<HashMap<u32, PendingGroup>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Per-stream download bookkeeping. Bounds concurrent downloads so a
    // shell script that spams `term-dl` against many files can't open
    // unbounded fds. `next_download_id` only needs uniqueness among
    // *this stream's* in-flight downloads. The JoinSet + Notify pair
    // give us cancellation so we can stop in-flight downloads as soon
    // as the stream goes away (browser close, agent shutdown).
    let download_sem = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_DOWNLOADS));
    let next_download_id = Arc::new(std::sync::atomic::AtomicU32::new(1));
    let download_cancel: Arc<tokio::sync::Notify> = Arc::new(tokio::sync::Notify::new());
    let download_tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> =
        Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));

    let pty_to_writer = {
        let writer = writer.clone();
        let pty_w = pty_w.clone();
        let download_sem = download_sem.clone();
        let next_download_id = next_download_id.clone();
        let download_cancel = download_cancel.clone();
        let download_tasks = download_tasks.clone();
        async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut osc = OscScanner::new();
            loop {
                let n = pty_r.read(&mut buf).await?;
                if n == 0 { return Ok::<(), anyhow::Error>(()); }
                let (fwd, captured) = osc.feed(&buf[..n]);
                if !fwd.is_empty()
                    && send_frame_to_hub(&writer, Frame::data(sid, fwd)).await.is_err()
                {
                    return Err(anyhow!("writer closed"));
                }
                for payload in captured {
                    dispatch_app_osc(
                        sid, payload,
                        &writer, &pty_w,
                        &download_sem, &next_download_id,
                        &download_cancel, &download_tasks,
                    ).await;
                }
            }
        }
    };

    let rx_to_pty = {
        let pty_w = pty_w.clone();
        let pending_pastes = pending_pastes.clone();
        let pending_groups = pending_groups.clone();
        let writer = writer.clone();
        async move {
            while let Some(body) = rx.recv().await {
                match body {
                    Body::Data(b) => {
                        pty_w.lock().await.write_all(&b).await?;
                    }
                    Body::Resize { rows, cols } => {
                        if let Err(e) = pty_w.lock().await
                            .resize(pty_process::Size::new(rows, cols))
                        {
                            warn!(error = %e, "pty resize failed");
                        }
                    }
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
                            &pending_pastes, &pending_groups, &pty_w, &writer,
                        ).await;
                    }
                    Body::Close => break,
                    _ => debug!("ignored body on session stream"),
                }
            }
            Ok::<(), anyhow::Error>(())
        }
    };

    tokio::select! {
        _ = pty_to_writer => {}
        _ = rx_to_pty     => {}
    };

    // Tear down any in-flight downloads BEFORE running cleanup so they
    // stop pumping bytes into a dying stream. `notify_waiters` wakes
    // every in-flight `run_download` cancellation-aware select; aborting
    // the JoinSet for good measure handles tasks that haven't reached
    // their await point yet.
    download_cancel.notify_waiters();
    {
        let mut tasks = download_tasks.lock().await;
        tasks.abort_all();
        // Drain so we don't leak JoinHandles; ignore individual errors.
        while tasks.join_next().await.is_some() {}
    }

    // Cancellation-safe cleanup: works whether rx_to_pty completed
    // normally OR was cancelled because pty_to_writer finished first.
    // Both branches drop the local future tree, but `pending_pastes`/
    // `pending_groups` are Arcs and survive.
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

    let _ = child.start_kill();
    let _ = child.wait().await;
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
    pty_w: &tokio::sync::Mutex<pty_process::OwnedWritePty>,
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
        inject_paste_paths(sid, paths, pty_w).await;
    }
}

/// Build a single bracketed-paste sequence
/// `ESC[200~ p1 p2 ... pn ESC[201~` and write it to the PTY, so shells
/// / readline / vim treat the lot as literal text and do not execute
/// it. Trailing space lets the user keep typing without a gap.
async fn inject_paste_paths(
    sid: u32,
    paths: Vec<PathBuf>,
    pty_w: &tokio::sync::Mutex<pty_process::OwnedWritePty>,
) {
    let cap: usize = paths.iter().map(|p| p.as_os_str().len() + 1).sum::<usize>() + 16;
    let mut seq = Vec::with_capacity(cap);
    seq.extend_from_slice(b"\x1b[200~");
    for (i, p) in paths.iter().enumerate() {
        if i > 0 { seq.push(b' '); }
        seq.extend_from_slice(p.as_os_str().as_encoded_bytes());
    }
    seq.extend_from_slice(b" \x1b[201~");
    let mut w = pty_w.lock().await;
    if let Err(e) = w.write_all(&seq).await {
        warn!(stream_id = sid, error = %e, "pty write of pasted paths failed");
    }
}

// ----- application OSC dispatch (term-dl) -----------------------------------

/// Dispatch one application OSC payload captured from the PTY output.
/// The OSC `\x1b]5111;dl;<path>\x07` triggers a download of `<path>`
/// from the agent to the browser on the same mux stream.
#[allow(clippy::too_many_arguments)]
async fn dispatch_app_osc(
    sid: u32,
    payload: Vec<u8>,
    writer: &PrioTx,
    pty_w: &Arc<tokio::sync::Mutex<pty_process::OwnedWritePty>>,
    sem: &Arc<tokio::sync::Semaphore>,
    next_id: &Arc<std::sync::atomic::AtomicU32>,
    cancel: &Arc<tokio::sync::Notify>,
    tasks: &Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
) {
    // payload looks like `dl;/absolute/path/to/file`.
    let Some(semi) = payload.iter().position(|&b| b == b';') else {
        warn!(stream_id = sid, "app OSC missing subcommand separator");
        return;
    };
    let cmd = &payload[..semi];
    let arg = &payload[semi + 1..];
    if cmd != b"dl" {
        warn!(stream_id = sid, cmd = ?String::from_utf8_lossy(cmd),
              "unknown app OSC subcommand; ignoring");
        return;
    }
    let path = match std::str::from_utf8(arg) {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            warn!(stream_id = sid, "app OSC path not utf-8");
            return;
        }
    };

    let permit = match sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // Too many concurrent downloads — bail loudly into the PTY
            // so the user knows.
            term_dl_error(pty_w, "too many concurrent downloads").await;
            return;
        }
    };
    let download_id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let writer = writer.clone();
    let pty_w = pty_w.clone();
    let cancel = cancel.clone();
    tasks.lock().await.spawn(async move {
        // run_download bails fast if `cancel` fires, so a browser
        // disconnect doesn't keep streaming GiBs into a dead stream.
        let result = tokio::select! {
            biased;
            _ = cancel.notified() => Err(anyhow!("stream cancelled")),
            r = run_download(sid, download_id, &path, &writer) => r,
        };
        if let Err(e) = result {
            warn!(stream_id = sid, download_id, path = %path.display(),
                  error = %e, "download failed");
            // Best-effort cancel for whatever the browser may have seen.
            let _ = send_frame_to_hub(
                &writer,
                Frame::download_end(sid, download_id,
                    term_common::frame::DOWNLOAD_STATUS_CANCEL),
            ).await;
            term_dl_error(&pty_w, &format!("{}: {e}", path.display())).await;
        }
        drop(permit);
    });
}

/// Stream `path` to the browser on `sid` as a chunked download.
/// Returns Err on any I/O or send failure so the caller can emit a
/// `DownloadEnd(cancel)` and a PTY error line.
async fn run_download(
    sid: u32,
    download_id: u32,
    path: &Path,
    writer: &PrioTx,
) -> Result<()> {
    let mut file = fs::File::open(path).await
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = file.metadata().await
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let total_size = meta.len();
    if total_size > MAX_PASTE_TOTAL_BYTES {
        bail!(
            "{} is {} bytes; over 4 GiB cap",
            path.display(), total_size
        );
    }
    let name = path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download")
        .to_owned();

    info!(stream_id = sid, download_id, name = %name, total_size, "download begin");

    send_frame_to_hub(
        writer,
        Frame::download_begin(sid, download_id, total_size, name.clone()),
    ).await.map_err(|_| anyhow!("writer closed before download begin"))?;

    let mut buf = vec![0u8; MAX_PASTE_CHUNK_BYTES as usize];
    let mut sent: u64 = 0;
    loop {
        let n = file.read(&mut buf).await
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 { break; }
        // Refuse to overshoot the size declared in Begin. Bail rather
        // than truncate so the browser discards instead of saving a
        // file that lies about its own length. (Happens if the file
        // grew under us between stat and read.)
        if sent.saturating_add(n as u64) > total_size {
            bail!(
                "{} grew during read: declared {total_size}, would send {}",
                path.display(),
                sent + n as u64,
            );
        }
        let chunk = buf[..n].to_vec();
        sent = sent.saturating_add(n as u64);
        send_frame_to_hub(writer, Frame::download_chunk(sid, download_id, chunk))
            .await
            .map_err(|_| anyhow!("writer closed mid-download"))?;
    }

    if sent != total_size {
        // File shrank under us (race). Treat as failure so the browser
        // discards instead of saving a truncated file.
        bail!(
            "{} shrank during read: declared {total_size}, sent {sent}",
            path.display()
        );
    }

    send_frame_to_hub(writer, Frame::download_end(sid, download_id, DOWNLOAD_STATUS_OK))
        .await
        .map_err(|_| anyhow!("writer closed before download end"))?;

    info!(stream_id = sid, download_id, "download committed");
    Ok(())
}

/// Write a `\rterm-dl: <msg>\r\n` line into the PTY so the user sees a
/// visible error after running `term-dl`.
async fn term_dl_error(
    pty_w: &tokio::sync::Mutex<pty_process::OwnedWritePty>,
    msg: &str,
) {
    let line = format!("\rterm-dl: {msg}\r\n");
    let mut w = pty_w.lock().await;
    let _ = w.write_all(line.as_bytes()).await;
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
