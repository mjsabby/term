//! term-agent (push mode)
//!
//! Dials the hub on `hub` (host:port), authenticates with PSK in a
//! `Hello` frame, then runs the multiplex demuxer. Each `Open` frame on
//! a new stream spawns a tmux+PTY task whose stdout flows back as
//! `Data` frames on the same stream. Reconnects with exponential
//! backoff on any failure.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use term_common::frame::{
    Body, Frame, FrameError, HelloPayload, HEADER_LEN, HELLO_VERSION,
};

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

const WRITE_CHAN_CAP:    usize    = 256;
const STREAM_CHAN_CAP:   usize    = 64;
const PING_INTERVAL:     Duration = Duration::from_secs(30);
const IDLE_DEADLINE:     Duration = Duration::from_secs(90);
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX:     Duration = Duration::from_secs(60);

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
        match run_once(resolved.clone(), tls_connector.clone()).await {
            Ok(()) => {
                info!("hub closed connection cleanly; reconnecting");
                backoff = RECONNECT_INITIAL;
            }
            Err(e) => {
                warn!(error = %e, "connection failed; backoff {:?}", backoff);
                sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
                continue;
            }
        }
        sleep(Duration::from_millis(250)).await;
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
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHAN_CAP);
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
    write_tx.send(Frame::hello(hello_bytes).encode())
        .await
        .map_err(|_| anyhow!("writer closed before hello"))?;

    // Per-stream registry.
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Body>>>> = Arc::new(Mutex::new(HashMap::new()));

    // Pinger.
    let ping_writer = write_tx.clone();
    let pinger = tokio::spawn(async move {
        let mut tick = tokio::time::interval(PING_INTERVAL);
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if ping_writer.send(Frame::ping(vec![]).encode()).await.is_err() { return; }
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
                (0, Body::Ping(p))  => { let _ = write_tx.send(Frame::pong(p).encode()).await; }
                (0, Body::Pong(_))  => {}
                (0, Body::Hello(_)) => bail!("hub sent hello (protocol error)"),
                (0, _)              => bail!("unexpected control-stream frame"),
                (sid, Body::Open(session_id)) => {
                    // Spawn a per-session task.
                    let (s_tx, s_rx) = mpsc::channel::<Body>(STREAM_CHAN_CAP);
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
                        let _ = writer.send(Frame::close(sid).encode()).await;
                        streams.lock().await.remove(&sid);
                    });
                }
                (sid, body @ (Body::Data(_) | Body::Resize { .. })) => {
                    let tx = { streams.lock().await.get(&sid).cloned() };
                    if let Some(tx) = tx { let _ = tx.send(body).await; }
                    else { debug!(sid, "frame for unknown stream; ignoring"); }
                }
                (sid, Body::Close) => {
                    let _ = streams.lock().await.remove(&sid); // drops sender -> session sees recv None
                }
                _ => debug!("ignored frame"),
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

/// Spawn tmux+PTY and pump data both ways for one stream.
async fn run_session_stream(
    cfg: Arc<ResolvedConfig>,
    sid: u32,
    session_id: String,
    mut rx: mpsc::Receiver<Body>,
    writer: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let (pty, pts) = pty_process::open().context("pty_process::open")?;
    pty.resize(pty_process::Size::new(24, 80)).context("initial resize")?;
    let mut child = pty_process::Command::new(&cfg.tmux)
        .args(["new-session", "-A", "-s", &session_id, "--", &cfg.shell])
        .spawn(pts)
        .context("spawn tmux")?;

    let (mut pty_r, mut pty_w) = pty.into_split();
    info!(stream_id = sid, session = %session_id, "tmux session started");

    let pty_to_writer = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = pty_r.read(&mut buf).await?;
            if n == 0 { return Ok::<(), anyhow::Error>(()); }
            let f = Frame::data(sid, buf[..n].to_vec());
            if writer.send(f.encode()).await.is_err() {
                return Err(anyhow!("writer closed"));
            }
        }
    };
    let rx_to_pty = async {
        while let Some(body) = rx.recv().await {
            match body {
                Body::Data(b) => {
                    pty_w.write_all(&b).await?;
                }
                Body::Resize { rows, cols } => {
                    if let Err(e) = pty_w.resize(pty_process::Size::new(rows, cols)) {
                        warn!(error = %e, "pty resize failed");
                    }
                }
                Body::Close => return Ok::<(), anyhow::Error>(()),
                _ => debug!("ignored body on session stream"),
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        _ = pty_to_writer => {}
        _ = rx_to_pty => {}
    };

    let _ = child.start_kill();
    let _ = child.wait().await;
    Ok(())
}
