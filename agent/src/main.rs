//! term-agent
//!
//! TCP server. One connection = one terminal. Each connection's first frame
//! must be a `FrameType::Open` carrying the tmux session id; the agent then
//! spawns `tmux new-session -A -s <id> -- <shell>` attached to a PTY and
//! shuttles bytes both ways. Resize frames adjust the PTY winsize.
//!
//! No authentication: by contract the agent is reachable only from the
//! trusted hub. Default bind is loopback (`127.0.0.1`); operators
//! deliberately bind it to an internal/WireGuard interface.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use term_common::frame::{Frame, FrameError, HEADER_LEN};

#[derive(Debug, Deserialize)]
struct AgentConfig {
    /// Address to bind, e.g. "127.0.0.1:7777". Defaults to 127.0.0.1:7777.
    #[serde(default = "default_bind")]
    bind: String,
    /// Shell program to run inside tmux. Defaults to $SHELL or /bin/sh.
    #[serde(default)]
    shell: Option<String>,
    /// tmux binary. Defaults to "tmux" (resolved via $PATH).
    #[serde(default = "default_tmux")]
    tmux: String,
}
fn default_bind() -> String {
    "127.0.0.1:7777".to_string()
}
fn default_tmux() -> String {
    "tmux".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg_path = std::env::var("TERM_AGENT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/term-agent/agent.toml"));
    let cfg: AgentConfig = match std::fs::read_to_string(&cfg_path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", cfg_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("config {} missing; using defaults", cfg_path.display());
            AgentConfig {
                bind: default_bind(),
                shell: None,
                tmux: default_tmux(),
            }
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", cfg_path.display())),
    };

    let shell = cfg
        .shell
        .clone()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let cfg = Arc::new(ResolvedConfig {
        bind: cfg.bind,
        shell,
        tmux: cfg.tmux,
    });

    let listener = TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("bind {}", cfg.bind))?;
    info!(
        "term-agent listening on {} (tmux={}, shell={})",
        cfg.bind, cfg.tmux, cfg.shell
    );

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(sock, cfg).await {
                warn!(peer = %peer, error = %e, "connection closed with error");
            } else {
                debug!(peer = %peer, "connection closed cleanly");
            }
        });
    }
}

struct ResolvedConfig {
    bind: String,
    shell: String,
    tmux: String,
}

async fn read_frame(sock: &mut TcpStream) -> Result<Option<Frame>, FrameError> {
    let mut hdr = [0u8; HEADER_LEN];
    match sock.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    };
    let ty_byte = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let (ty, len) = Frame::validate_header(ty_byte, len)?;
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        sock.read_exact(&mut payload).await.map_err(FrameError::Io)?;
    }
    Frame::from_payload(ty, payload).map(Some)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, f: &Frame) -> std::io::Result<()> {
    let bytes = f.encode();
    w.write_all(&bytes).await
}

async fn handle_connection(mut sock: TcpStream, cfg: Arc<ResolvedConfig>) -> Result<()> {
    // First frame must be Open(session_id).
    let first = read_frame(&mut sock)
        .await
        .context("reading open frame")?
        .ok_or_else(|| anyhow!("peer closed before open frame"))?;
    let session_id = match first {
        Frame::Open(id) => id,
        other => bail!("expected open frame, got {:?}", FrameKind::from(&other)),
    };
    info!(session = %session_id, "starting tmux session");

    // Allocate a PTY and spawn tmux attached to it.
    let (pty, pts) = pty_process::open().context("pty_process::open")?;
    // Default initial size; client will send a Resize right away.
    pty.resize(pty_process::Size::new(24, 80))
        .context("initial resize")?;

    let mut child = pty_process::Command::new(&cfg.tmux)
        .args(["new-session", "-A", "-s", &session_id, "--", &cfg.shell])
        .spawn(pts)
        .context("spawning tmux")?;

    let (mut pty_r, mut pty_w) = pty.into_split();
    let (mut sock_r, mut sock_w) = sock.split();

    // pty -> sock
    let pty_to_sock = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = pty_r.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            let frame = Frame::Data(buf[..n].to_vec());
            write_frame(&mut sock_w, &frame).await?;
        }
    };

    // sock -> pty
    let sock_to_pty = async {
        loop {
            let mut hdr = [0u8; HEADER_LEN];
            match sock_r.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok::<(), anyhow::Error>(())
                }
                Err(e) => return Err(e.into()),
            }
            let ty_byte = hdr[0];
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
            let (ty, len) = Frame::validate_header(ty_byte, len)?;
            let mut payload = vec![0u8; len as usize];
            if len > 0 {
                sock_r.read_exact(&mut payload).await?;
            }
            let frame = Frame::from_payload(ty, payload)?;
            match frame {
                Frame::Data(buf) => {
                    pty_w.write_all(&buf).await?;
                }
                Frame::Resize { rows, cols } => {
                    if let Err(e) = pty_w.resize(pty_process::Size::new(rows, cols)) {
                        warn!(error = %e, "pty resize failed");
                    }
                }
                Frame::Open(_) => {
                    // Open after the first frame is a protocol violation.
                    bail!("open frame after initial handshake");
                }
            }
        }
    };

    tokio::select! {
        r = pty_to_sock => {
            if let Err(e) = r { debug!(error=%e, "pty->sock ended"); }
        }
        r = sock_to_pty => {
            if let Err(e) = r { debug!(error=%e, "sock->pty ended"); }
        }
    };

    // Best-effort: kill the tmux client process so the tmux session itself
    // outlives this connection but our `tmux attach` returns. (Our tmux
    // process is the client, not the tmux server — the server detaches and
    // keeps the session around for future re-attach.)
    let _ = child.start_kill();
    let _ = child.wait().await;
    Ok(())
}

#[derive(Debug)]
enum FrameKind {
    Data,
    Resize,
    Open,
}
impl From<&Frame> for FrameKind {
    fn from(f: &Frame) -> Self {
        match f {
            Frame::Data(_) => FrameKind::Data,
            Frame::Resize { .. } => FrameKind::Resize,
            Frame::Open(_) => FrameKind::Open,
        }
    }
}
