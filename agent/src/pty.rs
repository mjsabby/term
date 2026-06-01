//! Cross-platform PTY wrapper that bridges [`portable-pty`]'s blocking
//! `std::io` master handles into the agent's async session manager.
//!
//! ## Why a bridge
//!
//! `portable-pty` exposes the PTY master as `Box<dyn std::io::Read +
//! Send>` and `Box<dyn std::io::Write + Send>` because that's the
//! lowest common denominator across openpty (Unix) and ConPTY
//! (Windows, which is just named pipes). Neither handle is pollable,
//! so we sit a dedicated OS thread next to each one and pump bytes
//! through `tokio::sync::mpsc`. The async [`session::Session`] then
//! talks to those channels instead of an async-PTY.
//!
//! Two threads per active session is fine: a typical agent has a
//! handful of sessions, and the threads spend almost all their time
//! parked in `read`/`recv` syscalls. `Builder::stack_size(64 KiB)`
//! keeps memory tight if many sessions ever pile up.
//!
//! ## Lifecycle
//!
//! Construct via [`AsyncPty::spawn`]. The bridge threads exit when:
//! - reader side: the underlying `Read` returns 0 (shell exited) or
//!   `Err` (handle closed). The async side sees `out_rx.recv() ==
//!   None`.
//! - writer side: the async side drops `in_tx`, the bridge thread's
//!   `blocking_recv()` returns `None`, the thread exits.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use portable_pty::{
    native_pty_system, Child, ChildKiller, CommandBuilder, MasterPty, PtySize,
};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

const READ_BUF_SIZE: usize = 16 * 1024;
const BRIDGE_QUEUE_LEN: usize = 32;
const BRIDGE_STACK_BYTES: usize = 64 * 1024;

pub struct AsyncPty {
    /// Bytes from the PTY (i.e. shell output). `None` once the shell
    /// has exited and the reader thread has cleaned up.
    pub out_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Bytes to write to the PTY (i.e. keyboard input + bracketed-
    /// paste injections). Dropping this end stops the writer thread.
    pub in_tx: mpsc::Sender<Vec<u8>>,
    /// Master handle, used for resize/get_size. Held in a Mutex
    /// because portable-pty's MasterPty is `Send` but not `Sync`,
    /// and we want to call resize from concurrent async tasks.
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    /// Killable handle on the child shell. Same Sync story.
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    /// Polled by [`exited`] so the GC sweeper can drop terminated
    /// sessions without waiting on `Child::wait` (which would
    /// blocking-park a tokio task).
    waitable: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
}

impl AsyncPty {
    /// Spawn `program` (with `args`) in a fresh PTY sized
    /// `(rows, cols)`. Returns once both bridge threads are running.
    pub fn spawn(
        program: &str,
        args: &[String],
        env: &[(&str, &str)],
        rows: u16,
        cols: u16,
    ) -> Result<Self> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .context("openpty")?;

        let mut cmd = CommandBuilder::new(program);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = pair.slave.spawn_command(cmd)
            .with_context(|| format!("spawn {program}"))?;
        // The slave half is owned by the spawned child; drop our copy
        // so EOF propagates to us when the shell exits.
        drop(pair.slave);

        let killer = child.clone_killer();

        let reader = pair.master.try_clone_reader().context("clone reader")?;
        let writer = pair.master.take_writer().context("take writer")?;

        // PTY → async: spawn a dedicated OS thread that pumps blocking
        // reads into an mpsc.
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_QUEUE_LEN);
        std::thread::Builder::new()
            .name("pty-r".into())
            .stack_size(BRIDGE_STACK_BYTES)
            .spawn(move || pty_reader_thread(reader, out_tx))
            .context("spawn pty reader thread")?;

        // async → PTY: same shape, opposite direction.
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_QUEUE_LEN);
        std::thread::Builder::new()
            .name("pty-w".into())
            .stack_size(BRIDGE_STACK_BYTES)
            .spawn(move || pty_writer_thread(writer, in_rx))
            .context("spawn pty writer thread")?;

        Ok(AsyncPty {
            out_rx: Mutex::new(out_rx),
            in_tx,
            master: Arc::new(Mutex::new(pair.master)),
            killer: Arc::new(Mutex::new(killer)),
            waitable: Arc::new(Mutex::new(child)),
        })
    }

    /// Resize the PTY. On Unix this is a `TIOCSWINSZ` ioctl; on
    /// Windows it's `ResizePseudoConsole`. Both are fast (microseconds)
    /// and synchronous, so we wrap in `spawn_blocking` only to be safe
    /// against any future expensive implementation; in practice the
    /// inner call returns immediately.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let master = self.master.clone();
        tokio::task::spawn_blocking(move || {
            let m = master.blocking_lock();
            m.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
                .map_err(|e| anyhow!("pty resize: {e}"))
        })
        .await
        .map_err(|e| anyhow!("spawn_blocking join: {e}"))?
    }

    /// Force the shell process to exit. Returns once the OS confirms
    /// it; the reader bridge will then see EOF and exit cleanly.
    pub async fn kill(&self) {
        let killer = self.killer.clone();
        let waitable = self.waitable.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut k = killer.blocking_lock();
            let _ = k.kill();
            // Drain wait status so the OS reclaims the zombie. Bounded
            // wait so a stuck child doesn't pin the blocking thread
            // forever; if SIGKILL didn't take the process down within
            // ~500ms we have bigger problems than a leaked thread.
            drop(k);
            let mut w = waitable.blocking_lock();
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            loop {
                match w.try_wait() {
                    Ok(Some(_)) => break,
                    _ if std::time::Instant::now() > deadline => {
                        warn!("kill: child did not reap within 500ms");
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        })
        .await;
    }

    /// Non-blocking check: has the shell process terminated?
    #[allow(dead_code)]
    pub async fn exited(&self) -> bool {
        let waitable = self.waitable.clone();
        tokio::task::spawn_blocking(move || {
            let mut w = waitable.blocking_lock();
            matches!(w.try_wait(), Ok(Some(_)))
        })
        .await
        .unwrap_or(false)
    }
}

fn pty_reader_thread(
    mut reader: Box<dyn Read + Send>,
    out_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0)  => break, // EOF: shell exited / handle closed
            Ok(n)  => n,
            Err(e) => {
                debug!(error = %e, "pty reader: read error; exiting");
                break;
            }
        };
        // blocking_send is fine — we're a dedicated OS thread, never on
        // a tokio runtime.
        if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
            // Receiver dropped: session torn down. Stop pumping.
            break;
        }
    }
}

fn pty_writer_thread(
    mut writer: Box<dyn Write + Send>,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(bytes) = in_rx.blocking_recv() {
        if let Err(e) = writer.write_all(&bytes) {
            debug!(error = %e, "pty writer: write error; exiting");
            break;
        }
        // Deliberately no flush — see the existing windows-sync-pipe
        // memory: on Windows, FlushFileBuffers on the server side
        // blocks until the client drains. On Unix it's harmless but
        // unbuffered Vec<u8>::write_all already hits the kernel.
    }
}

/// Split an `agent.toml` `shell` value into `(program, args)`. Handles
/// the common cases:
///   - `"/bin/bash"` → `("/bin/bash", [])`
///   - `"/bin/bash -l"` → `("/bin/bash", ["-l"])`
///   - `"powershell -NoLogo -NoProfile"` → `(..., ["-NoLogo", "-NoProfile"])`
///
/// Splits on ASCII whitespace; does **not** handle quoted args. If you
/// need spaces in arguments, point `shell` at a wrapper script.
pub fn split_shell(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split_whitespace();
    let program = parts.next().unwrap_or("/bin/sh").to_owned();
    let args = parts.map(|s| s.to_owned()).collect();
    (program, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_shell_basic() {
        assert_eq!(split_shell("/bin/bash"), ("/bin/bash".into(), vec![]));
        assert_eq!(
            split_shell("/bin/bash -l"),
            ("/bin/bash".into(), vec!["-l".into()])
        );
        assert_eq!(
            split_shell("powershell -NoLogo -NoProfile"),
            ("powershell".into(), vec!["-NoLogo".into(), "-NoProfile".into()])
        );
        assert_eq!(split_shell("   leading"), ("leading".into(), vec![]));
        assert_eq!(split_shell(""), ("/bin/sh".into(), vec![]));
    }

    #[tokio::test]
    async fn spawn_echo_round_trip() {
        // Round-trip a tiny command through the bridge. Skips on
        // platforms without /bin/sh.
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let pty = AsyncPty::spawn(
            "/bin/sh",
            &["-c".into(), "printf 'hi'; exit 0".into()],
            &[("TERM", "xterm-256color")],
            24, 80,
        ).expect("spawn");

        // Read until EOF. Allow up to 2s for the shell to print and
        // exit; PTY echoing means we may see the command before "hi".
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { break; }
            let mut rx = pty.out_rx.lock().await;
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(b)) => got.extend(b),
                Ok(None)    => break, // EOF
                Err(_)      => break, // timeout
            }
        }
        assert!(got.windows(2).any(|w| w == b"hi"),
                "expected 'hi' in PTY output, got: {:?}", String::from_utf8_lossy(&got));
        assert!(pty.exited().await);
    }
}
