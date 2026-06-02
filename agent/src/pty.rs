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
//!
//! ## ConPTY DSR-cursor-query interception (Windows only)
//!
//! `portable-pty` 0.9 hard-codes the `PSUEDOCONSOLE_INHERIT_CURSOR`
//! flag when creating the pseudoconsole. With that flag set, ConPTY
//! emits `\x1b[6n` (DSR cursor position request) on init and **waits
//! for a reply** before forwarding any shell output. Without a reply
//! the shell appears completely silent — no banner, no prompt, no
//! echo. To unblock it we run an inline CSI scanner on the reader-side
//! bridge that intercepts every `\x1b[6n` and writes a synthetic
//! `\x1b[1;1R` back through the input bridge. We strip the original
//! query from the bytes forwarded to the browser; xterm.js gets the
//! actual cursor it manages locally anyway.

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
        // Defensive clamp: ConPTY rejects zero-sized consoles, and
        // openpty(3) on Unix silently accepts them but the resulting
        // PTY is unusable. Browsers usually don't send 0×0 but hidden
        // tabs / first-attach races can.
        let rows = rows.max(1);
        let cols = cols.max(1);
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

        // async → PTY: same shape, opposite direction. We allocate this
        // BEFORE the reader thread on Windows because the reader needs
        // a clone of `in_tx` to write synthetic DSR replies (see module
        // doc — ConPTY `\x1b[6n` handshake).
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_QUEUE_LEN);

        #[cfg(windows)]
        let dsr_reply_tx = in_tx.clone();
        std::thread::Builder::new()
            .name("pty-r".into())
            .stack_size(BRIDGE_STACK_BYTES)
            .spawn(move || {
                pty_reader_thread(
                    reader,
                    out_tx,
                    #[cfg(windows)] dsr_reply_tx,
                )
            })
            .context("spawn pty reader thread")?;

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
        // Clamp for the same reason as in `spawn` — ConPTY refuses
        // zero-sized resizes.
        let rows = rows.max(1);
        let cols = cols.max(1);
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

/// Tiny CSI scanner that intercepts `\x1b[6n` (DSR cursor position
/// request) and replaces it with a synthetic `\x1b[1;1R` reply written
/// back into the PTY's input. Everything else passes through verbatim.
///
/// Used only on Windows because `portable-pty` enables ConPTY's
/// `PSUEDOCONSOLE_INHERIT_CURSOR` flag, which makes ConPTY emit a DSR
/// query on init and BLOCK shell output until it gets a reply. On
/// Unix there's nothing to intercept — apps issue DSRs but the
/// browser-side xterm.js handles them just fine.
///
/// We deliberately reply to ALL `\x1b[6n` queries, not just the first.
/// Apps that use DSR for cursor read-back (very rare on Windows) will
/// get our `\x1b[1;1R` instead of an accurate position; for the
/// minimum-viable Windows port that's an acceptable trade-off versus
/// the alternative of round-tripping through the browser.
#[cfg(windows)]
struct DsrScanner {
    state: DsrState,
    /// Bytes accumulated between `\x1b[` and the CSI final byte
    /// (0x40..=0x7e). Capped at MAX_CSI_LEN to bound memory.
    args: Vec<u8>,
}

#[cfg(windows)]
enum DsrState {
    Normal,
    Esc,
    Csi,
}

/// Cap on a single CSI parameter+intermediate run. Real CSIs are
/// dozens of bytes at most; anything longer is malformed and we
/// flush + reset.
#[cfg(windows)]
const MAX_CSI_LEN: usize = 64;

#[cfg(windows)]
impl DsrScanner {
    fn new() -> Self {
        Self { state: DsrState::Normal, args: Vec::new() }
    }

    /// Feed a chunk of PTY output. Returns
    /// `(forwarded, dsr_replies)`:
    /// - `forwarded` is the byte run to emit to the async out channel
    ///   (with intercepted `\x1b[6n` queries removed).
    /// - `dsr_replies` is the list of synthetic `\x1b[1;1R` byte
    ///   strings to inject back into the PTY's input, one per
    ///   intercepted query.
    fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        const ESC: u8 = 0x1b;
        let mut out = Vec::with_capacity(input.len());
        let mut replies = Vec::new();
        for &b in input {
            match self.state {
                DsrState::Normal => {
                    if b == ESC {
                        self.state = DsrState::Esc;
                    } else {
                        out.push(b);
                    }
                }
                DsrState::Esc => {
                    if b == b'[' {
                        self.state = DsrState::Csi;
                        self.args.clear();
                    } else {
                        // Not a CSI — emit ESC + byte and resync.
                        out.push(ESC);
                        out.push(b);
                        self.state = DsrState::Normal;
                    }
                }
                DsrState::Csi => {
                    // CSI ends on a "final byte" in 0x40..=0x7e.
                    if (0x40..=0x7e).contains(&b) {
                        let is_dsr_cpr = self.args == b"6" && b == b'n';
                        if is_dsr_cpr {
                            // Intercept: synthesize a cursor-at-(1,1)
                            // reply. Strip the original query from
                            // forwarded output.
                            replies.push(b"\x1b[1;1R".to_vec());
                        } else {
                            // Forward the CSI verbatim.
                            out.push(ESC);
                            out.push(b'[');
                            out.extend_from_slice(&self.args);
                            out.push(b);
                        }
                        self.args.clear();
                        self.state = DsrState::Normal;
                    } else if self.args.len() >= MAX_CSI_LEN {
                        // Overrun a sensible CSI length — bail out by
                        // forwarding the accumulated bytes and resync.
                        // Better to leak a malformed escape to the
                        // browser than to swallow real terminal data.
                        out.push(ESC);
                        out.push(b'[');
                        out.extend_from_slice(&self.args);
                        out.push(b);
                        self.args.clear();
                        self.state = DsrState::Normal;
                    } else {
                        self.args.push(b);
                    }
                }
            }
        }
        (out, replies)
    }
}

fn pty_reader_thread(
    mut reader: Box<dyn Read + Send>,
    out_tx: mpsc::Sender<Vec<u8>>,
    #[cfg(windows)] dsr_reply_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    #[cfg(windows)]
    let mut dsr = DsrScanner::new();
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0)  => break, // EOF: shell exited / handle closed
            Ok(n)  => n,
            Err(e) => {
                debug!(error = %e, "pty reader: read error; exiting");
                break;
            }
        };
        // On Windows, intercept ConPTY's `\x1b[6n` DSR cursor query
        // and reply locally so the shell doesn't deadlock waiting for
        // a response that would otherwise have to round-trip through
        // the browser. On Unix the chunk passes through unchanged.
        #[cfg(windows)]
        let chunk = {
            let (fwd, replies) = dsr.feed(&buf[..n]);
            for r in replies {
                if dsr_reply_tx.blocking_send(r).is_err() {
                    debug!("pty reader: writer closed; cannot send DSR reply");
                    break;
                }
            }
            fwd
        };
        #[cfg(not(windows))]
        let chunk = buf[..n].to_vec();

        if chunk.is_empty() {
            // Whole read was a DSR query — nothing left to forward.
            continue;
        }
        // blocking_send is fine — we're a dedicated OS thread, never on
        // a tokio runtime.
        if out_tx.blocking_send(chunk).is_err() {
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
///
/// Empty input falls back to a platform default: `/bin/sh` on Unix,
/// `cmd.exe` on Windows. In normal operation this fallback is dead
/// code — `main` resolves the empty case before calling us — but the
/// per-platform sensible default keeps tests and direct callers
/// portable.
pub fn split_shell(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split_whitespace();
    let program = parts.next()
        .map(|s| s.to_owned())
        .unwrap_or_else(default_shell_for_split);
    let args = parts.map(|s| s.to_owned()).collect();
    (program, args)
}

#[cfg(unix)]
fn default_shell_for_split() -> String { "/bin/sh".into() }
#[cfg(windows)]
fn default_shell_for_split() -> String {
    std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn run_dsr(input: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut s = DsrScanner::new();
        s.feed(input)
    }

    #[cfg(windows)]
    #[test]
    fn dsr_passthrough_plain_bytes() {
        let (fwd, replies) = run_dsr(b"hello world\n");
        assert_eq!(fwd, b"hello world\n");
        assert!(replies.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn dsr_intercepts_cursor_position_request() {
        let (fwd, replies) = run_dsr(b"before\x1b[6nafter");
        assert_eq!(fwd, b"beforeafter");
        assert_eq!(replies, vec![b"\x1b[1;1R".to_vec()]);
    }

    #[cfg(windows)]
    #[test]
    fn dsr_does_not_intercept_status_request() {
        // \x1b[5n is DSR status report — not what ConPTY queries; we
        // must forward it so xterm.js can reply normally.
        let input = b"x\x1b[5ny";
        let (fwd, replies) = run_dsr(input);
        assert_eq!(fwd, input);
        assert!(replies.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn dsr_does_not_intercept_dec_private() {
        // \x1b[?6n is a DEC-private DSR — different semantics, forward.
        let input = b"\x1b[?6n";
        let (fwd, replies) = run_dsr(input);
        assert_eq!(fwd, input);
        assert!(replies.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn dsr_passes_through_color_csi() {
        let input = b"\x1b[31mred\x1b[0m";
        let (fwd, replies) = run_dsr(input);
        assert_eq!(fwd, input);
        assert!(replies.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn dsr_handles_split_across_feeds() {
        let mut s = DsrScanner::new();
        let full = b"pre\x1b[6npost";
        let mut fwd_total = Vec::new();
        let mut replies_total: Vec<Vec<u8>> = Vec::new();
        for chunk in full.chunks(1) {
            let (f, r) = s.feed(chunk);
            fwd_total.extend(f);
            replies_total.extend(r);
        }
        assert_eq!(fwd_total, b"prepost");
        assert_eq!(replies_total, vec![b"\x1b[1;1R".to_vec()]);
    }

    #[cfg(windows)]
    #[test]
    fn dsr_intercepts_multiple_queries() {
        let (fwd, replies) = run_dsr(b"a\x1b[6nb\x1b[6nc");
        assert_eq!(fwd, b"abc");
        assert_eq!(replies, vec![
            b"\x1b[1;1R".to_vec(),
            b"\x1b[1;1R".to_vec(),
        ]);
    }

    #[cfg(windows)]
    #[test]
    fn dsr_stray_esc_passes_through() {
        // ESC c (full reset) isn't a CSI — emit verbatim.
        let input = b"a\x1bcb";
        let (fwd, replies) = run_dsr(input);
        assert_eq!(fwd, input);
        assert!(replies.is_empty());
    }

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
        // Empty input falls back to a platform default. We check the
        // tuple shape (no args) and that the program is non-empty,
        // rather than hard-coding `/bin/sh` (which would break on
        // Windows where the fallback is `cmd.exe`).
        let (prog, args) = split_shell("");
        assert!(!prog.is_empty(), "fallback program must be non-empty");
        assert!(args.is_empty());
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

    /// Windows ConPTY round-trip. Spawn cmd.exe interactively, write a
    /// command, look for the literal output. We use an interactive
    /// shell rather than `cmd /c echo hi` because ConPTY rasterizes
    /// the screen and short-lived children may exit before the writer
    /// drains anything useful (per the existing spike notes that
    /// "short-lived children's stdout is NOT passed through").
    ///
    /// Catches the PSUEDOCONSOLE_INHERIT_CURSOR DSR-cursor-query stall
    /// (if portable-pty hands us a shell whose first output is just
    /// `\x1b[6n` and then nothing, this test times out).
    #[cfg(windows)]
    #[tokio::test]
    async fn spawn_cmd_round_trip_windows() {
        let comspec = std::env::var("ComSpec")
            .unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into());
        if !std::path::Path::new(&comspec).exists() {
            return;
        }
        // /Q disables echo of typed input so we look only at the
        // explicit `echo` output, avoiding double-counting needle bytes
        // from local echo of `echo TERMHITEST\r\n`.
        let pty = AsyncPty::spawn(
            &comspec,
            &["/Q".into(), "/K".into(), "prompt $G".into()],
            &[],
            24, 80,
        ).expect("spawn cmd.exe");

        // Write `echo TERMHITEST\r\n` then read until we either see
        // the needle in the rasterized output or hit the deadline.
        const NEEDLE: &[u8] = b"TERMHITEST";
        pty.in_tx.send(b"echo TERMHITEST\r\n".to_vec())
            .await
            .expect("send echo command");

        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { break; }
            let mut rx = pty.out_rx.lock().await;
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(b)) => {
                    got.extend(b);
                    if got.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
                        found = true;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_)   => break,
            }
        }
        // Kill the child + drain so test teardown is clean.
        pty.kill().await;

        assert!(found,
            "expected `TERMHITEST` in ConPTY output within 5s, \
             got {} bytes: {:?}",
            got.len(), String::from_utf8_lossy(&got));
    }
}
