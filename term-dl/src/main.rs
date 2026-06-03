//! `term-dl <path>...` — emit an application OSC for each file path
//! that asks the term-agent to ship the file's bytes to the browser
//! and trigger a download there. Intended to be run inside the shell
//! that's attached to a term-agent's PTY (so the OSC reaches the
//! agent's PTY-output reader).
//!
//! Wire: `ESC ] 5111 ; dl ; <token> ; <absolute path> BEL`.
//!
//! The agent sets `TERM_DL_TOKEN` in the shell's environment at
//! session spawn. We echo it back so the agent can distinguish
//! legitimate `term-dl` invocations from a hostile process printing
//! the same OSC bytes into the PTY output (e.g. `cat /etc/motd` on
//! an untrusted host). Without the right token, the agent silently
//! drops the OSC.
//!
//! Designed to be tiny, no deps. Errors go to stderr; stdout carries
//! only the OSC sequences.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
term-dl <path>...

Ship one or more files from the agent host to the browser, triggering
a download save. Files are read on the agent side and streamed over
the existing terminal mux; paths must be readable by the agent's user.

Each invocation can name multiple paths; each becomes its own
download. Exit status is the count of paths that failed local
validation (the OSC was still emitted for the ones that passed).

env:
  TERM_DL_TOKEN   set by the agent in the shell's environment. If
                  unset, this binary exits non-zero without emitting
                  any OSC: you're probably not running inside a
                  term-agent PTY.
";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let first = match args.next() {
        Some(a) => a,
        None => {
            eprint!("{USAGE}");
            return ExitCode::from(64); // EX_USAGE
        }
    };
    if matches!(first.as_str(), "-h" | "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let token = match env::var("TERM_DL_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!(
                "term-dl: TERM_DL_TOKEN not set in the environment. \
                 This binary only works inside a term-agent session shell. \
                 If you're seeing this message in such a shell, the agent \
                 may be too old (pre-Phase-4.5)."
            );
            return ExitCode::from(69); // EX_UNAVAILABLE
        }
    };

    // Token must only contain ASCII alphanumeric + base64url chars (the
    // agent generates it from URL_SAFE_NO_PAD); refuse to emit if a
    // user has tampered with their own env, since otherwise we'd
    // potentially write something that breaks OSC framing.
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        eprintln!("term-dl: TERM_DL_TOKEN contains unexpected characters; refusing");
        return ExitCode::from(78); // EX_CONFIG
    }

    let mut failed: u8 = 0;
    let mut stdout = io::stdout().lock();
    for raw in std::iter::once(first).chain(args) {
        match prepare(&raw) {
            Ok(abs) => {
                // OSC: ESC ] 5111 ; dl ; <token> ; <abs path> BEL
                let _ = stdout.write_all(b"\x1b]5111;dl;");
                let _ = stdout.write_all(token.as_bytes());
                let _ = stdout.write_all(b";");
                let _ = stdout.write_all(abs.as_os_str().as_encoded_bytes());
                let _ = stdout.write_all(b"\x07");
                let _ = stdout.flush();
            }
            Err(e) => {
                eprintln!("term-dl: {raw}: {e}");
                failed = failed.saturating_add(1);
            }
        }
    }
    ExitCode::from(failed)
}

/// Validate `path` is a readable regular file from this process's
/// perspective, and return an absolute, canonicalized path. The agent
/// re-opens it in its own mount namespace, so we don't strictly need
/// the file to be readable here — but failing fast in the user's shell
/// gives a much better error message than waiting for the agent to
/// silently drop the OSC.
///
/// Rejects paths containing bytes that would break the OSC framing —
/// the absolute path goes directly into `ESC ] 5111 ; dl ; <token> ; <path> BEL`
/// and an embedded BEL (`0x07`) would terminate the OSC early; an
/// embedded ESC (`0x1b`) ditto. Real filenames almost never contain
/// these so this only ever fires on adversarially-named files.
fn prepare(raw: &str) -> Result<PathBuf, String> {
    let p = Path::new(raw);
    let meta = fs::metadata(p).map_err(|e| format!("{e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let abs = fs::canonicalize(p).map_err(|e| format!("canonicalize: {e}"))?;
    let bytes = abs.as_os_str().as_encoded_bytes();
    if bytes.iter().any(|&b| b == 0x07 || b == 0x1b) {
        return Err("path contains BEL or ESC byte; refusing to emit OSC".into());
    }
    Ok(abs)
}
