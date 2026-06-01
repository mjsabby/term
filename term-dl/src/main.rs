//! `term-dl <path>...` — emit an application OSC for each file path
//! that asks the term-agent to ship the file's bytes to the browser
//! and trigger a download there. Intended to be run inside the shell
//! that's attached to a term-agent's PTY (so the OSC reaches the
//! agent's PTY-output reader).
//!
//! Wire: `ESC ] 5111 ; dl ; <absolute path> BEL`.
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

    let mut failed: u8 = 0;
    let mut stdout = io::stdout().lock();
    for raw in std::iter::once(first).chain(args) {
        match prepare(&raw) {
            Ok(abs) => {
                // OSC: ESC ] 5111 ; dl ; <abs path> BEL
                let _ = stdout.write_all(b"\x1b]5111;dl;");
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
/// the absolute path goes directly into `ESC ] 5111 ; dl ; <path> BEL`
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
