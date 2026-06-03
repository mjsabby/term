//! hub-admin
//!
//! Out-of-band passkey registration CLI. The operator pastes the base64
//! blob produced by the registration page on the hub host:
//!
//!     hub-admin add-passkey '<blob>'
//!     hub-admin add-passkey -      # read blob from stdin
//!
//! Other subcommands:
//!
//!     hub-admin list
//!     hub-admin remove <label-or-credential-id>
//!     hub-admin secret-info
//!
//! Configuration: reads `TERM_HUB_CONFIG` (default `/etc/term-hub/hub.toml`)
//! for `data_dir`, or `TERM_HUB_DATA_DIR` directly (overrides).

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

use term_common::creds::{self, CredentialStore, StoredCredential};
use term_common::envelope::{self, PasteBlob};
use term_common::flock::FileLock;
use term_common::webauthn;

const DEFAULT_HUB_CONFIG: &str = "/etc/term-hub/hub.toml";
const DEFAULT_DATA_DIR: &str = "/var/lib/term-hub";

#[derive(Debug, Deserialize)]
struct HubConfigSlice {
    data_dir: Option<String>,
}

fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("TERM_HUB_DATA_DIR") {
        return PathBuf::from(d);
    }
    let cfg_path = std::env::var("TERM_HUB_CONFIG").unwrap_or_else(|_| DEFAULT_HUB_CONFIG.into());
    match std::fs::read_to_string(&cfg_path) {
        Ok(s) => match toml::from_str::<HubConfigSlice>(&s) {
            Ok(c) => c
                .data_dir
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR)),
            Err(_) => PathBuf::from(DEFAULT_DATA_DIR),
        },
        Err(_) => PathBuf::from(DEFAULT_DATA_DIR),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hub-admin: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        bail!("missing subcommand");
    }
    match args[0].as_str() {
        "add-passkey" => cmd_add(&args[1..]),
        "list" => cmd_list(),
        "remove" => cmd_remove(&args[1..]),
        "secret-info" => cmd_secret_info(),
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            bail!("unknown subcommand: {other}");
        }
    }
}

fn usage() {
    eprintln!(
        "usage:
  hub-admin add-passkey <BLOB | ->        register a new credential
  hub-admin list                          list registered credentials
  hub-admin remove <LABEL_OR_CRED_ID>     remove a credential
  hub-admin secret-info                   show HMAC secret fingerprint
  hub-admin help

env:
  TERM_HUB_CONFIG   path to hub.toml (default {DEFAULT_HUB_CONFIG})
  TERM_HUB_DATA_DIR overrides data_dir from config",
    );
}

fn cmd_add(args: &[String]) -> Result<()> {
    let blob_arg = args.first().ok_or_else(|| anyhow!("missing blob"))?;
    let blob_text = if blob_arg == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s).context("read stdin")?;
        s
    } else {
        blob_arg.clone()
    };

    let dir = data_dir();
    let secret = creds::load_or_create_secret(&dir).context("load secret")?;

    let paste: PasteBlob = envelope::decode_paste_blob(blob_text.trim())
        .context("decode paste blob (not valid base64+json)")?;

    let response = paste.response;
    let label_in = paste.label;
    let inner = paste
        .envelope
        .verify(&secret)
        .context("envelope verification failed")?;

    let challenge = inner.challenge().context("envelope challenge")?;

    let registered = webauthn::finish_register(&response, &challenge, &inner.rp_id, &inner.origin)
        .context("finish_register")?;

    let cred_id_b64 =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(&registered.credential_id);
    let pubkey_b64 =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(registered.credential_public_key);
    let label = label_in
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("cred-{}", &cred_id_b64[..cred_id_b64.len().min(8)]));

    // Mutate the store under the advisory lock.
    creds::ensure_lock_file(&dir).context("ensure lock")?;
    let _guard = FileLock::acquire_exclusive(&creds::lock_path(&dir)).context("flock")?;
    let mut store = CredentialStore::load(&dir).context("load credentials.json")?;
    if store
        .credentials
        .iter()
        .any(|c| c.credential_id_b64 == cred_id_b64)
    {
        bail!("credential already registered (id={cred_id_b64})");
    }
    let added_at = iso8601_now();
    store.credentials.push(StoredCredential {
        label: label.clone(),
        added_at,
        credential_id_b64: cred_id_b64.clone(),
        credential_public_key_b64: pubkey_b64,
        sign_count: registered.sign_count,
    });
    store.save_atomic(&dir).context("save credentials.json")?;

    println!("ok: added credential label={label} id={cred_id_b64}");
    Ok(())
}

fn cmd_list() -> Result<()> {
    let dir = data_dir();
    let store = CredentialStore::load(&dir)?;
    if store.credentials.is_empty() {
        println!("(no credentials registered)");
        return Ok(());
    }
    for c in &store.credentials {
        println!("{}\t{}\t{}", c.label, c.added_at, c.credential_id_b64);
    }
    Ok(())
}

fn cmd_remove(args: &[String]) -> Result<()> {
    let target = args.first().ok_or_else(|| anyhow!("missing target"))?;
    let dir = data_dir();
    creds::ensure_lock_file(&dir)?;
    let _guard = FileLock::acquire_exclusive(&creds::lock_path(&dir)).context("flock")?;
    let mut store = CredentialStore::load(&dir)?;
    let before = store.credentials.len();
    store.credentials.retain(|c| {
        let id = &c.credential_id_b64;
        !(c.label == *target || id == target || id.starts_with(target))
    });
    let removed = before - store.credentials.len();
    if removed == 0 {
        bail!("no credential matched {target}");
    }
    store.save_atomic(&dir)?;
    println!("ok: removed {removed} credential(s)");
    Ok(())
}

fn cmd_secret_info() -> Result<()> {
    use sha2::{Digest, Sha256};
    let dir = data_dir();
    let secret = creds::load_or_create_secret(&dir)?;
    let h = Sha256::digest(secret);
    let fp = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &h[..8]);
    println!("data_dir: {}", dir.display());
    println!("secret_fingerprint: {fp}");
    Ok(())
}

fn iso8601_now() -> String {
    // No chrono; emit a minimal UTC ISO-8601 (seconds precision).
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    fmt_utc(secs)
}

fn fmt_utc(mut t: i64) -> String {
    // Algorithm from Howard Hinnant's date library (civil_from_days).
    let days = t.div_euclid(86_400);
    let sod = t.rem_euclid(86_400);
    let h = sod / 3600;
    let m = (sod / 60) % 60;
    let s = sod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    // Silence unused warning if branch never fires in practice.
    let _ = &mut t;
    format!(
        "{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z",
        month = month,
        d = d,
        h = h,
        m = m,
        s = s
    )
}
