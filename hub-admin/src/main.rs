//! hub-admin
//!
//! Out-of-band passkey registration CLI:
//!
//!     hub-admin add-passkey '<blob>'
//!     hub-admin add-passkey -      # read blob from stdin
//!
//! Agent mTLS provisioning (Phase 4.6):
//!
//!     hub-admin init-ca                          # one-shot, creates the agent CA
//!     hub-admin issue-cert --id alpha            # mint a per-machine cert
//!     hub-admin list-certs
//!     hub-admin revoke-cert --serial <hex>
//!     hub-admin revoke-cert --id <machine_id>
//!     hub-admin show-ca                          # print agent-ca.crt to stdout
//!
//! Misc:
//!
//!     hub-admin list                # list registered passkeys
//!     hub-admin remove <label|id>   # remove a passkey
//!     hub-admin secret-info         # show HMAC secret fingerprint
//!
//! Configuration: reads `TERM_HUB_CONFIG` (default `/etc/term-hub/hub.toml`)
//! for `data_dir`, or `TERM_HUB_DATA_DIR` directly (overrides).

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::Deserialize;

use term_common::agent_pki::ca::{self, DEFAULT_CA_DAYS, DEFAULT_LEAF_DAYS, agent_ca_cert_path};
use term_common::creds::{self, CredentialStore, StoredCredential};
use term_common::envelope::{self, PasteBlob};
use term_common::flock::FileLock;
use term_common::issued_certs::{IssuedCertEntry, IssuedCertStore, issued_certs_lock_path};
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
        "init-ca" => cmd_init_ca(&args[1..]),
        "issue-cert" => cmd_issue_cert(&args[1..]),
        "list-certs" => cmd_list_certs(),
        "revoke-cert" => cmd_revoke_cert(&args[1..]),
        "show-ca" => cmd_show_ca(),
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
  hub-admin add-passkey <BLOB | ->        register a new passkey
  hub-admin list                          list registered passkeys
  hub-admin remove <LABEL_OR_CRED_ID>     remove a passkey
  hub-admin secret-info                   show HMAC secret fingerprint

  hub-admin init-ca [--days N]            create the agent CA (one-shot)
  hub-admin issue-cert --id ID [--label L] [--days N] [--out-dir DIR]
                                          mint a per-machine cert
  hub-admin list-certs                    list issued certs
  hub-admin revoke-cert (--serial HEX | --id MACHINE_ID)
                                          revoke matching certs
  hub-admin show-ca                       print agent-ca.crt to stdout

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
    // Prefer an exact match (full label or full credential id). Only fall
    // back to id-prefix matching when nothing matches exactly, and then
    // only when the prefix is unambiguous — otherwise a short prefix like
    // `a` could silently delete several credentials at once.
    let exact = store
        .credentials
        .iter()
        .filter(|c| c.label == *target || c.credential_id_b64 == *target)
        .count();
    if exact > 0 {
        store
            .credentials
            .retain(|c| !(c.label == *target || c.credential_id_b64 == *target));
    } else {
        let prefix_n = store
            .credentials
            .iter()
            .filter(|c| c.credential_id_b64.starts_with(target))
            .count();
        if prefix_n > 1 {
            bail!(
                "{target:?} is an ambiguous id prefix matching {prefix_n} credentials; \
                 pass a full credential id or an exact label"
            );
        }
        store
            .credentials
            .retain(|c| !c.credential_id_b64.starts_with(target));
    }
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

fn cmd_init_ca(args: &[String]) -> Result<()> {
    let mut days = DEFAULT_CA_DAYS;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--days" => {
                days = next_arg(args, &mut i, "--days")?
                    .parse()
                    .context("--days")?;
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }
    let dir = data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create data_dir {}", dir.display()))?;
    let ca = ca::init_ca(&dir, days).context("init CA")?;
    println!(
        "ok: created agent CA at {} ({} days, ECDSA-P256, {} bytes DER)",
        agent_ca_cert_path(&dir).display(),
        days,
        ca.cert_der.as_ref().len(),
    );
    println!("  cert: {}", agent_ca_cert_path(&dir).display());
    println!(
        "  key:  {} (KEEP PRIVATE — only hub-admin needs read access)",
        ca::agent_ca_key_path(&dir).display(),
    );
    Ok(())
}

fn cmd_issue_cert(args: &[String]) -> Result<()> {
    let mut id: Option<String> = None;
    let mut label: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut days = DEFAULT_LEAF_DAYS;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => id = Some(next_arg(args, &mut i, "--id")?.into()),
            "--label" => label = Some(next_arg(args, &mut i, "--label")?.into()),
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut i, "--out-dir")?)),
            "--days" => {
                days = next_arg(args, &mut i, "--days")?
                    .parse()
                    .context("--days")?
            }
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }
    let id = id.ok_or_else(|| anyhow!("--id is required"))?;
    let dir = data_dir();
    let out_dir = out_dir.unwrap_or_else(|| std::env::current_dir().unwrap_or(PathBuf::from(".")));

    let signer = ca::load_ca_signer(&dir).context("load CA (run `hub-admin init-ca` first?)")?;
    let issued = ca::issue_machine_cert(&signer, &id, days).context("issue cert")?;

    let cert_path = out_dir.join(format!("{id}.crt"));
    let key_path = out_dir.join(format!("{id}.key"));
    if cert_path.exists() {
        bail!(
            "{} already exists; refusing to overwrite",
            cert_path.display()
        );
    }
    if key_path.exists() {
        bail!(
            "{} already exists; refusing to overwrite",
            key_path.display()
        );
    }
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create out-dir {}", out_dir.display()))?;
    write_with_mode(&cert_path, issued.cert_pem.as_bytes(), 0o644)?;
    write_with_mode(&key_path, issued.key_pem.as_bytes(), 0o600)?;

    // Track the issuance in issued-certs.json so the hub will allow
    // this fingerprint at TLS-handshake time.
    IssuedCertStore::ensure_lock_file(&dir).context("ensure issued-certs lock")?;
    let _guard =
        FileLock::acquire_exclusive(&issued_certs_lock_path(&dir)).context("flock issued-certs")?;
    let mut store = IssuedCertStore::load(&dir).context("load issued-certs.json")?;
    if store
        .certs
        .iter()
        .any(|c| c.fingerprint == issued.fingerprint)
    {
        bail!(
            "fingerprint {} already present in issued-certs.json",
            issued.fingerprint
        );
    }
    store.certs.push(IssuedCertEntry {
        machine_id: id.clone(),
        fingerprint: issued.fingerprint.clone(),
        serial_hex: issued.serial_hex.clone(),
        issued_at: iso8601_now(),
        not_after_unix: issued.not_after_unix,
        label,
    });
    store.save_atomic(&dir).context("save issued-certs.json")?;

    println!("ok: issued cert for machine_id={id}");
    println!("  cert:        {}", cert_path.display());
    println!(
        "  key:         {} (0600 — copy to the agent host)",
        key_path.display()
    );
    println!("  fingerprint: {}", issued.fingerprint);
    println!("  serial:      {}", issued.serial_hex);
    println!(
        "  not_after:   unix {} ({} days)",
        issued.not_after_unix, days
    );
    println!();
    println!("agent.toml snippet:");
    println!();
    println!("  hub        = \"<hub-host>:7700\"");
    println!("  cert_path  = \"/etc/term-agent/agent.crt\"");
    println!("  key_path   = \"/etc/term-agent/agent.key\"");
    println!("  tls        = \"on\"");
    Ok(())
}

fn cmd_list_certs() -> Result<()> {
    let dir = data_dir();
    let store = IssuedCertStore::load(&dir)?;
    if store.certs.is_empty() {
        println!("(no agent certs issued)");
        return Ok(());
    }
    println!(
        "{:<32}{:<24}{:<14}{:<64}",
        "machine_id", "issued_at", "serial(8)", "fingerprint"
    );
    for c in &store.certs {
        let serial_short: String = c.serial_hex.chars().take(12).collect();
        println!(
            "{:<32}{:<24}{:<14}{:<64}",
            c.machine_id, c.issued_at, serial_short, c.fingerprint
        );
    }
    Ok(())
}

fn cmd_revoke_cert(args: &[String]) -> Result<()> {
    let mut serial: Option<String> = None;
    let mut id: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--serial" => serial = Some(next_arg(args, &mut i, "--serial")?.into()),
            "--id" => id = Some(next_arg(args, &mut i, "--id")?.into()),
            other => bail!("unknown flag: {other}"),
        }
        i += 1;
    }
    if serial.is_none() && id.is_none() {
        bail!("specify --serial <hex> or --id <machine_id>");
    }

    let dir = data_dir();
    IssuedCertStore::ensure_lock_file(&dir).context("ensure issued-certs lock")?;
    let _guard =
        FileLock::acquire_exclusive(&issued_certs_lock_path(&dir)).context("flock issued-certs")?;
    let mut store = IssuedCertStore::load(&dir).context("load issued-certs.json")?;

    let removed = store.remove_where(|c| {
        serial.as_deref().is_some_and(|s| c.serial_hex == s)
            || id.as_deref().is_some_and(|m| c.machine_id == m)
    });
    if removed == 0 {
        bail!("no matching cert in issued-certs.json");
    }
    store.save_atomic(&dir).context("save issued-certs.json")?;
    println!(
        "ok: removed {removed} cert entry(ies); hub will pick up the revocation on its next reload"
    );
    Ok(())
}

fn cmd_show_ca() -> Result<()> {
    let dir = data_dir();
    let path = agent_ca_cert_path(&dir);
    let pem = std::fs::read_to_string(&path)
        .with_context(|| format!("read {} (run `hub-admin init-ca` first?)", path.display()))?;
    print!("{pem}");
    Ok(())
}

fn next_arg<'a>(args: &'a [String], i: &mut usize, name: &str) -> Result<&'a str> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{name} expects a value"))
}

fn write_with_mode(path: &std::path::Path, contents: &[u8], _mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("tmp")
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(_mode)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
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
