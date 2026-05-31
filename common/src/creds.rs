//! Credential store and HMAC-secret file.
//!
//! On-disk layout under `data_dir` (default `/var/lib/term-hub`):
//!
//! ```text
//! data_dir/
//!   credentials.json          # array of stored SecurityKeys + labels
//!   credentials.json.lock     # advisory flock target (zero-byte file)
//!   secret.key                # 32 random bytes, 0600, HMAC key for the
//!                             # registration envelope (see envelope.rs)
//!   acme/                     # rustls-acme cache dir
//! ```
//!
//! `credentials.json` is rewritten atomically (write to tmp, rename) and
//! both the hub (which updates credential counters after login) and
//! `hub-admin` (which appends new credentials) coordinate via the
//! `credentials.json.lock` flock.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::SecurityKey;

pub const CREDENTIALS_FILE: &str = "credentials.json";
pub const LOCK_FILE: &str = "credentials.json.lock";
pub const SECRET_FILE: &str = "secret.key";
pub const ACME_CACHE_DIR: &str = "acme";

pub fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CREDENTIALS_FILE)
}
pub fn lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCK_FILE)
}
pub fn secret_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SECRET_FILE)
}
pub fn acme_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ACME_CACHE_DIR)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Human-readable label supplied at registration time (e.g. "yubikey-blue").
    pub label: String,
    /// ISO-8601 timestamp the credential was added.
    pub added_at: String,
    /// The actual webauthn-rs SecurityKey (serializable).
    pub credential: SecurityKey,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CredentialStore {
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io({path:?}): {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("parse({path:?}): {source}")]
    Parse { path: PathBuf, source: serde_json::Error },
}

impl CredentialStore {
    /// Read the store from disk. Missing file -> empty store.
    pub fn load(data_dir: &Path) -> Result<Self, StoreError> {
        let path = credentials_path(data_dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StoreError::Parse { path, source: e }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(StoreError::Io { path, source: e }),
        }
    }

    /// Write the store to `path.tmp` then `rename` over the real file.
    /// Caller is responsible for holding the advisory lock around this.
    pub fn save_atomic(&self, data_dir: &Path) -> Result<(), StoreError> {
        let final_path = credentials_path(data_dir);
        let mut tmp_path = final_path.clone();
        tmp_path.set_extension("json.tmp");

        let body = serde_json::to_vec_pretty(self).map_err(|e| StoreError::Parse {
            path: final_path.clone(),
            source: e,
        })?;
        {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| StoreError::Io { path: tmp_path.clone(), source: e })?;
            tmp.write_all(&body)
                .map_err(|e| StoreError::Io { path: tmp_path.clone(), source: e })?;
            tmp.sync_all()
                .map_err(|e| StoreError::Io { path: tmp_path.clone(), source: e })?;
        }
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| StoreError::Io { path: final_path.clone(), source: e })?;

        // fsync the directory so the rename is durable across crashes.
        if let Some(parent) = final_path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// Acquire an exclusive advisory lock on `credentials.json.lock`. Returned
/// guard drops the lock when dropped (file is closed).
///
/// We use `flock(2)` via `nix`-style ioctls, but since we don't want a
/// `nix` dep in the common crate, the lock is implemented via raw libc
/// in the hub and hub-admin crates. This function only ensures the lock
/// file exists with the right permissions.
pub fn ensure_lock_file(data_dir: &Path) -> Result<PathBuf, StoreError> {
    let p = lock_path(data_dir);
    if !p.exists() {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&p)
            .map_err(|e| StoreError::Io { path: p.clone(), source: e })?;
    }
    Ok(p)
}

/// Load or generate the HMAC secret used for registration envelopes.
/// Returns 32 random bytes. The file is mode 0600.
pub fn load_or_create_secret(data_dir: &Path) -> Result<[u8; 32], StoreError> {
    let path = secret_path(data_dir);
    match File::open(&path) {
        Ok(mut f) => {
            let mut buf = [0u8; 32];
            f.read_exact(&mut buf)
                .map_err(|e| StoreError::Io { path: path.clone(), source: e })?;
            Ok(buf)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut buf = [0u8; 32];
            // Read directly from /dev/urandom to avoid pulling `rand` into
            // the common crate.
            let mut urandom = File::open("/dev/urandom").map_err(|e| StoreError::Io {
                path: PathBuf::from("/dev/urandom"),
                source: e,
            })?;
            urandom
                .read_exact(&mut buf)
                .map_err(|e| StoreError::Io { path: path.clone(), source: e })?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| StoreError::Io { path: path.clone(), source: e })?;
            f.write_all(&buf)
                .map_err(|e| StoreError::Io { path: path.clone(), source: e })?;
            f.sync_all()
                .map_err(|e| StoreError::Io { path: path.clone(), source: e })?;
            Ok(buf)
        }
        Err(e) => Err(StoreError::Io { path, source: e }),
    }
}
