//! Credential store and HMAC-secret file.
//!
//! On-disk layout under `data_dir` (default `/var/lib/term-hub`):
//!
//! ```text
//! data_dir/
//!   credentials.json          # array of stored credentials + labels
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
//!
//! The on-disk format carries the raw credential bytes — credential id,
//! SEC1-uncompressed P-256 public key, sign count, label, timestamp.
//! No webauthn-rs types are persisted; nothing in here pins us to a
//! specific webauthn library or version.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::webauthn::cose::SEC1_UNCOMPRESSED_LEN;

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
    /// Raw credential id bytes (W3C "credentialId"), base64-no-pad.
    pub credential_id_b64: String,
    /// SEC1-uncompressed P-256 public key (0x04 || x || y), 65 bytes,
    /// base64-no-pad. Stored as base64 so the JSON file is human-
    /// inspectable.
    pub credential_public_key_b64: String,
    /// Last-seen signature counter. Bumped on every successful login.
    #[serde(default)]
    pub sign_count: u32,
}

impl StoredCredential {
    pub fn credential_id(&self) -> Result<Vec<u8>, StoreError> {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.credential_id_b64.as_bytes())
            .map_err(|e| StoreError::Base64(e.to_string()))
    }

    pub fn credential_public_key(&self) -> Result<[u8; SEC1_UNCOMPRESSED_LEN], StoreError> {
        let v = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.credential_public_key_b64.as_bytes())
            .map_err(|e| StoreError::Base64(e.to_string()))?;
        if v.len() != SEC1_UNCOMPRESSED_LEN {
            return Err(StoreError::WrongPubkeyLen(v.len()));
        }
        let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
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
    #[error("base64: {0}")]
    Base64(String),
    #[error("stored public key is {0} bytes, expected 65")]
    WrongPubkeyLen(usize),
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
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)] opts.mode(0o600);
            let mut tmp = opts.open(&tmp_path)
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

    /// Find a credential by its raw id bytes.
    pub fn find_by_id(&self, id: &[u8]) -> Option<&StoredCredential> {
        let target = base64::engine::general_purpose::STANDARD_NO_PAD.encode(id);
        self.credentials.iter().find(|c| c.credential_id_b64 == target)
    }

    /// Find a credential by its raw id bytes (mutable).
    pub fn find_by_id_mut(&mut self, id: &[u8]) -> Option<&mut StoredCredential> {
        let target = base64::engine::general_purpose::STANDARD_NO_PAD.encode(id);
        self.credentials.iter_mut().find(|c| c.credential_id_b64 == target)
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
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)] opts.mode(0o600);
        opts.open(&p)
            .map_err(|e| StoreError::Io { path: p.clone(), source: e })?;
    }
    Ok(p)
}

/// Load or generate the HMAC secret used for registration envelopes.
/// Returns 32 random bytes. The file is mode 0600 on Unix; inherits
/// the parent directory's ACL on Windows.
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
            // Reuse the same OS-RNG path the agent uses for download
            // tokens (Unix: /dev/urandom; Windows: BCryptGenRandom).
            crate::random::fill(&mut buf);
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)] opts.mode(0o600);
            let mut f = opts.open(&path)
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
