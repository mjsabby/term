//! Per-cert allowlist: a JSON file maintained by `hub-admin` and
//! consulted by `term-hub` at every TLS handshake to decide whether a
//! cert signed by our CA is actually allowed to log in *right now*.
//!
//! The chain-validity check (cert signed by `agent-ca.crt`) happens
//! inside rustls's `WebPkiClientVerifier`. This file adds the
//! *revocation* layer the CA alone can't provide: when an operator
//! runs `hub-admin revoke-cert --serial <hex>`, the entry is removed
//! from this file and the next TLS handshake from that cert tears
//! down with `bad_certificate`.
//!
//! On-disk layout under `<data_dir>`:
//!
//! ```text
//! issued-certs.json          # JSON array of IssuedCertEntry
//! issued-certs.json.lock     # advisory flock target (zero-byte)
//! ```
//!
//! Concurrency: writers (hub-admin) hold the flock for the whole RMW
//! cycle and write atomically (tmp + rename). The hub re-reads the
//! file every 30s (or on inotify-equivalent in a future patch); it
//! never writes.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const ISSUED_CERTS_FILE: &str = "issued-certs.json";
pub const ISSUED_CERTS_LOCK_FILE: &str = "issued-certs.json.lock";

pub fn issued_certs_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ISSUED_CERTS_FILE)
}
pub fn issued_certs_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ISSUED_CERTS_LOCK_FILE)
}

/// One row in `issued-certs.json`. Stored verbatim; both the hub and
/// hub-admin read/write this exact shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertEntry {
    /// machine_id baked into the cert's SAN URN. The hub uses this
    /// as the authenticated identity AFTER fingerprint+SAN match.
    pub machine_id: String,
    /// SHA-256 fingerprint of the leaf DER (URL-safe base64-no-pad).
    /// Stable across re-encoding and the primary key against which
    /// the hub matches peer certs.
    pub fingerprint: String,
    /// Hex-encoded serial. Stable id for `revoke-cert --serial`.
    pub serial_hex: String,
    /// ISO-8601 timestamp of issuance. Informational.
    pub issued_at: String,
    /// Unix-secs notAfter from the leaf cert. The hub additionally
    /// rejects expired entries even if the operator forgot to revoke.
    pub not_after_unix: u64,
    /// Optional human-readable label (e.g. "alpha-yubikey-2025-q1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IssuedCertStore {
    pub certs: Vec<IssuedCertEntry>,
}

impl IssuedCertStore {
    /// Load from disk; empty store if the file is missing.
    pub fn load(data_dir: &Path) -> io::Result<Self> {
        let path = issued_certs_path(data_dir);
        match fs::File::open(&path) {
            Ok(mut f) => {
                let mut buf = String::new();
                f.read_to_string(&mut buf)?;
                if buf.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_json::from_str(&buf).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("parse {}: {e}", path.display()),
                    )
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write atomically (tmp + rename). Caller is responsible for
    /// holding the advisory file lock around the read-modify-write
    /// cycle.
    pub fn save_atomic(&self, data_dir: &Path) -> io::Result<()> {
        let path = issued_certs_path(data_dir);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(".{ISSUED_CERTS_FILE}.tmp"));
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode JSON: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Ensure the lock file exists. Called once by hub-admin before
    /// it tries to acquire the flock.
    pub fn ensure_lock_file(data_dir: &Path) -> io::Result<()> {
        let p = issued_certs_lock_path(data_dir);
        if !p.exists() {
            fs::write(&p, b"")?;
        }
        Ok(())
    }

    /// Linear scan by fingerprint. Hub uses this on every accepted
    /// TLS handshake — the store is small (<= a few hundred entries
    /// in any realistic deployment) so O(n) is fine.
    pub fn find_by_fingerprint(&self, fp: &str) -> Option<&IssuedCertEntry> {
        self.certs.iter().find(|c| c.fingerprint == fp)
    }

    /// Remove entries matching the given predicate; returns the
    /// number of entries removed.
    pub fn remove_where<F>(&mut self, f: F) -> usize
    where
        F: Fn(&IssuedCertEntry) -> bool,
    {
        let before = self.certs.len();
        self.certs.retain(|c| !f(c));
        before - self.certs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("term-issued-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample(fp: &str, id: &str) -> IssuedCertEntry {
        IssuedCertEntry {
            machine_id: id.into(),
            fingerprint: fp.into(),
            serial_hex: "deadbeef".into(),
            issued_at: "2025-01-01T00:00:00Z".into(),
            not_after_unix: 9_999_999_999,
            label: None,
        }
    }

    #[test]
    fn round_trip_save_load() {
        let dir = temp_dir("rt");
        let mut s = IssuedCertStore::default();
        s.certs.push(sample("fp1", "alpha"));
        s.certs.push(sample("fp2", "beta"));
        s.save_atomic(&dir).unwrap();
        let loaded = IssuedCertStore::load(&dir).unwrap();
        assert_eq!(loaded.certs.len(), 2);
        assert_eq!(loaded.certs[0].machine_id, "alpha");
    }

    #[test]
    fn missing_file_is_empty_store() {
        let dir = temp_dir("missing");
        let loaded = IssuedCertStore::load(&dir).unwrap();
        assert!(loaded.certs.is_empty());
    }

    #[test]
    fn find_by_fingerprint() {
        let mut s = IssuedCertStore::default();
        s.certs.push(sample("aaa", "x"));
        s.certs.push(sample("bbb", "y"));
        assert_eq!(s.find_by_fingerprint("bbb").unwrap().machine_id, "y");
        assert!(s.find_by_fingerprint("zzz").is_none());
    }

    #[test]
    fn remove_where_returns_count() {
        let mut s = IssuedCertStore::default();
        s.certs.push(sample("aaa", "x"));
        s.certs.push(sample("bbb", "x"));
        s.certs.push(sample("ccc", "y"));
        assert_eq!(s.remove_where(|c| c.machine_id == "x"), 2);
        assert_eq!(s.certs.len(), 1);
        assert_eq!(s.certs[0].fingerprint, "ccc");
    }
}
