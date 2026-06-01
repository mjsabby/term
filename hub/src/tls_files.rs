//! `tls = "files"`: serve a cert+key pair from disk and quietly
//! re-read them on a fixed cadence so an external ACME bot
//! (lego / certbot / acme.sh / step-cli) can renew without
//! restarting the hub.
//!
//! Implementation: a [`DynamicResolver`] wraps the live `CertifiedKey`
//! in an `RwLock`. The same resolver is plugged into the rustls
//! `ServerConfig` used by both the browser listener and the agent
//! listener, so renewals propagate to both endpoints on the next
//! TLS handshake.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

#[derive(Debug)]
pub struct DynamicResolver {
    inner: RwLock<Arc<CertifiedKey>>,
}

impl DynamicResolver {
    /// Load an initial cert+key pair from disk and wrap it.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let ck = load_certified_key(cert_path, key_path)?;
        Ok(Arc::new(Self { inner: RwLock::new(ck) }))
    }

    pub fn replace(&self, ck: Arc<CertifiedKey>) {
        *self.inner.write().expect("resolver poisoned") = ck;
    }

    fn current(&self) -> Arc<CertifiedKey> {
        self.inner.read().expect("resolver poisoned").clone()
    }
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Parse a PEM cert chain + PEM private key from disk into a CertifiedKey.
pub fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("read {}", cert_path.display()))?;
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("read {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certs from {}", cert_path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no PEM certificates found in {}", cert_path.display()));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .with_context(|| format!("parse key from {}", key_path.display()))?
        .ok_or_else(|| anyhow!("no PEM private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .with_context(|| "build signing key (unsupported key type?)")?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Background task: every `period`, re-read the cert + key from disk and
/// atomically swap them into `resolver`. Read failures keep the previous
/// cert and log a warning — partial writes by the ACME bot (e.g. during
/// an atomic rename window) don't ground the hub.
pub fn spawn_reloader(
    resolver: Arc<DynamicResolver>,
    cert_path: PathBuf,
    key_path: PathBuf,
    period: Duration,
) {
    tokio::spawn(async move {
        let mut tick = interval(period);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Skip the immediate-first tick; the initial load already happened.
        tick.tick().await;
        loop {
            tick.tick().await;
            match load_certified_key(&cert_path, &key_path) {
                Ok(new) => {
                    resolver.replace(new);
                    info!(
                        "tls cert reloaded from {} (next check in {}s)",
                        cert_path.display(),
                        period.as_secs()
                    );
                }
                Err(e) => warn!(
                    error = ?e,
                    "tls cert reload failed; keeping previous (next check in {}s)",
                    period.as_secs()
                ),
            }
        }
    });
}
