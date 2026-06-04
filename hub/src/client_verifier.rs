//! Custom `rustls::server::ClientCertVerifier` for the agent listener.
//!
//! Wraps the stock `WebPkiClientVerifier` (which handles chain
//! validation against our agent CA + signature verification) and adds
//! the application-layer checks that MUST also fail at TLS-handshake
//! time so the TCP connection is dropped before a single byte of the
//! application protocol crosses the wire:
//!
//! 1. The leaf cert's SHA-256 fingerprint must be in
//!    `issued-certs.json` (managed by `hub-admin issue-cert` /
//!    `revoke-cert`). Defeats stolen certs after revocation.
//! 2. The leaf MUST carry exactly one `urn:term-agent:<machine_id>`
//!    URI SAN. Defeats stray client certs that happen to chain to
//!    our CA but were issued for some other purpose.
//! 3. The machine_id encoded in the SAN URN MUST also be the
//!    `machine_id` recorded in the matching `issued-certs.json`
//!    entry. Defeats a clever attacker who replays an old cert
//!    against a `[[machines]]` slot they don't own.
//!
//! `verify_tls{12,13}_signature` + `root_hint_subjects` +
//! `supported_verify_schemes` delegate to the wrapped
//! `WebPkiClientVerifier` so we get exactly the same crypto / hint
//! behaviour as the stock implementation.

use std::sync::{Arc, RwLock};

use rustls::DistinguishedName;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore};
use tracing::warn;

use term_common::agent_pki;
use term_common::agent_pki::ca::extract_machine_id_from_san;
use term_common::issued_certs::IssuedCertStore;

#[derive(Debug)]
pub struct AgentClientVerifier {
    /// Stock chain verifier, configured with our agent CA as the
    /// only trust anchor.
    inner: Arc<dyn ClientCertVerifier>,
    /// Hot-reloaded snapshot of the allowed-cert list. Held under a
    /// stdlib `RwLock` because rustls calls us from synchronous
    /// handshake threads — we can't await a tokio mutex here.
    issued_certs: Arc<RwLock<IssuedCertStore>>,
}

impl AgentClientVerifier {
    /// Construct a verifier that trusts ONLY the given agent CA and
    /// requires every accepted cert's fingerprint to be in
    /// `issued_certs`. Returns an `Arc<dyn ClientCertVerifier>`
    /// because rustls's `ServerConfig::with_client_cert_verifier`
    /// expects that erased trait object; the concrete `Self` is an
    /// internal implementation detail.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        agent_ca: CertificateDer<'static>,
        issued_certs: Arc<RwLock<IssuedCertStore>>,
    ) -> Result<Arc<dyn ClientCertVerifier>, VerifierBuilderError> {
        let mut roots = RootCertStore::empty();
        roots.add(agent_ca).map_err(|e| {
            // map() not in scope; just panic — feeding our own freshly
            // loaded CA cert in shouldn't be able to fail at runtime.
            panic!("agent CA failed to add to RootCertStore: {e:?}")
        });
        let inner = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        Ok(Arc::new(Self {
            inner,
            issued_certs,
        }))
    }
}

impl ClientCertVerifier for AgentClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // 1. Chain validation (signed by our CA, not expired, etc.).
        //    This is the heavy lift; if it fails the TLS handshake
        //    aborts here.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // 2. Fingerprint allow-list. Held under a stdlib RwLock; the
        //    read is O(n) over the store (small), but the lock is
        //    held only for the lookup + clone of the matched entry.
        let fp = agent_pki::cert_fingerprint(end_entity.as_ref());
        let matched = {
            let store = self
                .issued_certs
                .read()
                .map_err(|_| TlsError::General("issued_certs lock poisoned".into()))?;
            store.find_by_fingerprint(&fp).cloned()
        };
        let entry = matched.ok_or_else(|| {
            // Don't echo the fingerprint to a (possibly hostile)
            // peer's TLS alert; log it here for the operator.
            warn!(
                fingerprint = %fp,
                "rejecting agent: fingerprint not in issued-certs.json (revoked or never issued)"
            );
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        })?;

        // 3. SAN URN match. extract_machine_id_from_san enforces
        //    "exactly one urn:term-agent:<id> SAN" + valid id chars.
        let san_id = extract_machine_id_from_san(end_entity.as_ref()).map_err(|e| {
            warn!(error = %e, "rejecting agent: malformed SAN");
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        })?;
        if san_id != entry.machine_id {
            warn!(
                san_machine_id = %san_id,
                expected = %entry.machine_id,
                "rejecting agent: cert SAN machine_id does not match issued-certs.json entry"
            );
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        // 4. Belt-and-suspenders expiry check. WebPkiClientVerifier
        //    has already validated NotBefore/NotAfter against `now`,
        //    but the issued-certs entry's stored not_after may be
        //    tighter (e.g. operator marked an expiry override in a
        //    future patch). For now this is a sanity-check ladder.
        if entry.not_after_unix > 0 && now.as_secs() > entry.not_after_unix {
            warn!(
                machine_id = %entry.machine_id,
                "rejecting agent: issued-certs entry says cert expired"
            );
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use term_common::agent_pki;
    use term_common::agent_pki::ca::{init_ca, issue_machine_cert, load_ca_signer};
    use term_common::issued_certs::IssuedCertEntry;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("term-clientv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// End-to-end: issue a cert, register it in IssuedCertStore, then
    /// verify the cert passes. Revoke + re-verify and it should be
    /// rejected. The full TLS handshake isn't run here (that's covered
    /// by the loopback test in agent_link); this exercises the
    /// verifier's application-layer logic in isolation.
    #[test]
    fn fingerprint_allowlist_gates_verification() {
        let dir = temp_dir("gate");
        let _ = init_ca(&dir, 365).unwrap();
        let ca = load_ca_signer(&dir).unwrap();
        let issued = issue_machine_cert(&ca, "alpha", 30).unwrap();

        // Install the entry, build the verifier, verify success.
        let mut store = IssuedCertStore::default();
        store.certs.push(IssuedCertEntry {
            machine_id: issued.machine_id.clone(),
            fingerprint: issued.fingerprint.clone(),
            serial_hex: issued.serial_hex.clone(),
            issued_at: "2025-01-01T00:00:00Z".into(),
            not_after_unix: issued.not_after_unix,
            label: None,
        });
        let store = Arc::new(RwLock::new(store));
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let verifier = AgentClientVerifier::new(ca.cert_der.clone(), store.clone()).unwrap();

        let leaf_pem = issued.cert_pem.as_bytes();
        let chain = agent_pki::load_pem_cert_chain(leaf_pem).unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        verifier.verify_client_cert(&chain[0], &[], now).unwrap();

        // Revoke (drop the entry), verifier must reject.
        store.write().unwrap().certs.clear();
        let err = verifier
            .verify_client_cert(&chain[0], &[], now)
            .unwrap_err();
        assert!(matches!(
            err,
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        ));
    }

    #[test]
    fn san_machine_id_must_match_issued_cert_entry() {
        let dir = temp_dir("sanmatch");
        let _ = init_ca(&dir, 365).unwrap();
        let ca = load_ca_signer(&dir).unwrap();
        let issued = issue_machine_cert(&ca, "alpha", 30).unwrap();

        // Stash an entry with the right fingerprint but the WRONG
        // machine_id — the verifier must reject the mismatch.
        let mut store = IssuedCertStore::default();
        store.certs.push(IssuedCertEntry {
            machine_id: "beta".into(),
            fingerprint: issued.fingerprint.clone(),
            serial_hex: issued.serial_hex.clone(),
            issued_at: "2025-01-01T00:00:00Z".into(),
            not_after_unix: issued.not_after_unix,
            label: None,
        });
        let store = Arc::new(RwLock::new(store));
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let verifier = AgentClientVerifier::new(ca.cert_der.clone(), store).unwrap();
        let chain = agent_pki::load_pem_cert_chain(issued.cert_pem.as_bytes()).unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        let err = verifier
            .verify_client_cert(&chain[0], &[], now)
            .unwrap_err();
        assert!(matches!(
            err,
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        ));
    }
}
