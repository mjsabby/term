//! Agent ↔ hub mutual-TLS primitives shared by `term-agent`,
//! `term-hub`, and `hub-admin`.
//!
//! The hub maintains a private CA at `<data_dir>/agent-ca.crt` (cert)
//! and `<data_dir>/agent-ca.key` (private key, hub-admin only — the
//! hub service NEVER reads the key). `hub-admin issue-cert` signs a
//! per-machine ECDSA-P256 leaf cert whose Subject Alternative Name
//! carries `urn:term-agent:<machine_id>`; the hub verifies that URI
//! at TLS-handshake time and uses it as the agent's identity.
//!
//! Module split:
//!
//! - This file ([`mod.rs`]): always-built helpers (PEM loading, the
//!   canonical WS-auth assertion bytes, machine_id URN encoding /
//!   decoding). Compiled into the agent so it can load its own cert
//!   files and produce the WS-perimeter auth header.
//! - [`ca`]: hub-side primitives (CA generation, leaf cert issuance,
//!   peer-cert SAN extraction, WS-auth verification, fingerprinting).
//!   Gated behind the `hub` feature so the agent doesn't pull in
//!   `rcgen` / `x509-parser`.
//!
//! ## WS-perimeter auth (HTTP header bridge for the wss path)
//!
//! On the raw TCP+TLS transport the client cert is verified by the
//! hub at TLS-handshake time so a wrong cert tears the connection
//! down at the TCP layer. On the WSS transport (where a perimeter
//! such as a Microsoft Dev Tunnel terminates TLS), the hub never
//! sees the agent's cert via TLS, so the agent attaches two upgrade
//! headers:
//!
//! - `X-Agent-Cert: <base64-no-pad of leaf cert DER>`
//! - `X-Agent-Auth: <unix_secs>.<nonce_b64u>.<ecdsa_sig_b64u>`,
//!   where the signature is over [`ws_auth_payload`] of
//!   `(host, unix_secs, nonce)`. Binding the host (the perimeter URL
//!   the agent thinks it's reaching) defeats a tunnel-eavesdropper
//!   from replaying the assertion against a different hub.

#[cfg(feature = "hub")]
pub mod ca;

use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
pub use rustls_pemfile::Item as PemItem;

/// Re-export so callers don't need a direct `rustls-pki-types` dep
/// just to name the return type of [`load_pem_cert_chain`] /
/// [`load_pem_private_key`].
pub mod pki {
    pub use rustls_pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };
}

/// Domain-separator prefix for the WS-perimeter auth assertion.
/// Hard-coded into the canonical signed payload so a signature that
/// proves possession of an agent key for THIS protocol can't be
/// repurposed against some future protocol that re-uses the same
/// keypair.
pub const WS_AUTH_DOMAIN: &str = "term-agent-ws-auth";

/// SAN URI prefix encoding the machine_id. The full URI shape is
/// `urn:term-agent:<machine_id>`. Issuance ([`ca::issue_machine_cert`])
/// embeds it; verification ([`ca::extract_machine_id_from_san`])
/// requires exactly one matching URI SAN.
pub const MACHINE_URN_PREFIX: &str = "urn:term-agent:";

/// Encode `machine_id` as the canonical SAN URN.
pub fn machine_urn(machine_id: &str) -> String {
    format!("{MACHINE_URN_PREFIX}{machine_id}")
}

/// Maximum size of an `X-Agent-Cert` header value, in bytes (base64
/// of leaf DER). A P-256 EE cert is ~500 bytes DER → ~700 base64;
/// 8 KiB is generous headroom for a leaf with weird extensions while
/// still rejecting outsize header spam from a misbehaving client.
pub const MAX_AGENT_CERT_HEADER_BYTES: usize = 8 * 1024;
/// Maximum size of an `X-Agent-Auth` header value, in bytes. A
/// unix-secs timestamp + base64 nonce + base64 ECDSA-P256 signature
/// comes out to ~150 bytes. 512 leaves slack without inviting DoS.
pub const MAX_AGENT_AUTH_HEADER_BYTES: usize = 512;
/// Half-window for accepting an `X-Agent-Auth` timestamp (in seconds).
/// Anything older than `now - WS_AUTH_SKEW_SECS` or newer than
/// `now + WS_AUTH_SKEW_SECS` is rejected.
pub const WS_AUTH_SKEW_SECS: u64 = 300; // ±5 minutes
/// Length of the per-upgrade replay nonce, in bytes. Sized so a
/// uniformly random nonce collision within the replay-cache lifetime
/// is astronomical.
pub const WS_AUTH_NONCE_LEN: usize = 16;

/// HTTP header carrying the base64-no-pad DER of the agent's leaf cert.
pub const HEADER_AGENT_CERT: &str = "x-agent-cert";
/// HTTP header carrying the unix-secs.nonce.signature triple.
pub const HEADER_AGENT_AUTH: &str = "x-agent-auth";

/// Canonical bytes that an `X-Agent-Auth` signature must cover. Both
/// the agent (signer) and the hub (verifier) MUST construct this the
/// exact same way; any drift here would silently break auth.
///
/// Format:
/// ```text
/// term-agent-ws-auth\n<host>\n<unix_secs>\n<nonce_b64url_no_pad>
/// ```
///
/// `host` is the HTTP `Host:` header value the agent is sending the
/// upgrade to; binding it ensures a captured signature can't be
/// replayed against a different hub.
pub fn ws_auth_payload(host: &str, unix_secs: u64, nonce: &[u8]) -> Vec<u8> {
    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    format!("{WS_AUTH_DOMAIN}\n{host}\n{unix_secs}\n{nonce_b64}").into_bytes()
}

/// Parse a PEM blob containing one or more `CERTIFICATE` entries and
/// return them in order. The leaf MUST be first (matching every
/// `cert_path = "..."` produced by `hub-admin issue-cert`).
pub fn load_pem_cert_chain(pem: &[u8]) -> io::Result<Vec<pki::CertificateDer<'static>>> {
    let mut out = Vec::new();
    let mut rest = pem;
    for item in rustls_pemfile::certs(&mut rest) {
        let item = item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        out.push(item);
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no CERTIFICATE entries in PEM",
        ));
    }
    Ok(out)
}

/// Parse a PEM blob containing one private key (PKCS#8 / PKCS#1 / SEC1).
/// Returns the rustls native key enum so callers can pass it straight
/// to `rustls::ClientConfig::with_client_auth_cert`.
pub fn load_pem_private_key(pem: &[u8]) -> io::Result<pki::PrivateKeyDer<'static>> {
    let mut rest = pem;
    let key = rustls_pemfile::private_key(&mut rest)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no PRIVATE KEY entry in PEM"))?;
    Ok(key)
}

/// Read PEM cert chain + private key from disk in one shot. Used by
/// the agent at startup and by hub-admin tests.
pub fn load_cert_files(
    cert_path: &Path,
    key_path: &Path,
) -> io::Result<(
    Vec<pki::CertificateDer<'static>>,
    pki::PrivateKeyDer<'static>,
)> {
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(key_path)?;
    let chain = load_pem_cert_chain(&cert_bytes)?;
    let key = load_pem_private_key(&key_bytes)?;
    Ok((chain, key))
}

/// SHA-256 fingerprint of `cert_der`, base64-no-pad (URL-safe). Used
/// as the stable identifier for an issued cert in `issued-certs.json`
/// and in the in-memory replay cache.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::Digest;
    let h = sha2::Sha256::digest(cert_der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_urn_round_trip() {
        let u = machine_urn("alpha-1");
        assert!(u.starts_with(MACHINE_URN_PREFIX));
        assert_eq!(&u[MACHINE_URN_PREFIX.len()..], "alpha-1");
    }

    #[test]
    fn ws_auth_payload_includes_all_inputs() {
        let p = ws_auth_payload("hub.example.com", 1_700_000_000, b"\x01\x02\x03\x04");
        let s = std::str::from_utf8(&p).unwrap();
        // Must start with the domain separator (defeats cross-protocol
        // reuse of an agent's signing key).
        assert!(s.starts_with(WS_AUTH_DOMAIN));
        // Must contain the host (defeats cross-hub replay).
        assert!(s.contains("hub.example.com"));
        // Must contain the timestamp + nonce.
        assert!(s.contains("1700000000"));
        // 4 bytes -> URL-safe-no-pad 6 chars.
        assert!(s.ends_with("AQIDBA"));
    }

    #[test]
    fn ws_auth_payload_changes_when_any_input_changes() {
        let base = ws_auth_payload("h", 1, b"n");
        assert_ne!(base, ws_auth_payload("h2", 1, b"n"));
        assert_ne!(base, ws_auth_payload("h", 2, b"n"));
        assert_ne!(base, ws_auth_payload("h", 1, b"n2"));
    }

    #[test]
    fn fingerprint_is_stable_and_base64url() {
        let fp = cert_fingerprint(b"hello");
        // sha256("hello") = 2cf24d... base64url-no-pad =
        // "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        assert_eq!(fp, "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
        // No padding, no +/, only URL-safe alphabet.
        assert!(!fp.contains('='));
        assert!(!fp.contains('+'));
        assert!(!fp.contains('/'));
    }

    #[test]
    fn load_pem_cert_chain_rejects_empty() {
        let r =
            load_pem_cert_chain(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        assert!(r.is_err());
    }
}
