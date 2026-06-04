//! Hub-side mTLS primitives: CA generation, leaf-cert issuance, peer
//! cert SAN extraction, and WS-perimeter signature verification.
//!
//! Compiled only when the `hub` feature is on (i.e. into `term-hub`
//! and `hub-admin`; not into the lean `term-agent` binary). Brings
//! in `rcgen` + `x509-parser`.
//!
//! ## CA layout on disk
//!
//! - `<data_dir>/agent-ca.crt` — PEM, 0644. Loaded by the hub at
//!   startup ([`load_ca_cert`]).
//! - `<data_dir>/agent-ca.key` — PEM, 0600. Loaded by hub-admin only
//!   ([`load_ca_signer`]). The hub service user must NOT have read
//!   access.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;

use super::{MACHINE_URN_PREFIX, WS_AUTH_NONCE_LEN, WS_AUTH_SKEW_SECS, cert_fingerprint};

pub const AGENT_CA_CERT_FILE: &str = "agent-ca.crt";
pub const AGENT_CA_KEY_FILE: &str = "agent-ca.key";

/// Default CA validity (10 years). The CA outlives every leaf it'll
/// ever sign; rotation = re-init + re-issue everything.
pub const DEFAULT_CA_DAYS: u64 = 365 * 10;
/// Default per-machine leaf validity (1 year). Tune via
/// `hub-admin issue-cert --days`.
pub const DEFAULT_LEAF_DAYS: u64 = 365;

pub fn agent_ca_cert_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AGENT_CA_CERT_FILE)
}
pub fn agent_ca_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AGENT_CA_KEY_FILE)
}

/// Result of [`init_ca`] / [`load_ca_signer`].
pub struct CaSigner {
    /// The CA cert (DER).
    pub cert_der: CertificateDer<'static>,
    /// rcgen-side parsed CertificateParams + private key, ready to
    /// sign leaves with [`issue_machine_cert`].
    issuer_params: CertificateParams,
    issuer_key: KeyPair,
}

impl std::fmt::Debug for CaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the issuer_key: it's the CA's signing material.
        f.debug_struct("CaSigner")
            .field("cert_der_len", &self.cert_der.as_ref().len())
            .finish_non_exhaustive()
    }
}

/// Result of [`issue_machine_cert`].
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the leaf DER (URL-safe base64, no padding). Stable
    /// identifier used by `issued-certs.json` and the in-memory
    /// allowlist.
    pub fingerprint: String,
    /// Hex-encoded serial (big-endian). Stable identifier suitable
    /// for `hub-admin revoke-cert --serial <hex>`.
    pub serial_hex: String,
    /// The machine_id baked into the cert's SAN URN.
    pub machine_id: String,
    /// Unix-secs notAfter of the leaf, for `issued-certs.json`.
    pub not_after_unix: u64,
}

/// Create the agent CA at `<data_dir>/agent-ca.{crt,key}`. Refuses to
/// overwrite an existing cert or key. Generates ECDSA-P256.
///
/// Permissions: cert 0644, key 0600 on Unix. Both files end up
/// owned by whoever runs `hub-admin init-ca` (typically root); the
/// hub service user reads only the cert.
pub fn init_ca(data_dir: &Path, validity_days: u64) -> Result<CaSigner> {
    let cert_path = agent_ca_cert_path(data_dir);
    let key_path = agent_ca_key_path(data_dir);
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
    fs::create_dir_all(data_dir)
        .with_context(|| format!("create data_dir {}", data_dir.display()))?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate CA keypair")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let (nb, na) = clock_window(validity_days)?;
    params.not_before = nb;
    params.not_after = na;
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "term-agent root CA");
        dn
    };
    params.serial_number = Some(random_serial());

    let cert = params.clone().self_signed(&key).context("self-sign CA")?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    write_atomic(&cert_path, cert_pem.as_bytes(), 0o644)
        .with_context(|| format!("write {}", cert_path.display()))?;
    write_atomic(&key_path, key_pem.as_bytes(), 0o600)
        .with_context(|| format!("write {}", key_path.display()))?;

    Ok(CaSigner {
        cert_der: cert.der().clone(),
        issuer_params: params,
        issuer_key: key,
    })
}

/// Load the CA cert (PEM) only. Used by the hub at startup; never
/// touches the private key.
pub fn load_ca_cert(data_dir: &Path) -> Result<CertificateDer<'static>> {
    let path = agent_ca_cert_path(data_dir);
    let pem = fs::read(&path)
        .with_context(|| format!("read {} (run `hub-admin init-ca` first?)", path.display()))?;
    let mut chain =
        super::load_pem_cert_chain(&pem).with_context(|| format!("parse {}", path.display()))?;
    if chain.len() != 1 {
        bail!(
            "{} should contain exactly one CERTIFICATE entry (found {})",
            path.display(),
            chain.len()
        );
    }
    Ok(chain.remove(0))
}

/// Load the CA cert + private key, ready to sign new leaves. Used by
/// hub-admin only.
pub fn load_ca_signer(data_dir: &Path) -> Result<CaSigner> {
    let cert_path = agent_ca_cert_path(data_dir);
    let key_path = agent_ca_key_path(data_dir);
    let cert_pem =
        fs::read_to_string(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        fs::read_to_string(&key_path).with_context(|| format!("read {}", key_path.display()))?;
    let issuer_params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .with_context(|| format!("parse CA cert {}", cert_path.display()))?;
    let issuer_key = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parse CA key {}", key_path.display()))?;
    let chain = super::load_pem_cert_chain(cert_pem.as_bytes())
        .with_context(|| format!("decode {}", cert_path.display()))?;
    let cert_der = chain
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{} has no CERTIFICATE", cert_path.display()))?;
    Ok(CaSigner {
        cert_der,
        issuer_params,
        issuer_key,
    })
}

/// Issue a new ECDSA-P256 leaf cert for `machine_id`, signed by `ca`.
/// The cert carries `urn:term-agent:<machine_id>` as a URI SAN — this
/// is the canonical identity bound by the hub at TLS handshake.
pub fn issue_machine_cert(
    ca: &CaSigner,
    machine_id: &str,
    validity_days: u64,
) -> Result<IssuedCert> {
    validate_machine_id(machine_id)?;

    let urn = format!("{MACHINE_URN_PREFIX}{machine_id}");
    let urn_ia5 = Ia5String::try_from(urn).map_err(|e| anyhow!("URN not IA5: {e}"))?;

    let leaf_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate leaf keypair")?;

    let mut params = CertificateParams::default();
    let (nb, na) = clock_window(validity_days)?;
    params.not_before = nb;
    params.not_after = na;
    params.is_ca = IsCa::ExplicitNoCa;
    params.subject_alt_names = vec![SanType::URI(urn_ia5)];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        // CN is informational only (the hub binds to the SAN URI);
        // setting it to machine_id keeps logs / `openssl x509` output
        // human-readable.
        dn.push(DnType::CommonName, machine_id);
        dn
    };
    let serial = random_serial();
    let serial_hex = serial_hex(&serial);
    params.serial_number = Some(serial);

    let cert = params
        .signed_by(
            &leaf_key,
            &rcgen_cert_from(&ca.issuer_params, &ca.issuer_key)?,
            &ca.issuer_key,
        )
        .context("sign leaf with CA")?;

    let cert_der = cert.der();
    let fingerprint = cert_fingerprint(cert_der.as_ref());
    let not_after_unix = u64::try_from(na.unix_timestamp().max(0)).unwrap_or(0);

    Ok(IssuedCert {
        cert_pem: cert.pem(),
        key_pem: leaf_key.serialize_pem(),
        fingerprint,
        serial_hex,
        machine_id: machine_id.to_string(),
        not_after_unix,
    })
}

/// Verify `unix_secs` is within [`WS_AUTH_SKEW_SECS`] of `now_unix`.
pub fn check_ws_auth_timestamp(now_unix: u64, ts: u64) -> Result<()> {
    let diff = ts.abs_diff(now_unix);
    if diff > WS_AUTH_SKEW_SECS {
        bail!("auth timestamp out of range: |now-ts|={diff}s > {WS_AUTH_SKEW_SECS}s");
    }
    Ok(())
}

/// Parse the `<unix_secs>.<nonce_b64u>.<sig_b64u>` body of the
/// `X-Agent-Auth` header.
pub fn parse_ws_auth_header(value: &str) -> Result<(u64, Vec<u8>, Vec<u8>)> {
    let mut parts = value.splitn(3, '.');
    let ts_str = parts.next().ok_or_else(|| anyhow!("missing timestamp"))?;
    let nonce_str = parts.next().ok_or_else(|| anyhow!("missing nonce"))?;
    let sig_str = parts.next().ok_or_else(|| anyhow!("missing signature"))?;
    if parts.next().is_some() {
        bail!("X-Agent-Auth has too many fields");
    }
    let ts: u64 = ts_str.parse().context("parse timestamp as u64")?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce_str.as_bytes())
        .context("decode nonce")?;
    if nonce.len() != WS_AUTH_NONCE_LEN {
        bail!(
            "nonce length {} != expected {WS_AUTH_NONCE_LEN}",
            nonce.len()
        );
    }
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_str.as_bytes())
        .context("decode signature")?;
    Ok((ts, nonce, sig))
}

/// Extract the canonical `urn:term-agent:<machine_id>` from a cert's
/// Subject Alternative Name. Requires exactly one matching URI SAN
/// (multiple, missing, or wrong-prefix are all errors); the inner
/// machine_id must also match [`validate_machine_id`].
pub fn extract_machine_id_from_san(cert_der: &[u8]) -> Result<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parse cert: {e}"))?;
    let san_ext = cert
        .subject_alternative_name()
        .map_err(|e| anyhow!("read SAN: {e}"))?
        .ok_or_else(|| anyhow!("cert has no Subject Alternative Name"))?;

    let mut found: Option<String> = None;
    for name in &san_ext.value.general_names {
        if let GeneralName::URI(uri) = name
            && let Some(rest) = uri.strip_prefix(MACHINE_URN_PREFIX)
        {
            if found.is_some() {
                bail!("cert has multiple {MACHINE_URN_PREFIX}* SAN URIs");
            }
            found = Some(rest.to_string());
        }
    }
    let id =
        found.ok_or_else(|| anyhow!("cert SAN does not include {MACHINE_URN_PREFIX}<id> URI"))?;
    validate_machine_id(&id)?;
    Ok(id)
}

/// Verify an ECDSA-P256-SHA256 fixed-length signature over `payload`
/// using the public key from a P-256 leaf cert (`cert_der`). Used by
/// the WS-perimeter auth path on the hub side. Sig MUST be the
/// 64-byte fixed-length encoding produced by ring's
/// `ECDSA_P256_SHA256_FIXED_SIGNING` — *not* DER.
pub fn verify_p256_signature(cert_der: &[u8], payload: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};

    let spki = extract_spki_uncompressed_p256(cert_der)?;
    let vk = VerifyingKey::from_sec1_bytes(&spki)
        .map_err(|e| anyhow!("decode SPKI as P-256 verifying key: {e}"))?;
    let sig = Signature::from_slice(sig)
        .map_err(|_| anyhow!("X-Agent-Auth signature wrong length / out-of-range"))?;
    vk.verify(payload, &sig)
        .map_err(|_| anyhow!("X-Agent-Auth signature did not verify"))?;
    Ok(())
}

/// Pull the SEC1-uncompressed P-256 public key (65 bytes, 0x04 ‖ X ‖ Y)
/// out of a leaf cert's SubjectPublicKeyInfo.
fn extract_spki_uncompressed_p256(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parse cert: {e}"))?;
    let spki = &cert.tbs_certificate.subject_pki;
    let algo_oid = &spki.algorithm.algorithm;
    // id-ecPublicKey
    if algo_oid.to_string() != "1.2.840.10045.2.1" {
        bail!(
            "cert SPKI algorithm is {:?}, expected id-ecPublicKey",
            algo_oid.to_string()
        );
    }
    // Curve OID (P-256 = 1.2.840.10045.3.1.7) is in algorithm.parameters
    // as a DER OID. x509-parser hands us the content bytes only (no
    // tag/length wrapper), so we compare the 8 OID content bytes
    // directly.
    let raw_params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| anyhow!("missing EC named-curve parameter"))?
        .as_bytes();
    // P-256 named-curve OID content: 2A 86 48 CE 3D 03 01 07
    if raw_params != [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] {
        bail!("cert SPKI is not named-curve P-256 (params={raw_params:02x?})");
    }
    let key = spki.subject_public_key.data.as_ref();
    if key.len() != 65 || key[0] != 0x04 {
        bail!(
            "cert SPKI is not 65-byte SEC1-uncompressed P-256 (got {} bytes, prefix 0x{:02x})",
            key.len(),
            key.first().copied().unwrap_or(0)
        );
    }
    Ok(key.to_vec())
}

fn random_serial() -> SerialNumber {
    // RFC 5280 limits serials to 20 bytes; 16 bytes is plenty and
    // matches the size of common UUID-derived serials. The high bit
    // of the first byte must be 0 so the encoded INTEGER is positive.
    let mut bytes = [0u8; 16];
    crate::random::fill(&mut bytes);
    bytes[0] &= 0x7f;
    SerialNumber::from_slice(&bytes)
}

fn serial_hex(s: &SerialNumber) -> String {
    let mut out = String::with_capacity(s.as_ref().len() * 2);
    for b in s.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn clock_window(days: u64) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?;
    let nb = OffsetDateTime::from_unix_timestamp(now.as_secs() as i64 - 60)
        .map_err(|e| anyhow!("not_before out of range: {e}"))?;
    let na = OffsetDateTime::from_unix_timestamp(
        (now + Duration::from_secs(days * 86_400)).as_secs() as i64,
    )
    .map_err(|e| anyhow!("not_after out of range: {e}"))?;
    Ok((nb, na))
}

/// Reconstruct the rcgen `Certificate` for the CA so we can call
/// `signed_by` against it. rcgen wants the CA `Certificate` value
/// (not just its DER) so it can copy issuer DN + AKI fields into the
/// leaf.
fn rcgen_cert_from(params: &CertificateParams, key: &KeyPair) -> Result<rcgen::Certificate> {
    // self_signed is the only way to get back a `Certificate` from
    // parsed params; we don't use the produced cert's DER (the
    // leaf's `issuer` is taken from params.distinguished_name), so
    // re-signing is cheap and side-effect-free.
    params
        .clone()
        .self_signed(key)
        .context("rebuild rcgen Certificate for CA params")
}

/// Mirror of `is_valid_machine_id` from `hub::config` — duplicated
/// here so common can validate machine IDs without depending on the
/// hub crate.
pub fn validate_machine_id(id: &str) -> Result<()> {
    let n = id.len();
    if n == 0 || n > 32 {
        bail!("machine_id length {n} not in 1..=32");
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("machine_id {id:?} contains chars outside [A-Za-z0-9_-]");
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &[u8], _mode: u32) -> io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("tmp")
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(_mode)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    // POSIX rename is atomic; on Windows it's "atomic enough" for
    // this use (single-writer, no concurrent reader-mid-rename).
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("term-mtls-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn init_and_issue_round_trip() {
        let dir = temp_dir("init");
        let _ca = init_ca(&dir, 365).unwrap();
        // Reload from disk (simulates hub-admin issue-cert workflow).
        let ca = load_ca_signer(&dir).unwrap();
        let issued = issue_machine_cert(&ca, "alpha", 30).unwrap();
        assert_eq!(issued.machine_id, "alpha");
        assert!(!issued.fingerprint.is_empty());
        assert_eq!(issued.serial_hex.len(), 32, "16-byte serial = 32 hex chars");
        // Parse the freshly-issued PEM back and check the SAN.
        let chain = super::super::load_pem_cert_chain(issued.cert_pem.as_bytes()).unwrap();
        let id = extract_machine_id_from_san(chain[0].as_ref()).unwrap();
        assert_eq!(id, "alpha");
    }

    #[test]
    fn init_refuses_overwrite() {
        let dir = temp_dir("init-twice");
        let _ = init_ca(&dir, 365).unwrap();
        let err = init_ca(&dir, 365).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn load_ca_cert_errors_when_missing() {
        let dir = temp_dir("missing");
        let err = load_ca_cert(&dir).unwrap_err();
        assert!(err.to_string().contains("hub-admin init-ca"));
    }

    #[test]
    fn extract_machine_id_rejects_certs_without_san() {
        let dir = temp_dir("nosan");
        let _ = init_ca(&dir, 365).unwrap();
        let ca_pem = std::fs::read(agent_ca_cert_path(&dir)).unwrap();
        let ca_chain = super::super::load_pem_cert_chain(&ca_pem).unwrap();
        // CA cert has no SAN at all.
        let err = extract_machine_id_from_san(ca_chain[0].as_ref()).unwrap_err();
        assert!(err.to_string().contains("Subject Alternative Name"));
    }

    #[test]
    fn validate_machine_id_rules() {
        assert!(validate_machine_id("abc-123_XYZ").is_ok());
        assert!(validate_machine_id("").is_err());
        assert!(validate_machine_id(&"x".repeat(33)).is_err());
        assert!(validate_machine_id("bad name").is_err());
        assert!(validate_machine_id("bad/name").is_err());
    }

    #[test]
    fn timestamp_window() {
        let now = 1_700_000_000u64;
        assert!(check_ws_auth_timestamp(now, now).is_ok());
        assert!(check_ws_auth_timestamp(now, now + WS_AUTH_SKEW_SECS).is_ok());
        assert!(check_ws_auth_timestamp(now, now - WS_AUTH_SKEW_SECS).is_ok());
        assert!(check_ws_auth_timestamp(now, now + WS_AUTH_SKEW_SECS + 1).is_err());
        assert!(check_ws_auth_timestamp(now, now.saturating_sub(WS_AUTH_SKEW_SECS + 1)).is_err());
    }

    #[test]
    fn parse_ws_auth_header_round_trip() {
        let mut nonce = [0u8; WS_AUTH_NONCE_LEN];
        nonce[0] = 0xAB;
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        let header = format!("1700000000.{nonce_b64}.{sig_b64}");
        let (ts, n, s) = parse_ws_auth_header(&header).unwrap();
        assert_eq!(ts, 1_700_000_000);
        assert_eq!(n, nonce.to_vec());
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn parse_ws_auth_header_rejects_malformed() {
        assert!(parse_ws_auth_header("").is_err());
        assert!(parse_ws_auth_header("abc.def").is_err());
        assert!(parse_ws_auth_header("notanumber.nonce.sig").is_err());
        // Too many dots.
        let nonce =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; WS_AUTH_NONCE_LEN]);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        assert!(parse_ws_auth_header(&format!("1.{nonce}.{sig}.extra")).is_err());
    }

    #[test]
    fn verify_p256_signature_round_trip() {
        // End-to-end: issue a leaf, sign with the *leaf* private key
        // using ring (mirrors what the agent's WS-auth signer does in
        // production), then verify against the cert's pubkey using
        // the hub-side p256 verifier. This catches any drift between
        // the two crypto backends (ring on the agent, p256 on the hub).
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

        let dir = temp_dir("verify");
        let _ = init_ca(&dir, 365).unwrap();
        let ca = load_ca_signer(&dir).unwrap();
        let issued = issue_machine_cert(&ca, "alpha", 30).unwrap();
        let chain = super::super::load_pem_cert_chain(issued.cert_pem.as_bytes()).unwrap();
        let leaf_der = chain[0].as_ref();

        // Decode the rcgen-produced PKCS#8 key into a ring signer.
        let key_der = super::super::load_pem_private_key(issued.key_pem.as_bytes()).unwrap();
        let key_bytes = match &key_der {
            rustls_pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der(),
            _ => panic!("rcgen-issued key should be PKCS#8"),
        };
        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key_bytes, &rng)
            .expect("load ring keypair");

        let payload = super::super::ws_auth_payload(
            "hub.example.com",
            1_700_000_000,
            b"nonce-xxxx-yyyy-zzzz",
        );
        let sig = kp.sign(&rng, &payload).expect("sign");

        // Happy path verifies.
        verify_p256_signature(leaf_der, &payload, sig.as_ref()).unwrap();
        // Tampered payload fails.
        let mut tampered = payload.clone();
        tampered[0] ^= 0x01;
        assert!(verify_p256_signature(leaf_der, &tampered, sig.as_ref()).is_err());
        // Wrong-length sig fails.
        assert!(verify_p256_signature(leaf_der, &payload, &sig.as_ref()[..63]).is_err());
    }
}
