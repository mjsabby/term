//! Hand-rolled WebAuthn / FIDO2 for the `term` hub.
//!
//! Scope is deliberately tiny:
//! - **ES256 (P-256 + SHA-256) only.** Every FIDO2 hardware key supports
//!   this algorithm; no production authenticator does Ed25519 or RSA
//!   exclusively. If a key shows up that can't speak ES256, we'll add
//!   a second branch when it does.
//! - **No attestation verification.** The hub's trust gate is the
//!   operator pasting the registration blob on the hub host
//!   (`hub-admin add-passkey`), not the cryptographic attestation
//!   chain. We extract the public key from the attestation object and
//!   throw the rest away.
//! - **No extensions.** No `largeBlob`, `hmac-secret`, `prf`,
//!   `credProtect`, etc. Authenticators that send extension bytes
//!   (the ED flag in authData) are tolerated — we just don't act on
//!   the contents.
//! - **Touch only.** `userVerification: "discouraged"` everywhere;
//!   matches the old webauthn-rs `danger_user_presence_only_security_keys`.
//!
//! Replaces `webauthn-rs` 0.5 and its `openssl-sys` transitive
//! dependency. Total surface: ~350 LOC across this module + its 5
//! submodules.

pub mod authdata;
pub mod cbor;
pub mod challenge;
pub mod client_data;
pub mod cose;

use base64::Engine;
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use challenge::{Challenge, CHALLENGE_LEN};

// -------- creation (registration) options --------

/// Serializes to the `publicKey` member of `navigator.credentials
/// .create({publicKey: ...})`. The SPA decodes the base64url-encoded
/// `challenge` and `user.id` to ArrayBuffers (the W3C type wants
/// BufferSource, JSON can only carry strings).
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RelyingParty,
    pub user: UserInfo,
    /// Base64url-no-pad of the 32 random challenge bytes.
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: &'static str,
    pub timeout: u32,
}

#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    /// Base64url-no-pad of a fresh 16-byte UUID — we re-issue per
    /// registration and never refer to it again. WebAuthn requires
    /// it; we don't.
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub alg: i32,
}

#[derive(Debug, Serialize)]
pub struct AuthenticatorSelection {
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

impl PublicKeyCredentialCreationOptions {
    /// Build the options the SPA hands to `navigator.credentials.create`.
    pub fn build(
        rp_id: &str,
        rp_name: &str,
        user_id_16: [u8; 16],
        user_name: &str,
        display_name: &str,
        challenge: &Challenge,
    ) -> Self {
        let user_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id_16);
        PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                id: rp_id.into(),
                name: rp_name.into(),
            },
            user: UserInfo {
                id: user_id_b64,
                name: user_name.into(),
                display_name: display_name.into(),
            },
            challenge: challenge.to_b64url(),
            pub_key_cred_params: vec![PubKeyCredParam {
                ty: "public-key",
                alg: cose::ES256_ALG as i32,
            }],
            authenticator_selection: AuthenticatorSelection {
                user_verification: "discouraged",
            },
            attestation: "none",
            timeout: 60_000,
        }
    }
}

/// The exact JSON the SPA shipped back from
/// `navigator.credentials.create()`, base64url decoded by us.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Echo of `rawId` — we don't read it (the cred id is in authData).
    #[allow(dead_code)]
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub response: RegistrationInner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInner {
    /// Base64url of the raw clientDataJSON bytes.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url of the CBOR attestationObject.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

// -------- request (authentication) options --------

#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    pub timeout: u32,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<AllowedCredential>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AllowedCredential {
    #[serde(rename = "type")]
    pub ty: &'static str,
    /// Base64url-no-pad of the credential id bytes.
    pub id: String,
}

impl PublicKeyCredentialRequestOptions {
    pub fn build(rp_id: &str, challenge: &Challenge, allow: &[Vec<u8>]) -> Self {
        let allow = allow
            .iter()
            .map(|raw| AllowedCredential {
                ty: "public-key",
                id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
            })
            .collect();
        PublicKeyCredentialRequestOptions {
            challenge: challenge.to_b64url(),
            timeout: 60_000,
            rp_id: rp_id.into(),
            allow_credentials: allow,
            user_verification: "discouraged",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub response: AuthenticationInner,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationInner {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url of the raw authenticatorData bytes (NOT CBOR).
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Base64url of the DER ECDSA signature.
    pub signature: String,
    #[allow(dead_code)]
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

// -------- finish_register / finish_authenticate --------

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("base64url decode of {0}: {1}")]
    Base64(&'static str, base64::DecodeError),
    #[error("wrong credential type: {0:?} (expected 'public-key')")]
    WrongType(String),
    #[error("attestationObject: {0}")]
    AttestationObject(String),
    #[error("cbor: {0}")]
    Cbor(#[from] cbor::CborError),
    #[error("authData: {0}")]
    AuthData(#[from] authdata::AuthDataError),
    #[error("clientData: {0}")]
    ClientData(#[from] client_data::ClientDataError),
    #[error("rpIdHash mismatch")]
    RpIdHashMismatch,
    #[error("user-presence flag not set")]
    UserPresenceNotSet,
    #[error("ECDSA verify failed")]
    SignatureInvalid,
    #[error("unknown credential id")]
    UnknownCredential,
    #[error("signCount {got} <= stored {stored} (possible cloned authenticator)")]
    SignCountRegression { got: u32, stored: u32 },
    #[error("invalid SEC1 P-256 public key")]
    InvalidStoredPubkey,
}

/// What a successful registration produces. The caller persists it.
#[derive(Debug, Clone)]
pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    /// SEC1-uncompressed P-256 public key (0x04 || x || y, 65 bytes).
    pub credential_public_key: [u8; cose::SEC1_UNCOMPRESSED_LEN],
    pub sign_count: u32,
}

/// What a successful authentication produces. The caller persists the
/// new sign_count if it advanced.
#[derive(Debug, Clone)]
pub struct AuthenticatedCredential {
    pub credential_id: Vec<u8>,
    pub new_sign_count: u32,
    /// True if the new sign_count is strictly greater than the old
    /// one (the caller should persist).
    pub sign_count_advanced: bool,
}

/// Validate a `navigator.credentials.create()` response against the
/// challenge we issued. Returns the credential's public key, ready to
/// store in `credentials.json`.
pub fn finish_register(
    response: &RegistrationResponse,
    expected_challenge: &Challenge,
    rp_id: &str,
    expected_origin: &str,
) -> Result<RegisteredCredential, WebauthnError> {
    if response.ty != "public-key" {
        return Err(WebauthnError::WrongType(response.ty.clone()));
    }
    let client_data = b64u(&response.response.client_data_json, "clientDataJSON")?;
    client_data::validate(
        &client_data,
        client_data::TYPE_CREATE,
        &expected_challenge.to_b64url(),
        expected_origin,
    )?;

    let attestation_object = b64u(&response.response.attestation_object, "attestationObject")?;
    let auth_data = extract_auth_data(&attestation_object)?;
    let parsed = authdata::parse_attested(&auth_data)?;
    check_rp_id_hash(&parsed.prefix.rp_id_hash, rp_id)?;
    if !parsed.prefix.user_present() {
        return Err(WebauthnError::UserPresenceNotSet);
    }
    Ok(RegisteredCredential {
        credential_id: parsed.credential_id,
        credential_public_key: parsed.credential_public_key,
        sign_count: parsed.prefix.sign_count,
    })
}

/// Validate a `navigator.credentials.get()` response against the
/// challenge we issued. Caller-supplied `find_credential` looks up the
/// stored public key for the credential id the authenticator returned.
pub fn finish_authenticate<F>(
    response: &AuthenticationResponse,
    expected_challenge: &Challenge,
    rp_id: &str,
    expected_origin: &str,
    find_credential: F,
) -> Result<AuthenticatedCredential, WebauthnError>
where
    F: FnOnce(&[u8]) -> Option<StoredCredentialView>,
{
    if response.ty != "public-key" {
        return Err(WebauthnError::WrongType(response.ty.clone()));
    }
    let raw_id = b64u(&response.raw_id, "rawId")?;
    let client_data = b64u(&response.response.client_data_json, "clientDataJSON")?;
    client_data::validate(
        &client_data,
        client_data::TYPE_GET,
        &expected_challenge.to_b64url(),
        expected_origin,
    )?;

    let auth_data = b64u(&response.response.authenticator_data, "authenticatorData")?;
    let signature = b64u(&response.response.signature, "signature")?;

    let prefix = authdata::parse_prefix(&auth_data)?;
    check_rp_id_hash(&prefix.rp_id_hash, rp_id)?;
    if !prefix.user_present() {
        return Err(WebauthnError::UserPresenceNotSet);
    }

    let stored = find_credential(&raw_id).ok_or(WebauthnError::UnknownCredential)?;

    // ECDSA-with-SHA256 over (authData || sha256(clientDataJSON)). The
    // p256 `verify` method itself hashes its input with SHA-256; we
    // pass the unhashed concatenation.
    let mut msg = Vec::with_capacity(auth_data.len() + 32);
    msg.extend_from_slice(&auth_data);
    msg.extend_from_slice(&Sha256::digest(&client_data));

    let verifying_key = VerifyingKey::from_sec1_bytes(&stored.credential_public_key)
        .map_err(|_| WebauthnError::InvalidStoredPubkey)?;
    let sig = Signature::from_der(&signature).map_err(|_| WebauthnError::SignatureInvalid)?;
    verifying_key
        .verify(&msg, &sig)
        .map_err(|_| WebauthnError::SignatureInvalid)?;

    // signCount: spec says >0 means the authenticator tracks them; if
    // both old and new are 0 we have no signal. If new <= old and
    // new != 0, treat as a possible clone.
    let advanced = prefix.sign_count > stored.sign_count;
    if !advanced && prefix.sign_count != 0 {
        return Err(WebauthnError::SignCountRegression {
            got: prefix.sign_count,
            stored: stored.sign_count,
        });
    }
    Ok(AuthenticatedCredential {
        credential_id: raw_id,
        new_sign_count: prefix.sign_count,
        sign_count_advanced: advanced,
    })
}

/// View of a stored credential that's enough for signature verification.
/// The store may keep more (label, added_at) — we don't care.
#[derive(Debug, Clone)]
pub struct StoredCredentialView {
    pub credential_public_key: [u8; cose::SEC1_UNCOMPRESSED_LEN],
    pub sign_count: u32,
}

// -------- internals --------

fn b64u(s: &str, field: &'static str) -> Result<Vec<u8>, WebauthnError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| WebauthnError::Base64(field, e))
}

fn check_rp_id_hash(got: &[u8; 32], rp_id: &str) -> Result<(), WebauthnError> {
    let expected = Sha256::digest(rp_id.as_bytes());
    // Constant time isn't strictly necessary here (RP ID is public),
    // but it's cheap.
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(WebauthnError::RpIdHashMismatch);
    }
    Ok(())
}

/// Crack open an attestationObject CBOR map and return the raw
/// `authData` byte string. Other fields (`fmt`, `attStmt`) are
/// skipped — we don't verify attestation.
fn extract_auth_data(att_obj: &[u8]) -> Result<Vec<u8>, WebauthnError> {
    let mut buf = att_obj;
    let n = cbor::read_map_header(&mut buf)?;
    let mut auth_data: Option<Vec<u8>> = None;
    for _ in 0..n {
        let key = cbor::read_text(&mut buf)?;
        if key == "authData" {
            auth_data = Some(cbor::read_bytes(&mut buf)?.to_vec());
        } else {
            cbor::skip_value(&mut buf)?;
        }
    }
    auth_data.ok_or_else(|| WebauthnError::AttestationObject("missing authData field".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, SigningKey};

    /// Build an attestationObject of the form
    /// `{"fmt": "none", "attStmt": {}, "authData": h'<bytes>'}`.
    fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(auth_data.len() + 64);
        // map(3)
        v.push(0xa3);
        // "fmt" -> "none"
        v.extend_from_slice(b"\x63fmt\x64none");
        // "attStmt" -> {}
        v.extend_from_slice(b"\x67attStmt\xa0");
        // "authData" -> bytes(len)
        v.extend_from_slice(b"\x68authData");
        // bytes header
        let n = auth_data.len();
        if n <= 23 {
            v.push(0x40 + n as u8);
        } else if n <= 255 {
            v.push(0x58);
            v.push(n as u8);
        } else {
            v.push(0x59);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
        v.extend_from_slice(auth_data);
        v
    }

    fn build_auth_data(
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        cred_id: &[u8],
        cose_key: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        v.push(flags);
        v.extend_from_slice(&sign_count.to_be_bytes());
        if flags & (1 << 6) != 0 {
            v.extend_from_slice(&[0u8; 16]); // aaguid
            v.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            v.extend_from_slice(cred_id);
            v.extend_from_slice(cose_key);
        }
        v
    }

    fn build_cose_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut v = vec![0xa5];
        v.extend_from_slice(&[0x01, 0x02]);
        v.extend_from_slice(&[0x03, 0x26]);
        v.extend_from_slice(&[0x20, 0x01]);
        v.extend_from_slice(&[0x21, 0x58, 32]);
        v.extend_from_slice(x);
        v.extend_from_slice(&[0x22, 0x58, 32]);
        v.extend_from_slice(y);
        v
    }

    fn b64u_encode(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    fn signing_key_to_sec1_xy(sk: &SigningKey) -> ([u8; 32], [u8; 32]) {
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false); // uncompressed
        let bytes = point.as_bytes();
        assert_eq!(bytes[0], 0x04);
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        let mut y = [0u8; 32];
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    #[test]
    fn extract_auth_data_pulls_inner_bytes() {
        let auth_data = vec![0xaa; 50];
        let obj = build_attestation_object(&auth_data);
        let got = extract_auth_data(&obj).unwrap();
        assert_eq!(got, auth_data);
    }

    #[test]
    fn finish_register_happy_path() {
        let rp_id = "term.xyz.com";
        let origin = "https://term.xyz.com";
        let challenge = Challenge([5u8; 32]);
        let chal_b64 = challenge.to_b64url();

        let cred_id = b"my-credential";
        let x = [11u8; 32];
        let y = [12u8; 32];
        let cose = build_cose_es256(&x, &y);
        let auth_data = build_auth_data(rp_id, 1 | (1 << 6), 0, cred_id, &cose);
        let att_obj = build_attestation_object(&auth_data);

        let client_data_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
            chal_b64, origin
        );

        let resp = RegistrationResponse {
            id: b64u_encode(cred_id),
            raw_id: b64u_encode(cred_id),
            ty: "public-key".into(),
            response: RegistrationInner {
                client_data_json: b64u_encode(client_data_json.as_bytes()),
                attestation_object: b64u_encode(&att_obj),
            },
        };
        let reg = finish_register(&resp, &challenge, rp_id, origin).unwrap();
        assert_eq!(reg.credential_id, cred_id);
        assert_eq!(&reg.credential_public_key[1..33], &x);
        assert_eq!(&reg.credential_public_key[33..65], &y);
        assert_eq!(reg.sign_count, 0);
    }

    #[test]
    fn finish_authenticate_round_trip() {
        let rp_id = "term.xyz.com";
        let origin = "https://term.xyz.com";
        let challenge = Challenge([9u8; 32]);
        let chal_b64 = challenge.to_b64url();

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let (x, y) = signing_key_to_sec1_xy(&sk);
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);

        let cred_id = b"cred-1";
        let auth_data = build_auth_data(rp_id, 1, 7, &[], &[]);

        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            chal_b64, origin
        );
        let cd_bytes = client_data_json.as_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(&auth_data);
        msg.extend_from_slice(&Sha256::digest(cd_bytes));
        let sig: Signature = sk.sign(&msg);
        let der = sig.to_der();

        let resp = AuthenticationResponse {
            id: b64u_encode(cred_id),
            raw_id: b64u_encode(cred_id),
            ty: "public-key".into(),
            response: AuthenticationInner {
                client_data_json: b64u_encode(cd_bytes),
                authenticator_data: b64u_encode(&auth_data),
                signature: b64u_encode(der.as_bytes()),
                user_handle: None,
            },
        };

        let ok = finish_authenticate(&resp, &challenge, rp_id, origin, |id| {
            assert_eq!(id, cred_id);
            Some(StoredCredentialView {
                credential_public_key: sec1,
                sign_count: 6,
            })
        })
        .unwrap();
        assert_eq!(ok.credential_id, cred_id);
        assert_eq!(ok.new_sign_count, 7);
        assert!(ok.sign_count_advanced);
    }

    #[test]
    fn finish_authenticate_rejects_bad_signature() {
        let rp_id = "term.xyz.com";
        let origin = "https://term.xyz.com";
        let challenge = Challenge([9u8; 32]);
        let chal_b64 = challenge.to_b64url();

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let (x, y) = signing_key_to_sec1_xy(&sk);
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);

        let auth_data = build_auth_data(rp_id, 1, 1, &[], &[]);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            chal_b64, origin
        );

        // Sign over the WRONG message and check verify fails.
        let sig: Signature = sk.sign(b"different message");

        let resp = AuthenticationResponse {
            id: "x".into(),
            raw_id: b64u_encode(b"id"),
            ty: "public-key".into(),
            response: AuthenticationInner {
                client_data_json: b64u_encode(client_data_json.as_bytes()),
                authenticator_data: b64u_encode(&auth_data),
                signature: b64u_encode(sig.to_der().as_bytes()),
                user_handle: None,
            },
        };
        let err = finish_authenticate(&resp, &challenge, rp_id, origin, |_| {
            Some(StoredCredentialView {
                credential_public_key: sec1,
                sign_count: 0,
            })
        })
        .unwrap_err();
        assert!(
            matches!(err, WebauthnError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn finish_authenticate_rejects_unknown_credential() {
        let rp_id = "x.com";
        let origin = "https://x.com";
        let challenge = Challenge([0u8; 32]);
        let chal_b64 = challenge.to_b64url();

        let auth_data = build_auth_data(rp_id, 1, 0, &[], &[]);
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            chal_b64, origin
        );
        let resp = AuthenticationResponse {
            id: "x".into(),
            raw_id: b64u_encode(b"id"),
            ty: "public-key".into(),
            response: AuthenticationInner {
                client_data_json: b64u_encode(cd.as_bytes()),
                authenticator_data: b64u_encode(&auth_data),
                signature: b64u_encode(b""),
                user_handle: None,
            },
        };
        let err = finish_authenticate(&resp, &challenge, rp_id, origin, |_| None).unwrap_err();
        assert!(
            matches!(err, WebauthnError::UnknownCredential),
            "got {err:?}"
        );
    }

    #[test]
    fn check_rp_id_hash_matches() {
        let h = Sha256::digest(b"term.xyz.com");
        let mut a = [0u8; 32];
        a.copy_from_slice(&h);
        check_rp_id_hash(&a, "term.xyz.com").unwrap();
    }

    #[test]
    fn check_rp_id_hash_rejects_mismatch() {
        let h = Sha256::digest(b"other");
        let mut a = [0u8; 32];
        a.copy_from_slice(&h);
        assert!(matches!(
            check_rp_id_hash(&a, "term.xyz.com"),
            Err(WebauthnError::RpIdHashMismatch)
        ));
    }
}
