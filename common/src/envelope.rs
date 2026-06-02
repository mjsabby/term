//! HMAC-signed registration envelope.
//!
//! Used as a bag of bytes to round-trip the registration challenge from
//! the hub through the operator's browser to `hub-admin add-passkey`
//! on the hub host. The hub doesn't keep server-side registration
//! state — the envelope IS the state, signed by a host-local HMAC key
//! so the operator can't trivially forge it (and so the browser can't
//! either).
//!
//! Wire shape — opaque to the browser, deserialized only by hub-admin:
//!
//! ```text
//! SignedEnvelope { inner: EnvelopeInner, hmac_b64: String }
//! EnvelopeInner   { rp_id, origin, issued_at, challenge_b64 }
//! ```
//!
//! Plus a `PasteBlob { envelope, response, label }` that bundles the
//! envelope with the navigator.credentials.create response so the
//! operator pastes a single base64 string into `hub-admin`.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::webauthn::{Challenge, RegistrationResponse};

type HmacSha256 = Hmac<Sha256>;

/// Maximum age of an envelope, in seconds. After this the paste blob is
/// rejected by `hub-admin` even if the HMAC matches.
pub const ENVELOPE_TTL_SECS: u64 = 10 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeInner {
    pub rp_id: String,
    pub origin: String,
    pub issued_at: u64,
    /// Base64url-no-pad of the 32-byte challenge.
    pub challenge_b64u: String,
}

impl EnvelopeInner {
    pub fn challenge(&self) -> Result<Challenge, EnvelopeError> {
        Challenge::from_b64url(&self.challenge_b64u).map_err(|e| EnvelopeError::Decode(e.to_string()))
    }
}

/// Wire format of the envelope: JSON body + base64 HMAC tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub inner: EnvelopeInner,
    /// Base64-standard-no-pad of the HMAC tag over `serde_json::to_vec(&inner)`.
    pub hmac_b64: String,
}

/// Full paste blob: envelope + the navigator.credentials.create response.
/// Serialized to JSON then base64 for copy/paste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasteBlob {
    pub envelope: SignedEnvelope,
    pub response: RegistrationResponse,
    /// Optional human-readable label provided by the operator.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("system time error: {0}")]
    Time(String),
    #[error("hmac key length")]
    KeyLen,
    #[error("hmac mismatch")]
    HmacMismatch,
    #[error("envelope expired ({age_secs}s old, ttl {ttl}s)")]
    Expired { age_secs: u64, ttl: u64 },
    #[error("decode: {0}")]
    Decode(String),
}

fn now_secs() -> Result<u64, EnvelopeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| EnvelopeError::Time(e.to_string()))
}

fn mac(key: &[u8]) -> Result<HmacSha256, EnvelopeError> {
    HmacSha256::new_from_slice(key).map_err(|_| EnvelopeError::KeyLen)
}

impl SignedEnvelope {
    pub fn sign(inner: EnvelopeInner, key: &[u8]) -> Result<Self, EnvelopeError> {
        let body = serde_json::to_vec(&inner).map_err(|e| EnvelopeError::Decode(e.to_string()))?;
        let mut m = mac(key)?;
        m.update(&body);
        let tag = m.finalize().into_bytes();
        let hmac_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(tag);
        Ok(Self { inner, hmac_b64 })
    }

    /// Verify the HMAC and the TTL. On success returns the inner envelope.
    pub fn verify(self, key: &[u8]) -> Result<EnvelopeInner, EnvelopeError> {
        let body =
            serde_json::to_vec(&self.inner).map_err(|e| EnvelopeError::Decode(e.to_string()))?;
        let mut m = mac(key)?;
        m.update(&body);
        let expected = m.finalize().into_bytes();
        let provided = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.hmac_b64.as_bytes())
            .map_err(|e| EnvelopeError::Decode(e.to_string()))?;

        // constant-time compare
        if provided.len() != expected.len() {
            return Err(EnvelopeError::HmacMismatch);
        }
        let mut diff = 0u8;
        for (a, b) in provided.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(EnvelopeError::HmacMismatch);
        }

        let now = now_secs()?;
        let age = now.saturating_sub(self.inner.issued_at);
        if age > ENVELOPE_TTL_SECS {
            return Err(EnvelopeError::Expired {
                age_secs: age,
                ttl: ENVELOPE_TTL_SECS,
            });
        }
        Ok(self.inner)
    }
}

/// Encode a paste blob for `hub-admin add-passkey '<blob>'`.
pub fn encode_paste_blob(blob: &PasteBlob) -> Result<String, EnvelopeError> {
    let body = serde_json::to_vec(blob).map_err(|e| EnvelopeError::Decode(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(body))
}

/// Decode the base64 paste blob.
pub fn decode_paste_blob(s: &str) -> Result<PasteBlob, EnvelopeError> {
    // Strip whitespace operators often paste in.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|e| EnvelopeError::Decode(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| EnvelopeError::Decode(e.to_string()))
}

pub fn issued_at_now() -> u64 {
    now_secs().unwrap_or(0)
}
