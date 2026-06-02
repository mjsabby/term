//! Parse + validate WebAuthn `clientDataJSON`.
//!
//! Shape (W3C WebAuthn §5.8.1 / §7.1 step 11):
//!
//! ```json
//! {
//!   "type": "webauthn.create" | "webauthn.get",
//!   "challenge": "<base64url>",
//!   "origin": "https://...",
//!   "crossOrigin": false,
//!   ... extra fields allowed and ignored ...
//! }
//! ```
//!
//! Per spec, extra fields MAY be present; unknown fields MUST be
//! ignored. We use `serde_json::Value` rather than a strict struct so
//! we tolerate them and don't bind the schema to a single Rust type.

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ClientDataError {
    #[error("not valid JSON: {0}")]
    Json(String),
    #[error("not a JSON object")]
    NotObject,
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("field {0} is not a string")]
    NotString(&'static str),
    #[error("wrong type: expected {expected:?}, got {got:?}")]
    WrongType { expected: &'static str, got: String },
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("origin mismatch: expected {expected:?}, got {got:?}")]
    OriginMismatch { expected: String, got: String },
}

pub const TYPE_CREATE: &str = "webauthn.create";
pub const TYPE_GET: &str = "webauthn.get";

/// Validate clientDataJSON for either registration (`type` =
/// `webauthn.create`) or authentication (`type` = `webauthn.get`).
///
/// `expected_challenge_b64u` is the base64url-no-pad encoding of the
/// 32-byte challenge we issued. We compare strings directly (not raw
/// bytes), per the spec note about the verifier comparing base64url
/// strings.
///
/// `expected_origin` is the exact origin string we expect (scheme +
/// host + optional port, no trailing slash). We do a byte-for-byte
/// equality check rather than parsing — origin matching gotchas (case
/// folding on host, default port elision, etc.) all reduce to "use the
/// exact string we computed for the WebAuthn rp_id binding".
pub fn validate(
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge_b64u: &str,
    expected_origin: &str,
) -> Result<(), ClientDataError> {
    let v: Value = serde_json::from_slice(client_data_json)
        .map_err(|e| ClientDataError::Json(e.to_string()))?;
    let obj = v.as_object().ok_or(ClientDataError::NotObject)?;

    let ty = obj.get("type").ok_or(ClientDataError::MissingField("type"))?
        .as_str().ok_or(ClientDataError::NotString("type"))?;
    if ty != expected_type {
        return Err(ClientDataError::WrongType {
            expected: if expected_type == TYPE_CREATE { "webauthn.create" } else { "webauthn.get" },
            got: ty.to_owned(),
        });
    }

    let chal = obj.get("challenge").ok_or(ClientDataError::MissingField("challenge"))?
        .as_str().ok_or(ClientDataError::NotString("challenge"))?;
    if !constant_time_eq(chal.as_bytes(), expected_challenge_b64u.as_bytes()) {
        return Err(ClientDataError::ChallengeMismatch);
    }

    let origin = obj.get("origin").ok_or(ClientDataError::MissingField("origin"))?
        .as_str().ok_or(ClientDataError::NotString("origin"))?;
    if origin != expected_origin {
        return Err(ClientDataError::OriginMismatch {
            expected: expected_origin.to_owned(),
            got: origin.to_owned(),
        });
    }
    Ok(())
}

/// Constant-time byte compare so a poison-the-challenge attacker can't
/// derive bytes via timing. Bytes vs bytes only — we already restricted
/// to base64url strings so length is itself well-known.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimum_create() {
        let body = br#"{"type":"webauthn.create","challenge":"abc123","origin":"https://example.com"}"#;
        validate(body, TYPE_CREATE, "abc123", "https://example.com").unwrap();
    }

    #[test]
    fn accepts_extra_fields() {
        let body = br#"{
            "type":"webauthn.get",
            "challenge":"chal",
            "origin":"https://x.com",
            "crossOrigin":false,
            "tokenBinding":{"status":"present","id":"foo"},
            "extraField":42
        }"#;
        validate(body, TYPE_GET, "chal", "https://x.com").unwrap();
    }

    #[test]
    fn rejects_wrong_type() {
        let body = br#"{"type":"webauthn.create","challenge":"c","origin":"https://x.com"}"#;
        let err = validate(body, TYPE_GET, "c", "https://x.com").unwrap_err();
        assert!(matches!(err, ClientDataError::WrongType { .. }));
    }

    #[test]
    fn rejects_challenge_mismatch() {
        let body = br#"{"type":"webauthn.get","challenge":"xxx","origin":"https://x.com"}"#;
        let err = validate(body, TYPE_GET, "yyy", "https://x.com").unwrap_err();
        assert!(matches!(err, ClientDataError::ChallengeMismatch));
    }

    #[test]
    fn rejects_origin_mismatch() {
        let body = br#"{"type":"webauthn.get","challenge":"c","origin":"https://evil.com"}"#;
        let err = validate(body, TYPE_GET, "c", "https://good.com").unwrap_err();
        assert!(matches!(err, ClientDataError::OriginMismatch { .. }));
    }

    #[test]
    fn rejects_missing_origin() {
        let body = br#"{"type":"webauthn.get","challenge":"c"}"#;
        let err = validate(body, TYPE_GET, "c", "https://x.com").unwrap_err();
        assert!(matches!(err, ClientDataError::MissingField("origin")));
    }

    #[test]
    fn rejects_non_object() {
        let body = br#"["not","an","object"]"#;
        let err = validate(body, TYPE_GET, "c", "https://x.com").unwrap_err();
        assert!(matches!(err, ClientDataError::NotObject));
    }
}
