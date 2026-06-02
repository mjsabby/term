//! Random challenge generation + base64url encoding helpers.

use base64::Engine;

/// Length of every challenge we issue. Per W3C WebAuthn §13.4.3 the
/// challenge should be at least 16 bytes; 32 is the common practice.
pub const CHALLENGE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(pub [u8; CHALLENGE_LEN]);

impl Challenge {
    /// 32 cryptographically-random bytes via the OS RNG.
    pub fn random() -> Self {
        let mut buf = [0u8; CHALLENGE_LEN];
        crate::random::fill(&mut buf);
        Self(buf)
    }

    /// Base64url-no-pad string. This is the exact string `clientDataJSON.challenge`
    /// will hold on the wire.
    pub fn to_b64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_b64url(s: &str) -> Result<Self, base64::DecodeError> {
        let v = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        if v.len() != CHALLENGE_LEN {
            return Err(base64::DecodeError::InvalidLength(v.len()));
        }
        let mut a = [0u8; CHALLENGE_LEN];
        a.copy_from_slice(&v);
        Ok(Self(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_changes() {
        let a = Challenge::random();
        let b = Challenge::random();
        assert_ne!(a, b);
    }

    #[test]
    fn b64url_round_trip() {
        let c = Challenge::random();
        let s = c.to_b64url();
        let back = Challenge::from_b64url(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn b64url_is_no_pad() {
        let c = Challenge([0u8; CHALLENGE_LEN]);
        assert!(!c.to_b64url().contains('='));
    }

    #[test]
    fn rejects_wrong_length() {
        // 31 bytes -> base64url of 42 chars without padding.
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 31]);
        assert!(Challenge::from_b64url(&s).is_err());
    }
}
