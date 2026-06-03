//! Parse WebAuthn `authenticatorData`.
//!
//! Wire layout (W3C WebAuthn §6.1):
//!
//! ```text
//! rpIdHash:       [u8; 32]          (sha256(rpId))
//! flags:          u8                (bit 0: UP, bit 2: UV, bit 6: AT, bit 7: ED)
//! signCount:      u32 (big-endian)
//! attestedCredentialData (when AT):
//!   aaguid:       [u8; 16]
//!   credIdLen:    u16 (big-endian)
//!   credId:       [u8; credIdLen]
//!   credentialPublicKey: COSE_Key (CBOR)
//! extensions (when ED): CBOR map      (we don't parse, just allow it)
//! ```
//!
//! For registration we expect AT to be set (so the attested credential
//! data is present). For authentication we only need the prefix
//! (rpIdHash + flags + signCount) — `signature` is computed over the
//! whole `authenticatorData` byte string, so we keep the original
//! bytes too.

use super::cbor;
use super::cose;

#[derive(Debug, thiserror::Error)]
pub enum AuthDataError {
    #[error("authenticatorData too short ({len} bytes, need >= 37)")]
    TooShort { len: usize },
    #[error("AT flag set but no attested-credential-data follows")]
    MissingAttestedCredData,
    #[error("credential id length {0} exceeds 1023-byte WebAuthn cap")]
    CredIdTooLong(usize),
    #[error("trailing bytes after parse: {0}")]
    TrailingBytes(usize),
    #[error("cose: {0}")]
    Cose(#[from] cose::CoseError),
    #[error("cbor: {0}")]
    Cbor(#[from] cbor::CborError),
}

const FLAG_UP: u8 = 1 << 0;
#[allow(dead_code)]
const FLAG_UV: u8 = 1 << 2;
const FLAG_AT: u8 = 1 << 6;
#[allow(dead_code)]
const FLAG_ED: u8 = 1 << 7;
const HEADER_LEN: usize = 37; // 32 + 1 + 4

/// Prefix that's always present.
#[derive(Debug, Clone, Copy)]
pub struct AuthDataPrefix {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
}

impl AuthDataPrefix {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub fn attested_cred_data(&self) -> bool {
        self.flags & FLAG_AT != 0
    }
}

/// Full registration-time parse (AT must be set). `credential_public_key`
/// is the 65-byte SEC1-uncompressed encoding for an ES256 key.
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    pub prefix: AuthDataPrefix,
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: [u8; cose::SEC1_UNCOMPRESSED_LEN],
}

/// Parse just the prefix (32 + 1 + 4 bytes). Useful for authentication
/// where we only need the rpIdHash + flags + signCount.
pub fn parse_prefix(data: &[u8]) -> Result<AuthDataPrefix, AuthDataError> {
    if data.len() < HEADER_LEN {
        return Err(AuthDataError::TooShort { len: data.len() });
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    Ok(AuthDataPrefix {
        rp_id_hash,
        flags,
        sign_count,
    })
}

/// Parse a registration-time authenticatorData, returning the prefix +
/// attested credential data. The AT flag must be set; ED bytes (if
/// present) are skipped over.
pub fn parse_attested(data: &[u8]) -> Result<AttestedCredentialData, AuthDataError> {
    let prefix = parse_prefix(data)?;
    if !prefix.attested_cred_data() {
        return Err(AuthDataError::MissingAttestedCredData);
    }
    let mut buf = &data[HEADER_LEN..];
    if buf.len() < 16 + 2 {
        return Err(AuthDataError::TooShort { len: data.len() });
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&buf[..16]);
    let cred_id_len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    if cred_id_len > 1023 {
        // W3C WebAuthn §5.8.3 says credentialId is at most 1023 bytes
        // for backwards compat with CTAP1.
        return Err(AuthDataError::CredIdTooLong(cred_id_len));
    }
    buf = &buf[18..];
    if buf.len() < cred_id_len {
        return Err(AuthDataError::TooShort { len: data.len() });
    }
    let credential_id = buf[..cred_id_len].to_vec();
    buf = &buf[cred_id_len..];

    // The COSE key is a CBOR map. Decode it AND advance past it so we
    // can correctly skip any trailing ED extensions block.
    let mut cbor_buf = buf;
    let credential_public_key = cose::decode_es256(buf)?;
    // Step over the COSE key's bytes by skip_value on a fresh cursor.
    cbor::skip_value(&mut cbor_buf)?;
    let _ = cbor_buf; // remaining bytes (if any) are the ED extensions block

    // We don't parse the ED block — its presence is allowed by the
    // spec. Don't error on trailing bytes; just ignore them.
    Ok(AttestedCredentialData {
        prefix,
        aaguid,
        credential_id,
        credential_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal authenticatorData with AT set and a canonical
    /// ES256 COSE key.
    fn build(
        rp_hash: [u8; 32],
        flags: u8,
        sign_count: u32,
        cred_id: &[u8],
        x: &[u8; 32],
        y: &[u8; 32],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&rp_hash);
        v.push(flags);
        v.extend_from_slice(&sign_count.to_be_bytes());
        // attested cred data
        v.extend_from_slice(&[0u8; 16]); // aaguid
        v.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        v.extend_from_slice(cred_id);
        // COSE key (canonical, 5-entry map)
        v.push(0xa5);
        v.extend_from_slice(&[0x01, 0x02]);
        v.extend_from_slice(&[0x03, 0x26]);
        v.extend_from_slice(&[0x20, 0x01]);
        v.extend_from_slice(&[0x21, 0x58, 32]);
        v.extend_from_slice(x);
        v.extend_from_slice(&[0x22, 0x58, 32]);
        v.extend_from_slice(y);
        v
    }

    #[test]
    fn parses_prefix() {
        let data = build(
            [9u8; 32],
            FLAG_UP | FLAG_AT,
            42,
            &[1, 2, 3],
            &[7u8; 32],
            &[8u8; 32],
        );
        let p = parse_prefix(&data).unwrap();
        assert_eq!(p.rp_id_hash, [9u8; 32]);
        assert_eq!(p.flags, FLAG_UP | FLAG_AT);
        assert_eq!(p.sign_count, 42);
        assert!(p.user_present());
        assert!(p.attested_cred_data());
    }

    #[test]
    fn parses_attested_credential_data() {
        let cred_id = b"my-credential-id";
        let x = [11u8; 32];
        let y = [12u8; 32];
        let data = build([0u8; 32], FLAG_UP | FLAG_AT, 1, cred_id, &x, &y);
        let parsed = parse_attested(&data).unwrap();
        assert_eq!(parsed.credential_id, cred_id);
        assert_eq!(parsed.aaguid, [0u8; 16]);
        assert_eq!(&parsed.credential_public_key[1..33], &x);
        assert_eq!(&parsed.credential_public_key[33..65], &y);
        assert_eq!(parsed.prefix.sign_count, 1);
    }

    #[test]
    fn rejects_missing_at_flag() {
        let data = build([0u8; 32], FLAG_UP, 0, &[1, 2], &[1u8; 32], &[2u8; 32]);
        // Strip the attested cred data so length doesn't lie about it.
        let data = data[..HEADER_LEN].to_vec();
        let err = parse_attested(&data).unwrap_err();
        assert!(
            matches!(err, AuthDataError::MissingAttestedCredData),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_too_short() {
        let data = [0u8; 36];
        assert!(matches!(
            parse_prefix(&data),
            Err(AuthDataError::TooShort { .. })
        ));
    }

    #[test]
    fn tolerates_trailing_ed_bytes() {
        // Build a normal authData then append a CBOR map(0) (0xa0) as
        // a fake ED extensions block.
        let mut data = build(
            [0u8; 32],
            FLAG_UP | FLAG_AT | FLAG_ED,
            7,
            &[1],
            &[3u8; 32],
            &[4u8; 32],
        );
        data.push(0xa0);
        let parsed = parse_attested(&data).unwrap();
        assert_eq!(parsed.credential_id, &[1]);
    }
}
