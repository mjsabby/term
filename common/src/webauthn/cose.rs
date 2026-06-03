//! Parse an ES256 COSE_Key (RFC 8152 §13.1.1) into a SEC1-uncompressed
//! P-256 public key (0x04 || x || y, 65 bytes).
//!
//! The COSE map for ES256 has these labels:
//!
//! ```text
//!  1 (kty)  -> 2   (EC2)
//!  3 (alg)  -> -7  (ES256)
//! -1 (crv)  -> 1   (P-256)
//! -2 (x)    -> bytes(32)
//! -3 (y)    -> bytes(32)
//! ```
//!
//! Extra fields are ignored (some authenticators include alg even when
//! we didn't ask for it, or attach extension labels). We do require
//! kty/crv/x/y to be present and well-typed; alg is sanity-checked if
//! present.

use super::cbor::{self, CborError};

#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    #[error("cbor: {0}")]
    Cbor(#[from] CborError),
    #[error("unsupported algorithm: expected ES256 (-7), got {0}")]
    UnsupportedAlg(i64),
    #[error("unsupported curve: expected P-256 (1), got {0}")]
    UnsupportedCurve(i64),
    #[error("unsupported key type: expected EC2 (2), got {0}")]
    UnsupportedKty(i64),
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error("coordinate {0} is {1} bytes, expected 32")]
    BadCoordLen(&'static str, usize),
}

/// SEC1-uncompressed encoding of a P-256 public key.
pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const ES256_ALG: i64 = -7;
pub const P256_CRV: i64 = 1;
pub const EC2_KTY: i64 = 2;

/// Decode an ES256 COSE key. Returns the 65-byte SEC1-uncompressed
/// encoding suitable for `p256::ecdsa::VerifyingKey::from_sec1_bytes`.
pub fn decode_es256(bytes: &[u8]) -> Result<[u8; SEC1_UNCOMPRESSED_LEN], CoseError> {
    let mut buf = bytes;
    let n = cbor::read_map_header(&mut buf)?;

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;

    for _ in 0..n {
        let key = cbor::read_int(&mut buf)?;
        match key {
            1 => kty = Some(cbor::read_int(&mut buf)?),
            3 => alg = Some(cbor::read_int(&mut buf)?),
            -1 => crv = Some(cbor::read_int(&mut buf)?),
            -2 => x = Some(cbor::read_bytes(&mut buf)?.to_vec()),
            -3 => y = Some(cbor::read_bytes(&mut buf)?.to_vec()),
            _ => cbor::skip_value(&mut buf)?,
        }
    }

    let kty = kty.ok_or(CoseError::MissingField("kty"))?;
    if kty != EC2_KTY {
        return Err(CoseError::UnsupportedKty(kty));
    }
    if let Some(a) = alg {
        if a != ES256_ALG {
            return Err(CoseError::UnsupportedAlg(a));
        }
    }
    let crv = crv.ok_or(CoseError::MissingField("crv"))?;
    if crv != P256_CRV {
        return Err(CoseError::UnsupportedCurve(crv));
    }
    let x = x.ok_or(CoseError::MissingField("x"))?;
    let y = y.ok_or(CoseError::MissingField("y"))?;
    if x.len() != 32 {
        return Err(CoseError::BadCoordLen("x", x.len()));
    }
    if y.len() != 32 {
        return Err(CoseError::BadCoordLen("y", y.len()));
    }

    let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&x);
    out[33..65].copy_from_slice(&y);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a canonical ES256 COSE_Key with the given (x, y).
    fn build_cose(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(80);
        // map(5)
        v.push(0xa5);
        // 1 (kty) -> 2 (EC2)
        v.push(0x01);
        v.push(0x02);
        // 3 (alg) -> -7 (ES256) ; -7 == nint(6) => 0x26
        v.push(0x03);
        v.push(0x26);
        // -1 (crv) -> 1 (P-256) ; -1 == nint(0) => 0x20
        v.push(0x20);
        v.push(0x01);
        // -2 (x) -> bytes(32)
        v.push(0x21);
        v.push(0x58);
        v.push(32);
        v.extend_from_slice(x);
        // -3 (y) -> bytes(32)
        v.push(0x22);
        v.push(0x58);
        v.push(32);
        v.extend_from_slice(y);
        v
    }

    #[test]
    fn decodes_canonical_es256() {
        let x = [1u8; 32];
        let y = [2u8; 32];
        let cose = build_cose(&x, &y);
        let sec1 = decode_es256(&cose).unwrap();
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x);
        assert_eq!(&sec1[33..65], &y);
    }

    #[test]
    fn ignores_extra_fields() {
        // Add a bogus field 99 -> "hi" between alg and crv.
        let x = [1u8; 32];
        let y = [2u8; 32];
        let mut v = vec![0xa6]; // map(6)
        v.extend_from_slice(&[0x01, 0x02]); // kty
        v.extend_from_slice(&[0x03, 0x26]); // alg
        v.extend_from_slice(&[0x18, 99, 0x62, b'h', b'i']); // 99 -> "hi"
        v.extend_from_slice(&[0x20, 0x01]); // crv
        v.extend_from_slice(&[0x21, 0x58, 32]);
        v.extend_from_slice(&x);
        v.extend_from_slice(&[0x22, 0x58, 32]);
        v.extend_from_slice(&y);
        let sec1 = decode_es256(&v).unwrap();
        assert_eq!(&sec1[1..33], &x);
    }

    #[test]
    fn rejects_wrong_alg() {
        let mut v = build_cose(&[3u8; 32], &[4u8; 32]);
        v[5] = 0x39; // 2-byte nint encoding starts at info=25, but
                     // simpler: rewrite alg value 0x26 → some other.
                     // Easier: build a custom map.
        let mut v = vec![
            0xa4, // map(4)
            0x01, 0x02, // kty=2
            0x03, 0x27, // alg=-8 (nint 7)
            0x20, 0x01, // crv=1
            0x21, 0x58, 32, // x
        ];
        v.extend_from_slice(&[5u8; 32]);
        v.extend_from_slice(&[0x22, 0x58, 32]);
        v.extend_from_slice(&[6u8; 32]);
        // Need to update map header to 5 entries; we have 4 above.
        v[0] = 0xa5;
        v.insert(1, 0x22);
        v.insert(2, 0x58);
        v.insert(3, 32);
        // ↑ this is getting silly; rewrite properly:
        let v = {
            let mut v = vec![0xa4];
            v.extend_from_slice(&[0x01, 0x02]);
            v.extend_from_slice(&[0x03, 0x27]); // alg -8
            v.extend_from_slice(&[0x20, 0x01]);
            v.extend_from_slice(&[0x21, 0x58, 32]);
            v.extend_from_slice(&[5u8; 32]);
            v.extend_from_slice(&[0x22, 0x58, 32]);
            v.extend_from_slice(&[6u8; 32]);
            v[0] = 0xa5;
            v
        };
        assert!(matches!(
            decode_es256(&v),
            Err(CoseError::UnsupportedAlg(-8))
        ));
    }

    #[test]
    fn rejects_missing_x() {
        let mut v = vec![0xa4, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x22, 0x58, 32];
        v.extend_from_slice(&[7u8; 32]);
        assert!(matches!(
            decode_es256(&v),
            Err(CoseError::MissingField("x"))
        ));
    }

    #[test]
    fn rejects_short_y() {
        let mut v = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 32];
        v.extend_from_slice(&[1u8; 32]);
        v.extend_from_slice(&[0x22, 0x58, 16]); // claim only 16 bytes
        v.extend_from_slice(&[2u8; 16]);
        assert!(matches!(
            decode_es256(&v),
            Err(CoseError::BadCoordLen("y", 16))
        ));
    }
}
