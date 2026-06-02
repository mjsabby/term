//! Minimal CBOR reader. Sized for exactly the two shapes WebAuthn hands
//! us — `attestationObject` (a 2- or 3-entry text-keyed map) and the
//! COSE public key (a 4- or 5-entry integer-keyed map) — not a general
//! decoder. RFC 8949 major types 0..5 are supported, indefinite-length
//! items and tagged items are not (none of the wire shapes we parse
//! use them).
//!
//! Cursor-style API: each `read_*` advances `*buf`; on failure the
//! cursor is left in an undefined position (callers are expected to
//! bail on the first error).

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CborError {
    #[error("unexpected EOF (need {need} more bytes)")]
    Eof { need: usize },
    #[error("unsupported additional-info {info} for major {major}")]
    UnsupportedInfo { major: u8, info: u8 },
    #[error("expected major {expected}, got {got}")]
    WrongMajor { expected: u8, got: u8 },
    #[error("length {n} exceeds {cap}")]
    TooLarge { n: u64, cap: u64 },
    #[error("invalid utf-8")]
    Utf8,
    #[error("nesting too deep")]
    NestingTooDeep,
}

/// Hard cap on any single byte/text string length we'll allocate.
/// 64 KiB comfortably fits credential IDs (≤256 B), COSE keys
/// (≤200 B), and the largest plausible authData (~1 KiB).
const MAX_STRING: u64 = 64 * 1024;
const MAX_NESTING: u32 = 6;

pub const MAJOR_UINT:  u8 = 0;
pub const MAJOR_NINT:  u8 = 1;
pub const MAJOR_BYTES: u8 = 2;
pub const MAJOR_TEXT:  u8 = 3;
pub const MAJOR_ARRAY: u8 = 4;
pub const MAJOR_MAP:   u8 = 5;

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], CborError> {
    if buf.len() < n {
        return Err(CborError::Eof { need: n - buf.len() });
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Ok(head)
}

/// Read one initial byte, returning `(major, additional_info)`.
fn peek_header(buf: &[u8]) -> Result<(u8, u8), CborError> {
    if buf.is_empty() { return Err(CborError::Eof { need: 1 }); }
    let b = buf[0];
    Ok((b >> 5, b & 0x1f))
}

/// Read the initial byte and (where the additional-info indicates)
/// the following 1/2/4/8 bytes of length-or-value. Returns
/// `(major, value)`.
pub fn read_head(buf: &mut &[u8]) -> Result<(u8, u64), CborError> {
    let (major, info) = peek_header(buf)?;
    take(buf, 1)?;
    let v = match info {
        0..=23 => info as u64,
        24 => take(buf, 1)?[0] as u64,
        25 => {
            let b = take(buf, 2)?;
            u16::from_be_bytes([b[0], b[1]]) as u64
        }
        26 => {
            let b = take(buf, 4)?;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
        }
        27 => {
            let b = take(buf, 8)?;
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
        _ => return Err(CborError::UnsupportedInfo { major, info }),
    };
    Ok((major, v))
}

/// Read a positive integer (major 0). Returns the value as u64.
pub fn read_uint(buf: &mut &[u8]) -> Result<u64, CborError> {
    let (m, v) = read_head(buf)?;
    if m != MAJOR_UINT {
        return Err(CborError::WrongMajor { expected: MAJOR_UINT, got: m });
    }
    Ok(v)
}

/// Read either a positive or negative integer and return it as i64.
/// CBOR negative-integer encoding: value `v` decodes to `-1 - v`.
pub fn read_int(buf: &mut &[u8]) -> Result<i64, CborError> {
    let (m, v) = read_head(buf)?;
    match m {
        MAJOR_UINT => i64::try_from(v).map_err(|_| CborError::TooLarge { n: v, cap: i64::MAX as u64 }),
        MAJOR_NINT => {
            let neg = -1i128 - v as i128;
            i64::try_from(neg).map_err(|_| CborError::TooLarge { n: v, cap: i64::MAX as u64 })
        }
        _ => Err(CborError::WrongMajor { expected: MAJOR_UINT, got: m }),
    }
}

/// Read a byte string (major 2). Borrows from the underlying buffer.
pub fn read_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], CborError> {
    let (m, len) = read_head(buf)?;
    if m != MAJOR_BYTES {
        return Err(CborError::WrongMajor { expected: MAJOR_BYTES, got: m });
    }
    if len > MAX_STRING {
        return Err(CborError::TooLarge { n: len, cap: MAX_STRING });
    }
    take(buf, len as usize)
}

/// Read a text string (major 3). Borrows from the underlying buffer.
pub fn read_text<'a>(buf: &mut &'a [u8]) -> Result<&'a str, CborError> {
    let (m, len) = read_head(buf)?;
    if m != MAJOR_TEXT {
        return Err(CborError::WrongMajor { expected: MAJOR_TEXT, got: m });
    }
    if len > MAX_STRING {
        return Err(CborError::TooLarge { n: len, cap: MAX_STRING });
    }
    let raw = take(buf, len as usize)?;
    std::str::from_utf8(raw).map_err(|_| CborError::Utf8)
}

/// Read a map header (major 5), returning the entry count.
pub fn read_map_header(buf: &mut &[u8]) -> Result<u64, CborError> {
    let (m, n) = read_head(buf)?;
    if m != MAJOR_MAP {
        return Err(CborError::WrongMajor { expected: MAJOR_MAP, got: m });
    }
    Ok(n)
}

/// Skip exactly one CBOR value (of any major type 0..=5). Used to
/// step over a map value we don't care about (e.g. `attStmt`).
pub fn skip_value(buf: &mut &[u8]) -> Result<(), CborError> {
    skip_value_depth(buf, 0)
}

fn skip_value_depth(buf: &mut &[u8], depth: u32) -> Result<(), CborError> {
    if depth > MAX_NESTING { return Err(CborError::NestingTooDeep); }
    let (major, len) = read_head(buf)?;
    match major {
        MAJOR_UINT | MAJOR_NINT => Ok(()),
        MAJOR_BYTES | MAJOR_TEXT => {
            if len > MAX_STRING { return Err(CborError::TooLarge { n: len, cap: MAX_STRING }); }
            take(buf, len as usize)?;
            Ok(())
        }
        MAJOR_ARRAY => {
            for _ in 0..len { skip_value_depth(buf, depth + 1)?; }
            Ok(())
        }
        MAJOR_MAP => {
            for _ in 0..len {
                skip_value_depth(buf, depth + 1)?; // key
                skip_value_depth(buf, depth + 1)?; // value
            }
            Ok(())
        }
        _ => Err(CborError::UnsupportedInfo { major, info: 0 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_small_uint() {
        let mut b: &[u8] = &[0x05];
        assert_eq!(read_uint(&mut b).unwrap(), 5);
    }

    #[test]
    fn read_uint_24() {
        let mut b: &[u8] = &[0x18, 0xff];
        assert_eq!(read_uint(&mut b).unwrap(), 255);
    }

    #[test]
    fn read_uint_64bit() {
        let mut b: &[u8] = &[0x1b, 0,0,0,0, 0,0,0x01,0x00];
        assert_eq!(read_uint(&mut b).unwrap(), 256);
    }

    #[test]
    fn read_negative_int() {
        // -7 encodes as major 1, value 6 (because -1 - 6 == -7).
        let mut b: &[u8] = &[0x26];
        assert_eq!(read_int(&mut b).unwrap(), -7);
        // -1 -> major 1, value 0.
        let mut b: &[u8] = &[0x20];
        assert_eq!(read_int(&mut b).unwrap(), -1);
    }

    #[test]
    fn read_byte_string() {
        let mut b: &[u8] = &[0x43, 0xaa, 0xbb, 0xcc];
        assert_eq!(read_bytes(&mut b).unwrap(), &[0xaa, 0xbb, 0xcc][..]);
    }

    #[test]
    fn read_text_string() {
        // "abc" = 0x63 0x61 0x62 0x63
        let mut b: &[u8] = &[0x63, b'a', b'b', b'c'];
        assert_eq!(read_text(&mut b).unwrap(), "abc");
    }

    #[test]
    fn read_text_long() {
        // 24-byte text "abcdefghijklmnopqrstuvwx" → 0x78 0x18 ...
        let s = "abcdefghijklmnopqrstuvwx";
        let mut v = vec![0x78, 0x18];
        v.extend_from_slice(s.as_bytes());
        let mut b: &[u8] = &v;
        assert_eq!(read_text(&mut b).unwrap(), s);
    }

    #[test]
    fn read_map_two_entries() {
        // {1: 2}  → 0xa1 0x01 0x02
        let mut b: &[u8] = &[0xa1, 0x01, 0x02];
        assert_eq!(read_map_header(&mut b).unwrap(), 1);
        assert_eq!(read_uint(&mut b).unwrap(), 1);
        assert_eq!(read_uint(&mut b).unwrap(), 2);
    }

    #[test]
    fn skip_value_handles_nested_map() {
        // {0: {1: [2, 3]}, 4: 5}  — skip the whole thing
        let cbor = &[
            0xa2,                   // map(2)
              0x00,                 // key 0
              0xa1,                 // map(1)
                0x01,               // key 1
                0x82, 0x02, 0x03,   // array [2,3]
              0x04, 0x05,           // 4 -> 5
        ];
        let mut b: &[u8] = cbor;
        skip_value(&mut b).unwrap();
        assert!(b.is_empty());
    }

    #[test]
    fn skip_value_steps_past_byte_string() {
        // map(1) { "a": h'aabb' }  followed by trailing 0xff
        let cbor: &[u8] = &[0xa1, 0x61, b'a', 0x42, 0xaa, 0xbb, 0xff];
        let mut b: &[u8] = cbor;
        skip_value(&mut b).unwrap();
        assert_eq!(b, &[0xff][..]);
    }

    #[test]
    fn eof_short_byte_string() {
        let mut b: &[u8] = &[0x43, 0xaa]; // declares 3 bytes, gives 1
        assert_eq!(read_bytes(&mut b).unwrap_err(), CborError::Eof { need: 2 });
    }

    #[test]
    fn rejects_too_large_string() {
        // Major 2, info 27 → next 8 bytes = length. 1 MiB > 64 KiB cap.
        let mut b: &[u8] = &[
            0x5b, 0,0,0,0, 0,0x10,0,0, // length 0x100000 = 1 MiB
        ];
        assert!(matches!(read_bytes(&mut b), Err(CborError::TooLarge { .. })));
    }

    #[test]
    fn rejects_wrong_major() {
        let mut b: &[u8] = &[0x05]; // uint, not bytes
        assert!(matches!(read_bytes(&mut b), Err(CborError::WrongMajor { .. })));
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x9f = array(*) — indefinite length, not supported.
        let mut b: &[u8] = &[0x9f, 0xff];
        assert!(matches!(skip_value(&mut b), Err(CborError::UnsupportedInfo { .. })));
    }
}
