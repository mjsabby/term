//! Wire frame protocol used both hub<->agent (raw TCP) and browser<->hub
//! (binary WebSocket messages).
//!
//! ```text
//! +------+-------------+---------------+
//! | type | length (BE) | payload       |
//! | u8   | u32         | length bytes  |
//! +------+-------------+---------------+
//! ```
//!
//! Header is exactly 5 bytes; payload is `length` bytes (0..=MAX_DATA_LEN).
//! Unknown frame types are rejected. Reserve type IDs 3..=7 for a future
//! file-transfer bolt-on so a connection can multiplex transfers.

use std::io;

pub const HEADER_LEN: usize = 5;

/// Maximum payload size for a `data` frame, in bytes.
pub const MAX_DATA_LEN: u32 = 64 * 1024;
/// Maximum size of the `session_id` payload in an `open` frame.
pub const MAX_SESSION_ID_LEN: u32 = 64;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
    /// PTY bytes, both directions. Payload is the raw bytes.
    Data = 0,
    /// Terminal resize. Payload is exactly 4 bytes: `rows:u16 BE`, `cols:u16 BE`.
    /// Sent only from browser/hub toward the agent.
    Resize = 1,
    /// First frame on every hub->agent connection. Payload is a UTF-8
    /// `session_id` matching `[A-Za-z0-9_-]{1,64}`. Selects (and on the
    /// agent, creates-or-attaches) the tmux session.
    Open = 2,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(FrameType::Data),
            1 => Some(FrameType::Resize),
            2 => Some(FrameType::Open),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("unknown frame type: {0}")]
    UnknownType(u8),
    #[error("payload too large: type={ty:?} len={len} max={max}")]
    PayloadTooLarge { ty: FrameType, len: u32, max: u32 },
    #[error("invalid resize payload length: {0} (expected 4)")]
    InvalidResizeLen(u32),
    #[error("invalid session id (must be 1..=64 of [A-Za-z0-9_-])")]
    InvalidSessionId,
    #[error("session_id not utf-8")]
    SessionIdNotUtf8,
}

#[derive(Debug, Clone)]
pub enum Frame {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Open(String),
}

impl Frame {
    /// Encode a frame to a fresh Vec<u8>. Header + payload, ready to write.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Data(buf) => {
                let mut out = Vec::with_capacity(HEADER_LEN + buf.len());
                out.push(FrameType::Data as u8);
                out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
                out.extend_from_slice(buf);
                out
            }
            Frame::Resize { rows, cols } => {
                let mut out = Vec::with_capacity(HEADER_LEN + 4);
                out.push(FrameType::Resize as u8);
                out.extend_from_slice(&4u32.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
                out.extend_from_slice(&cols.to_be_bytes());
                out
            }
            Frame::Open(id) => {
                let bytes = id.as_bytes();
                let mut out = Vec::with_capacity(HEADER_LEN + bytes.len());
                out.push(FrameType::Open as u8);
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
                out
            }
        }
    }

    /// Validate the header pair (type, length) without reading payload.
    /// Returns the typed kind plus the validated length.
    pub fn validate_header(ty_byte: u8, len: u32) -> Result<(FrameType, u32), FrameError> {
        let ty = FrameType::from_u8(ty_byte).ok_or(FrameError::UnknownType(ty_byte))?;
        match ty {
            FrameType::Data => {
                if len > MAX_DATA_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_DATA_LEN });
                }
            }
            FrameType::Resize => {
                if len != 4 {
                    return Err(FrameError::InvalidResizeLen(len));
                }
            }
            FrameType::Open => {
                if len == 0 || len > MAX_SESSION_ID_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_SESSION_ID_LEN });
                }
            }
        }
        Ok((ty, len))
    }

    /// Construct a typed frame from a validated header and a payload buffer.
    pub fn from_payload(ty: FrameType, payload: Vec<u8>) -> Result<Self, FrameError> {
        match ty {
            FrameType::Data => Ok(Frame::Data(payload)),
            FrameType::Resize => {
                // length was validated == 4
                let rows = u16::from_be_bytes([payload[0], payload[1]]);
                let cols = u16::from_be_bytes([payload[2], payload[3]]);
                Ok(Frame::Resize { rows, cols })
            }
            FrameType::Open => {
                let s = String::from_utf8(payload).map_err(|_| FrameError::SessionIdNotUtf8)?;
                if !is_valid_session_id(&s) {
                    return Err(FrameError::InvalidSessionId);
                }
                Ok(Frame::Open(s))
            }
        }
    }
}

/// Session IDs may contain only `[A-Za-z0-9_-]` and must be 1..=64 chars.
/// Restricting to this set means we can safely pass them to `tmux -s ARG`
/// without any quoting concerns.
pub fn is_valid_session_id(s: &str) -> bool {
    let n = s.len();
    if n == 0 || n > MAX_SESSION_ID_LEN as usize {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_data() {
        let f = Frame::Data(b"hello world".to_vec());
        let bytes = f.encode();
        assert_eq!(bytes[0], 0);
        assert_eq!(u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]), 11);
        assert_eq!(&bytes[5..], b"hello world");

        let (ty, len) = Frame::validate_header(bytes[0], 11).unwrap();
        assert_eq!(ty, FrameType::Data);
        assert_eq!(len, 11);
    }

    #[test]
    fn round_trip_resize() {
        let f = Frame::Resize { rows: 24, cols: 80 };
        let bytes = f.encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes.len(), HEADER_LEN + 4);
        let (ty, _) = Frame::validate_header(1, 4).unwrap();
        let decoded = Frame::from_payload(ty, bytes[5..].to_vec()).unwrap();
        match decoded {
            Frame::Resize { rows, cols } => assert_eq!((rows, cols), (24, 80)),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn open_session_validation() {
        assert!(is_valid_session_id("abc-123_XYZ"));
        assert!(!is_valid_session_id(""));
        assert!(!is_valid_session_id("a b"));
        assert!(!is_valid_session_id("a;b"));
        assert!(!is_valid_session_id(&"x".repeat(65)));
    }

    #[test]
    fn rejects_oversized_data() {
        let err = Frame::validate_header(0, MAX_DATA_LEN + 1).unwrap_err();
        matches!(err, FrameError::PayloadTooLarge { .. });
    }

    #[test]
    fn rejects_bad_resize_len() {
        let err = Frame::validate_header(1, 6).unwrap_err();
        matches!(err, FrameError::InvalidResizeLen(6));
    }

    #[test]
    fn rejects_unknown_type() {
        let err = Frame::validate_header(99, 0).unwrap_err();
        matches!(err, FrameError::UnknownType(99));
    }
}
