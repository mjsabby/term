//! Wire frame protocol used both hub<->agent (single persistent TCP/TLS,
//! multiplexed) and browser<->hub (binary WebSocket messages).
//!
//! ```text
//! +-------------+------+-------------+---------------+
//! | stream_id   | type | length (BE) | payload       |
//! | u32 BE      | u8   | u32         | length bytes  |
//! +-------------+------+-------------+---------------+
//! ```
//!
//! Header is exactly 9 bytes; payload is `length` bytes (0..=max-per-type).
//!
//! Stream IDs:
//! - **0** is reserved for control frames (`Hello`, `Ping`, `Pong`).
//! - All other IDs are allocated by the **hub** when it opens a new
//!   data stream toward the agent (monotonic per connection).
//!
//! On the browser<->hub WebSocket, `stream_id` is always 0 (the WS
//! connection itself is the demux), and the hub injects a real
//! `stream_id` when forwarding into the agent multiplex.

use std::io;

pub const HEADER_LEN: usize = 9;

/// Per-frame-type payload caps.
pub const MAX_DATA_LEN:        u32 = 64 * 1024;
pub const MAX_SESSION_ID_LEN:  u32 = 64;
pub const MAX_HELLO_LEN:       u32 = 1024;
pub const MAX_PING_LEN:        u32 = 64;

pub const CONTROL_STREAM: u32 = 0;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
    /// PTY bytes, both directions. Stream-scoped; stream_id != 0.
    Data = 0,
    /// Terminal resize. Payload = `rows:u16 BE, cols:u16 BE` (4 bytes).
    /// Hub -> agent only. Stream-scoped; stream_id != 0.
    Resize = 1,
    /// First frame of a new data stream. Hub -> agent only. Payload is
    /// a UTF-8 `session_id` matching `[A-Za-z0-9_-]{1,64}`. The agent
    /// uses this to `tmux new-session -A -s <id>`.
    Open = 2,
    /// Stream end. Either direction. No payload. After sending Close
    /// for a stream, neither side sends more frames on that stream.
    Close = 3,
    /// Keepalive, sender side. Stream 0. Payload <= 64B, echoed back.
    Ping = 4,
    /// Keepalive reply. Stream 0. Payload is the matching Ping's payload.
    Pong = 5,
    /// Connection-level greeting, agent -> hub, sent as the FIRST frame
    /// on stream 0. Payload is JSON: `{ "version": u32, "machine_id":
    /// "<id>", "psk_b64": "<base64-32-bytes>" }`.
    Hello = 6,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(FrameType::Data),
            1 => Some(FrameType::Resize),
            2 => Some(FrameType::Open),
            3 => Some(FrameType::Close),
            4 => Some(FrameType::Ping),
            5 => Some(FrameType::Pong),
            6 => Some(FrameType::Hello),
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
    #[error("invalid close payload length: {0} (expected 0)")]
    InvalidCloseLen(u32),
    #[error("invalid session id (must be 1..=64 of [A-Za-z0-9_-])")]
    InvalidSessionId,
    #[error("session_id not utf-8")]
    SessionIdNotUtf8,
    #[error("control frame on data stream (id={0})")]
    ControlOnDataStream(u32),
    #[error("data frame on control stream")]
    DataOnControlStream,
}

#[derive(Debug, Clone)]
pub enum Body {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Open(String),
    Close,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Hello(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub stream_id: u32,
    pub body: Body,
}

impl Frame {
    pub fn data(stream_id: u32, bytes: Vec<u8>) -> Self {
        Self { stream_id, body: Body::Data(bytes) }
    }
    pub fn resize(stream_id: u32, rows: u16, cols: u16) -> Self {
        Self { stream_id, body: Body::Resize { rows, cols } }
    }
    pub fn open(stream_id: u32, session_id: String) -> Self {
        Self { stream_id, body: Body::Open(session_id) }
    }
    pub fn close(stream_id: u32) -> Self {
        Self { stream_id, body: Body::Close }
    }
    pub fn ping(payload: Vec<u8>) -> Self {
        Self { stream_id: CONTROL_STREAM, body: Body::Ping(payload) }
    }
    pub fn pong(payload: Vec<u8>) -> Self {
        Self { stream_id: CONTROL_STREAM, body: Body::Pong(payload) }
    }
    pub fn hello(payload: Vec<u8>) -> Self {
        Self { stream_id: CONTROL_STREAM, body: Body::Hello(payload) }
    }

    pub fn ty(&self) -> FrameType {
        match &self.body {
            Body::Data(_)     => FrameType::Data,
            Body::Resize { .. } => FrameType::Resize,
            Body::Open(_)     => FrameType::Open,
            Body::Close       => FrameType::Close,
            Body::Ping(_)     => FrameType::Ping,
            Body::Pong(_)     => FrameType::Pong,
            Body::Hello(_)    => FrameType::Hello,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload: std::borrow::Cow<'_, [u8]> = match &self.body {
            Body::Data(b)  => std::borrow::Cow::Borrowed(b),
            Body::Open(s)  => std::borrow::Cow::Borrowed(s.as_bytes()),
            Body::Ping(b)  => std::borrow::Cow::Borrowed(b),
            Body::Pong(b)  => std::borrow::Cow::Borrowed(b),
            Body::Hello(b) => std::borrow::Cow::Borrowed(b),
            Body::Close    => std::borrow::Cow::Borrowed(&[][..]),
            Body::Resize { rows, cols } => {
                let mut p = Vec::with_capacity(4);
                p.extend_from_slice(&rows.to_be_bytes());
                p.extend_from_slice(&cols.to_be_bytes());
                std::borrow::Cow::Owned(p)
            }
        };
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.ty() as u8);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Validate header `(stream_id, type, length)` without touching the
    /// payload. Returns the typed frame type plus the validated length.
    pub fn validate_header(
        stream_id: u32,
        ty_byte: u8,
        len: u32,
    ) -> Result<(FrameType, u32), FrameError> {
        let ty = FrameType::from_u8(ty_byte).ok_or(FrameError::UnknownType(ty_byte))?;
        match ty {
            FrameType::Data => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len > MAX_DATA_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_DATA_LEN });
                }
            }
            FrameType::Resize => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != 4 { return Err(FrameError::InvalidResizeLen(len)); }
            }
            FrameType::Open => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len == 0 || len > MAX_SESSION_ID_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_SESSION_ID_LEN });
                }
            }
            FrameType::Close => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != 0 { return Err(FrameError::InvalidCloseLen(len)); }
            }
            FrameType::Ping | FrameType::Pong => {
                if stream_id != CONTROL_STREAM {
                    return Err(FrameError::ControlOnDataStream(stream_id));
                }
                if len > MAX_PING_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_PING_LEN });
                }
            }
            FrameType::Hello => {
                if stream_id != CONTROL_STREAM {
                    return Err(FrameError::ControlOnDataStream(stream_id));
                }
                if len == 0 || len > MAX_HELLO_LEN {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_HELLO_LEN });
                }
            }
        }
        Ok((ty, len))
    }

    pub fn from_payload(
        stream_id: u32,
        ty: FrameType,
        payload: Vec<u8>,
    ) -> Result<Self, FrameError> {
        let body = match ty {
            FrameType::Data   => Body::Data(payload),
            FrameType::Open   => {
                let s = String::from_utf8(payload).map_err(|_| FrameError::SessionIdNotUtf8)?;
                if !is_valid_session_id(&s) { return Err(FrameError::InvalidSessionId); }
                Body::Open(s)
            }
            FrameType::Close  => Body::Close,
            FrameType::Resize => {
                let rows = u16::from_be_bytes([payload[0], payload[1]]);
                let cols = u16::from_be_bytes([payload[2], payload[3]]);
                Body::Resize { rows, cols }
            }
            FrameType::Ping   => Body::Ping(payload),
            FrameType::Pong   => Body::Pong(payload),
            FrameType::Hello  => Body::Hello(payload),
        };
        Ok(Frame { stream_id, body })
    }
}

/// Session IDs may contain only `[A-Za-z0-9_-]` and must be 1..=64 chars.
/// Restricting to this set means we can safely pass them as a `tmux -s`
/// argument with no quoting concerns.
pub fn is_valid_session_id(s: &str) -> bool {
    let n = s.len();
    if n == 0 || n > MAX_SESSION_ID_LEN as usize { return false; }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The agent's first frame to the hub. JSON-encoded into the Hello frame
/// payload so we can add fields later without breaking the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HelloPayload {
    pub version: u32,
    pub machine_id: String,
    pub psk_b64: String,
}
pub const HELLO_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_data() {
        let f = Frame::data(7, b"hi".to_vec());
        let bytes = f.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2);
        assert_eq!(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 7);
        assert_eq!(bytes[4], FrameType::Data as u8);
        assert_eq!(u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]), 2);
    }

    #[test]
    fn round_trip_resize() {
        let f = Frame::resize(3, 24, 80);
        let bytes = f.encode();
        let (ty, len) = Frame::validate_header(3, bytes[4], 4).unwrap();
        assert_eq!(ty, FrameType::Resize);
        assert_eq!(len, 4);
        let decoded = Frame::from_payload(3, ty, bytes[HEADER_LEN..].to_vec()).unwrap();
        match decoded.body {
            Body::Resize { rows, cols } => assert_eq!((rows, cols), (24, 80)),
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_data_on_control_stream() {
        let e = Frame::validate_header(0, FrameType::Data as u8, 1).unwrap_err();
        assert!(matches!(e, FrameError::DataOnControlStream));
    }

    #[test]
    fn rejects_ping_on_data_stream() {
        let e = Frame::validate_header(5, FrameType::Ping as u8, 0).unwrap_err();
        assert!(matches!(e, FrameError::ControlOnDataStream(5)));
    }

    #[test]
    fn rejects_oversized_data() {
        let e = Frame::validate_header(1, 0, MAX_DATA_LEN + 1).unwrap_err();
        assert!(matches!(e, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn rejects_bad_resize_len() {
        let e = Frame::validate_header(1, 1, 6).unwrap_err();
        assert!(matches!(e, FrameError::InvalidResizeLen(6)));
    }

    #[test]
    fn rejects_unknown_type() {
        let e = Frame::validate_header(1, 99, 0).unwrap_err();
        assert!(matches!(e, FrameError::UnknownType(99)));
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
    fn hello_round_trip() {
        let h = HelloPayload {
            version: HELLO_VERSION,
            machine_id: "alpha".into(),
            psk_b64: "AAAA".into(),
        };
        let bytes = serde_json::to_vec(&h).unwrap();
        let f = Frame::hello(bytes.clone());
        let enc = f.encode();
        let (ty, _) = Frame::validate_header(0, enc[4], bytes.len() as u32).unwrap();
        assert_eq!(ty, FrameType::Hello);
        let back = Frame::from_payload(0, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::Hello(b) => {
                let h2: HelloPayload = serde_json::from_slice(&b).unwrap();
                assert_eq!(h2.machine_id, "alpha");
            }
            _ => panic!(),
        }
    }
}
