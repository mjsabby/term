//! Transport abstraction for the agent↔hub mux.
//!
//! The wire [`Frame`] protocol is carried over two interchangeable
//! transports:
//!
//! - a **length-delimited byte stream** (raw TCP or TLS) — the original
//!   `agent_bind` path, used when the agent and hub share a network;
//! - **one-frame-per-binary-WebSocket-message** — used when the agent
//!   dials the hub through an HTTP/WS perimeter (e.g. a Microsoft Dev
//!   Tunnel), which only forwards HTTP/WebSocket, not arbitrary TCP.
//!
//! Both ends (`hub::agent_link::handle_connection` and
//! `agent::run_session`) are generic over [`FrameRecv`] + [`FrameSend`]
//! so the mux / session / RPC logic is identical regardless of
//! transport. This module provides the trait definitions plus the
//! byte-stream implementations; the WebSocket implementations live in
//! the hub and agent crates (each over its own `Message` type).

use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::{Frame, FrameError, HEADER_LEN};

/// Reads decoded frames off a transport. `Ok(None)` signals a clean
/// EOF / peer close. The `u64` is the number of wire bytes the frame
/// occupied (header + payload), used for the hub's per-agent metrics.
pub trait FrameRecv {
    fn recv(&mut self) -> impl Future<Output = Result<Option<(Frame, u64)>, FrameError>> + Send;
}

/// Writes already-encoded frame bytes to a transport.
pub trait FrameSend {
    fn send(&mut self, bytes: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
    /// Best-effort graceful shutdown of the underlying transport.
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

/// [`FrameRecv`] over a length-delimited byte stream (TCP / TLS).
pub struct ByteStreamRecv<R>(pub R);

impl<R: AsyncRead + Unpin + Send> FrameRecv for ByteStreamRecv<R> {
    async fn recv(&mut self) -> Result<Option<(Frame, u64)>, FrameError> {
        let mut hdr = [0u8; HEADER_LEN];
        match self.0.read_exact(&mut hdr).await {
            Ok(_) => {}
            // A clean EOF *between* frames (no header bytes) is a normal
            // disconnect; a short read mid-header is a truncation error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(FrameError::Io(e)),
        }
        let stream_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ty_byte = hdr[4];
        let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        let (ty, len) = Frame::validate_header(stream_id, ty_byte, len)?;
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            self.0
                .read_exact(&mut payload)
                .await
                .map_err(FrameError::Io)?;
        }
        let total = HEADER_LEN as u64 + len as u64;
        Frame::from_payload(stream_id, ty, payload).map(|f| Some((f, total)))
    }
}

/// [`FrameSend`] over a byte stream. Each `send` writes exactly one
/// pre-encoded frame; the receiver re-delimits via the length header.
pub struct ByteStreamSend<W>(pub W);

impl<W: AsyncWrite + Unpin + Send> FrameSend for ByteStreamSend<W> {
    async fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.0.write_all(&bytes).await
    }
    async fn close(&mut self) {
        let _ = self.0.shutdown().await;
    }
}

/// Decode one wire frame from a single WebSocket **binary message**
/// payload (the whole message is exactly one frame). Shared by the hub
/// and agent WebSocket [`FrameRecv`] impls so the validation is
/// identical to the byte-stream path. Returns the frame + its wire byte
/// count.
pub fn frame_from_ws_payload(data: &[u8]) -> Result<(Frame, u64), FrameError> {
    if data.len() < HEADER_LEN {
        return Err(FrameError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame shorter than header",
        )));
    }
    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let ty_byte = data[4];
    let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let (ty, len) = Frame::validate_header(stream_id, ty_byte, len)?;
    if data.len() != HEADER_LEN + len as usize {
        return Err(FrameError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame length mismatch",
        )));
    }
    let payload = data[HEADER_LEN..].to_vec();
    let total = (HEADER_LEN + payload.len()) as u64;
    Frame::from_payload(stream_id, ty, payload).map(|f| (f, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Body;

    #[tokio::test]
    async fn byte_stream_round_trips_frames() {
        // Encode two frames into an in-memory duplex, read them back.
        let f1 = Frame::data(7, b"hello".to_vec());
        let f2 = Frame::resize(7, 24, 80);
        let mut buf = Vec::new();
        buf.extend_from_slice(&f1.encode());
        buf.extend_from_slice(&f2.encode());

        let mut recv = ByteStreamRecv(std::io::Cursor::new(buf));
        let (g1, n1) = recv.recv().await.unwrap().unwrap();
        assert_eq!(n1 as usize, f1.encode().len());
        assert!(matches!(g1.body, Body::Data(d) if d == b"hello"));
        let (g2, _) = recv.recv().await.unwrap().unwrap();
        assert!(matches!(g2.body, Body::Resize { rows: 24, cols: 80 }));
        // Clean EOF between frames -> None.
        assert!(recv.recv().await.unwrap().is_none());
    }

    #[test]
    fn ws_payload_decodes_one_frame() {
        let f = Frame::data(3, b"xyz".to_vec());
        let bytes = f.encode();
        let (g, n) = frame_from_ws_payload(&bytes).unwrap();
        assert_eq!(n as usize, bytes.len());
        assert_eq!(g.stream_id, 3);
        assert!(matches!(g.body, Body::Data(d) if d == b"xyz"));
    }

    #[test]
    fn ws_payload_rejects_short_and_mismatched() {
        // Shorter than the 9-byte header.
        assert!(frame_from_ws_payload(&[0u8; 4]).is_err());
        // Header claims a length that doesn't match the trailing bytes.
        let mut bytes = Frame::data(1, b"ab".to_vec()).encode();
        bytes.push(0xff); // one extra trailing byte
        assert!(frame_from_ws_payload(&bytes).is_err());
    }
}
