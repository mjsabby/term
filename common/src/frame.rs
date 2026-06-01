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

// --- Chunked paste-file upload (browser -> agent) -------------------------
//
// A logical file is a triple of frames on one mux stream:
//
//   PasteBegin(paste_id, total_size, name)
//   PasteChunk(paste_id, bytes)        × ceil(total_size / MAX_PASTE_CHUNK_BYTES)
//   PasteEnd  (paste_id, status)
//
// `paste_id` is browser-allocated and must be unique among that stream's
// in-flight pastes. Multiple pastes may interleave on the same stream
// (multi-file paste fires N paste_ids near-simultaneously). The agent
// looks each chunk up by paste_id and appends in receive order. Status
// in PasteEnd: 0 = ok (commit + inject path into PTY), 1 = cancel
// (drop tempfile).

/// Maximum logical file size carried by one paste sequence (4 GiB - 1).
pub const MAX_PASTE_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024 - 1;
/// Maximum raw bytes carried in a single `PasteChunk` frame.
pub const MAX_PASTE_CHUNK_BYTES: u32 = 1024 * 1024;
/// Maximum length of a browser-supplied filename (sanitized by the agent).
pub const MAX_PASTE_NAME_LEN:    u32 = 255;
/// Total `PasteBegin` payload cap: `[paste_id:u32][total_size:u64]
/// [group_id:u32][group_size:u32][name_len:u8][name]`.
pub const MAX_PASTE_BEGIN_LEN:   u32 = 4 + 8 + 4 + 4 + 1 + MAX_PASTE_NAME_LEN;
/// Total `PasteChunk` payload cap: `[paste_id:u32] + bytes`.
pub const MAX_PASTE_CHUNK_LEN:   u32 = 4 + MAX_PASTE_CHUNK_BYTES;
/// Total `PasteEnd` payload: `[paste_id:u32] + [status:u8]`.
pub const PASTE_END_LEN:         u32 = 4 + 1;
/// Total `PasteReject` payload: `[paste_id:u32] + [reason:u8]`.
pub const PASTE_REJECT_LEN:      u32 = 4 + 1;
/// PasteEnd status: commit the upload, agent injects the path into the PTY.
pub const PASTE_STATUS_OK:     u8 = 0;
/// PasteEnd status: cancel — drop the tempfile, don't inject a path.
pub const PASTE_STATUS_CANCEL: u8 = 1;

/// PasteReject reason codes. Agent → browser when a paste fails on the
/// agent side; the browser surfaces a toast and stops the upload.
pub const PASTE_REJECT_REGISTRY_FULL:     u8 = 0;
pub const PASTE_REJECT_OPEN_FAILED:       u8 = 1;
pub const PASTE_REJECT_SIZE_MISMATCH:     u8 = 2;
pub const PASTE_REJECT_WRITE_FAILED:      u8 = 3;
pub const PASTE_REJECT_DUPLICATE_PASTE:   u8 = 4;
pub const PASTE_REJECT_GROUP_OVERSIZE:    u8 = 5;
/// Maximum legal `PasteReject` reason value (inclusive).
pub const PASTE_REJECT_MAX_REASON:        u8 = PASTE_REJECT_GROUP_OVERSIZE;

// --- Chunked file download (agent -> browser) -----------------------------
//
// Triggered by the `term-dl <path>` helper running in the shell, which
// emits an application OSC `\x1b]5111;dl;<abs_path>\x07`. The agent's
// PTY-output OSC scanner intercepts that, opens the file, and emits:
//
//   DownloadBegin(download_id, total_size, name)
//   DownloadChunk(download_id, bytes)     × ceil(total_size / 1 MiB)
//   DownloadEnd  (download_id, status)
//
// Same per-file 4 GiB cap, same 1 MiB chunk size, same name length cap
// as paste. Direction-only: agent always allocates download_id (only
// needs to be unique per agent connection's in-flight downloads).

/// Total `DownloadBegin` payload cap: same layout as PasteBegin but no
/// group fields → `[download_id:u32][total_size:u64][name_len:u8][name]`.
pub const MAX_DOWNLOAD_BEGIN_LEN: u32 = 4 + 8 + 1 + MAX_PASTE_NAME_LEN;
/// Total `DownloadChunk` payload cap.
pub const MAX_DOWNLOAD_CHUNK_LEN: u32 = 4 + MAX_PASTE_CHUNK_BYTES;
/// Total `DownloadEnd` payload (5 bytes).
pub const DOWNLOAD_END_LEN:       u32 = 4 + 1;
/// DownloadEnd status: commit the download, browser builds Blob + saves.
pub const DOWNLOAD_STATUS_OK:     u8 = 0;
/// DownloadEnd status: cancel — browser discards accumulated chunks.
pub const DOWNLOAD_STATUS_CANCEL: u8 = 1;

// --- Controller / multi-attach handoff (Phase 4.2) ------------------------

/// `Open` payload may optionally carry an initial terminal size after
/// the session_id: `[session_id bytes][rows:u16 BE][cols:u16 BE]`.
/// Bound = MAX_SESSION_ID_LEN + 4 trailing bytes.
pub const MAX_OPEN_LEN: u32 = MAX_SESSION_ID_LEN + 4;
/// `ControllerChanged` payload is a single `u8` status. The agent's
/// per-stream outbound task maps the session's controller into this
/// status when emitting on each stream:
///   * `CONTROLLER_STATUS_NONE`  — no controller currently.
///   * `CONTROLLER_STATUS_SELF`  — *this* browser is controller.
///   * `CONTROLLER_STATUS_OTHER` — someone else is controller.
///
/// This way the browser never has to know its own (hub-allocated)
/// stream_id.
pub const CONTROLLER_CHANGED_LEN: u32 = 1;
pub const CONTROLLER_STATUS_NONE:  u8 = 0;
pub const CONTROLLER_STATUS_SELF:  u8 = 1;
pub const CONTROLLER_STATUS_OTHER: u8 = 2;
/// Legacy alias retained for the agent's internal SessionEvent
/// (where the per-stream task can use the real stream_id before
/// mapping). Wire payload uses the status byte above.
pub const CONTROLLER_NONE_STREAM_ID: u32 = 0;

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
    /// Begins a chunked file paste from the browser. Stream-scoped
    /// (stream_id != 0). Browser → hub → agent only. Payload:
    /// `[paste_id:u32 BE][total_size:u64 BE][group_id:u32 BE]
    ///  [group_size:u32 BE][name_len:u8][name UTF-8]`.
    /// `paste_id` is browser-allocated and unique among the stream's
    /// in-flight pastes. `total_size` is bounded by
    /// `MAX_PASTE_TOTAL_BYTES`. `group_id` is browser-allocated; all
    /// pastes that share a `group_id` belong to one batch (multi-file
    /// paste action). `group_size` is the total number of pastes in
    /// that batch (≥ 1). The agent collects finished paths for a group
    /// and injects them all in one bracketed-paste block once
    /// `group_size` pastes complete. `name` is the browser-supplied
    /// filename (may be empty; agent sanitizes and falls back to a
    /// generated name).
    PasteBegin = 7,
    /// One chunk of a paste. Stream-scoped. Payload:
    /// `[paste_id:u32 BE][raw bytes ≤ MAX_PASTE_CHUNK_BYTES]`. Chunks
    /// for a paste_id are appended in receive order; agent rejects
    /// chunks whose cumulative size exceeds the Begin's `total_size`.
    PasteChunk = 8,
    /// Finalizes a paste. Stream-scoped. Payload:
    /// `[paste_id:u32 BE][status:u8]`. `status` is `PASTE_STATUS_OK`
    /// (commit + inject path) or `PASTE_STATUS_CANCEL` (drop tempfile,
    /// no PTY injection).
    PasteEnd = 9,
    /// Agent-side rejection of a paste. Stream-scoped, agent → browser
    /// only. Payload: `[paste_id:u32 BE][reason:u8]`. Sent when the
    /// agent cannot honor a PasteBegin (registry full, open failure,
    /// duplicate id, group aggregate over cap) or fails mid-stream
    /// (size mismatch, write error). The browser stops feeding chunks
    /// for that paste_id and surfaces a toast.
    PasteReject = 10,
    /// Begins a chunked file download from the agent. Stream-scoped,
    /// agent → browser only. Payload:
    /// `[download_id:u32 BE][total_size:u64 BE][name_len:u8][name UTF-8]`.
    /// `download_id` is agent-allocated and unique among that mux
    /// connection's in-flight downloads; the browser keys its chunk
    /// buffer by `download_id`. `total_size` is bounded by
    /// `MAX_PASTE_TOTAL_BYTES`. `name` is the absolute path's basename.
    DownloadBegin = 11,
    /// One chunk of a download. Stream-scoped, agent → browser only.
    /// Payload: `[download_id:u32 BE][raw bytes ≤ MAX_PASTE_CHUNK_BYTES]`.
    /// Chunks for a download_id are appended in receive order.
    DownloadChunk = 12,
    /// Finalize a download. Stream-scoped, agent → browser only.
    /// Payload: `[download_id:u32 BE][status:u8]`. `status` is
    /// `DOWNLOAD_STATUS_OK` (browser triggers save) or
    /// `DOWNLOAD_STATUS_CANCEL` (browser discards buffer).
    DownloadEnd = 13,
    /// A viewer asks to become the session's controller. Stream-scoped
    /// (stream_id != 0). Browser → agent only. No payload. Succeeds
    /// only when the session has no current controller; otherwise
    /// silently ignored (use `TakeControl` to preempt).
    AcquireControl = 14,
    /// The current controller voluntarily relinquishes control. Stream-
    /// scoped. Browser → agent only. No payload. Honored only when the
    /// sender is the current controller.
    ReleaseControl = 15,
    /// Force-take control of a session, demoting the prior controller
    /// to viewer. Stream-scoped. Browser → agent only. No payload.
    /// Always succeeds; the PTY is resized to the new controller's
    /// last-reported geometry.
    TakeControl = 16,
    /// Broadcast to every attached browser whenever a session's
    /// controller changes. Stream-scoped, agent → browser only.
    /// Payload: `[status:u8]` — one of `CONTROLLER_STATUS_NONE`,
    /// `CONTROLLER_STATUS_SELF`, `CONTROLLER_STATUS_OTHER`. The
    /// agent's per-stream task remaps the session's internal
    /// controller stream_id into one of these three values before
    /// emitting, so the browser doesn't need to know its own
    /// (hub-allocated) sid. Used to render the controlling / viewing
    /// pill in the tab strip.
    ControllerChanged = 17,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0  => Some(FrameType::Data),
            1  => Some(FrameType::Resize),
            2  => Some(FrameType::Open),
            3  => Some(FrameType::Close),
            4  => Some(FrameType::Ping),
            5  => Some(FrameType::Pong),
            6  => Some(FrameType::Hello),
            7  => Some(FrameType::PasteBegin),
            8  => Some(FrameType::PasteChunk),
            9  => Some(FrameType::PasteEnd),
            10 => Some(FrameType::PasteReject),
            11 => Some(FrameType::DownloadBegin),
            12 => Some(FrameType::DownloadChunk),
            13 => Some(FrameType::DownloadEnd),
            14 => Some(FrameType::AcquireControl),
            15 => Some(FrameType::ReleaseControl),
            16 => Some(FrameType::TakeControl),
            17 => Some(FrameType::ControllerChanged),
            _  => None,
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
    #[error("paste-begin payload too short ({0} bytes; need >= 21)")]
    PasteBeginTruncated(u32),
    #[error("paste-begin name not utf-8")]
    PasteBeginNameNotUtf8,
    #[error("paste-begin total_size {0} exceeds {max}", max = MAX_PASTE_TOTAL_BYTES)]
    PasteBeginTotalSize(u64),
    #[error("paste-begin group_size {0} is zero (must be ≥ 1)")]
    PasteBeginGroupSizeZero(u32),
    #[error("paste-chunk payload too short ({0} bytes; need paste_id prefix)")]
    PasteChunkTruncated(u32),
    #[error("paste-end payload must be exactly 5 bytes (got {0})")]
    PasteEndLen(u32),
    #[error("paste-end status {0} invalid (expected 0 or 1)")]
    PasteEndStatus(u8),
    #[error("paste-reject payload must be exactly 5 bytes (got {0})")]
    PasteRejectLen(u32),
    #[error("paste-reject reason {0} invalid (max {max})", max = PASTE_REJECT_MAX_REASON)]
    PasteRejectReason(u8),
    #[error("download-begin payload too short ({0} bytes; need >= 13)")]
    DownloadBeginTruncated(u32),
    #[error("download-begin name not utf-8")]
    DownloadBeginNameNotUtf8,
    #[error("download-begin total_size {0} exceeds {max}", max = MAX_PASTE_TOTAL_BYTES)]
    DownloadBeginTotalSize(u64),
    #[error("download-chunk payload too short ({0} bytes; need download_id prefix)")]
    DownloadChunkTruncated(u32),
    #[error("download-end payload must be exactly 5 bytes (got {0})")]
    DownloadEndLen(u32),
    #[error("download-end status {0} invalid (expected 0 or 1)")]
    DownloadEndStatus(u8),
    #[error("controller-changed payload must be exactly 1 byte (got {0})")]
    ControllerChangedLen(u32),
    #[error("controller-changed status {0} invalid (max {max})", max = CONTROLLER_STATUS_OTHER)]
    ControllerChangedStatus(u8),
    #[error("control frame {ty:?} must have empty payload (got {len})")]
    ControlFrameNonEmpty { ty: FrameType, len: u32 },
}

#[derive(Debug, Clone)]
pub enum Body {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    /// First frame on a new mux stream. `session_id` matches
    /// `[A-Za-z0-9_-]{1,64}`. `initial_size` carries the browser's
    /// terminal geometry at attach time so the agent can spawn a fresh
    /// session at the right size. Wire layout:
    /// `[session_id bytes][rows:u16 BE][cols:u16 BE]` — size is
    /// **mandatory** (the agent has no other way to know the geometry
    /// before any Resize arrives, and the protocol versions here are
    /// shipped in lockstep so there is no backward-compat client to
    /// preserve).
    Open { session_id: String, initial_size: (u16, u16) },
    Close,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Hello(Vec<u8>),
    /// Begin a paste. `name` is the browser-supplied filename; may be
    /// empty (agent picks). `total_size` is bounded by
    /// `MAX_PASTE_TOTAL_BYTES`. `group_id` ties this paste to a batch
    /// of `group_size` pastes (drag-N-files / multi-image clipboard);
    /// agent buffers finished paths until all `group_size` pastes
    /// complete, then injects them together. `group_size == 1` is the
    /// common single-file case. The agent must reserve a
    /// `PendingPaste` keyed by `paste_id` until a matching `PasteEnd`
    /// arrives.
    PasteBegin {
        paste_id:   u32,
        total_size: u64,
        group_id:   u32,
        group_size: u32,
        name:       String,
    },
    /// One chunk of file bytes. Chunks must arrive in order on the
    /// stream's mux; cumulative byte count cannot exceed Begin's
    /// `total_size`.
    PasteChunk { paste_id: u32, bytes: Vec<u8> },
    /// Finalize a paste. `status` is `PASTE_STATUS_OK` or
    /// `PASTE_STATUS_CANCEL`.
    PasteEnd { paste_id: u32, status: u8 },
    /// Agent-side rejection. Sent agent → browser only.
    PasteReject { paste_id: u32, reason: u8 },
    /// Begin a download. `name` is the basename of the file the agent
    /// is sending. `total_size` is bounded by `MAX_PASTE_TOTAL_BYTES`.
    DownloadBegin { download_id: u32, total_size: u64, name: String },
    /// One chunk of a download. Chunks arrive in order.
    DownloadChunk { download_id: u32, bytes: Vec<u8> },
    /// Finalize a download. `status` is `DOWNLOAD_STATUS_OK` or
    /// `DOWNLOAD_STATUS_CANCEL`.
    DownloadEnd { download_id: u32, status: u8 },
    /// Viewer asks to become controller.
    AcquireControl,
    /// Controller voluntarily relinquishes control.
    ReleaseControl,
    /// Force preemption: caller becomes controller.
    TakeControl,
    /// Broadcast: per-receiver controller status. Use
    /// `CONTROLLER_STATUS_*` constants.
    ControllerChanged { status: u8 },
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
    pub fn open(stream_id: u32, session_id: String, initial_size: (u16, u16)) -> Self {
        Self { stream_id, body: Body::Open { session_id, initial_size } }
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
    pub fn paste_begin(
        stream_id: u32,
        paste_id: u32,
        total_size: u64,
        group_id: u32,
        group_size: u32,
        name: String,
    ) -> Self {
        Self {
            stream_id,
            body: Body::PasteBegin { paste_id, total_size, group_id, group_size, name },
        }
    }
    pub fn paste_chunk(stream_id: u32, paste_id: u32, bytes: Vec<u8>) -> Self {
        Self { stream_id, body: Body::PasteChunk { paste_id, bytes } }
    }
    pub fn paste_end(stream_id: u32, paste_id: u32, status: u8) -> Self {
        Self { stream_id, body: Body::PasteEnd { paste_id, status } }
    }
    pub fn paste_reject(stream_id: u32, paste_id: u32, reason: u8) -> Self {
        Self { stream_id, body: Body::PasteReject { paste_id, reason } }
    }
    pub fn download_begin(stream_id: u32, download_id: u32, total_size: u64, name: String) -> Self {
        Self { stream_id, body: Body::DownloadBegin { download_id, total_size, name } }
    }
    pub fn download_chunk(stream_id: u32, download_id: u32, bytes: Vec<u8>) -> Self {
        Self { stream_id, body: Body::DownloadChunk { download_id, bytes } }
    }
    pub fn download_end(stream_id: u32, download_id: u32, status: u8) -> Self {
        Self { stream_id, body: Body::DownloadEnd { download_id, status } }
    }
    pub fn acquire_control(stream_id: u32) -> Self {
        Self { stream_id, body: Body::AcquireControl }
    }
    pub fn release_control(stream_id: u32) -> Self {
        Self { stream_id, body: Body::ReleaseControl }
    }
    pub fn take_control(stream_id: u32) -> Self {
        Self { stream_id, body: Body::TakeControl }
    }
    pub fn controller_changed(stream_id: u32, status: u8) -> Self {
        Self { stream_id, body: Body::ControllerChanged { status } }
    }

    pub fn ty(&self) -> FrameType {
        match &self.body {
            Body::Data(_)                => FrameType::Data,
            Body::Resize { .. }          => FrameType::Resize,
            Body::Open { .. }            => FrameType::Open,
            Body::Close                  => FrameType::Close,
            Body::Ping(_)                => FrameType::Ping,
            Body::Pong(_)                => FrameType::Pong,
            Body::Hello(_)               => FrameType::Hello,
            Body::PasteBegin { .. }      => FrameType::PasteBegin,
            Body::PasteChunk { .. }      => FrameType::PasteChunk,
            Body::PasteEnd { .. }        => FrameType::PasteEnd,
            Body::PasteReject { .. }     => FrameType::PasteReject,
            Body::DownloadBegin { .. }   => FrameType::DownloadBegin,
            Body::DownloadChunk { .. }   => FrameType::DownloadChunk,
            Body::DownloadEnd { .. }     => FrameType::DownloadEnd,
            Body::AcquireControl         => FrameType::AcquireControl,
            Body::ReleaseControl         => FrameType::ReleaseControl,
            Body::TakeControl            => FrameType::TakeControl,
            Body::ControllerChanged { .. } => FrameType::ControllerChanged,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload: std::borrow::Cow<'_, [u8]> = match &self.body {
            Body::Data(b)  => std::borrow::Cow::Borrowed(b),
            Body::Open { session_id, initial_size: (rows, cols) } => {
                let mut p = Vec::with_capacity(session_id.len() + 4);
                p.extend_from_slice(session_id.as_bytes());
                p.extend_from_slice(&rows.to_be_bytes());
                p.extend_from_slice(&cols.to_be_bytes());
                std::borrow::Cow::Owned(p)
            }
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
            Body::PasteBegin { paste_id, total_size, group_id, group_size, name } => {
                // Truncate `name` along UTF-8 char boundaries so encode
                // never emits a malformed string that `from_payload`
                // would reject on the other end.
                let max = MAX_PASTE_NAME_LEN as usize;
                let n = if name.len() <= max {
                    name.len()
                } else {
                    // Round down to the highest char boundary ≤ max.
                    let mut k = max;
                    while k > 0 && !name.is_char_boundary(k) { k -= 1; }
                    k
                };
                let mut p = Vec::with_capacity(4 + 8 + 4 + 4 + 1 + n);
                p.extend_from_slice(&paste_id.to_be_bytes());
                p.extend_from_slice(&total_size.to_be_bytes());
                p.extend_from_slice(&group_id.to_be_bytes());
                p.extend_from_slice(&group_size.to_be_bytes());
                p.push(n as u8);
                p.extend_from_slice(&name.as_bytes()[..n]);
                std::borrow::Cow::Owned(p)
            }
            Body::PasteChunk { paste_id, bytes } => {
                let mut p = Vec::with_capacity(4 + bytes.len());
                p.extend_from_slice(&paste_id.to_be_bytes());
                p.extend_from_slice(bytes);
                std::borrow::Cow::Owned(p)
            }
            Body::PasteEnd { paste_id, status } => {
                let mut p = Vec::with_capacity(5);
                p.extend_from_slice(&paste_id.to_be_bytes());
                p.push(*status);
                std::borrow::Cow::Owned(p)
            }
            Body::PasteReject { paste_id, reason } => {
                let mut p = Vec::with_capacity(5);
                p.extend_from_slice(&paste_id.to_be_bytes());
                p.push(*reason);
                std::borrow::Cow::Owned(p)
            }
            Body::DownloadBegin { download_id, total_size, name } => {
                // Same UTF-8-safe truncation as PasteBegin.
                let max = MAX_PASTE_NAME_LEN as usize;
                let n = if name.len() <= max {
                    name.len()
                } else {
                    let mut k = max;
                    while k > 0 && !name.is_char_boundary(k) { k -= 1; }
                    k
                };
                let mut p = Vec::with_capacity(4 + 8 + 1 + n);
                p.extend_from_slice(&download_id.to_be_bytes());
                p.extend_from_slice(&total_size.to_be_bytes());
                p.push(n as u8);
                p.extend_from_slice(&name.as_bytes()[..n]);
                std::borrow::Cow::Owned(p)
            }
            Body::DownloadChunk { download_id, bytes } => {
                let mut p = Vec::with_capacity(4 + bytes.len());
                p.extend_from_slice(&download_id.to_be_bytes());
                p.extend_from_slice(bytes);
                std::borrow::Cow::Owned(p)
            }
            Body::DownloadEnd { download_id, status } => {
                let mut p = Vec::with_capacity(5);
                p.extend_from_slice(&download_id.to_be_bytes());
                p.push(*status);
                std::borrow::Cow::Owned(p)
            }
            Body::AcquireControl | Body::ReleaseControl | Body::TakeControl => {
                std::borrow::Cow::Borrowed(&[][..])
            }
            Body::ControllerChanged { status } => {
                std::borrow::Cow::Owned(vec![*status])
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
                // Payload = session_id (1..=64 bytes) + 4 bytes
                // (rows:u16 BE, cols:u16 BE). Min 5, max 68.
                if !(5..=MAX_OPEN_LEN).contains(&len) {
                    return Err(FrameError::PayloadTooLarge { ty, len, max: MAX_OPEN_LEN });
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
            FrameType::PasteBegin => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                // Min: 4 (paste_id) + 8 (total_size) + 4 (group_id) +
                // 4 (group_size) + 1 (name_len=0) = 21.
                if len < 21 {
                    return Err(FrameError::PasteBeginTruncated(len));
                }
                if len > MAX_PASTE_BEGIN_LEN {
                    return Err(FrameError::PayloadTooLarge {
                        ty, len, max: MAX_PASTE_BEGIN_LEN,
                    });
                }
            }
            FrameType::PasteChunk => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                // Must have at least the paste_id (4 bytes); zero data
                // bytes is legal (e.g. a heartbeat). Max = paste_id + 1 MiB.
                if len < 4 {
                    return Err(FrameError::PasteChunkTruncated(len));
                }
                if len > MAX_PASTE_CHUNK_LEN {
                    return Err(FrameError::PayloadTooLarge {
                        ty, len, max: MAX_PASTE_CHUNK_LEN,
                    });
                }
            }
            FrameType::PasteEnd => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != PASTE_END_LEN {
                    return Err(FrameError::PasteEndLen(len));
                }
            }
            FrameType::PasteReject => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != PASTE_REJECT_LEN {
                    return Err(FrameError::PasteRejectLen(len));
                }
            }
            FrameType::DownloadBegin => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len < 13 {
                    return Err(FrameError::DownloadBeginTruncated(len));
                }
                if len > MAX_DOWNLOAD_BEGIN_LEN {
                    return Err(FrameError::PayloadTooLarge {
                        ty, len, max: MAX_DOWNLOAD_BEGIN_LEN,
                    });
                }
            }
            FrameType::DownloadChunk => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len < 4 {
                    return Err(FrameError::DownloadChunkTruncated(len));
                }
                if len > MAX_DOWNLOAD_CHUNK_LEN {
                    return Err(FrameError::PayloadTooLarge {
                        ty, len, max: MAX_DOWNLOAD_CHUNK_LEN,
                    });
                }
            }
            FrameType::DownloadEnd => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != DOWNLOAD_END_LEN {
                    return Err(FrameError::DownloadEndLen(len));
                }
            }
            FrameType::AcquireControl | FrameType::ReleaseControl | FrameType::TakeControl => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != 0 {
                    return Err(FrameError::ControlFrameNonEmpty { ty, len });
                }
            }
            FrameType::ControllerChanged => {
                if stream_id == CONTROL_STREAM { return Err(FrameError::DataOnControlStream); }
                if len != CONTROLLER_CHANGED_LEN {
                    return Err(FrameError::ControllerChangedLen(len));
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
                // Layout: [session_id bytes][rows:u16 BE][cols:u16 BE].
                // header-validated payload.len() in 5..=68; trailing
                // 4 bytes are the initial size.
                if payload.len() < 5 {
                    return Err(FrameError::PayloadTooLarge {
                        ty, len: payload.len() as u32, max: MAX_OPEN_LEN,
                    });
                }
                let split = payload.len() - 4;
                let rows = u16::from_be_bytes([payload[split],     payload[split + 1]]);
                let cols = u16::from_be_bytes([payload[split + 2], payload[split + 3]]);
                let id_bytes = payload[..split].to_vec();
                let s = String::from_utf8(id_bytes).map_err(|_| FrameError::SessionIdNotUtf8)?;
                if !is_valid_session_id(&s) { return Err(FrameError::InvalidSessionId); }
                Body::Open { session_id: s, initial_size: (rows, cols) }
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
            FrameType::PasteBegin => {
                if payload.len() < 21 {
                    return Err(FrameError::PasteBeginTruncated(payload.len() as u32));
                }
                let paste_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let total_size = u64::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                    payload[8], payload[9], payload[10], payload[11],
                ]);
                if total_size > MAX_PASTE_TOTAL_BYTES {
                    return Err(FrameError::PasteBeginTotalSize(total_size));
                }
                let group_id = u32::from_be_bytes(
                    [payload[12], payload[13], payload[14], payload[15]]);
                let group_size = u32::from_be_bytes(
                    [payload[16], payload[17], payload[18], payload[19]]);
                if group_size == 0 {
                    return Err(FrameError::PasteBeginGroupSizeZero(group_size));
                }
                let name_len = payload[20] as usize;
                let name_end = 21 + name_len;
                if payload.len() != name_end {
                    return Err(FrameError::PasteBeginTruncated(payload.len() as u32));
                }
                let name = String::from_utf8(payload[21..name_end].to_vec())
                    .map_err(|_| FrameError::PasteBeginNameNotUtf8)?;
                Body::PasteBegin { paste_id, total_size, group_id, group_size, name }
            }
            FrameType::PasteChunk => {
                if payload.len() < 4 {
                    return Err(FrameError::PasteChunkTruncated(payload.len() as u32));
                }
                let paste_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if payload.len() > (4 + MAX_PASTE_CHUNK_BYTES as usize) {
                    return Err(FrameError::PayloadTooLarge {
                        ty,
                        len: payload.len() as u32,
                        max: MAX_PASTE_CHUNK_LEN,
                    });
                }
                let bytes = payload[4..].to_vec();
                Body::PasteChunk { paste_id, bytes }
            }
            FrameType::PasteEnd => {
                if payload.len() != PASTE_END_LEN as usize {
                    return Err(FrameError::PasteEndLen(payload.len() as u32));
                }
                let paste_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let status = payload[4];
                if status != PASTE_STATUS_OK && status != PASTE_STATUS_CANCEL {
                    return Err(FrameError::PasteEndStatus(status));
                }
                Body::PasteEnd { paste_id, status }
            }
            FrameType::PasteReject => {
                if payload.len() != PASTE_REJECT_LEN as usize {
                    return Err(FrameError::PasteRejectLen(payload.len() as u32));
                }
                let paste_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let reason = payload[4];
                if reason > PASTE_REJECT_MAX_REASON {
                    return Err(FrameError::PasteRejectReason(reason));
                }
                Body::PasteReject { paste_id, reason }
            }
            FrameType::DownloadBegin => {
                if payload.len() < 13 {
                    return Err(FrameError::DownloadBeginTruncated(payload.len() as u32));
                }
                let download_id = u32::from_be_bytes(
                    [payload[0], payload[1], payload[2], payload[3]]);
                let total_size = u64::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                    payload[8], payload[9], payload[10], payload[11],
                ]);
                if total_size > MAX_PASTE_TOTAL_BYTES {
                    return Err(FrameError::DownloadBeginTotalSize(total_size));
                }
                let name_len = payload[12] as usize;
                let name_end = 13 + name_len;
                if payload.len() != name_end {
                    return Err(FrameError::DownloadBeginTruncated(payload.len() as u32));
                }
                let name = String::from_utf8(payload[13..name_end].to_vec())
                    .map_err(|_| FrameError::DownloadBeginNameNotUtf8)?;
                Body::DownloadBegin { download_id, total_size, name }
            }
            FrameType::DownloadChunk => {
                if payload.len() < 4 {
                    return Err(FrameError::DownloadChunkTruncated(payload.len() as u32));
                }
                let download_id = u32::from_be_bytes(
                    [payload[0], payload[1], payload[2], payload[3]]);
                if payload.len() > (4 + MAX_PASTE_CHUNK_BYTES as usize) {
                    return Err(FrameError::PayloadTooLarge {
                        ty,
                        len: payload.len() as u32,
                        max: MAX_DOWNLOAD_CHUNK_LEN,
                    });
                }
                let bytes = payload[4..].to_vec();
                Body::DownloadChunk { download_id, bytes }
            }
            FrameType::DownloadEnd => {
                if payload.len() != DOWNLOAD_END_LEN as usize {
                    return Err(FrameError::DownloadEndLen(payload.len() as u32));
                }
                let download_id = u32::from_be_bytes(
                    [payload[0], payload[1], payload[2], payload[3]]);
                let status = payload[4];
                if status != DOWNLOAD_STATUS_OK && status != DOWNLOAD_STATUS_CANCEL {
                    return Err(FrameError::DownloadEndStatus(status));
                }
                Body::DownloadEnd { download_id, status }
            }
            FrameType::AcquireControl => Body::AcquireControl,
            FrameType::ReleaseControl => Body::ReleaseControl,
            FrameType::TakeControl    => Body::TakeControl,
            FrameType::ControllerChanged => {
                if payload.len() != CONTROLLER_CHANGED_LEN as usize {
                    return Err(FrameError::ControllerChangedLen(payload.len() as u32));
                }
                let status = payload[0];
                if status > CONTROLLER_STATUS_OTHER {
                    return Err(FrameError::ControllerChangedStatus(status));
                }
                Body::ControllerChanged { status }
            }
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

    #[test]
    fn paste_begin_round_trip() {
        let f = Frame::paste_begin(11, 0xdeadbeef, 1_234_567, 0xabcd, 3, "screenshot.png".into());
        let enc = f.encode();
        let stream_id = u32::from_be_bytes([enc[0], enc[1], enc[2], enc[3]]);
        let ty_byte = enc[4];
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        let (ty, _) = Frame::validate_header(stream_id, ty_byte, len).unwrap();
        assert_eq!(ty, FrameType::PasteBegin);
        let back = Frame::from_payload(stream_id, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteBegin { paste_id, total_size, group_id, group_size, name } => {
                assert_eq!(paste_id, 0xdeadbeef);
                assert_eq!(total_size, 1_234_567);
                assert_eq!(group_id, 0xabcd);
                assert_eq!(group_size, 3);
                assert_eq!(name, "screenshot.png");
            }
            _ => panic!("expected PasteBegin"),
        }
    }

    #[test]
    fn paste_begin_empty_name() {
        let f = Frame::paste_begin(2, 0, 0, 0, 1, "".into());
        let enc = f.encode();
        let back = Frame::from_payload(2, FrameType::PasteBegin, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteBegin { name, .. } => assert!(name.is_empty()),
            _ => panic!(),
        }
    }

    #[test]
    fn paste_begin_max_name() {
        let name: String = "a".repeat(MAX_PASTE_NAME_LEN as usize);
        let f = Frame::paste_begin(2, 1, 100, 0, 1, name.clone());
        let enc = f.encode();
        let back = Frame::from_payload(2, FrameType::PasteBegin, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteBegin { name: n, .. } => assert_eq!(n, name),
            _ => panic!(),
        }
    }

    #[test]
    fn paste_begin_utf8_safe_truncation() {
        // 4-byte emoji ('🎉' = 4 bytes) repeated past MAX_PASTE_NAME_LEN.
        // The encoder must NOT cut a multibyte sequence in the middle.
        let s: String = "🎉".repeat(MAX_PASTE_NAME_LEN as usize); // way too long
        let f = Frame::paste_begin(2, 1, 1, 0, 1, s);
        let enc = f.encode();
        // Must decode successfully — i.e. encoded bytes were truncated
        // on a char boundary.
        let back = Frame::from_payload(2, FrameType::PasteBegin, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteBegin { name, .. } => {
                assert!(name.is_char_boundary(name.len()));
                assert!(name.chars().all(|c| c == '🎉'));
                assert!(name.len() <= MAX_PASTE_NAME_LEN as usize);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn paste_begin_rejected_on_control_stream() {
        let e = Frame::validate_header(0, FrameType::PasteBegin as u8, 21).unwrap_err();
        assert!(matches!(e, FrameError::DataOnControlStream));
    }

    #[test]
    fn paste_begin_rejects_truncated() {
        let e = Frame::validate_header(1, FrameType::PasteBegin as u8, 20).unwrap_err();
        assert!(matches!(e, FrameError::PasteBeginTruncated(20)));
    }

    #[test]
    fn paste_begin_rejects_oversize_total() {
        let mut p = Vec::with_capacity(21);
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&(MAX_PASTE_TOTAL_BYTES + 1).to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(0);
        let e = Frame::from_payload(1, FrameType::PasteBegin, p).unwrap_err();
        assert!(matches!(e, FrameError::PasteBeginTotalSize(_)));
    }

    #[test]
    fn paste_begin_rejects_zero_group_size() {
        let mut p = Vec::with_capacity(21);
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // group_size = 0 — illegal
        p.push(0);
        let e = Frame::from_payload(1, FrameType::PasteBegin, p).unwrap_err();
        assert!(matches!(e, FrameError::PasteBeginGroupSizeZero(0)));
    }

    #[test]
    fn paste_begin_rejects_name_len_mismatch() {
        let mut p = Vec::with_capacity(21);
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(10); // name_len=10 but no name bytes follow
        let e = Frame::from_payload(1, FrameType::PasteBegin, p).unwrap_err();
        assert!(matches!(e, FrameError::PasteBeginTruncated(_)));
    }

    #[test]
    fn paste_chunk_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let f = Frame::paste_chunk(5, 0xcafe_babe, bytes.clone());
        let enc = f.encode();
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        let (ty, _) = Frame::validate_header(5, enc[4], len).unwrap();
        assert_eq!(ty, FrameType::PasteChunk);
        let back = Frame::from_payload(5, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteChunk { paste_id, bytes: b } => {
                assert_eq!(paste_id, 0xcafe_babe);
                assert_eq!(b, bytes);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn paste_chunk_zero_bytes_is_legal() {
        let f = Frame::paste_chunk(1, 0, vec![]);
        let enc = f.encode();
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        assert_eq!(len, 4); // just the paste_id
        let back = Frame::from_payload(1, FrameType::PasteChunk, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteChunk { bytes, .. } => assert!(bytes.is_empty()),
            _ => panic!(),
        }
    }

    #[test]
    fn paste_chunk_rejects_oversize() {
        let e = Frame::validate_header(1, FrameType::PasteChunk as u8, MAX_PASTE_CHUNK_LEN + 1)
            .unwrap_err();
        assert!(matches!(e, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn paste_chunk_rejects_missing_paste_id() {
        let e = Frame::validate_header(1, FrameType::PasteChunk as u8, 3).unwrap_err();
        assert!(matches!(e, FrameError::PasteChunkTruncated(3)));
    }

    #[test]
    fn paste_end_round_trip_ok() {
        let f = Frame::paste_end(7, 42, PASTE_STATUS_OK);
        let enc = f.encode();
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        assert_eq!(len, PASTE_END_LEN);
        let (ty, _) = Frame::validate_header(7, enc[4], len).unwrap();
        let back = Frame::from_payload(7, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteEnd { paste_id, status } => {
                assert_eq!(paste_id, 42);
                assert_eq!(status, PASTE_STATUS_OK);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn paste_end_cancel_round_trips() {
        let f = Frame::paste_end(7, 42, PASTE_STATUS_CANCEL);
        let enc = f.encode();
        let back = Frame::from_payload(7, FrameType::PasteEnd, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteEnd { status, .. } => assert_eq!(status, PASTE_STATUS_CANCEL),
            _ => panic!(),
        }
    }

    #[test]
    fn paste_end_rejects_wrong_len() {
        let e = Frame::validate_header(1, FrameType::PasteEnd as u8, 4).unwrap_err();
        assert!(matches!(e, FrameError::PasteEndLen(4)));
        let e = Frame::validate_header(1, FrameType::PasteEnd as u8, 6).unwrap_err();
        assert!(matches!(e, FrameError::PasteEndLen(6)));
    }

    #[test]
    fn paste_end_rejects_bad_status() {
        let mut p = Vec::with_capacity(5);
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(7);
        let e = Frame::from_payload(1, FrameType::PasteEnd, p).unwrap_err();
        assert!(matches!(e, FrameError::PasteEndStatus(7)));
    }

    #[test]
    fn paste_end_rejected_on_control_stream() {
        let e = Frame::validate_header(0, FrameType::PasteEnd as u8, 5).unwrap_err();
        assert!(matches!(e, FrameError::DataOnControlStream));
    }

    #[test]
    fn paste_reject_round_trip() {
        let f = Frame::paste_reject(7, 0x1234, PASTE_REJECT_REGISTRY_FULL);
        let enc = f.encode();
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        assert_eq!(len, PASTE_REJECT_LEN);
        let (ty, _) = Frame::validate_header(7, enc[4], len).unwrap();
        assert_eq!(ty, FrameType::PasteReject);
        let back = Frame::from_payload(7, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::PasteReject { paste_id, reason } => {
                assert_eq!(paste_id, 0x1234);
                assert_eq!(reason, PASTE_REJECT_REGISTRY_FULL);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn paste_reject_all_reasons_decode() {
        for r in 0..=PASTE_REJECT_MAX_REASON {
            let f = Frame::paste_reject(1, 0, r);
            let enc = f.encode();
            let back = Frame::from_payload(1, FrameType::PasteReject, enc[HEADER_LEN..].to_vec())
                .unwrap();
            match back.body {
                Body::PasteReject { reason, .. } => assert_eq!(reason, r),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn paste_reject_rejects_unknown_reason() {
        let mut p = Vec::with_capacity(5);
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(PASTE_REJECT_MAX_REASON + 1);
        let e = Frame::from_payload(1, FrameType::PasteReject, p).unwrap_err();
        assert!(matches!(e, FrameError::PasteRejectReason(_)));
    }

    #[test]
    fn paste_reject_rejects_wrong_len() {
        let e = Frame::validate_header(1, FrameType::PasteReject as u8, 4).unwrap_err();
        assert!(matches!(e, FrameError::PasteRejectLen(4)));
    }

    #[test]
    fn paste_reject_rejected_on_control_stream() {
        let e = Frame::validate_header(0, FrameType::PasteReject as u8, 5).unwrap_err();
        assert!(matches!(e, FrameError::DataOnControlStream));
    }

    #[test]
    fn download_begin_round_trip() {
        let f = Frame::download_begin(5, 0xfeedface, 42, "report.pdf".into());
        let enc = f.encode();
        let stream_id = u32::from_be_bytes([enc[0], enc[1], enc[2], enc[3]]);
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        let (ty, _) = Frame::validate_header(stream_id, enc[4], len).unwrap();
        assert_eq!(ty, FrameType::DownloadBegin);
        let back = Frame::from_payload(stream_id, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::DownloadBegin { download_id, total_size, name } => {
                assert_eq!(download_id, 0xfeedface);
                assert_eq!(total_size, 42);
                assert_eq!(name, "report.pdf");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn download_begin_rejects_oversize_total() {
        let mut p = Vec::with_capacity(13);
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&(MAX_PASTE_TOTAL_BYTES + 1).to_be_bytes());
        p.push(0);
        let e = Frame::from_payload(1, FrameType::DownloadBegin, p).unwrap_err();
        assert!(matches!(e, FrameError::DownloadBeginTotalSize(_)));
    }

    #[test]
    fn download_begin_rejects_truncated() {
        let e = Frame::validate_header(1, FrameType::DownloadBegin as u8, 12).unwrap_err();
        assert!(matches!(e, FrameError::DownloadBeginTruncated(12)));
    }

    #[test]
    fn download_chunk_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let f = Frame::download_chunk(2, 7, bytes.clone());
        let enc = f.encode();
        let back = Frame::from_payload(
            2, FrameType::DownloadChunk, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::DownloadChunk { download_id, bytes: b } => {
                assert_eq!(download_id, 7);
                assert_eq!(b, bytes);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn download_chunk_rejects_oversize() {
        let e = Frame::validate_header(1, FrameType::DownloadChunk as u8,
            MAX_DOWNLOAD_CHUNK_LEN + 1).unwrap_err();
        assert!(matches!(e, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn download_chunk_rejects_truncated() {
        let e = Frame::validate_header(1, FrameType::DownloadChunk as u8, 3).unwrap_err();
        assert!(matches!(e, FrameError::DownloadChunkTruncated(3)));
    }

    #[test]
    fn download_end_round_trip_ok_and_cancel() {
        for st in [DOWNLOAD_STATUS_OK, DOWNLOAD_STATUS_CANCEL] {
            let f = Frame::download_end(2, 5, st);
            let enc = f.encode();
            let back = Frame::from_payload(
                2, FrameType::DownloadEnd, enc[HEADER_LEN..].to_vec()).unwrap();
            match back.body {
                Body::DownloadEnd { download_id, status } => {
                    assert_eq!(download_id, 5);
                    assert_eq!(status, st);
                }
                _ => panic!(),
            }
        }
    }

    #[test]
    fn download_end_rejects_bad_status() {
        let mut p = Vec::with_capacity(5);
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(7);
        let e = Frame::from_payload(1, FrameType::DownloadEnd, p).unwrap_err();
        assert!(matches!(e, FrameError::DownloadEndStatus(7)));
    }

    #[test]
    fn download_end_rejects_wrong_len() {
        let e = Frame::validate_header(1, FrameType::DownloadEnd as u8, 4).unwrap_err();
        assert!(matches!(e, FrameError::DownloadEndLen(4)));
    }

    #[test]
    fn download_frames_rejected_on_control_stream() {
        for ty in [FrameType::DownloadBegin, FrameType::DownloadChunk, FrameType::DownloadEnd] {
            let len = match ty {
                FrameType::DownloadBegin => 13,
                FrameType::DownloadChunk => 4,
                FrameType::DownloadEnd   => 5,
                _ => unreachable!(),
            };
            let e = Frame::validate_header(0, ty as u8, len).unwrap_err();
            assert!(matches!(e, FrameError::DataOnControlStream));
        }
    }

    // ----- controller frames + Open size piggyback -----

    #[test]
    fn open_with_size_round_trips() {
        let f = Frame::open(7, "abc-123".into(), (24, 80));
        let enc = f.encode();
        let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
        assert_eq!(len, 7 + 4);
        let (ty, _) = Frame::validate_header(7, enc[4], len).unwrap();
        let back = Frame::from_payload(7, ty, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::Open { session_id, initial_size } => {
                assert_eq!(session_id, "abc-123");
                assert_eq!(initial_size, (24, 80));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn open_64byte_id_with_size_works() {
        // Exactly MAX_SESSION_ID_LEN id + 4 bytes size = 68 = MAX_OPEN_LEN.
        let id = "a".repeat(MAX_SESSION_ID_LEN as usize);
        let f = Frame::open(7, id.clone(), (50, 200));
        let enc = f.encode();
        let back = Frame::from_payload(7, FrameType::Open, enc[HEADER_LEN..].to_vec()).unwrap();
        match back.body {
            Body::Open { session_id, initial_size } => {
                assert_eq!(session_id, id);
                assert_eq!(initial_size, (50, 200));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn open_rejects_too_short() {
        // len 4 = no room for session_id even with size.
        let e = Frame::validate_header(7, FrameType::Open as u8, 4).unwrap_err();
        assert!(matches!(e, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn open_rejects_oversize() {
        let e = Frame::validate_header(7, FrameType::Open as u8, MAX_OPEN_LEN + 1).unwrap_err();
        assert!(matches!(e, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn open_rejects_invalid_session_id() {
        // "a b" id + (1,2) size — invalid charset; valid length 7.
        let mut p = b"a b".to_vec();
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&2u16.to_be_bytes());
        let e = Frame::from_payload(7, FrameType::Open, p).unwrap_err();
        assert!(matches!(e, FrameError::InvalidSessionId));
    }

    #[test]
    fn control_frames_round_trip() {
        type Ctor = fn(u32) -> Frame;
        let cases: &[(Ctor, FrameType)] = &[
            (Frame::acquire_control, FrameType::AcquireControl),
            (Frame::release_control, FrameType::ReleaseControl),
            (Frame::take_control,    FrameType::TakeControl),
        ];
        for (ctor, expected_ty) in cases.iter().copied() {
            let f = ctor(3);
            let enc = f.encode();
            let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
            assert_eq!(len, 0);
            let (ty, _) = Frame::validate_header(3, enc[4], len).unwrap();
            assert_eq!(ty, expected_ty);
            let back = Frame::from_payload(3, ty, vec![]).unwrap();
            assert_eq!(back.ty(), expected_ty);
        }
    }

    #[test]
    fn control_frames_reject_nonempty_payload() {
        let e = Frame::validate_header(3, FrameType::AcquireControl as u8, 1).unwrap_err();
        assert!(matches!(e, FrameError::ControlFrameNonEmpty { .. }));
    }

    #[test]
    fn control_frames_rejected_on_control_stream() {
        for ty in [
            FrameType::AcquireControl,
            FrameType::ReleaseControl,
            FrameType::TakeControl,
        ] {
            let e = Frame::validate_header(0, ty as u8, 0).unwrap_err();
            assert!(matches!(e, FrameError::DataOnControlStream));
        }
    }

    #[test]
    fn controller_changed_round_trip() {
        for st in [
            CONTROLLER_STATUS_NONE,
            CONTROLLER_STATUS_SELF,
            CONTROLLER_STATUS_OTHER,
        ] {
            let f = Frame::controller_changed(5, st);
            let enc = f.encode();
            let len = u32::from_be_bytes([enc[5], enc[6], enc[7], enc[8]]);
            assert_eq!(len, CONTROLLER_CHANGED_LEN);
            let (ty, _) = Frame::validate_header(5, enc[4], len).unwrap();
            assert_eq!(ty, FrameType::ControllerChanged);
            let back = Frame::from_payload(5, ty, enc[HEADER_LEN..].to_vec()).unwrap();
            match back.body {
                Body::ControllerChanged { status } => assert_eq!(status, st),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn controller_changed_rejects_wrong_len() {
        let e = Frame::validate_header(5, FrameType::ControllerChanged as u8, 4).unwrap_err();
        assert!(matches!(e, FrameError::ControllerChangedLen(4)));
    }

    #[test]
    fn controller_changed_rejects_bad_status() {
        let e = Frame::from_payload(5, FrameType::ControllerChanged, vec![7]).unwrap_err();
        assert!(matches!(e, FrameError::ControllerChangedStatus(7)));
    }
}
