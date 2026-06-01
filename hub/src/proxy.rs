//! Browser-facing WebSocket endpoint that proxies one tab to one stream
//! on the agent's persistent multiplexed connection.
//!
//! Auth: bearer token via `Sec-WebSocket-Protocol: bearer.<token>`.
//! Origin check against the configured public origin.
//!
//! Browser side: each WS binary message is exactly one frame with
//! `stream_id = 0`. The hub injects the real stream id when forwarding
//! to the agent, and strips it back to 0 on the way back to the browser.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tracing::{debug, info, warn};

use term_common::frame::{Frame, HEADER_LEN, MAX_PASTE_CHUNK_LEN};

use crate::auth::{check_origin, token_from_ws_protocol, validate_token};
use crate::state::AppState;

pub async fn term_ws(
    ws: WebSocketUpgrade,
    Path(machine_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    // Origin check.
    let expected = state.cfg.origin();
    if check_origin(&headers, &expected).is_err() {
        return (StatusCode::FORBIDDEN, "bad origin").into_response();
    }

    // Bearer via subprotocol.
    let (token, subprotocol) = match token_from_ws_protocol(&headers) {
        Some(p) => p,
        None    => return (StatusCode::UNAUTHORIZED, "missing bearer subprotocol").into_response(),
    };
    if !validate_token(&state, &token).await {
        return (StatusCode::UNAUTHORIZED, "invalid bearer").into_response();
    }

    // Look up agent link.
    let link = {
        let map = state.agents.lock().await;
        map.get(&machine_id).cloned()
    };
    let link = match link {
        Some(l) => l,
        None => {
            warn!(machine = %machine_id, "ws upgrade: agent not connected");
            return (StatusCode::SERVICE_UNAVAILABLE, "agent not connected").into_response();
        }
    };

    let machine_id = machine_id.clone();
    info!(machine = %machine_id, "ws upgrade -> agent link");

    // Cap WS messages just above the largest legal stream-scoped frame
    // (a maximally-sized PasteChunk). The browser sends a paste as
    // (Begin, Chunk × N, End) with chunks of at most MAX_PASTE_CHUNK_LEN
    // payload bytes; this bound covers the worst case with plenty of
    // header room. axum 0.8 defaults to 64 MiB / 16 MiB; the explicit
    // cap protects us if those defaults change and keeps a malicious
    // browser from ballooning per-connection memory.
    const WS_MAX_BYTES: usize = HEADER_LEN + MAX_PASTE_CHUNK_LEN as usize + 1024;
    ws.max_message_size(WS_MAX_BYTES)
        .max_frame_size(WS_MAX_BYTES)
        .protocols([subprotocol])
        .on_upgrade(move |ws| async move { run_proxy(ws, link, machine_id).await })
}

async fn run_proxy(
    ws: WebSocket,
    link: std::sync::Arc<crate::agent_link::AgentLink>,
    machine_id: String,
) {
    let (sink, mut source) = link.open_stream().await;
    let stream_id = sink.id;
    debug!(machine = %machine_id, stream_id, "opened mux stream");

    let (mut ws_tx, mut ws_rx) = ws.split();

    // Browser -> stream. Each WS binary message is one frame with
    // stream_id=0; we re-frame with the real stream_id on the way out.
    let ws_to_stream = async {
        loop {
            let msg = match ws_rx.next().await {
                Some(Ok(m))  => m,
                Some(Err(e)) => { debug!(error=%e, "ws rx error"); break; }
                None         => break,
            };
            match msg {
                Message::Binary(data) => {
                    if data.len() < HEADER_LEN {
                        warn!("ws frame shorter than header"); break;
                    }
                    let in_stream = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    if in_stream != 0 {
                        warn!("browser frame had non-zero stream id {in_stream}"); break;
                    }
                    let ty_byte = data[4];
                    let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                    let (ty, len) = match Frame::validate_header(stream_id, ty_byte, len) {
                        Ok(v)  => v,
                        Err(e) => { warn!(error=%e, "ws frame rejected"); break; }
                    };
                    if data.len() != HEADER_LEN + len as usize {
                        warn!("ws frame length mismatch"); break;
                    }
                    let body = match Frame::from_payload(stream_id, ty, data[HEADER_LEN..].to_vec()) {
                        Ok(f)  => f.body,
                        Err(e) => { warn!(error=%e, "ws frame payload rejected"); break; }
                    };
                    if sink.send(body).await.is_err() {
                        debug!("agent link closed"); break;
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => { /* axum auto-pongs */ }
                Message::Text(_)  => { warn!("unexpected text ws message"); break; }
            }
        }
    };

    // Stream -> browser. Each Body arrives with stream_id implicit (it's
    // OURS). Emit as a frame with stream_id=0.
    let stream_to_ws = async {
        while let Some(body) = source.recv().await {
            let outbound = Frame { stream_id: 0, body }.encode();
            if ws_tx.send(Message::Binary(outbound.into())).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = ws_to_stream => {}
        _ = stream_to_ws => {}
    }
    let _ = ws_tx.send(Message::Close(None)).await;
    // Dropping `sink` (and the implicit `source` move into stream_to_ws)
    // releases the shared StreamGuard, which sends Close to the agent.
}
