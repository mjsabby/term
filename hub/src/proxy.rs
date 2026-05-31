//! WS endpoint that proxies one browser terminal to one TCP connection on
//! the agent. Auth is via `Sec-WebSocket-Protocol: bearer.<token>`.
//! Each WS binary message is exactly one frame; the hub validates the
//! frame header on the way in and re-frames the agent's TCP stream on the
//! way out so the browser sees one WS message per frame.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::auth::{check_origin, token_from_ws_protocol, validate_token};
use crate::state::AppState;
use term_common::frame::{Frame, HEADER_LEN};

pub async fn term_ws(
    ws: WebSocketUpgrade,
    Path(machine_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    // Origin check: defense in depth alongside the bearer.
    let expected = state.cfg.origin();
    if check_origin(&headers, &expected).is_err() {
        return (StatusCode::FORBIDDEN, "bad origin").into_response();
    }

    // Bearer token via subprotocol.
    let (token, subprotocol) = match token_from_ws_protocol(&headers) {
        Some(p) => p,
        None => return (StatusCode::UNAUTHORIZED, "missing bearer subprotocol").into_response(),
    };
    if !validate_token(&state, &token).await {
        return (StatusCode::UNAUTHORIZED, "invalid bearer").into_response();
    }

    // Resolve agent address.
    let agent_addr = match state
        .cfg
        .machines
        .iter()
        .find(|m| m.id == machine_id)
        .map(|m| m.address.clone())
    {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, "unknown machine").into_response(),
    };

    info!(machine = %machine_id, "ws upgrade -> agent {}", agent_addr);
    ws.protocols([subprotocol.clone()])
        .on_upgrade(move |ws| async move { run_proxy(ws, agent_addr, machine_id).await })
}

async fn run_proxy(ws: WebSocket, agent_addr: String, machine_id: String) {
    let tcp = match TcpStream::connect(&agent_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(machine = %machine_id, error = %e, "agent connect failed");
            let _ = send_close(ws, 1011, "agent unavailable").await;
            return;
        }
    };
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Browser -> agent. One WS binary message == one frame.
    let ws_to_tcp = async {
        loop {
            let msg = match ws_rx.next().await {
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    debug!(error=%e, "ws rx error");
                    break;
                }
                None => break,
            };
            match msg {
                Message::Binary(data) => {
                    if data.len() < HEADER_LEN {
                        warn!("ws frame shorter than header");
                        break;
                    }
                    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    if Frame::validate_header(data[0], len).is_err() {
                        warn!("ws frame header rejected");
                        break;
                    }
                    if data.len() != HEADER_LEN + len as usize {
                        warn!("ws frame length mismatch (msg={} hdr={})", data.len(), len);
                        break;
                    }
                    if let Err(e) = tcp_w.write_all(&data).await {
                        debug!(error=%e, "tcp write failed");
                        break;
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {} // axum auto-pongs
                Message::Text(_) => {
                    warn!("unexpected text ws message");
                    break;
                }
            }
        }
    };

    // Agent -> browser. Read one frame, emit one WS Binary message.
    let tcp_to_ws = async {
        loop {
            let mut hdr = [0u8; HEADER_LEN];
            if let Err(e) = tcp_r.read_exact(&mut hdr).await {
                debug!(error=%e, "tcp read header eof");
                break;
            }
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
            if Frame::validate_header(hdr[0], len).is_err() {
                warn!("agent sent invalid frame header");
                break;
            }
            let mut buf = vec![0u8; HEADER_LEN + len as usize];
            buf[..HEADER_LEN].copy_from_slice(&hdr);
            if len > 0 {
                if let Err(e) = tcp_r.read_exact(&mut buf[HEADER_LEN..]).await {
                    debug!(error=%e, "tcp read payload eof");
                    break;
                }
            }
            if let Err(e) = ws_tx.send(Message::Binary(buf.into())).await {
                debug!(error=%e, "ws send failed");
                break;
            }
        }
    };

    tokio::select! {
        _ = ws_to_tcp => {}
        _ = tcp_to_ws => {}
    }
    let _ = ws_tx.send(Message::Close(None)).await;
}

async fn send_close(ws: WebSocket, code: u16, reason: &'static str) -> anyhow::Result<()> {
    use axum::extract::ws::CloseFrame;
    let (mut tx, _rx) = ws.split();
    tx.send(Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    })))
    .await?;
    Ok(())
}
