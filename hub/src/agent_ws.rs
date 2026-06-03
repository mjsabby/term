//! WebSocket transport for the agent↔hub mux.
//!
//! Lets an agent dial the hub over `wss://…/agent/connect` instead of a
//! raw TCP/TLS connection to `agent_bind`. This is what makes the agent
//! reachable through an HTTP/WS-only perimeter (e.g. a Microsoft Dev
//! Tunnel): one tunnel-fronted hub can serve agents on any machine that
//! can reach the tunnel and present its access claim.
//!
//! Each agent frame is carried as exactly one binary WebSocket message
//! (same shape as the browser proxy). Authentication is unchanged — the
//! agent's PSK still rides in the Hello frame and is checked by
//! [`crate::agent_link::handle_connection`]; the WebSocket layer adds no
//! hub-side auth of its own (the perimeter + PSK are the gates).

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use tracing::{info, warn};

use term_common::frame::{Frame, FrameError, HEADER_LEN, MAX_PASTE_CHUNK_LEN};
use term_common::transport::{frame_from_ws_payload, FrameRecv, FrameSend};

use crate::agent_link::handle_connection;
use crate::state::AppState;

/// Cap on a single agent WebSocket message — one frame, at most a
/// maximally-sized PasteChunk/DownloadChunk plus header slack. Mirrors
/// the browser proxy's bound.
const AGENT_WS_MAX_BYTES: usize = HEADER_LEN + MAX_PASTE_CHUNK_LEN as usize + 1024;

/// `GET /agent/connect` — upgrade to a WebSocket and run the agent mux
/// over it. No bearer/Origin requirement: agents authenticate by PSK in
/// the Hello frame, and (unlike browsers) send no `Origin` header.
pub async fn connect(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let peer = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| format!("ws:{s}"))
        .unwrap_or_else(|| "ws".to_string());

    ws.max_message_size(AGENT_WS_MAX_BYTES)
        .max_frame_size(AGENT_WS_MAX_BYTES)
        .on_upgrade(move |socket| async move {
            let (sink, stream) = socket.split();
            info!(peer = %peer, "agent ws connected");
            if let Err(e) =
                handle_connection(state, WsRecv(stream), WsSend(sink), peer.clone()).await
            {
                warn!(peer = %peer, error = %e, "agent ws connection ended with error");
            }
        })
}

/// [`FrameRecv`] over the read half of an axum [`WebSocket`].
pub struct WsRecv(pub SplitStream<WebSocket>);

impl FrameRecv for WsRecv {
    async fn recv(&mut self) -> Result<Option<(Frame, u64)>, FrameError> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(data))) => {
                    return frame_from_ws_payload(&data).map(Some);
                }
                // Control frames: axum answers Ping automatically; Pong /
                // Text aren't part of our protocol — skip and keep reading.
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) => {
                    continue;
                }
                // Clean close, end of stream, or a transport error all
                // mean "no more frames" — surface as EOF so the mux tears
                // down gracefully.
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Err(_)) => return Ok(None),
            }
        }
    }
}

/// [`FrameSend`] over the write half of an axum [`WebSocket`].
pub struct WsSend(pub SplitSink<WebSocket, Message>);

impl FrameSend for WsSend {
    async fn send(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        self.0
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
    async fn close(&mut self) {
        let _ = self.0.send(Message::Close(None)).await;
        let _ = self.0.close().await;
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end test of the `/agent/connect` WebSocket route: spin up
    //! the real authed router on a loopback port, dial it with a
    //! tungstenite client, send a Hello frame, and assert the agent
    //! registers (correct PSK) or doesn't (wrong PSK). Exercises the
    //! route wiring + `WsRecv`/`WsSend` + Hello/PSK over a real socket.

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    use crate::config::{HubConfig, MachineConfig, TlsMode};
    use crate::state::AppState;
    use term_common::frame::{Frame, HelloPayload, HELLO_VERSION};

    const PSK_BYTES: [u8; 32] = [7u8; 32];

    fn psk_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode(PSK_BYTES)
    }

    /// Bind the authed router on an ephemeral loopback port and spawn it.
    /// Returns the bound address + the shared `AppState` so the test can
    /// observe agent registration.
    async fn spawn_hub() -> (SocketAddr, AppState) {
        let cfg = HubConfig {
            domain: "term.example.com".into(),
            rp_id: "example.com".into(),
            rp_name: "term".into(),
            tls: TlsMode::Off,
            acme_email: None,
            acme_production: false,
            cert_path: None,
            key_path: None,
            tls_reload_interval_secs: None,
            data_dir: std::env::temp_dir(),
            bind: None,
            agent_bind: "[::]:0".into(),
            public_origin: Some("http://127.0.0.1".into()),
            no_auth: None,
            machines: vec![MachineConfig {
                id: "alpha".into(),
                label: "alpha".into(),
                psk: psk_b64(),
            }],
        };
        let state = AppState::new(Arc::new(cfg), [0u8; 32]);
        let mode = crate::listener_mode::ListenerMode {
            no_auth: false,
            origin: state.cfg.origin(),
        };
        let app = crate::build_authed_router(state.clone(), mode);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (addr, state)
    }

    /// Dial `/agent/connect` and send one Hello frame with `psk`.
    async fn send_hello(addr: SocketAddr, machine_id: &str, psk: &str) {
        let url = format!("ws://{addr}/agent/connect");
        let req = url.into_client_request().unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
        let hello = HelloPayload {
            version: HELLO_VERSION,
            machine_id: machine_id.into(),
            psk_b64: psk.into(),
        };
        let frame = Frame::hello(serde_json::to_vec(&hello).unwrap());
        ws.send(Message::Binary(frame.encode().into())).await.unwrap();
        // Keep the socket open briefly so the hub processes the Hello.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = ws.close(None).await;
    }

    async fn agent_registered(state: &AppState, id: &str) -> bool {
        for _ in 0..40 {
            if state.agents.lock().await.contains_key(id) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    #[tokio::test]
    async fn correct_psk_registers_agent_over_ws() {
        let (addr, state) = spawn_hub().await;
        send_hello(addr, "alpha", &psk_b64()).await;
        assert!(
            agent_registered(&state, "alpha").await,
            "agent with the correct PSK should register over the ws transport",
        );
    }

    #[tokio::test]
    async fn wrong_psk_does_not_register_over_ws() {
        let (addr, state) = spawn_hub().await;
        let bad = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        send_hello(addr, "alpha", &bad).await;
        // Give the hub a moment; it must reject the Hello and never
        // register the machine.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !state.agents.lock().await.contains_key("alpha"),
            "a wrong PSK must not register the agent",
        );
    }
}
