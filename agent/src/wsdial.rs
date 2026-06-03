//! WebSocket *client* dial path: lets the agent reach the hub through an
//! HTTP/WS-only perimeter (e.g. a Microsoft Dev Tunnel) instead of a raw
//! TCP/TLS connection to `agent_bind`. Selected when `hub` is a `ws://`
//! or `wss://` URL.
//!
//! The agent's PSK auth is unchanged (it rides in the Hello frame). On
//! top of that, the WS upgrade request carries a perimeter access token
//! header (`X-Tunnel-Authorization: tunnel <token>` by default) so the
//! tunnel lets the dial through. TLS for `wss` reuses the agent's
//! existing rustls (ring) connector, so tungstenite needs no TLS feature
//! of its own — avoiding a second crypto provider in the binary.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::client_async_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info};

use term_common::frame::{Frame, FrameError};
use term_common::transport::{frame_from_ws_payload, FrameRecv, FrameSend};

use crate::ResolvedConfig;

/// Dial `cfg.hub` (a ws/wss URL) and run the agent mux over the
/// resulting WebSocket.
pub async fn run_ws(cfg: Arc<ResolvedConfig>, tls: tokio_rustls::TlsConnector) -> Result<()> {
    let url = url::Url::parse(&cfg.hub).with_context(|| format!("parse hub url {}", cfg.hub))?;
    let secure = match url.scheme() {
        "wss" => true,
        "ws" => false,
        other => return Err(anyhow!("unsupported hub url scheme {other:?} (want ws/wss)")),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("hub url {} has no host", cfg.hub))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(if secure { 443 } else { 80 });

    // Build the WS upgrade request (Host/Upgrade/Sec-WebSocket-* are
    // filled in by `into_client_request`) and attach the perimeter token
    // header, read fresh on every reconnect so a rotated token is used.
    let mut request = cfg
        .hub
        .as_str()
        .into_client_request()
        .context("build ws upgrade request")?;
    if let Some((name, value)) = tunnel_auth_header(&cfg)? {
        request.headers_mut().insert(name, value);
        debug!("attached perimeter auth header to ws upgrade");
    }

    debug!("dialing {} (websocket, tls={})", cfg.hub, secure);
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("tcp connect {host}:{port}"))?;
    tcp.set_nodelay(true).ok();

    if secure {
        let sn = ServerName::try_from(cfg.server_name.clone())
            .context("server_name must be a valid DNS name")?;
        let tls_stream = tls.connect(sn, tcp).await.context("tls handshake")?;
        let (ws, _resp) = client_async_with_config(request, tls_stream, None)
            .await
            .context("websocket handshake")?;
        info!(machine = %cfg.machine_id, "agent connected over wss");
        drive(cfg, ws).await
    } else {
        let (ws, _resp) = client_async_with_config(request, tcp, None)
            .await
            .context("websocket handshake")?;
        info!(machine = %cfg.machine_id, "agent connected over ws");
        drive(cfg, ws).await
    }
}

async fn drive<S>(cfg: Arc<ResolvedConfig>, ws: WebSocketStream<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    crate::run_session(cfg, WsRecv(stream), WsSend(sink)).await
}

/// Resolve the perimeter auth header from the configured token source.
/// `tunnel_token_file` wins over `tunnel_token_env`. Returns `None` (no
/// header) when neither yields a token — fine for an anonymous tunnel.
fn tunnel_auth_header(cfg: &ResolvedConfig) -> Result<Option<(HeaderName, HeaderValue)>> {
    let token = match &cfg.tunnel_token_file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("read tunnel_token_file {path}"))?,
        None => std::env::var(&cfg.tunnel_token_env).unwrap_or_default(),
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let value = if cfg.tunnel_auth_scheme.is_empty() {
        token.to_string()
    } else {
        format!("{} {}", cfg.tunnel_auth_scheme, token)
    };
    let name = HeaderName::from_bytes(cfg.tunnel_auth_header.as_bytes())
        .with_context(|| format!("invalid tunnel_auth_header {:?}", cfg.tunnel_auth_header))?;
    let value =
        HeaderValue::from_str(&value).context("tunnel token produced an invalid header value")?;
    Ok(Some((name, value)))
}

/// [`FrameRecv`] over the read half of a tungstenite WebSocket.
struct WsRecv<S>(SplitStream<WebSocketStream<S>>);

impl<S> FrameRecv for WsRecv<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn recv(&mut self) -> Result<Option<(Frame, u64)>, FrameError> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(data))) => return frame_from_ws_payload(&data).map(Some),
                // Clean close / end of stream / transport error -> EOF.
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Err(_)) => return Ok(None),
                // Ping/Pong/Text/raw-Frame aren't part of our protocol.
                Some(Ok(_)) => continue,
            }
        }
    }
}

/// [`FrameSend`] over the write half of a tungstenite WebSocket.
struct WsSend<S>(SplitSink<WebSocketStream<S>, Message>);

impl<S> FrameSend for WsSend<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.0
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }
    async fn close(&mut self) {
        let _ = self.0.send(Message::Close(None)).await;
        let _ = self.0.close().await;
    }
}
