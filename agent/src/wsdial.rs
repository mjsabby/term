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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tracing::{debug, info};

use term_common::frame::{Frame, FrameError};
use term_common::transport::{FrameRecv, FrameSend, frame_from_ws_payload};

use crate::ResolvedConfig;

/// Dial `cfg.hub` (a ws/wss URL) and run the agent mux over the
/// resulting WebSocket.
pub async fn run_ws(cfg: Arc<ResolvedConfig>, tls: tokio_rustls::TlsConnector) -> Result<()> {
    let url = url::Url::parse(&cfg.hub).with_context(|| format!("parse hub url {}", cfg.hub))?;
    let secure = match url.scheme() {
        "wss" => true,
        "ws" => false,
        other => {
            return Err(anyhow!(
                "unsupported hub url scheme {other:?} (want ws/wss)"
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("hub url {} has no host", cfg.hub))?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if secure { 443 } else { 80 });

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

/// Cached perimeter token + its parsed expiry.
pub(crate) struct CachedToken {
    raw: String,
    expires_at: SystemTime,
}

/// Refresh the token this long before its `exp`, so we never hand the
/// perimeter a token that lapses mid-handshake (and to absorb clock skew).
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Resolve the perimeter auth header from `tunnel_token_file`. Returns
/// `None` (no header) when no file is configured — fine for an anonymous
/// tunnel.
fn tunnel_auth_header(cfg: &ResolvedConfig) -> Result<Option<(HeaderName, HeaderValue)>> {
    let Some(path) = cfg.tunnel_token_file.as_deref() else {
        return Ok(None);
    };
    let token = current_token(cfg, path)?;
    if token.is_empty() {
        return Ok(None);
    }
    let value = if cfg.tunnel_auth_scheme.is_empty() {
        token
    } else {
        format!("{} {}", cfg.tunnel_auth_scheme, token)
    };
    let name = HeaderName::from_bytes(cfg.tunnel_auth_header.as_bytes())
        .with_context(|| format!("invalid tunnel_auth_header {:?}", cfg.tunnel_auth_header))?;
    let value =
        HeaderValue::from_str(&value).context("tunnel token produced an invalid header value")?;
    Ok(Some((name, value)))
}

/// Return the current perimeter token, reusing the in-memory cache while
/// it's still valid and only re-reading `path` when the cached token is
/// near expiry. A token whose `exp` we can't parse (not a JWT) is not
/// cached, so it's re-read on every reconnect — the safe fallback.
fn current_token(cfg: &ResolvedConfig, path: &str) -> Result<String> {
    let now = SystemTime::now();
    if let Some(c) = cfg.tunnel_token_cache.lock().unwrap().as_ref()
        && c.expires_at > now + TOKEN_REFRESH_MARGIN
    {
        return Ok(c.raw.clone());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read tunnel_token_file {path}"))?
        .trim()
        .to_string();
    *cfg.tunnel_token_cache.lock().unwrap() = jwt_exp(&raw).map(|expires_at| CachedToken {
        raw: raw.clone(),
        expires_at,
    });
    Ok(raw)
}

/// Best-effort parse of a JWT's `exp` (unix seconds) from its payload
/// segment. `None` for anything that isn't a 3-segment JWT with a numeric
/// `exp` — callers treat that as "expiry unknown" and don't cache.
fn jwt_exp(token: &str) -> Option<SystemTime> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    parts.next()?; // signature segment must exist (JWT shape)
    if parts.next().is_some() {
        return None; // more than 3 segments -> not a JWT
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = v.get("exp")?.as_u64()?;
    Some(UNIX_EPOCH + Duration::from_secs(exp))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build a structurally-valid JWT (`header.payload.sig`) whose payload
    /// carries the given `exp`. The signature is bogus — we never verify
    /// it, only read `exp`.
    fn make_jwt(exp_secs: u64) -> String {
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = enc(br#"{"alg":"none"}"#);
        let payload = enc(format!(r#"{{"exp":{exp_secs}}}"#).as_bytes());
        format!("{header}.{payload}.sig")
    }

    fn test_cfg(token_file: Option<String>) -> ResolvedConfig {
        ResolvedConfig {
            hub: "wss://example.test/agent/connect".into(),
            machine_id: "m".into(),
            psk: "p".into(),
            tls_on: true,
            server_name: "example.test".into(),
            shell: "/bin/sh".into(),
            limits: crate::Limits::default(),
            tunnel_token_file: token_file,
            tunnel_auth_header: "X-Tunnel-Authorization".into(),
            tunnel_auth_scheme: "tunnel".into(),
            tunnel_token_cache: std::sync::Mutex::new(None),
        }
    }

    #[test]
    fn jwt_exp_parses_and_rejects() {
        let exp = unix_now() + 3600;
        let got = jwt_exp(&make_jwt(exp)).unwrap();
        assert_eq!(got.duration_since(UNIX_EPOCH).unwrap().as_secs(), exp);
        // Not a JWT / wrong segment count / no exp -> None.
        assert!(jwt_exp("not-a-jwt").is_none());
        assert!(jwt_exp("only.two").is_none());
        assert!(jwt_exp("a.b.c.d").is_none());
    }

    #[test]
    fn token_cache_reuses_until_expiry() {
        let path = std::env::temp_dir().join(format!("term-tok-reuse-{}.jwt", std::process::id()));
        std::fs::write(&path, make_jwt(unix_now() + 3600)).unwrap();
        let cfg = test_cfg(Some(path.to_string_lossy().into_owned()));

        let t1 = current_token(&cfg, path.to_str().unwrap()).unwrap();
        // A still-valid cache must serve the token without touching disk:
        // delete the file and confirm the next call still succeeds.
        std::fs::remove_file(&path).unwrap();
        let t2 = current_token(&cfg, path.to_str().unwrap()).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn token_cache_refreshes_when_expired() {
        let now = unix_now();
        let path = std::env::temp_dir().join(format!("term-tok-exp-{}.jwt", std::process::id()));
        std::fs::write(&path, make_jwt(now.saturating_sub(10))).unwrap(); // already expired
        let cfg = test_cfg(Some(path.to_string_lossy().into_owned()));
        let _ = current_token(&cfg, path.to_str().unwrap()).unwrap();

        // Rotator writes a fresh token; an expired cache must re-read it.
        let fresh = make_jwt(now + 3600);
        std::fs::write(&path, &fresh).unwrap();
        let got = current_token(&cfg, path.to_str().unwrap()).unwrap();
        assert_eq!(got, fresh);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_jwt_token_is_not_cached() {
        let path = std::env::temp_dir().join(format!("term-tok-opaque-{}.jwt", std::process::id()));
        std::fs::write(&path, "opaque-token-v1").unwrap();
        let cfg = test_cfg(Some(path.to_string_lossy().into_owned()));
        assert_eq!(
            current_token(&cfg, path.to_str().unwrap()).unwrap(),
            "opaque-token-v1"
        );
        // Expiry unknown -> nothing cached, so a rotated file is picked up.
        std::fs::write(&path, "opaque-token-v2").unwrap();
        assert_eq!(
            current_token(&cfg, path.to_str().unwrap()).unwrap(),
            "opaque-token-v2"
        );
        let _ = std::fs::remove_file(&path);
    }
}
