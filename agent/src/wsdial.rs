//! WebSocket *client* dial path: lets the agent reach the hub through an
//! HTTP/WS-only perimeter (e.g. a Microsoft Dev Tunnel) instead of a raw
//! TCP/TLS connection to `agent_bind`. Selected when `hub` is a `ws://`
//! or `wss://` URL.
//!
//! Authentication: the agent attaches two HTTP headers on every WS
//! upgrade so the hub can verify it without an mTLS handshake (which
//! is impossible end-to-end through a TLS-terminating perimeter):
//!
//! - `X-Agent-Cert: <base64-no-pad of leaf cert DER>`
//! - `X-Agent-Auth: <unix_secs>.<nonce>.<ECDSA-P256 sig>` over a
//!   domain-separated payload that includes the Host header. The hub
//!   verifies signature freshness against a small replay cache so a
//!   tunnel-eavesdropper can't replay the assertion.
//!
//! On top of that, the WS upgrade request also carries the legacy
//! perimeter token header (`X-Tunnel-Authorization: tunnel <token>` by
//! default) so the tunnel lets the dial through. TLS for `wss` reuses
//! the agent's existing rustls (ring) connector, so tungstenite needs
//! no TLS feature of its own — avoiding a second crypto provider in
//! the binary.

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

use term_common::agent_pki::{
    HEADER_AGENT_AUTH, HEADER_AGENT_CERT, WS_AUTH_NONCE_LEN, ws_auth_payload,
};
use term_common::frame::{Frame, FrameError};
use term_common::random;
use term_common::transport::{FrameRecv, FrameSend, frame_from_ws_payload};

use crate::ResolvedConfig;

/// Dial `cfg.hub` (a ws/wss URL) and run the agent mux over the
/// resulting WebSocket. `sessions` is the process-wide session manager
/// (owned by `main`), shared across reconnects so shells persist.
pub async fn run_ws(
    cfg: Arc<ResolvedConfig>,
    tls: tokio_rustls::TlsConnector,
    sessions: Arc<crate::session::SessionManager>,
) -> Result<()> {
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
    let host_for_tcp = url
        .host_str()
        .ok_or_else(|| anyhow!("hub url {} has no host", cfg.hub))?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if secure { 443 } else { 80 });

    // Build the WS upgrade request (Host/Upgrade/Sec-WebSocket-* are
    // filled in by `into_client_request`) and attach (a) the perimeter
    // token header, read fresh on every reconnect so a rotated token
    // is used; and (b) the agent's mTLS-equivalent assertion
    // (X-Agent-Cert + X-Agent-Auth) so the hub can authenticate us
    // through the TLS-terminating perimeter.
    let mut request = cfg
        .hub
        .as_str()
        .into_client_request()
        .context("build ws upgrade request")?;
    if let Some((name, value)) = tunnel_auth_header(&cfg)? {
        request.headers_mut().insert(name, value);
        debug!("attached perimeter auth header to ws upgrade");
    }
    let host = request
        .uri()
        .host()
        .ok_or_else(|| anyhow!("ws upgrade uri has no host"))?
        .to_string();
    let (cert_header, auth_header) = agent_auth_headers(&cfg, &host)?;
    request
        .headers_mut()
        .insert(HeaderName::from_static(HEADER_AGENT_CERT), cert_header);
    request
        .headers_mut()
        .insert(HeaderName::from_static(HEADER_AGENT_AUTH), auth_header);

    debug!("dialing {} (websocket, tls={})", cfg.hub, secure);
    let tcp = TcpStream::connect((host_for_tcp.as_str(), port))
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
        info!(host = %cfg.server_name, "agent connected over wss");
        drive(ws, sessions).await
    } else {
        let (ws, _resp) = client_async_with_config(request, tcp, None)
            .await
            .context("websocket handshake")?;
        info!(host = %cfg.server_name, "agent connected over ws");
        drive(ws, sessions).await
    }
}

async fn drive<S>(
    ws: WebSocketStream<S>,
    sessions: Arc<crate::session::SessionManager>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    crate::run_session(sessions, WsRecv(stream), WsSend(sink)).await
}

/// Build the X-Agent-Cert and X-Agent-Auth header values for the WS
/// upgrade to `host`. Generates a fresh 16-byte nonce per upgrade and
/// signs the canonical `ws_auth_payload(host, now, nonce)` bytes with
/// the agent's PKCS#8 ECDSA-P256 key using ring.
fn agent_auth_headers(cfg: &ResolvedConfig, host: &str) -> Result<(HeaderValue, HeaderValue)> {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let leaf = cfg
        .cert_chain
        .first()
        .ok_or_else(|| anyhow!("cert_chain is empty"))?;
    let cert_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf.as_ref());

    let mut nonce = [0u8; WS_AUTH_NONCE_LEN];
    random::fill(&mut nonce);
    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let payload = ws_auth_payload(host, now, &nonce);

    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &cfg.key_pkcs8, &rng)
        .map_err(|e| anyhow!("load PKCS#8 ECDSA key: {e:?}"))?;
    let sig = kp
        .sign(&rng, &payload)
        .map_err(|_| anyhow!("ring ECDSA sign failed"))?;
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref());

    let auth_value = format!("{now}.{nonce_b64}.{sig_b64}");
    let cert_header =
        HeaderValue::from_str(&cert_b64).context("encode X-Agent-Cert header value")?;
    let auth_header =
        HeaderValue::from_str(&auth_value).context("encode X-Agent-Auth header value")?;
    Ok((cert_header, auth_header))
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
            tls_on: true,
            server_name: "example.test".into(),
            shell: "/bin/sh".into(),
            limits: crate::Limits::default(),
            tunnel_token_file: token_file,
            tunnel_auth_header: "X-Tunnel-Authorization".into(),
            tunnel_auth_scheme: "tunnel".into(),
            tunnel_token_cache: std::sync::Mutex::new(None),
            cert_chain: vec![],
            key_pkcs8: vec![],
            hub_ca_path: None,
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
