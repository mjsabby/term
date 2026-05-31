//! Bearer-token auth. No cookies anywhere: the token is returned in JSON
//! from `/webauthn/login/finish` and the SPA holds it in a JS variable
//! for the lifetime of the tab.
//!
//! Transports:
//! - HTTP: `Authorization: Bearer <token>`
//! - WebSocket: `Sec-WebSocket-Protocol: bearer.<token>` (browsers can't
//!   set custom headers on WS upgrade). We echo the chosen subprotocol back.

use std::time::{Duration, SystemTime};

use axum::extract::FromRequestParts;
use axum::http::{request::Parts, HeaderMap, StatusCode};
use base64::Engine;
use rand::RngCore;

use crate::state::{gc, AppState, Session, SESSION_TTL};

/// 32 random bytes encoded as URL-safe base64 (no padding) = 43 chars.
pub fn mint_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub async fn store_token(state: &AppState, token: String) -> SystemTime {
    let expires_at = SystemTime::now() + SESSION_TTL;
    let mut sessions = state.sessions.lock().await;
    gc(&mut sessions, |s| s.expires_at);
    sessions.insert(token, Session { expires_at });
    expires_at
}

pub async fn validate_token(state: &AppState, token: &str) -> bool {
    let mut sessions = state.sessions.lock().await;
    gc(&mut sessions, |s| s.expires_at);
    sessions
        .get(token)
        .map(|s| s.expires_at > SystemTime::now())
        .unwrap_or(false)
}

pub async fn drop_token(state: &AppState, token: &str) {
    let mut sessions = state.sessions.lock().await;
    sessions.remove(token);
}

/// Authorization: Bearer extractor. Returns 401 when missing/invalid.
pub struct Bearer(pub String);

impl FromRequestParts<AppState> for Bearer {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "missing bearer"))?;

        if validate_token(state, &token).await {
            Ok(Bearer(token))
        } else {
            Err((StatusCode::UNAUTHORIZED, "invalid bearer"))
        }
    }
}

/// Extract a bearer token from the `Sec-WebSocket-Protocol` header.
/// Returns `(token, full_subprotocol_value)` on success. The subprotocol
/// value must be echoed back by the upgrade handler.
pub fn token_from_ws_protocol(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers
        .get_all(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .find(|s| s.starts_with("bearer."))?;
    let token = raw.strip_prefix("bearer.")?.to_string();
    Some((token, raw))
}

/// Validate the origin header (browser sends `Origin: https://term.xyz.com`)
/// against the configured public origin. Returns Ok(()) if allowed.
pub fn check_origin(headers: &HeaderMap, expected_origin: &str) -> Result<(), ()> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or(())?;
    if origin == expected_origin {
        Ok(())
    } else {
        Err(())
    }
}

/// Compute remaining TTL in whole seconds for the SPA.
pub fn ttl_secs(expires_at: SystemTime) -> u64 {
    expires_at
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
