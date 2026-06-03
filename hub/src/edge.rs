//! Edge middleware applied to both browser-facing routers: response
//! security headers + `Origin` enforcement.
//!
//! - **Security headers.** A CSP that pins scripts to same-origin (so an
//!   injected `<script>` or inline handler can't run — a backstop for any
//!   DOM-injection bug) plus clickjacking / sniffing / referrer
//!   protections. `style-src`/`img-src`/`connect-src`/`worker-src` are
//!   left permissive enough not to break xterm.js (which creates `<style>`
//!   elements, draws to canvas/WebGL, and may decode images in a worker).
//!
//! - **Origin check.** Any request that carries an `Origin` header must
//!   match this listener's expected origin. Same-origin top-level GETs
//!   send no `Origin` and pass through; cross-origin browser `fetch`/WS
//!   always send one and get rejected here. This closes cross-site
//!   request / WebSocket access on every route — most importantly the
//!   no-auth listener's JSON API, which previously enforced `Origin`
//!   only on the WebSocket upgrade.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Content-Security-Policy. `script-src 'self'` (no `unsafe-inline`) is
/// the load-bearing directive; `frame-ancestors`/`base-uri`/`object-src`
/// lock down clickjacking and base-tag / plugin abuse.
const CSP: &str = "default-src 'self'; \
script-src 'self'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob:; \
font-src 'self'; \
connect-src 'self' ws: wss:; \
worker-src 'self' blob:; \
frame-ancestors 'none'; \
base-uri 'none'; \
object-src 'none'; \
form-action 'none'";

/// Per-listener edge config (just the expected browser `Origin`).
#[derive(Clone)]
pub struct EdgeConfig {
    pub origin: String,
}

pub async fn middleware(State(cfg): State<EdgeConfig>, req: Request, next: Next) -> Response {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let ok = origin.to_str().map(|o| o == cfg.origin).unwrap_or(false);
        if !ok {
            return (StatusCode::FORBIDDEN, "bad origin").into_response();
        }
    }

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}
