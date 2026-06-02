//! Per-listener context carried as an axum `Extension` so handlers can
//! tell which browser-facing socket served them.
//!
//! Inserted into each browser router via
//! `.layer(Extension(ListenerMode { … }))` in `main.rs`. Two distinct
//! values exist at runtime:
//!
//! - the **authed** listener (TLS or plain, depending on `tls = …`),
//!   `no_auth = false`, `origin = cfg.origin()`;
//! - the optional **no-auth** listener (plain HTTP behind an external
//!   perimeter), `no_auth = true`, `origin = no_auth.public_origin`.
//!
//! `Bearer::from_request_parts` and `proxy::term_ws` both look this up
//! to decide whether to enforce bearer-token auth and which origin to
//! compare against.

#[derive(Debug, Clone)]
pub struct ListenerMode {
    /// True iff this listener bypasses bearer / WebAuthn enforcement.
    pub no_auth: bool,
    /// Expected browser `Origin:` value. For the authed listener this
    /// is `https://<domain>` (or `public_origin`); for the no-auth
    /// listener this is `no_auth.public_origin`.
    pub origin: String,
}
