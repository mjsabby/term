//! WebAuthn endpoint handlers.
//!
//! Three endpoints:
//! - `POST /webauthn/register/start` -> `{ ccr, envelope }`. State is NOT
//!   stored on the hub: it lives inside the HMAC-signed envelope that
//!   round-trips through the browser into the paste blob.
//! - `POST /webauthn/login/start`    -> `{ nonce, rcr }`. State IS stored
//!   server-side keyed by nonce.
//! - `POST /webauthn/login/finish`   -> `{ token, expires_in }`. Verifies
//!   the assertion, persists any counter update, mints a bearer token.

use std::time::SystemTime;

use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::auth::{mint_token, store_token, ttl_secs};
use crate::state::{gc, AppState, PendingLogin, PENDING_LOGIN_TTL};
use term_common::creds::{self, CredentialStore};
use term_common::envelope::{issued_at_now, EnvelopeInner, SignedEnvelope};
use term_common::flock::FileLock;

#[derive(Debug, Deserialize, Default)]
pub struct RegisterStartReq {}

#[derive(Debug, Serialize)]
pub struct RegisterStartResp {
    /// `CreationChallengeResponse` from webauthn-rs. The browser passes
    /// `.publicKey` straight to `navigator.credentials.create`.
    pub ccr: CreationChallengeResponse,
    /// Opaque to the browser; lands back inside the paste blob.
    pub envelope: SignedEnvelope,
    /// Repeat of rp_id/origin/ttl so the SPA can show useful UI.
    pub rp_id: String,
    pub origin: String,
    pub ttl_secs: u64,
}

pub async fn register_start(
    State(state): State<AppState>,
    Json(_req): Json<RegisterStartReq>,
) -> Result<Json<RegisterStartResp>, (StatusCode, String)> {
    // Each registration gets a brand-new opaque user handle. We never use
    // it to associate credentials with a user (any credential = admin).
    let user_id = Uuid::new_v4();
    let user_name = format!("term-admin-{}", &user_id.simple().to_string()[..8]);

    // Don't exclude existing credentials at the protocol layer. The
    // SecurityKey authenticator may not enforce this anyway, and we also
    // check for duplicates server-side in hub-admin.
    let (ccr, reg_state) = state
        .webauthn
        .start_securitykey_registration(user_id, &user_name, "term admin", None, None, None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("start_securitykey_registration: {e:?}"),
            )
        })?;

    let inner = EnvelopeInner {
        rp_id: state.cfg.rp_id.clone(),
        origin: state.cfg.origin(),
        issued_at: issued_at_now(),
        state: reg_state,
    };
    let envelope = SignedEnvelope::sign(inner, &state.secret).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("sign envelope: {e:?}"),
        )
    })?;
    Ok(Json(RegisterStartResp {
        ccr,
        envelope,
        rp_id: state.cfg.rp_id.clone(),
        origin: state.cfg.origin(),
        ttl_secs: term_common::envelope::ENVELOPE_TTL_SECS,
    }))
}

#[derive(Debug, Serialize)]
pub struct LoginStartResp {
    pub nonce: String,
    pub rcr: RequestChallengeResponse,
}

pub async fn login_start(
    State(state): State<AppState>,
) -> Result<Json<LoginStartResp>, (StatusCode, String)> {
    let store = CredentialStore::load(&state.cfg.data_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("load credentials.json: {e}"),
        )
    })?;
    if store.credentials.is_empty() {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            "no credentials registered yet; register one first".into(),
        ));
    }
    let creds: Vec<SecurityKey> = store.credentials.iter().map(|c| c.credential.clone()).collect();
    let (rcr, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&creds)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("start_securitykey_authentication: {e:?}"),
            )
        })?;

    let nonce = mint_token(); // re-use the random-token helper
    let mut pending = state.pending_logins.lock().await;
    gc(&mut pending, |p| p.expires_at);
    pending.insert(
        nonce.clone(),
        PendingLogin {
            state: auth_state,
            expires_at: SystemTime::now() + PENDING_LOGIN_TTL,
        },
    );
    Ok(Json(LoginStartResp { nonce, rcr }))
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishReq {
    pub nonce: String,
    pub response: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct LoginFinishResp {
    pub token: String,
    pub expires_in_secs: u64,
}

pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishReq>,
) -> Result<Json<LoginFinishResp>, (StatusCode, String)> {
    let pending = {
        let mut map = state.pending_logins.lock().await;
        gc(&mut map, |p| p.expires_at);
        map.remove(&req.nonce)
    };
    let pending = pending.ok_or((StatusCode::UNAUTHORIZED, "unknown or expired nonce".into()))?;

    let auth_result = state
        .webauthn
        .finish_securitykey_authentication(&req.response, &pending.state)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e:?}")))?;

    // Persist updated credential counter if necessary.
    if auth_result.needs_update() {
        if let Err(e) = persist_counter_update(&state, &auth_result).await {
            // Don't fail the login — counter persistence is best-effort and
            // re-derivable on the next successful auth.
            warn!(error = ?e, "failed to persist counter update");
        }
    }

    let token = mint_token();
    let expires_at = store_token(&state, token.clone()).await;
    Ok(Json(LoginFinishResp {
        token,
        expires_in_secs: ttl_secs(expires_at),
    }))
}

async fn persist_counter_update(
    state: &AppState,
    res: &AuthenticationResult,
) -> anyhow::Result<()> {
    let data_dir = state.cfg.data_dir.clone();
    let cred_id = res.cred_id().clone();
    let res = res.clone();
    // Move the blocking file IO off the async runtime.
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        creds::ensure_lock_file(&data_dir).context("ensure lock file")?;
        let _g = FileLock::acquire_exclusive(&creds::lock_path(&data_dir)).context("flock")?;
        let mut store = CredentialStore::load(&data_dir).context("load store")?;
        let mut changed = false;
        for c in &mut store.credentials {
            if c.credential.cred_id() == &cred_id {
                if c.credential.update_credential(&res) == Some(true) {
                    changed = true;
                }
                break;
            }
        }
        if changed {
            store.save_atomic(&data_dir).context("save store")?;
        }
        Ok(())
    })
    .await??;
    Ok(())
}
