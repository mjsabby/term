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
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::{mint_token, store_token, ttl_secs};
use crate::state::{AppState, PENDING_LOGIN_TTL, PendingLogin, gc};
use term_common::creds::{self, CredentialStore};
use term_common::envelope::{EnvelopeInner, SignedEnvelope, issued_at_now};
use term_common::flock::FileLock;
use term_common::webauthn::{
    self, AuthenticationResponse, Challenge, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, StoredCredentialView,
};

/// Wrapper to keep the SPA's `prepCreateOptions(ccr.publicKey)` shape
/// working without changing the JS: the browser reads `ccr.publicKey`.
#[derive(Debug, Serialize)]
pub struct CcrEnvelope {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Serialize)]
pub struct RcrEnvelope {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[derive(Debug, Deserialize, Default)]
pub struct RegisterStartReq {}

#[derive(Debug, Serialize)]
pub struct RegisterStartResp {
    pub ccr: CcrEnvelope,
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
    // 16 random bytes for the per-registration user handle — WebAuthn
    // requires one; we never use it again.
    let mut user_id = [0u8; 16];
    rand::rng().fill_bytes(&mut user_id);
    let user_name = format!(
        "term-admin-{}",
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id)[..8],
    );

    let challenge = Challenge::random();
    let ccr = CcrEnvelope {
        public_key: PublicKeyCredentialCreationOptions::build(
            &state.cfg.rp_id,
            &state.cfg.rp_name,
            user_id,
            &user_name,
            "term admin",
            &challenge,
        ),
    };

    let inner = EnvelopeInner {
        rp_id: state.cfg.rp_id.clone(),
        origin: state.cfg.origin(),
        issued_at: issued_at_now(),
        challenge_b64u: challenge.to_b64url(),
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
    pub rcr: RcrEnvelope,
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
    let mut allowed_ids = Vec::with_capacity(store.credentials.len());
    for c in &store.credentials {
        allowed_ids.push(c.credential_id().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("decode credential id: {e}"),
            )
        })?);
    }
    let challenge = Challenge::random();
    let rcr = RcrEnvelope {
        public_key: PublicKeyCredentialRequestOptions::build(
            &state.cfg.rp_id,
            &challenge,
            &allowed_ids,
        ),
    };

    let nonce = mint_token(); // re-use the random-token helper
    let mut pending = state.pending_logins.lock().await;
    gc(&mut pending, |p| p.expires_at);
    // Backstop against an unauthenticated flood filling the map within
    // the TTL window. GC above already dropped expired entries.
    if pending.len() >= crate::state::MAX_PENDING_LOGINS {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "too many logins in progress; retry shortly".into(),
        ));
    }
    pending.insert(
        nonce.clone(),
        PendingLogin {
            challenge,
            allowed_ids,
            expires_at: SystemTime::now() + PENDING_LOGIN_TTL,
        },
    );
    Ok(Json(LoginStartResp { nonce, rcr }))
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishReq {
    pub nonce: String,
    pub response: AuthenticationResponse,
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

    // Load the current store. We look up the credential by raw id.
    // Reading credentials.json on every login is fine — it's tiny and
    // sits in the page cache.
    let store = CredentialStore::load(&state.cfg.data_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("load credentials.json: {e}"),
        )
    })?;

    // We need to keep the cred lookup simple: copy the 65-byte SEC1
    // public key into the view we hand to `finish_authenticate`.
    let lookup = |id: &[u8]| -> Option<StoredCredentialView> {
        // Reject ids the server didn't offer in login_start: a stale
        // assertion against a removed credential should not succeed.
        if !pending.allowed_ids.iter().any(|a| a.as_slice() == id) {
            return None;
        }
        let c = store.find_by_id(id)?;
        let pk = c.credential_public_key().ok()?;
        Some(StoredCredentialView {
            credential_public_key: pk,
            sign_count: c.sign_count,
        })
    };

    let auth = webauthn::finish_authenticate(
        &req.response,
        &pending.challenge,
        &state.cfg.rp_id,
        &state.cfg.origin(),
        lookup,
    )
    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))?;

    // Persist updated credential counter if it advanced.
    if auth.sign_count_advanced
        && let Err(e) =
            persist_counter_update(&state, &auth.credential_id, auth.new_sign_count).await
    {
        // Don't fail the login — counter persistence is best-effort
        // and re-derivable on the next successful auth.
        warn!(error = ?e, "failed to persist counter update");
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
    cred_id: &[u8],
    new_sign_count: u32,
) -> anyhow::Result<()> {
    let data_dir = state.cfg.data_dir.clone();
    let cred_id = cred_id.to_vec();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        creds::ensure_lock_file(&data_dir).context("ensure lock file")?;
        let _g = FileLock::acquire_exclusive(&creds::lock_path(&data_dir)).context("flock")?;
        let mut store = CredentialStore::load(&data_dir).context("load store")?;
        if let Some(c) = store.find_by_id_mut(&cred_id)
            && new_sign_count > c.sign_count
        {
            c.sign_count = new_sign_count;
            store.save_atomic(&data_dir).context("save store")?;
        }
        Ok(())
    })
    .await??;
    Ok(())
}
