//! Process-wide state shared by all axum handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;

use crate::config::HubConfig;

/// Bearer-token lifetime (no refresh; user re-auths via passkey).
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// How long a `/login/start` challenge is valid for before the matching
/// `/login/finish` must arrive.
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct AppState(pub Arc<AppStateInner>);

pub struct AppStateInner {
    pub cfg: Arc<HubConfig>,
    pub secret: [u8; 32],
    pub webauthn: Webauthn,
    pub pending_logins: Mutex<HashMap<String, PendingLogin>>,
    pub sessions: Mutex<HashMap<String, Session>>,
}

pub struct PendingLogin {
    pub state: SecurityKeyAuthentication,
    pub expires_at: SystemTime,
}

pub struct Session {
    pub expires_at: SystemTime,
}

impl AppState {
    pub fn new(cfg: Arc<HubConfig>, secret: [u8; 32], webauthn: Webauthn) -> Self {
        AppState(Arc::new(AppStateInner {
            cfg,
            secret,
            webauthn,
            pending_logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }))
    }
}

impl std::ops::Deref for AppState {
    type Target = AppStateInner;
    fn deref(&self) -> &AppStateInner {
        &self.0
    }
}

/// Remove expired entries from a `HashMap<K, V>` based on a closure that
/// extracts the expiry from V.
pub fn gc<K, V, F>(map: &mut HashMap<K, V>, expiry: F)
where
    F: Fn(&V) -> SystemTime,
{
    let now = SystemTime::now();
    map.retain(|_, v| expiry(v) > now);
}
