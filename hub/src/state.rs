//! Process-wide state shared by all axum handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Mutex;

use crate::agent_link::AgentLink;
use crate::config::HubConfig;
use term_common::webauthn::Challenge;

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
    /// Process-start time. Used by /metrics for `term_hub_uptime_seconds`.
    pub start_time: Instant,
    pub pending_logins: Mutex<HashMap<String, PendingLogin>>,
    pub sessions: Mutex<HashMap<String, Session>>,
    /// Currently-connected agents, keyed by `machine_id`. Replaced atomically
    /// on reconnect: if an agent reconnects while a previous link is still
    /// "alive" from the hub's view, the new link takes over and the old
    /// streams are dropped.
    pub agents: Mutex<HashMap<String, Arc<AgentLink>>>,
}

pub struct PendingLogin {
    pub challenge: Challenge,
    /// Raw credential ids we offered in `allowCredentials`. Used to
    /// narrow the lookup in `login_finish` to credentials known at
    /// `login_start` time, so a stale assertion against a removed
    /// credential can't succeed.
    pub allowed_ids: Vec<Vec<u8>>,
    pub expires_at: SystemTime,
}

pub struct Session {
    pub expires_at: SystemTime,
}

impl AppState {
    pub fn new(cfg: Arc<HubConfig>, secret: [u8; 32]) -> Self {
        AppState(Arc::new(AppStateInner {
            cfg,
            secret,
            start_time: Instant::now(),
            pending_logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            agents: Mutex::new(HashMap::new()),
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
