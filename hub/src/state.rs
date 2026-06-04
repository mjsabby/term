//! Process-wide state shared by all axum handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

use rustls_pki_types::CertificateDer;
use tokio::sync::Mutex;

use crate::agent_link::AgentLink;
use crate::config::HubConfig;
use term_common::issued_certs::IssuedCertStore;
use term_common::webauthn::Challenge;

/// Bearer-token lifetime (no refresh; user re-auths via passkey).
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// How long a `/login/start` challenge is valid for before the matching
/// `/login/finish` must arrive.
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(5 * 60);

/// How long to remember a (cert_fingerprint, nonce) tuple to defeat
/// WS-perimeter signature replays. Picked at 2× the auth timestamp
/// skew window so any legitimate retry within tolerance is still
/// rejected.
pub const WS_REPLAY_TTL_SECS: u64 = 2 * term_common::agent_pki::WS_AUTH_SKEW_SECS;

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
    /// The agent CA cert (loaded from `data_dir/agent-ca.crt` at
    /// startup, never the key). Used by the custom client-cert
    /// verifier on the raw TLS path and by the WS-perimeter auth
    /// header verifier. Wrapped in an Arc so the verifier (Send +
    /// Sync) can hold a cheap clone.
    pub agent_ca: Arc<CertificateDer<'static>>,
    /// Per-fingerprint allowlist of issued certs. Owned by hub-admin;
    /// the hub re-reads `issued-certs.json` periodically and swaps a
    /// fresh snapshot in here. Read on every TLS handshake.
    pub issued_certs: Arc<RwLock<IssuedCertStore>>,
    /// `(cert_fingerprint, nonce)` tuples seen in `X-Agent-Auth`
    /// headers within the last [`WS_REPLAY_TTL_SECS`] seconds.
    /// Defeats signature replay on the WSS-perimeter path.
    pub ws_replay: Mutex<HashMap<(String, Vec<u8>), Instant>>,
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
    pub fn new(
        cfg: Arc<HubConfig>,
        secret: [u8; 32],
        agent_ca: CertificateDer<'static>,
        issued_certs: IssuedCertStore,
    ) -> Self {
        AppState(Arc::new(AppStateInner {
            cfg,
            secret,
            start_time: Instant::now(),
            pending_logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            agents: Mutex::new(HashMap::new()),
            agent_ca: Arc::new(agent_ca),
            issued_certs: Arc::new(RwLock::new(issued_certs)),
            ws_replay: Mutex::new(HashMap::new()),
        }))
    }

    /// Run a single GC pass over the WS-replay cache. Cheap (the
    /// cache is bounded; eviction is O(n)) so the hub just polls it
    /// every few seconds rather than wiring up per-entry timers.
    pub async fn gc_ws_replay(&self) {
        let cutoff = Instant::now()
            .checked_sub(Duration::from_secs(WS_REPLAY_TTL_SECS))
            .unwrap_or_else(Instant::now);
        let mut map = self.ws_replay.lock().await;
        map.retain(|_, t| *t >= cutoff);
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
