//! Hub configuration: parsed from `TERM_HUB_CONFIG`
//! (default `/etc/term-hub/hub.toml`).

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Terminate TLS in the hub via Let's Encrypt (TLS-ALPN-01).
    /// Same ACME-managed cert is reused for the agent listener.
    #[default]
    Acme,
    /// Use cert + key from disk paths. Both browser and agent listeners
    /// share the loaded cert. Periodically re-read so an external ACME
    /// bot (lego / certbot / acme.sh) can renew without restarting the
    /// hub.
    Files,
    /// Serve plain HTTP (and plain TCP for agents). ONLY for local
    /// development or behind a reverse proxy that terminates TLS.
    Off,
}

#[derive(Debug, Deserialize)]
pub struct HubConfig {
    /// Public DNS name. Used by ACME and as the WebAuthn origin host.
    pub domain: String,
    /// WebAuthn RP id. Usually the eTLD+1 (e.g. "xyz.com"). Must be a
    /// registrable suffix of `domain`.
    pub rp_id: String,
    /// Human-readable RP name shown in the authenticator UI.
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// TLS mode. Default `acme`.
    #[serde(default)]
    pub tls: TlsMode,
    /// ACME contact email. Required when `tls = "acme"`.
    #[serde(default)]
    pub acme_email: Option<String>,
    /// Use Let's Encrypt production directory. Default false (staging).
    #[serde(default)]
    pub acme_production: bool,
    /// PEM cert chain (leaf first, intermediates after). Required when
    /// `tls = "files"`.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    /// PEM private key (PKCS#8, PKCS#1, or SEC1). Required when
    /// `tls = "files"`.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Seconds between re-reads of cert_path/key_path. Default 3600
    /// (1 hour). Match this to your ACME bot's cron cadence.
    #[serde(default)]
    pub tls_reload_interval_secs: Option<u64>,

    /// Where credentials.json, secret.key, and the ACME cache live.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Browser-facing bind. Default `[::]:443` (acme) / `[::]:8080` (off).
    #[serde(default)]
    pub bind: Option<String>,
    /// Agent-facing bind. Default `[::]:7700`. TLS (same cert) when
    /// `tls = "acme"`, plain TCP when `tls = "off"`.
    #[serde(default = "default_agent_bind")]
    pub agent_bind: String,

    /// Override the public origin used as the WebAuthn origin and for
    /// browser `Origin:` checks. Default: `https://<domain>`.
    /// Set this for `tls = "off"` deployments where you're reached at
    /// a different scheme/port than the default — for local dev,
    /// typically `"http://localhost:8080"`.
    #[serde(default)]
    pub public_origin: Option<String>,

    /// Optional second browser-facing listener that runs **without any
    /// browser-side authentication**. Intended for deployments fronted
    /// by an external perimeter (Microsoft Dev Tunnel, a corporate SSO
    /// reverse proxy, a private network …) that handles identity for
    /// us. The hub trusts every request it sees on this socket.
    ///
    /// Always plain HTTP — the perimeter terminates TLS. The agent
    /// listener and `/webauthn/*` routes are NOT exposed here.
    ///
    /// Can be force-disabled at runtime with the env var
    /// `TERM_HUB_NO_AUTH=off`, or force-enabled (provided the block is
    /// present) with `TERM_HUB_NO_AUTH=on`.
    #[serde(default)]
    pub no_auth: Option<NoAuthConfig>,

    /// Machines the hub knows about. Each entry produces a row in
    /// the UI. Agents identify themselves by their TLS client cert
    /// (raw transport) or by `X-Agent-Cert` + `X-Agent-Auth`
    /// upgrade headers (WSS-perimeter transport); the cert's SAN URN
    /// (`urn:term-agent:<machine_id>`) is matched against this `id`.
    /// hub.toml carries no secret material — see
    /// `hub-admin init-ca` + `hub-admin issue-cert`.
    #[serde(default)]
    pub machines: Vec<MachineConfig>,
}

fn default_rp_name() -> String {
    "term".into()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/term-hub")
}
fn default_agent_bind() -> String {
    "[::]:7700".into()
}

/// `[no_auth]` block: a second browser-facing listener with no auth.
/// Intended to sit behind an external perimeter (Dev Tunnel, SSO
/// reverse proxy, …) that handles identity.
#[derive(Debug, Deserialize, Clone)]
pub struct NoAuthConfig {
    /// Socket address to bind. Plain HTTP only.
    pub bind: String,
    /// Required. The browser-facing URL the perimeter exposes —
    /// compared verbatim against the `Origin:` header on WebSocket
    /// upgrades. Skipping this would let any web origin that can reach
    /// the listener open a terminal WS (WebSockets are not protected
    /// by CORS the way fetch responses are), so we require it.
    pub public_origin: String,
}

impl HubConfig {
    pub fn origin(&self) -> String {
        if let Some(p) = &self.public_origin {
            return p.clone();
        }
        format!("https://{}", self.domain)
    }
    pub fn effective_bind(&self) -> String {
        if let Some(b) = &self.bind {
            return b.clone();
        }
        match self.tls {
            TlsMode::Acme | TlsMode::Files => "[::]:443".into(),
            TlsMode::Off => "[::]:8080".into(),
        }
    }

    /// Decide whether the no-auth listener should actually run, given
    /// the config block and the `TERM_HUB_NO_AUTH` env-var override:
    ///   unset       — listener runs iff `[no_auth]` is present
    ///   "on"/"1"    — listener runs (config block REQUIRED; error otherwise)
    ///   "off"/"0"   — listener does NOT run, even if `[no_auth]` is present
    pub fn effective_no_auth(&self) -> anyhow::Result<Option<&NoAuthConfig>> {
        let env = std::env::var("TERM_HUB_NO_AUTH").ok();
        let want = match env.as_deref().map(str::trim) {
            Some("on") | Some("1") | Some("true") | Some("yes") => Some(true),
            Some("off") | Some("0") | Some("false") | Some("no") => Some(false),
            Some("") | None => None,
            Some(other) => {
                anyhow::bail!("TERM_HUB_NO_AUTH={other:?} not recognised (expected on/off/1/0)");
            }
        };
        match (want, self.no_auth.as_ref()) {
            (Some(false), _) => Ok(None),
            (Some(true), Some(c)) => Ok(Some(c)),
            (Some(true), None) => {
                anyhow::bail!("TERM_HUB_NO_AUTH=on but no [no_auth] section in hub.toml")
            }
            (None, opt) => Ok(opt),
        }
    }
}

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// Short id used in URLs, in the URL fragment, and matched against
    /// the agent cert's SAN URN. `[A-Za-z0-9_-]{1,32}`.
    pub id: String,
    /// Human-readable label shown in the sidebar.
    pub label: String,
}

/// Validate that machine id matches `[A-Za-z0-9_-]{1,32}` so we can
/// safely embed it in URLs and the URL fragment.
pub fn is_valid_machine_id(s: &str) -> bool {
    let n = s.len();
    if n == 0 || n > 32 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(no_auth: Option<NoAuthConfig>) -> HubConfig {
        HubConfig {
            domain: "term.example.com".into(),
            rp_id: "example.com".into(),
            rp_name: "term".into(),
            tls: TlsMode::Off,
            acme_email: None,
            acme_production: false,
            cert_path: None,
            key_path: None,
            tls_reload_interval_secs: None,
            data_dir: PathBuf::from("/tmp"),
            bind: None,
            agent_bind: default_agent_bind(),
            public_origin: None,
            no_auth,
            machines: vec![],
        }
    }

    fn na() -> NoAuthConfig {
        NoAuthConfig {
            bind: "[::]:18080".into(),
            public_origin: "https://example.devtunnels.ms".into(),
        }
    }

    /// Serialize tests that mutate the env var — Rust runs tests in
    /// parallel by default, and `std::env::set_var` is process-wide.
    /// On edition 2024+ these mutators are `unsafe` because they're
    /// not synchronized against other threads' `getenv`; we narrow the
    /// race to *this crate's* tests via `env_lock()`, which is good
    /// enough here because nothing else in this binary reads the env
    /// outside `effective_no_auth()` (called only from these tests).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn no_auth_present_unset_env_returns_some() {
        let _g = env_lock();
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
        let c = cfg_with(Some(na()));
        assert!(c.effective_no_auth().unwrap().is_some());
    }

    #[test]
    fn no_auth_absent_unset_env_returns_none() {
        let _g = env_lock();
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
        let c = cfg_with(None);
        assert!(c.effective_no_auth().unwrap().is_none());
    }

    #[test]
    fn no_auth_env_off_disables_even_when_configured() {
        let _g = env_lock();
        for v in ["off", "0", "false", "no"] {
            unsafe { std::env::set_var("TERM_HUB_NO_AUTH", v) };
            let c = cfg_with(Some(na()));
            assert!(c.effective_no_auth().unwrap().is_none(), "v={v}");
        }
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
    }

    #[test]
    fn no_auth_env_on_requires_config_block() {
        let _g = env_lock();
        unsafe { std::env::set_var("TERM_HUB_NO_AUTH", "on") };
        let c = cfg_with(None);
        assert!(c.effective_no_auth().is_err());
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
    }

    #[test]
    fn no_auth_env_on_passes_through_when_configured() {
        let _g = env_lock();
        for v in ["on", "1", "true", "yes"] {
            unsafe { std::env::set_var("TERM_HUB_NO_AUTH", v) };
            let c = cfg_with(Some(na()));
            assert!(c.effective_no_auth().unwrap().is_some(), "v={v}");
        }
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
    }

    #[test]
    fn no_auth_env_garbage_is_rejected() {
        let _g = env_lock();
        unsafe { std::env::set_var("TERM_HUB_NO_AUTH", "maybe") };
        let c = cfg_with(Some(na()));
        assert!(c.effective_no_auth().is_err());
        unsafe { std::env::remove_var("TERM_HUB_NO_AUTH") };
    }
}
