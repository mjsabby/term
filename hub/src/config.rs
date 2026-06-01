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

    /// Machines the hub knows about. Each entry produces a row in the UI.
    /// Agents identify themselves by `id` + `psk` in the Hello frame.
    #[serde(default)]
    pub machines: Vec<MachineConfig>,
}

fn default_rp_name() -> String { "term".into() }
fn default_data_dir() -> PathBuf { PathBuf::from("/var/lib/term-hub") }
fn default_agent_bind() -> String { "[::]:7700".into() }

impl HubConfig {
    pub fn origin(&self) -> String {
        if let Some(p) = &self.public_origin { return p.clone(); }
        format!("https://{}", self.domain)
    }
    pub fn effective_bind(&self) -> String {
        if let Some(b) = &self.bind { return b.clone(); }
        match self.tls {
            TlsMode::Acme | TlsMode::Files => "[::]:443".into(),
            TlsMode::Off                   => "[::]:8080".into(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
pub struct MachineConfig {
    /// Short id used in URLs, in the URL fragment, and in the agent's
    /// Hello frame. `[A-Za-z0-9_-]{1,32}`.
    pub id: String,
    /// Human-readable label shown in the sidebar.
    pub label: String,
    /// Pre-shared key the agent must present in its Hello frame.
    /// 32 random bytes, base64-encoded (44 chars with padding, 43
    /// without). Generate per agent with:
    ///   `head -c 32 /dev/urandom | base64`
    /// Not serialised back out via the /api/machines response.
    #[serde(skip_serializing)]
    pub psk: String,
}

/// Validate that machine id matches `[A-Za-z0-9_-]{1,32}` so we can
/// safely embed it in URLs and the URL fragment.
pub fn is_valid_machine_id(s: &str) -> bool {
    let n = s.len();
    if n == 0 || n > 32 { return false; }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
