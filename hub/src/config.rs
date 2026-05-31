//! Hub configuration: parsed from `TERM_HUB_CONFIG`
//! (default `/etc/term-hub/hub.toml`).

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Terminate TLS in the hub via Let's Encrypt (TLS-ALPN-01).
    #[default]
    Acme,
    /// Serve plain HTTP. ONLY for local development or behind a
    /// reverse proxy that terminates TLS.
    Off,
}

#[derive(Debug, Deserialize)]
pub struct HubConfig {
    /// Public DNS name. Used by ACME and as the WebAuthn origin host.
    pub domain: String,
    /// WebAuthn RP id. Usually the eTLD+1 (e.g. "xyz.com") so credentials
    /// can be reused across siblings. Must be a registrable suffix of
    /// `domain`.
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

    /// Where credentials.json, secret.key, and the ACME cache live.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Bind address. Default "[::]:443" for ACME, "[::]:8080" for off.
    #[serde(default)]
    pub bind: Option<String>,

    /// Machines the hub knows about. Each entry produces a row in the UI.
    #[serde(default)]
    pub machines: Vec<MachineConfig>,
}

fn default_rp_name() -> String {
    "term".into()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/term-hub")
}

impl HubConfig {
    pub fn origin(&self) -> String {
        format!("https://{}", self.domain)
    }
    pub fn effective_bind(&self) -> String {
        if let Some(b) = &self.bind {
            return b.clone();
        }
        match self.tls {
            TlsMode::Acme => "[::]:443".into(),
            TlsMode::Off => "[::]:8080".into(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
pub struct MachineConfig {
    /// Short id used in URLs and the URL fragment (e.g. "alpha").
    /// Must match `[A-Za-z0-9_-]{1,32}`.
    pub id: String,
    /// Human-readable label shown in the sidebar.
    pub label: String,
    /// `host:port` of the agent's TCP listener.
    pub address: String,
}
