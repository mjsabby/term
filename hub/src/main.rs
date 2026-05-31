//! term-hub
//!
//! HTTPS frontend + WebAuthn-gated WS proxy that fans tabs out to
//! agents over their persistent reverse-tunnel connections. TLS certs
//! via Let's Encrypt (TLS-ALPN-01) using rustls-acme; the same cert
//! resolver is shared with the agent listener so renewals propagate
//! to both endpoints.

mod agent_link;
mod api_routes;
mod auth;
mod config;
mod proxy;
mod state;
mod webauthn_routes;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use rustls_acme::{caches::DirCache, AcmeConfig};
use tokio_stream::StreamExt;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use webauthn_rs::prelude::Url;
use webauthn_rs::WebauthnBuilder;

use config::{HubConfig, TlsMode};
use state::AppState;
use term_common::creds;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,rustls_acme=info")),
        )
        .init();

    let cfg = load_config()?;
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("create data_dir {}", cfg.data_dir.display()))?;
    std::fs::create_dir_all(creds::acme_cache_path(&cfg.data_dir))
        .with_context(|| "create acme cache dir")?;
    let secret = creds::load_or_create_secret(&cfg.data_dir).context("load/create secret.key")?;

    // Default rustls crypto provider (rustls 0.23+ requires installation).
    let _ = rustls_acme::futures_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default();

    let origin_url = Url::parse(&cfg.origin()).context("parse origin url")?;
    let webauthn = WebauthnBuilder::new(&cfg.rp_id, &origin_url)
        .context("WebauthnBuilder::new")?
        .rp_name(&cfg.rp_name)
        .danger_set_user_presence_only_security_keys(true)
        .build()
        .context("WebauthnBuilder::build")?;

    let cfg = Arc::new(cfg);
    let app_state = AppState::new(cfg.clone(), secret, webauthn);

    let static_dir = resolve_static_dir();
    info!("serving static assets from {}", static_dir.display());

    let app = Router::new()
        .route("/webauthn/register/start", post(webauthn_routes::register_start))
        .route("/webauthn/login/start",    post(webauthn_routes::login_start))
        .route("/webauthn/login/finish",   post(webauthn_routes::login_finish))
        .route("/api/machines",            get(api_routes::machines))
        .route("/api/me",                  get(api_routes::me))
        .route("/api/logout",              post(api_routes::logout))
        .route("/ws/term/{machine_id}",    get(proxy::term_ws))
        .fallback_service(ServeDir::new(&static_dir).append_index_html_on_directories(true))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state.clone());

    let browser_bind: SocketAddr = cfg
        .effective_bind()
        .parse()
        .with_context(|| format!("parse bind {}", cfg.effective_bind()))?;

    match cfg.tls {
        TlsMode::Acme => serve_acme(app_state, cfg, browser_bind, app).await,
        TlsMode::Off  => serve_plain(app_state, cfg, browser_bind, app).await,
    }
}

fn load_config() -> Result<HubConfig> {
    let path = std::env::var("TERM_HUB_CONFIG").unwrap_or_else(|_| "/etc/term-hub/hub.toml".into());
    let s = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let cfg: HubConfig = toml::from_str(&s).with_context(|| format!("parse {path}"))?;

    if !cfg.domain.ends_with(&cfg.rp_id) && cfg.rp_id != cfg.domain {
        anyhow::bail!("rp_id ({}) must be a suffix of domain ({})", cfg.rp_id, cfg.domain);
    }
    if matches!(cfg.tls, TlsMode::Acme) && cfg.acme_email.is_none() {
        anyhow::bail!("tls = \"acme\" requires acme_email");
    }
    // Validate per-machine config up front.
    for m in &cfg.machines {
        if !config::is_valid_machine_id(&m.id) {
            anyhow::bail!("invalid machine id {:?} ([A-Za-z0-9_-]{{1,32}})", m.id);
        }
        if m.psk.trim().is_empty() {
            anyhow::bail!("machine {} missing psk", m.id);
        }
    }
    Ok(cfg)
}

fn resolve_static_dir() -> PathBuf {
    if let Ok(p) = std::env::var("TERM_HUB_STATIC_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("static");
            if candidate.is_dir() { return candidate; }
        }
    }
    PathBuf::from("hub/static")
}

async fn serve_acme(
    state: AppState,
    cfg: Arc<HubConfig>,
    browser_bind: SocketAddr,
    app: Router,
) -> Result<()> {
    let cache = DirCache::new(creds::acme_cache_path(&cfg.data_dir));
    let email = cfg.acme_email.clone().ok_or_else(|| anyhow::anyhow!("acme_email required"))?;
    let mut acme_state = AcmeConfig::new([cfg.domain.clone()])
        .contact_push(format!("mailto:{}", email))
        .cache(cache)
        .directory_lets_encrypt(cfg.acme_production)
        .state();
    let rustls_config = acme_state.default_rustls_config();
    let browser_acceptor = acme_state.axum_acceptor(rustls_config.clone());

    // Drive ACME state machine in the background.
    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(ev))  => info!("acme event: {ev:?}"),
                Some(Err(e))  => error!("acme error: {e:?}"),
                None          => break,
            }
        }
    });

    // Agent listener over TLS using the same rustls config.
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(rustls_config);
    let agent_state = state.clone();
    let agent_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_link::run_acceptor(agent_state, agent_cfg, Some(tls_acceptor)).await {
            error!("agent acceptor exited: {e:?}");
        }
    });

    info!(
        "term-hub listening on https://{} (acme {} for {}); agent_bind={}",
        browser_bind,
        if cfg.acme_production { "PROD" } else { "STAGING" },
        cfg.domain,
        cfg.agent_bind,
    );
    axum_server::bind(browser_bind)
        .acceptor(browser_acceptor)
        .serve(app.into_make_service())
        .await
        .context("axum_server")
}

async fn serve_plain(
    state: AppState,
    cfg: Arc<HubConfig>,
    browser_bind: SocketAddr,
    app: Router,
) -> Result<()> {
    info!(
        "term-hub listening on http://{} (TLS OFF; assume reverse proxy at https://{}); agent_bind={}",
        browser_bind, cfg.domain, cfg.agent_bind,
    );

    // Agent listener over plain TCP.
    let agent_state = state.clone();
    let agent_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_link::run_acceptor(agent_state, agent_cfg, None).await {
            error!("agent acceptor exited: {e:?}");
        }
    });

    let listener = tokio::net::TcpListener::bind(browser_bind)
        .await
        .with_context(|| format!("bind {}", browser_bind))?;
    axum::serve(listener, app.into_make_service())
        .await
        .context("axum::serve")
}
