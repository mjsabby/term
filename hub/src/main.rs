//! term-hub
//!
//! HTTPS frontend + WebAuthn-gated WS proxy to one or more agents.
//! TLS certs via Let's Encrypt (TLS-ALPN-01) using rustls-acme.

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

use config::HubConfig;
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

    // Build a default rustls crypto provider exactly once (rustls 0.23+
    // requires this; rustls-acme's default-features pulls aws-lc-rs).
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

    // Find static dir at runtime: env override, else $exe_dir/static, else
    // ./hub/static (dev).
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
        .with_state(app_state);

    let bind: SocketAddr = cfg
        .effective_bind()
        .parse()
        .with_context(|| format!("parse bind {}", cfg.effective_bind()))?;
    match cfg.tls {
        config::TlsMode::Acme => serve_acme(bind, cfg, app).await,
        config::TlsMode::Off => serve_plain(bind, cfg, app).await,
    }
}

fn load_config() -> Result<HubConfig> {
    let path = std::env::var("TERM_HUB_CONFIG").unwrap_or_else(|_| "/etc/term-hub/hub.toml".into());
    let s = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let cfg: HubConfig = toml::from_str(&s).with_context(|| format!("parse {path}"))?;
    if !cfg.domain.ends_with(&cfg.rp_id) && cfg.rp_id != cfg.domain {
        anyhow::bail!(
            "rp_id ({}) must be a suffix of domain ({})",
            cfg.rp_id,
            cfg.domain
        );
    }
    if matches!(cfg.tls, config::TlsMode::Acme) && cfg.acme_email.is_none() {
        anyhow::bail!("tls = \"acme\" requires acme_email");
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
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from("hub/static")
}

async fn serve_acme(bind: SocketAddr, cfg: Arc<HubConfig>, app: Router) -> Result<()> {
    let cache = DirCache::new(creds::acme_cache_path(&cfg.data_dir));
    let email = cfg
        .acme_email
        .clone()
        .ok_or_else(|| anyhow::anyhow!("acme_email required"))?;
    let mut state = AcmeConfig::new([cfg.domain.clone()])
        .contact_push(format!("mailto:{}", email))
        .cache(cache)
        .directory_lets_encrypt(cfg.acme_production)
        .state();
    let acceptor = state.axum_acceptor(state.default_rustls_config());

    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(ev)) => info!("acme event: {ev:?}"),
                Some(Err(e)) => error!("acme error: {e:?}"),
                None => break,
            }
        }
    });

    info!(
        "term-hub listening on https://{} (acme {} for {})",
        bind,
        if cfg.acme_production { "PROD" } else { "STAGING" },
        cfg.domain
    );
    axum_server::bind(bind)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .context("axum_server")
}

async fn serve_plain(bind: SocketAddr, cfg: Arc<HubConfig>, app: Router) -> Result<()> {
    info!(
        "term-hub listening on http://{} (TLS OFF; assume reverse proxy at https://{})",
        bind, cfg.domain
    );
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {}", bind))?;
    axum::serve(listener, app.into_make_service())
        .await
        .context("axum::serve")
}
