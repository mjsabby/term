//! term-hub
//!
//! HTTPS frontend + WebAuthn-gated WS proxy that fans tabs out to
//! agents over their persistent reverse-tunnel connections. TLS certs
//! via Let's Encrypt (TLS-ALPN-01) using rustls-acme; the same cert
//! resolver is shared with the agent listener so renewals propagate
//! to both endpoints.
//!
//! Optionally serves a SECOND browser-facing listener (`[no_auth]` in
//! `hub.toml`) that runs without WebAuthn — intended to live behind an
//! external perimeter such as Microsoft Dev Tunnel or a corporate SSO
//! reverse proxy. When configured, the two listeners share the same
//! `AppState` (so machine list, agent connections, etc. are unified)
//! but route requests through different `Router`s carrying different
//! `ListenerMode` extensions.

mod agent_link;
mod agent_ws;
mod api_routes;
mod auth;
mod config;
mod edge;
mod listener_mode;
mod metrics;
mod proxy;
mod state;
mod static_assets;
mod tls_files;
mod webauthn_routes;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::{Extension, Router};
use rustls_acme::{AcmeConfig, caches::DirCache};
use tokio_stream::StreamExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use config::{HubConfig, NoAuthConfig, TlsMode};
use listener_mode::ListenerMode;
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

    // Sanity-check the origin URL while we're here — it must be a valid
    // URL that the browser will use as its `Origin:` header. We don't
    // need the parsed form; we'll compare strings in webauthn_routes.
    {
        let origin = cfg.origin();
        url::Url::parse(&origin)
            .with_context(|| format!("origin {origin:?} is not a valid URL"))?;
    }

    // Resolve env-var overrides + validate the optional no-auth listener.
    let no_auth_cfg: Option<NoAuthConfig> = cfg.effective_no_auth()?.cloned();
    if let Some(na) = &no_auth_cfg {
        url::Url::parse(&na.public_origin).with_context(|| {
            format!(
                "no_auth.public_origin {:?} is not a valid URL",
                na.public_origin
            )
        })?;
        let browser_bind = cfg.effective_bind();
        if equal_socket_addr(&browser_bind, &na.bind) {
            anyhow::bail!(
                "no_auth.bind {:?} collides with the authed browser bind {:?}",
                na.bind,
                browser_bind,
            );
        }
    }

    let cfg = Arc::new(cfg);
    let app_state = AppState::new(cfg.clone(), secret);

    let authed_mode = ListenerMode {
        no_auth: false,
        origin: cfg.origin(),
    };
    let authed_app = build_authed_router(app_state.clone(), authed_mode);

    let browser_bind: SocketAddr = cfg
        .effective_bind()
        .parse()
        .with_context(|| format!("parse bind {}", cfg.effective_bind()))?;

    let authed_fut = async {
        match cfg.tls {
            TlsMode::Acme => {
                serve_acme(app_state.clone(), cfg.clone(), browser_bind, authed_app).await
            }
            TlsMode::Files => {
                serve_files(app_state.clone(), cfg.clone(), browser_bind, authed_app).await
            }
            TlsMode::Off => {
                serve_plain(app_state.clone(), cfg.clone(), browser_bind, authed_app).await
            }
        }
    };

    // Optional no-auth listener. We bind even when `no_auth_cfg` is
    // None — using a never-ready future — so the select! arms have a
    // uniform type.
    let no_auth_fut = serve_optional_no_auth(app_state.clone(), no_auth_cfg);

    tokio::select! {
        res = authed_fut  => res,
        res = no_auth_fut => res,
    }
}

/// Routes exposed on the authenticated listener. Same set as before
/// the dual-listener split, plus the public `/api/mode` probe.
fn build_authed_router(state: AppState, mode: ListenerMode) -> Router {
    let origin = mode.origin.clone();
    Router::new()
        .route(
            "/webauthn/register/start",
            post(webauthn_routes::register_start),
        )
        .route("/webauthn/login/start", post(webauthn_routes::login_start))
        .route(
            "/webauthn/login/finish",
            post(webauthn_routes::login_finish),
        )
        .route("/api/machines", get(api_routes::machines))
        .route(
            "/api/machines/{machine_id}/sessions",
            get(api_routes::list_sessions),
        )
        .route(
            "/api/machines/{machine_id}/sessions/{session_id}",
            axum::routing::delete(api_routes::kill_session),
        )
        .route("/api/me", get(api_routes::me))
        .route("/api/mode", get(api_routes::mode))
        .route("/api/logout", post(api_routes::logout))
        .route("/metrics", get(metrics::handler))
        .route("/ws/term/{machine_id}", get(proxy::term_ws))
        .route("/agent/connect", get(agent_ws::connect))
        .fallback(static_assets::handler)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(mode))
        .layer(axum::middleware::from_fn_with_state(
            edge::EdgeConfig { origin },
            edge::middleware,
        ))
        .with_state(state)
}

/// Routes exposed on the **no-auth** listener — a strict subset of the
/// authed surface. Notably absent: `/webauthn/*` (passkey registration
/// is meaningless behind a tunnel that handles identity itself),
/// `/api/logout` (there's no bearer to drop), and `/metrics` (we don't
/// want machine ids and connection counts leaving via the tunnel).
fn build_no_auth_router(state: AppState, mode: ListenerMode) -> Router {
    let origin = mode.origin.clone();
    Router::new()
        .route("/api/machines", get(api_routes::machines))
        .route(
            "/api/machines/{machine_id}/sessions",
            get(api_routes::list_sessions),
        )
        .route(
            "/api/machines/{machine_id}/sessions/{session_id}",
            axum::routing::delete(api_routes::kill_session),
        )
        .route("/api/me", get(api_routes::me))
        .route("/api/mode", get(api_routes::mode))
        .route("/ws/term/{machine_id}", get(proxy::term_ws))
        .route("/agent/connect", get(agent_ws::connect))
        .fallback(static_assets::handler)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(mode))
        .layer(axum::middleware::from_fn_with_state(
            edge::EdgeConfig { origin },
            edge::middleware,
        ))
        .with_state(state)
}

async fn serve_optional_no_auth(state: AppState, cfg: Option<NoAuthConfig>) -> Result<()> {
    let cfg = match cfg {
        Some(c) => c,
        None => return std::future::pending().await,
    };
    let bind: SocketAddr = cfg
        .bind
        .parse()
        .with_context(|| format!("parse no_auth.bind {}", cfg.bind))?;
    let mode = ListenerMode {
        no_auth: true,
        origin: cfg.public_origin.clone(),
    };
    let app = build_no_auth_router(state, mode);
    info!(
        "term-hub no-auth listener on http://{} (perimeter origin {}); \
         WebAuthn + bearer DISABLED on this socket",
        bind, cfg.public_origin,
    );
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind no_auth {}", bind))?;
    axum::serve(listener, app.into_make_service())
        .await
        .context("axum::serve (no-auth)")
}

/// Compare two bind strings by parsing them as `SocketAddr` so
/// `[::]:8080` and `[::1]:8080` aren't mistakenly considered identical
/// while `[::]:8080` and `[::]:8080` (different whitespace) are.
fn equal_socket_addr(a: &str, b: &str) -> bool {
    match (a.parse::<SocketAddr>(), b.parse::<SocketAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        // If either side fails to parse we leave the collision check
        // to the downstream parse error — but we don't want a typo to
        // silently bypass the check, so fall back to string equality.
        _ => a.trim() == b.trim(),
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

async fn serve_acme(
    state: AppState,
    cfg: Arc<HubConfig>,
    browser_bind: SocketAddr,
    app: Router,
) -> Result<()> {
    let cache = DirCache::new(creds::acme_cache_path(&cfg.data_dir));
    let email = cfg
        .acme_email
        .clone()
        .ok_or_else(|| anyhow::anyhow!("acme_email required"))?;
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
                Some(Ok(ev)) => info!("acme event: {ev:?}"),
                Some(Err(e)) => error!("acme error: {e:?}"),
                None => break,
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
        if cfg.acme_production {
            "PROD"
        } else {
            "STAGING"
        },
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

async fn serve_files(
    state: AppState,
    cfg: Arc<HubConfig>,
    browser_bind: SocketAddr,
    app: Router,
) -> Result<()> {
    use std::time::Duration;

    let cert_path = cfg
        .cert_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("tls = \"files\" requires cert_path"))?;
    let key_path = cfg
        .key_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("tls = \"files\" requires key_path"))?;
    let period = Duration::from_secs(cfg.tls_reload_interval_secs.unwrap_or(3600));

    let resolver = tls_files::DynamicResolver::load(&cert_path, &key_path)
        .context("loading initial TLS cert from disk")?;
    tls_files::spawn_reloader(
        resolver.clone(),
        cert_path.clone(),
        key_path.clone(),
        period,
    );
    info!(
        "tls=files: cert={} key={} reload_every={}s",
        cert_path.display(),
        key_path.display(),
        period.as_secs()
    );

    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );

    // Agent listener over TLS using the same dynamic-cert config.
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());
    let agent_state = state.clone();
    let agent_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_link::run_acceptor(agent_state, agent_cfg, Some(tls_acceptor)).await {
            error!("agent acceptor exited: {e:?}");
        }
    });

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    info!(
        "term-hub listening on https://{} (tls=files); agent_bind={}",
        browser_bind, cfg.agent_bind
    );
    axum_server::bind_rustls(browser_bind, rustls_config)
        .serve(app.into_make_service())
        .await
        .context("axum_server::bind_rustls")
}

#[cfg(test)]
mod tests {
    //! Router-level tests for the dual-listener split. We never bind a
    //! socket — `tower::ServiceExt::oneshot` drives the `Router` as a
    //! plain `Service` so the tests run in milliseconds and don't
    //! touch the network.

    use std::path::PathBuf;

    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode, header};
    use tower::ServiceExt;

    use crate::config::{HubConfig, NoAuthConfig, TlsMode};
    use crate::listener_mode::ListenerMode;
    use crate::state::AppState;

    fn test_cfg() -> HubConfig {
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
            agent_bind: "[::]:7700".into(),
            public_origin: None,
            no_auth: Some(NoAuthConfig {
                bind: "[::]:18080".into(),
                public_origin: "https://tunnel.example.com".into(),
            }),
            machines: vec![],
        }
    }

    fn state() -> AppState {
        AppState::new(std::sync::Arc::new(test_cfg()), [0u8; 32])
    }

    fn authed_router() -> axum::Router {
        let s = state();
        let mode = ListenerMode {
            no_auth: false,
            origin: s.cfg.origin(),
        };
        super::build_authed_router(s, mode)
    }

    fn no_auth_router() -> axum::Router {
        let s = state();
        let na = s.cfg.no_auth.clone().unwrap();
        let mode = ListenerMode {
            no_auth: true,
            origin: na.public_origin,
        };
        super::build_no_auth_router(s, mode)
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn authed_machines_without_bearer_is_401() {
        let resp = authed_router()
            .oneshot(
                Request::builder()
                    .uri("/api/machines")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_auth_machines_without_bearer_is_200() {
        let resp = no_auth_router()
            .oneshot(
                Request::builder()
                    .uri("/api/machines")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert!(v.get("machines").is_some(), "got {v:?}");
    }

    #[tokio::test]
    async fn no_auth_logout_is_absent() {
        let resp = no_auth_router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 404 (no matching route) — not 401 or 200.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_auth_webauthn_is_absent() {
        let resp = no_auth_router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/webauthn/login/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_auth_metrics_is_absent() {
        // /metrics on the no-auth port would leak machine ids /
        // connection counts to anyone past the perimeter. The route
        // must not be exposed there.
        let resp = no_auth_router()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Static-asset fallback may serve a 404 with HTML; either way
        // the route shouldn't return Prometheus text.
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mode_endpoint_reports_authed_listener() {
        let resp = authed_router()
            .oneshot(
                Request::builder()
                    .uri("/api/mode")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["no_auth"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn mode_endpoint_reports_no_auth_listener() {
        let resp = no_auth_router()
            .oneshot(
                Request::builder()
                    .uri("/api/mode")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["no_auth"], serde_json::Value::Bool(true));
    }

    #[test]
    fn equal_socket_addr_matches_canonical_forms() {
        // Same canonical address even if written differently — both
        // sides parse identically.
        assert!(super::equal_socket_addr("[::]:8080", "[::]:8080"));
        // Different ports.
        assert!(!super::equal_socket_addr("[::]:8080", "[::]:18080"));
        // Different addresses.
        assert!(!super::equal_socket_addr("[::]:8080", "[::1]:8080"));
        // Unparseable inputs fall back to string equality.
        assert!(super::equal_socket_addr("bogus", "bogus"));
        assert!(!super::equal_socket_addr("bogus", "different-bogus"));
    }
}
