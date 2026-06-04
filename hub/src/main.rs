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
mod client_verifier;
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
use std::time::Duration;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::{Extension, Router};
use rustls_acme::{AcmeConfig, caches::DirCache};
use tokio_stream::StreamExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use config::{HubConfig, NoAuthConfig, TlsMode};
use listener_mode::ListenerMode;
use state::AppState;
use term_common::agent_pki::ca as agent_ca;
use term_common::creds;
use term_common::issued_certs::IssuedCertStore;

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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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

    // Load the agent CA cert (never the key — the hub service user
    // doesn't need it). Refuse to start without one so an operator
    // who skipped `hub-admin init-ca` notices immediately rather
    // than discovering it via failing agent handshakes.
    let agent_ca_cert = agent_ca::load_ca_cert(&cfg.data_dir).context("load agent CA cert")?;
    let issued_certs = IssuedCertStore::load(&cfg.data_dir).context("load issued-certs.json")?;
    info!(
        ca_cert = %agent_ca::agent_ca_cert_path(&cfg.data_dir).display(),
        issued_certs = issued_certs.certs.len(),
        "agent mTLS material loaded"
    );

    let cfg = Arc::new(cfg);
    let app_state = AppState::new(cfg.clone(), secret, agent_ca_cert, issued_certs);

    // Background: re-read issued-certs.json every 30s so hub-admin
    // revoke-cert / issue-cert take effect without a hub restart.
    spawn_issued_certs_reloader(app_state.clone());
    // Background: evict stale entries from the WS-perimeter replay
    // cache every 60s.
    spawn_ws_replay_gc(app_state.clone());

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
    }
    Ok(cfg)
}

/// Background task: every 30s, re-read `issued-certs.json` from disk
/// and atomically swap it into `app_state`. `hub-admin issue-cert` /
/// `revoke-cert` mutations land in the hub within at most one reload
/// cycle, without needing a hub restart.
fn spawn_issued_certs_reloader(state: AppState) {
    let path = term_common::issued_certs::issued_certs_path(&state.cfg.data_dir);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            match IssuedCertStore::load(&state.cfg.data_dir) {
                Ok(new_store) => {
                    let new_len = new_store.certs.len();
                    let old_len = {
                        let mut w = state.issued_certs.write().unwrap();
                        let old = w.certs.len();
                        *w = new_store;
                        old
                    };
                    if new_len != old_len {
                        info!(
                            path = %path.display(),
                            old_count = old_len,
                            new_count = new_len,
                            "issued-certs.json reloaded"
                        );
                    }
                }
                Err(e) => warn!(
                    error = ?e,
                    path = %path.display(),
                    "failed to reload issued-certs.json; keeping previous snapshot"
                ),
            }
        }
    });
}

/// Background task: every 60s, evict stale entries from the WS-
/// perimeter replay cache so it doesn't grow without bound. The cache
/// is small (bounded by handshake rate × WS_REPLAY_TTL) so this is
/// cheap.
fn spawn_ws_replay_gc(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            state.gc_ws_replay().await;
        }
    });
}

/// Build a `rustls::ServerConfig` for the agent listener, layering the
/// custom client-cert verifier on top of the server's cert resolver.
/// Used by all three TLS modes so the verifier wiring is identical.
fn build_agent_server_config(
    state: &AppState,
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> Result<Arc<rustls::ServerConfig>> {
    let verifier = client_verifier::AgentClientVerifier::new(
        state.agent_ca.as_ref().clone(),
        state.issued_certs.clone(),
    )
    .map_err(|e| anyhow::anyhow!("build AgentClientVerifier: {e:?}"))?;
    Ok(Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver),
    ))
}

/// Spawn the agent listener using `server_config` (which MUST already
/// have the AgentClientVerifier installed). Logs and exits the task on
/// error.
fn spawn_agent_listener(
    state: AppState,
    cfg: Arc<HubConfig>,
    server_config: Arc<rustls::ServerConfig>,
) {
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    tokio::spawn(async move {
        if let Err(e) = agent_link::run_acceptor(state, cfg, tls_acceptor).await {
            error!("agent acceptor exited: {e:?}");
        }
    });
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

    // Agent listener: separate `ServerConfig` wrapping our custom
    // ClientCertVerifier, but reusing the ACME resolver from the
    // browser config so cert renewals propagate to both endpoints.
    // The rustls-acme `default_rustls_config()` ServerConfig wraps a
    // `ResolvesServerCertAcme`; we plug it into a fresh ServerConfig
    // so we can call `with_client_cert_verifier`. (The original
    // ServerConfig is `with_no_client_auth()` and can't be mutated.)
    let acme_resolver: Arc<dyn rustls::server::ResolvesServerCert> =
        rustls_config.cert_resolver.clone();
    let agent_server_config = build_agent_server_config(&state, acme_resolver)?;
    spawn_agent_listener(state.clone(), cfg.clone(), agent_server_config);

    info!(
        "term-hub listening on https://{} (acme {} for {}); agent_bind={} (mTLS)",
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
        "term-hub listening on http://{} (TLS OFF; assume reverse proxy at https://{}); \
         agent_bind={} NOT spawned — agents must use wss://…/agent/connect through a perimeter",
        browser_bind, cfg.domain, cfg.agent_bind,
    );

    // Intentionally NO raw agent listener: the cert-based auth scheme
    // requires TLS, and `tls = "off"` is reserved for deployments
    // where TLS is terminated by an upstream reverse proxy. Such
    // deployments accept agents on `/agent/connect` via the WSS-
    // perimeter path (auth via X-Agent-Cert + X-Agent-Auth headers).
    let _ = (&state, &cfg);

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

    // Browser server config: no client auth (browsers don't have
    // client certs). Agent server config: same resolver, but with
    // our AgentClientVerifier.
    let browser_server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone()),
    );
    let agent_server_config: Arc<rustls::ServerConfig> = build_agent_server_config(
        &state,
        resolver.clone() as Arc<dyn rustls::server::ResolvesServerCert>,
    )?;
    spawn_agent_listener(state.clone(), cfg.clone(), agent_server_config);

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(browser_server_config);
    info!(
        "term-hub listening on https://{} (tls=files); agent_bind={} (mTLS)",
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
        // Manufacture a fresh CA + empty issued-certs store on-the-fly
        // for the test fixture so we don't need filesystem state.
        use term_common::issued_certs::IssuedCertStore;
        let dir = std::env::temp_dir().join(format!(
            "term-router-tests-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let signer = term_common::agent_pki::ca::init_ca(&dir, 365).unwrap();
        AppState::new(
            std::sync::Arc::new(test_cfg()),
            [0u8; 32],
            signer.cert_der.clone(),
            IssuedCertStore::default(),
        )
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
