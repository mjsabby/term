//! Authenticated JSON API routes.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::agent_link::SessionInfoEnvelope;
use crate::auth::Bearer;
use crate::config::MachineConfig;
use crate::listener_mode::ListenerMode;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct MachinesResp {
    pub machines: Vec<MachineConfig>,
}

pub async fn machines(_auth: Bearer, State(state): State<AppState>) -> Json<MachinesResp> {
    Json(MachinesResp {
        machines: state.cfg.machines.clone(),
    })
}

#[derive(Debug, Serialize)]
pub struct MeResp {
    pub ok: bool,
}

pub async fn me(_auth: Bearer) -> Json<MeResp> {
    Json(MeResp { ok: true })
}

pub async fn logout(Bearer(tok): Bearer, State(state): State<AppState>) -> Json<MeResp> {
    crate::auth::drop_token(&state, &tok).await;
    Json(MeResp { ok: true })
}

#[derive(Debug, Serialize)]
pub struct ModeResp {
    /// True iff this listener does not require WebAuthn / bearer auth.
    /// The SPA uses this on bootstrap to decide whether to show the
    /// login screen.
    pub no_auth: bool,
}

/// `GET /api/mode` — public probe (no auth even on the authed
/// listener). The SPA hits this once on load to learn whether it
/// should display the login screen or jump straight to the app.
pub async fn mode(Extension(mode): Extension<ListenerMode>) -> Json<ModeResp> {
    Json(ModeResp { no_auth: mode.no_auth })
}

/// `GET /api/machines/:id/sessions` — ask `<id>`'s agent for its live
/// session list. 503 if the agent isn't connected; 504 if the agent
/// fails to reply within the RPC deadline.
pub async fn list_sessions(
    _auth: Bearer,
    State(state): State<AppState>,
    Path(machine_id): Path<String>,
) -> axum::response::Response {
    let link = match state.agents.lock().await.get(&machine_id).cloned() {
        Some(l) => l,
        None    => return (StatusCode::SERVICE_UNAVAILABLE, "agent not connected").into_response(),
    };
    match link.list_sessions().await {
        Ok(sessions) => Json(SessionInfoEnvelope { sessions }).into_response(),
        Err(e)       => {
            tracing::warn!(machine = %machine_id, error = %e, "list_sessions RPC failed");
            (StatusCode::GATEWAY_TIMEOUT, format!("{e}")).into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct KillResp {
    pub killed: bool,
}

/// `DELETE /api/machines/:id/sessions/:sid` — ask `<id>`'s agent to
/// kill `:sid`. Returns `{ "killed": true }` on success or `false` if
/// the agent didn't find that session.
pub async fn kill_session(
    _auth: Bearer,
    State(state): State<AppState>,
    Path((machine_id, session_id)): Path<(String, String)>,
) -> axum::response::Response {
    let link = match state.agents.lock().await.get(&machine_id).cloned() {
        Some(l) => l,
        None    => return (StatusCode::SERVICE_UNAVAILABLE, "agent not connected").into_response(),
    };
    match link.kill_session(&session_id).await {
        Ok(killed) => Json(KillResp { killed }).into_response(),
        Err(e)     => {
            tracing::warn!(machine = %machine_id, session = %session_id,
                           error = %e, "kill_session RPC failed");
            (StatusCode::GATEWAY_TIMEOUT, format!("{e}")).into_response()
        }
    }
}
