//! Authenticated JSON API routes.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::auth::Bearer;
use crate::config::MachineConfig;
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
