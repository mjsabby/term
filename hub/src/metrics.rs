//! `/metrics` endpoint — Prometheus exposition format (text/plain;
//! version=0.0.4).
//!
//! Bearer-token gated (same auth as the rest of `/api/*`). Each
//! scrape walks the agents map under a Mutex; cost is O(agents) plus
//! one HashMap lock per agent (for the streams count). For a hub with
//! a handful of agents this is fine; if it ever becomes a problem,
//! cache the stream counts in atomic counters next to bytes_in/out.

use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::auth::Bearer;
use crate::state::AppState;

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn handler(State(state): State<AppState>, _auth: Bearer) -> Response {
    let mut s = String::with_capacity(2048);

    // ---- uptime ----
    let uptime = state.start_time.elapsed().as_secs_f64();
    s.push_str("# HELP term_hub_uptime_seconds Hub process uptime in seconds.\n");
    s.push_str("# TYPE term_hub_uptime_seconds gauge\n");
    s.push_str(&format!("term_hub_uptime_seconds {uptime:.3}\n\n"));

    // ---- auth-state metrics ----
    let active_sessions = state.sessions.lock().await.len();
    s.push_str("# HELP term_hub_active_bearer_tokens Currently-valid bearer tokens (= logged-in browser sessions).\n");
    s.push_str("# TYPE term_hub_active_bearer_tokens gauge\n");
    s.push_str(&format!(
        "term_hub_active_bearer_tokens {active_sessions}\n\n"
    ));

    let pending_logins = state.pending_logins.lock().await.len();
    s.push_str("# HELP term_hub_pending_logins WebAuthn login ceremonies in flight.\n");
    s.push_str("# TYPE term_hub_pending_logins gauge\n");
    s.push_str(&format!("term_hub_pending_logins {pending_logins}\n\n"));

    // ---- per-agent gauges + counters ----
    let agents: Vec<_> = state.agents.lock().await.values().cloned().collect();
    let n_agents = agents.len();

    s.push_str("# HELP term_hub_active_agents Currently-connected agents.\n");
    s.push_str("# TYPE term_hub_active_agents gauge\n");
    s.push_str(&format!("term_hub_active_agents {n_agents}\n\n"));

    if !agents.is_empty() {
        // Active streams per agent.
        s.push_str("# HELP term_hub_active_streams Open mux streams per agent.\n");
        s.push_str("# TYPE term_hub_active_streams gauge\n");
        for link in &agents {
            let n = link.stream_count().await;
            let mid = escape_label(&link.machine_id);
            s.push_str(&format!(
                "term_hub_active_streams{{machine_id=\"{mid}\"}} {n}\n"
            ));
        }
        s.push('\n');

        // Bytes in/out per agent.
        s.push_str("# HELP term_hub_agent_bytes_in_total Bytes received from each agent (wire frames, header + payload).\n");
        s.push_str("# TYPE term_hub_agent_bytes_in_total counter\n");
        for link in &agents {
            let v = link.bytes_in.load(Ordering::Relaxed);
            let mid = escape_label(&link.machine_id);
            s.push_str(&format!(
                "term_hub_agent_bytes_in_total{{machine_id=\"{mid}\"}} {v}\n"
            ));
        }
        s.push('\n');

        s.push_str("# HELP term_hub_agent_bytes_out_total Bytes queued toward each agent.\n");
        s.push_str("# TYPE term_hub_agent_bytes_out_total counter\n");
        for link in &agents {
            let v = link.bytes_out.load(Ordering::Relaxed);
            let mid = escape_label(&link.machine_id);
            s.push_str(&format!(
                "term_hub_agent_bytes_out_total{{machine_id=\"{mid}\"}} {v}\n"
            ));
        }
        s.push('\n');

        // Frame counts.
        s.push_str(
            "# HELP term_hub_agent_frames_in_total Total wire frames received from each agent.\n",
        );
        s.push_str("# TYPE term_hub_agent_frames_in_total counter\n");
        for link in &agents {
            let v = link.frames_in.load(Ordering::Relaxed);
            let mid = escape_label(&link.machine_id);
            s.push_str(&format!(
                "term_hub_agent_frames_in_total{{machine_id=\"{mid}\"}} {v}\n"
            ));
        }
        s.push('\n');

        s.push_str(
            "# HELP term_hub_agent_frames_out_total Total wire frames queued toward each agent.\n",
        );
        s.push_str("# TYPE term_hub_agent_frames_out_total counter\n");
        for link in &agents {
            let v = link.frames_out.load(Ordering::Relaxed);
            let mid = escape_label(&link.machine_id);
            s.push_str(&format!(
                "term_hub_agent_frames_out_total{{machine_id=\"{mid}\"}} {v}\n"
            ));
        }
        s.push('\n');
    }

    Response::builder()
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .body(s.into())
        .unwrap_or_else(|_| "internal error".into_response())
}

/// Escape a label value for the Prometheus text format. The spec
/// requires backslash + " + \n be escaped. Our `machine_id`s already
/// match `[A-Za-z0-9_-]{1,32}` (validated at hub startup) so this is
/// belt-and-braces — but if someone ever loosens the regex we want a
/// well-formed exposition rather than a parser error in the scraper.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_backslash_and_quote() {
        assert_eq!(escape_label(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_label("normal_id-42"), "normal_id-42");
    }
}
