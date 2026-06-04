//! WebSocket transport for the agent↔hub mux.
//!
//! Lets an agent dial the hub over `wss://…/agent/connect` instead of a
//! raw TCP/TLS connection to `agent_bind`. This is what makes the agent
//! reachable through an HTTP/WS-only perimeter (e.g. a Microsoft Dev
//! Tunnel): one tunnel-fronted hub can serve agents on any machine that
//! can reach the tunnel and present its access claim.
//!
//! Each agent frame is carried as exactly one binary WebSocket message
//! (same shape as the browser proxy). Authentication is via two HTTP
//! upgrade headers, validated against the SAME agent CA + issued-certs
//! allowlist as the raw mTLS path:
//!
//! - `X-Agent-Cert: <base64-no-pad of leaf cert DER>`
//! - `X-Agent-Auth: <unix_secs>.<nonce_b64u>.<ecdsa_sig_b64u>`
//!
//! The signature covers a domain-separated payload that includes the
//! Host header so a tunnel-eavesdropper can't replay it against a
//! different hub. A per-(fingerprint, nonce) replay cache defeats
//! replay against the same hub within the timestamp skew window.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use tokio::time::Instant;
use tracing::{info, warn};

use term_common::agent_pki::ca::{
    check_ws_auth_timestamp, extract_machine_id_from_san, parse_ws_auth_header,
    verify_p256_signature,
};
use term_common::agent_pki::{
    HEADER_AGENT_AUTH, HEADER_AGENT_CERT, MAX_AGENT_AUTH_HEADER_BYTES, MAX_AGENT_CERT_HEADER_BYTES,
    cert_fingerprint, ws_auth_payload,
};
use term_common::frame::{Frame, FrameError, HEADER_LEN, MAX_PASTE_CHUNK_LEN};
use term_common::transport::{FrameRecv, FrameSend, frame_from_ws_payload};

use crate::agent_link::handle_connection;
use crate::state::AppState;

/// Cap on a single agent WebSocket message — one frame, at most a
/// maximally-sized PasteChunk/DownloadChunk plus header slack. Mirrors
/// the browser proxy's bound.
const AGENT_WS_MAX_BYTES: usize = HEADER_LEN + MAX_PASTE_CHUNK_LEN as usize + 1024;

/// `GET /agent/connect` — verify the X-Agent-Cert + X-Agent-Auth
/// headers (cert chains to agent CA, fingerprint in issued-certs,
/// signature valid, timestamp fresh, nonce not replayed), then upgrade
/// to a WebSocket and run the agent mux over it. Returns 401 on any
/// auth failure so the perimeter / operator gets a clear signal.
pub async fn connect(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let peer = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| format!("ws:{s}"))
        .unwrap_or_else(|| "ws".to_string());

    let machine_id = match authenticate_ws_upgrade(&state, &headers).await {
        Ok(id) => id,
        Err(reason) => {
            warn!(peer = %peer, error = %reason, "agent ws auth rejected");
            return (StatusCode::UNAUTHORIZED, format!("auth: {reason}\n")).into_response();
        }
    };

    ws.max_message_size(AGENT_WS_MAX_BYTES)
        .max_frame_size(AGENT_WS_MAX_BYTES)
        .on_upgrade(move |socket| async move {
            let (sink, stream) = socket.split();
            info!(peer = %peer, machine = %machine_id, "agent ws connected");
            if let Err(e) = handle_connection(
                state,
                WsRecv(stream),
                WsSend(sink),
                machine_id.clone(),
                peer.clone(),
            )
            .await
            {
                warn!(peer = %peer, error = %e, "agent ws connection ended with error");
            }
        })
}

/// Validate the two X-Agent-* headers against the agent CA + issued-
/// certs allowlist + replay cache. Returns the SAN URN on success;
/// a human-readable reason on failure.
async fn authenticate_ws_upgrade(state: &AppState, headers: &HeaderMap) -> Result<String, String> {
    // 1. Pull headers, enforce size bounds.
    let cert_b64 = headers
        .get(HEADER_AGENT_CERT)
        .ok_or_else(|| "missing X-Agent-Cert".to_string())?
        .to_str()
        .map_err(|_| "X-Agent-Cert not ASCII".to_string())?
        .trim();
    if cert_b64.len() > MAX_AGENT_CERT_HEADER_BYTES {
        return Err(format!(
            "X-Agent-Cert {} > {MAX_AGENT_CERT_HEADER_BYTES}",
            cert_b64.len()
        ));
    }
    let auth_header = headers
        .get(HEADER_AGENT_AUTH)
        .ok_or_else(|| "missing X-Agent-Auth".to_string())?
        .to_str()
        .map_err(|_| "X-Agent-Auth not ASCII".to_string())?
        .trim();
    if auth_header.len() > MAX_AGENT_AUTH_HEADER_BYTES {
        return Err(format!(
            "X-Agent-Auth {} > {MAX_AGENT_AUTH_HEADER_BYTES}",
            auth_header.len()
        ));
    }

    // 2. Decode the cert.
    let cert_der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cert_b64.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(cert_b64.as_bytes()))
        .map_err(|e| format!("decode X-Agent-Cert: {e}"))?;

    // 3. Chain validation against the agent CA. We use webpki
    //    directly (instead of going through rustls's
    //    WebPkiClientVerifier, which is wired into the TLS handshake)
    //    so we can do this from a plain axum handler.
    verify_chain_to_agent_ca(state, &cert_der).map_err(|e| format!("cert chain: {e}"))?;

    // 4. Fingerprint allow-list (same gate as the raw mTLS path).
    let fp = cert_fingerprint(&cert_der);
    let allowed_entry = {
        let store = state
            .issued_certs
            .read()
            .map_err(|_| "issued_certs lock poisoned".to_string())?;
        store.find_by_fingerprint(&fp).cloned()
    };
    let entry =
        allowed_entry.ok_or_else(|| format!("cert fingerprint {fp} not in issued-certs.json"))?;

    // 5. SAN URN -> machine_id; must equal entry.machine_id.
    let san_id =
        extract_machine_id_from_san(&cert_der).map_err(|e| format!("extract SAN URN: {e}"))?;
    if san_id != entry.machine_id {
        return Err(format!(
            "SAN URN {san_id} disagrees with issued-certs entry {}",
            entry.machine_id
        ));
    }

    // 6. Auth header (ts, nonce, sig).
    let (ts, nonce, sig) =
        parse_ws_auth_header(auth_header).map_err(|e| format!("parse X-Agent-Auth: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock: {e}"))?
        .as_secs();
    check_ws_auth_timestamp(now, ts).map_err(|e| format!("timestamp: {e}"))?;

    // 7. Signature, bound to host so a tunnel eavesdropper can't
    //    replay the assertion against a different hub.
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "missing Host header".to_string())?;
    let payload = ws_auth_payload(host, ts, &nonce);
    verify_p256_signature(&cert_der, &payload, &sig).map_err(|e| format!("signature: {e}"))?;

    // 8. Replay cache: (fingerprint, nonce) must not have been seen
    //    in the last skew window. Insert after all other checks pass
    //    so a failed handshake doesn't burn the nonce.
    {
        let mut cache = state.ws_replay.lock().await;
        let key = (fp.clone(), nonce.clone());
        if cache.contains_key(&key) {
            return Err("replayed (fingerprint, nonce)".to_string());
        }
        cache.insert(key, Instant::now().into_std());
    }

    Ok(entry.machine_id)
}

/// Verify `cert_der` chains to `state.agent_ca` using webpki directly.
/// Used by the WS-perimeter path where rustls isn't in the loop.
/// Only checks chain validity (incl. NotBefore/NotAfter) — the
/// fingerprint allowlist + SAN match are layered on by the caller.
fn verify_chain_to_agent_ca(state: &AppState, cert_der: &[u8]) -> Result<(), String> {
    use rustls_pki_types::{CertificateDer, UnixTime};
    use webpki::KeyUsage;
    let trust = webpki::anchor_from_trusted_cert(state.agent_ca.as_ref())
        .map_err(|e| format!("agent CA not a valid trust anchor: {e:?}"))?;
    let leaf = CertificateDer::from(cert_der);
    let cert = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| format!("decode leaf as EndEntityCert: {e:?}"))?;
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    ));
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust],
        &[],
        now,
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|e| format!("chain: {e:?}"))?;
    Ok(())
}

/// [`FrameRecv`] over the read half of an axum [`WebSocket`].
pub struct WsRecv(pub SplitStream<WebSocket>);

impl FrameRecv for WsRecv {
    async fn recv(&mut self) -> Result<Option<(Frame, u64)>, FrameError> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(data))) => {
                    return frame_from_ws_payload(&data).map(Some);
                }
                // Control frames: axum answers Ping automatically; Pong /
                // Text aren't part of our protocol — skip and keep reading.
                Some(Ok(Message::Ping(_)))
                | Some(Ok(Message::Pong(_)))
                | Some(Ok(Message::Text(_))) => {
                    continue;
                }
                // Clean close, end of stream, or a transport error all
                // mean "no more frames" — surface as EOF so the mux tears
                // down gracefully.
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Err(_)) => return Ok(None),
            }
        }
    }
}

/// [`FrameSend`] over the write half of an axum [`WebSocket`].
pub struct WsSend(pub SplitSink<WebSocket, Message>);

impl FrameSend for WsSend {
    async fn send(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        self.0
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
    async fn close(&mut self) {
        let _ = self.0.send(Message::Close(None)).await;
        let _ = self.0.close().await;
    }
}

// NOTE: The end-to-end tests previously here exercised PSK auth over
// a real loopback WS server. The equivalent cert-based tests live in
// `agent_link::tests` (which spins up a real rustls server with our
// AgentClientVerifier and dials it with an agent cert), so we don't
// duplicate the loopback wiring here. The authenticate_ws_upgrade
// helper is exercised directly below using axum HeaderMaps and a
// freshly issued cert + signature.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::HeaderValue;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use rustls_pki_types::CertificateDer;
    use term_common::agent_pki;
    use term_common::agent_pki::ca::{init_ca, issue_machine_cert, load_ca_signer};
    use term_common::issued_certs::{IssuedCertEntry, IssuedCertStore};

    use crate::config::{HubConfig, MachineConfig, TlsMode};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "term-aws-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn test_cfg() -> HubConfig {
        HubConfig {
            domain: "hub.example.com".into(),
            rp_id: "example.com".into(),
            rp_name: "term".into(),
            tls: TlsMode::Off,
            acme_email: None,
            acme_production: false,
            cert_path: None,
            key_path: None,
            tls_reload_interval_secs: None,
            data_dir: std::env::temp_dir(),
            bind: None,
            agent_bind: "[::]:0".into(),
            public_origin: Some("http://hub.example.com".into()),
            no_auth: None,
            machines: vec![MachineConfig {
                id: "alpha".into(),
                label: "alpha".into(),
            }],
        }
    }

    /// Bake a freshly-issued cert + matching headers and the AppState
    /// that knows about it. Returns (state, cert_der, key_pair).
    fn fixture() -> (AppState, CertificateDer<'static>, EcdsaKeyPair) {
        let dir = temp_dir("fx");
        let _ = init_ca(&dir, 365).unwrap();
        let ca = load_ca_signer(&dir).unwrap();
        let issued = issue_machine_cert(&ca, "alpha", 30).unwrap();

        let mut store = IssuedCertStore::default();
        store.certs.push(IssuedCertEntry {
            machine_id: issued.machine_id.clone(),
            fingerprint: issued.fingerprint.clone(),
            serial_hex: issued.serial_hex.clone(),
            issued_at: "2025-01-01T00:00:00Z".into(),
            not_after_unix: issued.not_after_unix,
            label: None,
        });

        let cfg = Arc::new(test_cfg());
        let state = AppState::new(cfg, [0u8; 32], ca.cert_der.clone(), store);

        let chain = agent_pki::load_pem_cert_chain(issued.cert_pem.as_bytes()).unwrap();
        let leaf = chain.into_iter().next().unwrap();
        let key_der = agent_pki::load_pem_private_key(issued.key_pem.as_bytes()).unwrap();
        let key_bytes = match &key_der {
            rustls_pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            _ => panic!("PKCS#8 expected"),
        };
        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_bytes, &rng)
            .expect("ring keypair");
        (state, leaf, kp)
    }

    fn headers_for(
        leaf: &CertificateDer<'_>,
        kp: &EcdsaKeyPair,
        host: &str,
        ts: u64,
        nonce: &[u8],
    ) -> HeaderMap {
        let cert_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf.as_ref());
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let payload = ws_auth_payload(host, ts, nonce);
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, &payload).expect("sign");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref());
        let auth_value = format!("{ts}.{nonce_b64}.{sig_b64}");

        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HOST,
            HeaderValue::from_str(host).unwrap(),
        );
        h.insert(HEADER_AGENT_CERT, HeaderValue::from_str(&cert_b64).unwrap());
        h.insert(
            HEADER_AGENT_AUTH,
            HeaderValue::from_str(&auth_value).unwrap(),
        );
        h
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn happy_path_returns_machine_id() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, leaf, kp) = fixture();
        let h = headers_for(&leaf, &kp, "hub.example.com", now_unix(), &[1u8; 16]);
        let id = authenticate_ws_upgrade(&state, &h).await.unwrap();
        assert_eq!(id, "alpha");
    }

    #[tokio::test]
    async fn missing_cert_header_is_401() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, _, _) = fixture();
        let err = authenticate_ws_upgrade(&state, &HeaderMap::new())
            .await
            .unwrap_err();
        assert!(err.contains("X-Agent-Cert"));
    }

    #[tokio::test]
    async fn stale_timestamp_rejected() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, leaf, kp) = fixture();
        let stale = now_unix().saturating_sub(agent_pki::WS_AUTH_SKEW_SECS + 10);
        let h = headers_for(&leaf, &kp, "hub.example.com", stale, &[2u8; 16]);
        let err = authenticate_ws_upgrade(&state, &h).await.unwrap_err();
        assert!(err.contains("timestamp"), "got: {err}");
    }

    #[tokio::test]
    async fn host_mismatch_rejected() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, leaf, kp) = fixture();
        // Sign for one host, send the request to another.
        let mut h = headers_for(&leaf, &kp, "evil.example.com", now_unix(), &[3u8; 16]);
        h.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("hub.example.com"),
        );
        let err = authenticate_ws_upgrade(&state, &h).await.unwrap_err();
        assert!(err.contains("signature"), "got: {err}");
    }

    #[tokio::test]
    async fn replayed_nonce_rejected() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, leaf, kp) = fixture();
        let h = headers_for(&leaf, &kp, "hub.example.com", now_unix(), &[4u8; 16]);
        let _ = authenticate_ws_upgrade(&state, &h).await.unwrap();
        let err = authenticate_ws_upgrade(&state, &h).await.unwrap_err();
        assert!(err.contains("replayed"), "got: {err}");
    }

    #[tokio::test]
    async fn fingerprint_not_in_allowlist_rejected() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (state, leaf, kp) = fixture();
        // Drop the entry from the allowlist (simulating a revoke).
        state.issued_certs.write().unwrap().certs.clear();
        let h = headers_for(&leaf, &kp, "hub.example.com", now_unix(), &[5u8; 16]);
        let err = authenticate_ws_upgrade(&state, &h).await.unwrap_err();
        assert!(err.contains("fingerprint"), "got: {err}");
    }

    // The cert generated by an unrelated CA would yield a chain-
    // validation failure; we cover that path via the lower-level
    // verifier test in client_verifier.rs (which uses the same code
    // path on the rustls side). Recreating it here would just
    // duplicate the rcgen + verify glue.

    #[tokio::test]
    async fn gc_ws_replay_evicts_old_entries() {
        let (state, _, _) = fixture();
        {
            let mut cache = state.ws_replay.lock().await;
            cache.insert(
                ("fp1".into(), vec![0u8; 16]),
                Instant::now().into_std()
                    - Duration::from_secs(crate::state::WS_REPLAY_TTL_SECS + 10),
            );
            cache.insert(("fp2".into(), vec![0u8; 16]), Instant::now().into_std());
        }
        state.gc_ws_replay().await;
        let cache = state.ws_replay.lock().await;
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&("fp2".to_string(), vec![0u8; 16])));
    }
}
