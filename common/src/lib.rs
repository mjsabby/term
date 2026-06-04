//! Shared types for the term hub/agent system.
//!
//! Module set varies by feature / target:
//!
//! - [`frame`], [`osc`], [`prio`], [`random`], [`transport`],
//!   [`agent_pki`]: always available. Used by both the agent and the
//!   hub. `agent_pki` covers the cert-file loading + WS-auth payload
//!   bytes that the agent needs to dial the hub over WSS through a
//!   perimeter; the heavier CA / issuance / verification helpers live
//!   in `agent_pki::ca`, gated by the `hub` feature so the agent
//!   binary stays small.
//! - [`webauthn`], [`creds`], [`envelope`], [`issued_certs`]: gated
//!   behind the `hub` feature (default-on). Used by hub + hub-admin.
//!   The agent disables the feature so it doesn't drag in `p256` /
//!   `rcgen` / `x509-parser`.
//! - [`flock`]: gated behind `cfg(unix)`. Used by hub + hub-admin to
//!   serialize concurrent `credentials.json` / `issued-certs.json`
//!   writes. The agent doesn't touch either, so the Windows agent
//!   build doesn't need a Windows file-lock impl.

pub mod agent_pki;
#[cfg(feature = "hub")]
pub mod creds;
#[cfg(feature = "hub")]
pub mod envelope;
#[cfg(feature = "hub")]
pub mod flock;
pub mod frame;
#[cfg(feature = "hub")]
pub mod issued_certs;
pub mod osc;
pub mod prio;
pub mod random;
pub mod transport;
#[cfg(feature = "hub")]
pub mod webauthn;
