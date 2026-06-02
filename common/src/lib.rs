//! Shared types for the term hub/agent system.
//!
//! Module set varies by feature / target:
//!
//! - [`frame`], [`osc`], [`prio`]: always available. Used by both
//!   the agent and the hub.
//! - [`webauthn`], [`creds`], [`envelope`]: gated behind the `hub`
//!   feature (default-on). Used by hub + hub-admin. The agent
//!   disables the feature so it doesn't drag in `p256` for our
//!   ECDSA verifier.
//! - [`flock`]: gated behind `cfg(unix)`. Used by hub + hub-admin to
//!   serialize concurrent `credentials.json` writes. The agent
//!   doesn't touch credentials, so the Windows agent build doesn't
//!   need a Windows file-lock impl.

#[cfg(feature = "hub")]
pub mod creds;
#[cfg(feature = "hub")]
pub mod envelope;
#[cfg(feature = "hub")]
pub mod flock;
pub mod frame;
pub mod osc;
pub mod prio;
pub mod random;
#[cfg(feature = "hub")]
pub mod webauthn;
