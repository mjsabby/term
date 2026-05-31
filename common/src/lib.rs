//! Shared types for the term hub/agent system.
//!
//! Three independent modules:
//!
//! - [`frame`]: the length-prefixed binary protocol used both hub<->agent
//!   (over TCP) and browser<->hub (as WebSocket binary messages). Keep
//!   identical so the hub can act as a near-trivial relay.
//! - [`creds`]: on-disk credential store (`credentials.json`) and the
//!   secret-key file used to HMAC-sign out-of-band registration envelopes.
//! - [`envelope`]: HMAC-signed registration envelope used by the OOB
//!   passkey paste flow. Produced by the hub, verified by `hub-admin`.

pub mod creds;
pub mod envelope;
pub mod flock;
pub mod frame;
