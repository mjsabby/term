# Plan

## ✅ Phases 1–3 — paste + download + polish (shipped)
## ✅ Phase 4.2 — drop tmux, in-agent session manager, controller model (shipped)
## ✅ Phase 4.2.1 — Session admin (ListSessions / KillSession) (shipped)
## ✅ Phase 4.1 — Cross-platform PTY abstraction  (shipped)
## ✅ Phase 4.3 — Windows binary + install  (shipped)
## ✅ Phase 4.4 — Drop webauthn-rs + openssl, hand-roll ES256 WebAuthn  (shipped)
## ✅ Phase 4.5 — CI + security + UX + ops batch  (just shipped)

Nine deferred items + GitHub Actions CI for four targets.

### `.github/workflows/ci.yml` — matrix across windows-x64, windows-arm64, linux-x64, linux-arm64

Each runner: `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `cargo build --workspace --release`, upload
binaries as `term-${target}` artifacts (14-day retention). Separate
`lint` job runs `rustfmt --check` and a `cargo tree | grep
openssl|webauthn-rs` guard that fails the build if either ever
reappears in the dep graph.

### `dl-token` — per-session TERM_DL_TOKEN gate (security fix)

- `term-common::random` module with `os_random_bytes` (Unix:
  `/dev/urandom`, Windows: `BCryptGenRandom`). Shared by webauthn
  challenges, the HMAC secret, and the new session token.
- `Session::dl_token`: 16 random bytes → 22 base64url chars,
  generated at spawn, set as `TERM_DL_TOKEN` env in the shell.
- OSC wire change: `\x1b]5111;dl;<token>;<path>\x07` (was just
  `dl;<path>`). Token check happens in the agent's PTY reader; a
  hostile `cat /etc/motd` on an untrusted host can no longer trick
  the agent into exfiltrating files because the token isn't in the
  PTY output stream.
- `term-dl` reads `TERM_DL_TOKEN`, refuses to emit OSCs without it.

### `paste-cmd` — Windows paste-path injection (UX fix)

- `PasteStyle::{Bracketed, Plain}` chosen at `Session::spawn` from
  the shell name. cmd.exe → Plain (no `\x1b[200~` wrapper, quote
  paths containing spaces); everything else → Bracketed.

### `toml-limits` — resource limits in `agent.toml`

- New optional `[limits]` table with `scrollback_cap_bytes`,
  `idle_ttl_secs`, `max_pending_pastes_per_stream`,
  `max_pending_groups_per_stream`. Defaults preserve pre-Phase-4.5
  behavior.
- Plumbed through `Limits` → `ResolvedConfig` → `SessionManager`
  → `Session::spawn` (scrollback cap) + `handle_paste_begin`
  (paste caps) + `gc_pass` (idle TTL).

### `install-dl` + `install-hub-ps1` — install scripts

- `scripts/install-term-dl.sh` — minimal: copies binary to a
  PATH directory; tries unprivileged install first, falls back to
  sudo.
- `scripts/install-hub.ps1` — Windows hub installer. Copies hub
  binaries to `%ProgramFiles%\term-hub\`, writes config to
  `%ProgramData%\term-hub\hub.toml` (ACL: SYSTEM + Admins only),
  generates a PSK per `-Machines <id:label>` arg, registers a
  Scheduled Task that runs at system boot as SYSTEM.

### `metrics` — `/metrics` Prometheus endpoint

- Bearer-token gated. Exposes: `term_hub_uptime_seconds`,
  `term_hub_active_bearer_tokens`, `term_hub_pending_logins`,
  `term_hub_active_agents`, plus per-agent counters:
  `active_streams`, `agent_bytes_in_total`, `agent_bytes_out_total`,
  `agent_frames_in_total`, `agent_frames_out_total`.
- `AgentLink` gained 4 `AtomicU64` counters incremented in the
  reader/writer hot path; `AppState::start_time` for uptime.

### `spa-progress` + `spa-hints` — SPA UX polish

- Per-tab transfer overlay (bottom-right of pane): one row per
  in-flight paste (↑) / download (↓) with name + progress bar +
  bytes/total. Driven by `setTransfer`/`updateTransfer`/`clearTransfer`
  hooked into the existing paste-send loop and download-receive
  handlers.
- Per-tab hints overlay (top-left of pane): three tips for new
  users (drag-drop, Ctrl-V, `term-dl <path>`). Shown on first
  activation, dismissable via × button, auto-fades after 12 s.

### `agent-tests` — agent integration tests

Four new `#[cfg(unix)] #[tokio::test]`s in `session::tests` that
spawn `/bin/sh` and exercise:

1. `session_attach_writes_and_reads` — controller writes flow to
   PTY, output flows back as `Data` events.
2. `session_dl_token_mismatch_silently_drops` — OSC with wrong
   token does NOT trigger a `DownloadBegin`; same OSC with the
   right token does, end-to-end including `DownloadEnd(OK)`.
3. `session_reattach_replays_scrollback` — second attach sees
   prior session output in `scrollback`.
4. `session_manager_respects_custom_idle_ttl` — `Limits` plumbing
   sanity check.

### Verification

- `cargo test --workspace` on Windows: **145 pass** (was 145 after
  4.4 too — the 4 unix-only integration tests are gated out on
  Windows and only run in CI on the linux runners).
- `cargo clippy --workspace --all-targets --no-deps`: clean.
- Release binaries unchanged in size apart from term-hub (+36 KiB
  for the metrics module): 9.2 / 3.8 / 0.68 / 0.14 MiB.
- Live hub smoke-test: `/metrics` returns 401 unauthorized without
  bearer (correct) and the existing /webauthn endpoints continue
  to return the right JSON shapes.

---

## 🪲 Deferred / known issues

1. **hub-admin migrate** — read pre-Phase-4.4 `credentials.json` and
   convert SecurityKey blobs to our new SEC1 format.
2. **End-to-end real-Yubikey WebAuthn verification** — current
   tests use synthetic signatures.
3. **Browser streaming-to-disk** for big downloads (raises 256 MiB
   browser cap back to 4 GiB wire cap).
4. **Aggregate paste-action 4 GiB cap** (currently per-file).
5. **Resume across reconnect** (PasteBegin/DownloadBegin carry
   `resume_offset`).

## Open questions

- Phase 4.6? The remaining list is mostly UX polish + nice-to-haves
  rather than load-bearing work.

Full workspace now compiles + runs on Windows. `term-hub.exe` works
end-to-end (TLS=off mode smoke-tested; /webauthn/register/start
returns the expected JSON shape, /webauthn/login/start 412s before
any credentials are registered). Zero `openssl-sys` anywhere in
`cargo tree --workspace`.

### `common/src/webauthn/` (new, ~700 LOC including tests)

Hand-rolled minimal WebAuthn:

- `cbor.rs` — tiny scanner for the rigid CBOR shapes WebAuthn hands
  us. Supports major types 0..5; no indefinite-length, no tagged.
  ~200 LOC + 12 unit tests.
- `cose.rs` — ES256 COSE key parser. Decodes the 5-entry CBOR map
  `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` to SEC1-uncompressed 65
  bytes. Tolerates extra fields. ~100 LOC + 5 tests.
- `authdata.rs` — parses
  `rpIdHash | flags | signCount | aaguid? | credIdLen? | credId? | cose-key?`.
  Tolerates trailing ED extension blocks. ~150 LOC + 5 tests.
- `client_data.rs` — JSON parse + validate
  type/challenge/origin. Constant-time challenge compare; tolerates
  unknown fields. ~120 LOC + 6 tests.
- `challenge.rs` — 32 random bytes via `/dev/urandom` on Unix,
  `BCryptGenRandom` on Windows. Base64url-no-pad helpers.
  ~100 LOC + 4 tests.
- `mod.rs` — public API: `PublicKeyCredentialCreationOptions::build`,
  `PublicKeyCredentialRequestOptions::build`, `finish_register`,
  `finish_authenticate`. ECDSA verify via `p256` (well-audited
  RustCrypto, pure Rust, no FFI). ~450 LOC + 6 end-to-end tests
  including a signing/verifying round-trip with a generated key.

### Hub + hub-admin rewrites

- `hub/src/webauthn_routes.rs`: 200 LOC, no webauthn-rs types.
- `hub/src/main.rs`: drops `WebauthnBuilder`; only a `url::Url::parse`
  sanity check remains for the configured origin.
- `hub/src/state.rs`: `PendingLogin` now carries the raw `Challenge`
  + the `allowed_ids` list (stale assertions against removed
  credentials get rejected up front).
- `hub-admin/src/main.rs`: `cmd_add` is one `webauthn::finish_register`
  call followed by a CredentialStore append. No envelope-state
  unwrapping.

### Envelope + creds shrink

- `common/src/envelope.rs`: `EnvelopeInner` carries
  `{rp_id, origin, issued_at, challenge_b64u}` instead of
  `SecurityKeyRegistration`. Same HMAC + TTL semantics.
- `common/src/creds.rs`: `StoredCredential` is now plain fields —
  `credential_id_b64`, `credential_public_key_b64` (65-byte SEC1),
  `sign_count`. No opaque `SecurityKey` blob.

### Cross-platform flock

`common/src/flock.rs` ports cleanly to Windows: `LockFileEx` /
`UnlockFileEx` over the whole file with a hand-rolled `OVERLAPPED`
struct. ~120 LOC, no `windows-sys` dep — just two `#[link(name =
"kernel32")]` FFI declarations.

### What this unlocks

- **No `openssl-sys`** anywhere in the dep tree. Windows MSVC build
  needs zero system libraries beyond what ships with Rust.
- **Hub + hub-admin build on Windows.** Verified end-to-end:
  `scripts/build.ps1` now builds all four binaries; `term-hub.exe`
  starts cleanly, responds to `/webauthn/register/start` with the
  expected JSON shape, and 412s on `/webauthn/login/start` when no
  credentials are registered.
- **Faster compile.** Workspace cold build dropped from ~3 minutes
  to ~1 minute on Windows.
- **Smaller hub binary.** 9.2 MiB now vs ~15 MiB before (webauthn-rs
  pulled in nom + a x509 parser + a TPM attestation parser + a fido
  metadata service client + ...).

### Wire / on-disk migration

This phase is **wire-incompatible** with old paste blobs (the envelope
now carries `{challenge_b64u}` instead of a `SecurityKeyRegistration`)
**and on-disk incompatible** with old `credentials.json`. Migration
path for an existing deployment:

1. Upgrade the hub.
2. `hub-admin remove <each-old-cred>` (or rm + restart with empty
   credentials).
3. Re-register passkeys via the SPA.

Since registration takes ~10 seconds per key, this is fine for the
expected deployment size. If we ever need a non-disruptive upgrade
we can add a `hub-admin migrate` subcommand that reads the old
webauthn-rs SecurityKey JSON and extracts the SEC1 pubkey.

### Verification

- `cargo test --workspace`: **140 pass** on Windows (14 agent + 126
  common; the others have no tests yet).
- `cargo clippy --workspace --no-deps`: clean.
- `cargo build --workspace --release`: clean. Binary sizes:
  - `term-hub.exe`    9,159 KiB
  - `term-agent.exe`  3,843 KiB
  - `hub-admin.exe`     681 KiB
  - `term-dl.exe`       143 KiB
- Smoke test: live hub binary on Windows answers `/webauthn/register/
  start` with the exact JSON shape the SPA expects (verified field by
  field against `prepCreateOptions` in `hub/static/app.js`).
- `cargo tree --workspace | grep -E 'openssl|webauthn'`: empty.

---
