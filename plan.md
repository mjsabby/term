# Plan

## ✅ Phases 1–3 — paste + download + polish (shipped)
## ✅ Phase 4.2 — drop tmux, in-agent session manager, controller model (shipped)
## ✅ Phase 4.2.1 — Session admin (ListSessions / KillSession) (shipped)

## ✅ Phase 4.1 — Cross-platform PTY abstraction  (just shipped)

Swapped `pty-process` (Unix-only) for `portable-pty` (openpty on Unix,
ConPTY on Windows). Because `portable-pty` exposes only blocking
`std::io::{Read, Write}` master handles, a thin bridge keeps the
async session manager untouched.

### `agent/src/pty.rs` (new, ~290 LOC)

- `AsyncPty { out_rx, in_tx, master, killer, waitable }`.
- `AsyncPty::spawn(program, args, env, rows, cols)` creates the PTY,
  spawns the child, and starts **two named OS threads**:
  - `pty-r` — `read(buf)` → `mpsc::Sender<Vec<u8>>::blocking_send`.
  - `pty-w` — `mpsc::Receiver<Vec<u8>>::blocking_recv` →
    `write_all(buf)`.
- 64 KiB stacks, 16 KiB read buffer, 32-item bounded queues per
  direction.
- `resize / kill / exited` wrap blocking `portable-pty` calls in
  `tokio::task::spawn_blocking` so they don't park a tokio worker.
- `split_shell("/bin/bash -l")` → `("/bin/bash", ["-l"])` so the
  agent.toml `shell` knob now supports an argv-style string.

### `agent/src/session.rs` (ported)

- `Session.pty_w + Session.child` → single `Session.pty: AsyncPty`.
- PTY reader task is the same shape but drains `pty.out_rx.lock()
  .await.recv().await` instead of `pty_r.read(&mut buf).await`.
- `write_input_from / write_internal / resize_for / acquire/release/
  take_control` all route through `pty.in_tx.send(...)` /
  `pty.resize(...)`.
- `Session::kill()` now just calls `pty.kill()`.

### Verification

- `cargo test -p term-agent --bin term-agent`: **5 pass** — includes
  the new `pty::tests::spawn_echo_round_trip` that actually spawns
  `/bin/sh -c "printf 'hi'; exit 0"` and reads `hi` back through the
  bridge.
- `cargo test --workspace`: 84 (common) + 5 (agent) = 89 total green.
- Release & clippy clean.
- `agent.toml.example` updated to document `"shell = \"/bin/bash -l\""`.

### Cost

Two OS threads per active session (~128 KiB stack budget per session,
plus negligible mpsc queue). With ~32 sessions that's ~64 threads —
well under tokio's default 512-thread `spawn_blocking` pool. If
session counts ever explode (collaborative use cases?), we can swap
back to async `pty_process` on Linux as an optional backend without
changing the session manager.

---

## 🔭 Phase 4.3 — Windows binary + install  (next)

Now genuinely possible — the PTY layer compiles on Windows.

- Cross-compile `term-agent.exe`, `term-dl.exe` (probably MSVC target
  given the windows-sys deps inside portable-pty).
- Windows service install via the `windows-service` crate, or
  Scheduled Task with auto-start.
- Validate against PowerShell, cmd.exe, pwsh, bash (WSL inside).
- Verify ConPTY-specific footguns:
  - `\x1b[6n` cursor query on session start — `portable-pty` may
    handle this already; if not, intercept in our OSC scanner.
  - Pipe DACL — only relevant if the agent ever runs as a different
    user than the shell (uncommon for our deployment model).
  - DSR replies, mouse modes, alt-screen — exercise interactively.
- Decide on default `shell`: `"powershell"`, `"pwsh"`, or `"cmd"`.

---

## 🪲 Deferred / known issues (unchanged)

1. **`TERM_DL_TOKEN` gate** — passive PTY-output content can trigger
   downloads. Per-session token in shell env.
2. **Browser streaming-to-disk** for big downloads (raises 256 MiB
   browser cap back to 4 GiB wire cap).
3. **Aggregate paste-action 4 GiB cap** (currently per-file).
4. **Paste/Download progress UI.**
5. **Resume across reconnect** (PasteBegin/DownloadBegin carry
   `resume_offset`).
6. **In-SPA hints** about drag-drop, Ctrl-V, `term-dl`.
7. **Install script for `term-dl`.**
8. **Resource limits in `agent.toml`** (currently hardcoded).
9. **Basic metrics** (active sessions, throughput).
10. **Agent-side integration tests** beyond the bridge round-trip.

## Open questions

- 4.3 next? Plan: spin up a Windows VM (or cross-compile and ask user
  to test), validate ConPTY + the `\x1b[6n` footgun, then write a
  `scripts/install-agent.ps1` mirroring the bash installer.
- Any tweaks wanted to the bridge model (e.g. larger read buffer,
  unbounded queues, separate priority)? Defaults seem fine.
