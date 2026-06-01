# term

Web terminal hub: passkey-gated, xterm.js front-end, **agents dial the
hub** so they work behind NAT, in WSL, in VMs with internal-only IPs,
or anywhere outbound TCP works. Tabs survive refresh via an in-agent
session manager (no tmux required) and a URL fragment in the browser;
multiple browsers can attach to the same session, with one *controller*
holding the input/resize lease and the rest as read-only viewers.

```
Browser  --HTTPS/WSS-->  Hub  <==TLS+mux+PSK==  Agent  --PTY-->  tmux -- $SHELL
       (WebAuthn, tabs)        ^                   ^
                          accepts on          dials hub on
                          agent_bind          agent_bind
                          (reuses ACME        (verifies hub
                           cert)               hostname)
```

## Crates

| crate      | binary       | role                                            |
|------------|--------------|-------------------------------------------------|
| `common`   | —            | wire frame (mux), credential store, envelope    |
| `agent`    | `term-agent` | dials hub, runs mux, in-agent session manager (drops tmux dep) |
| `hub`      | `term-hub`   | HTTPS+ACME, WebAuthn, agent acceptor, WS proxy, embedded SPA |
| `hub-admin`| `hub-admin`  | OOB passkey registration CLI on the hub host    |
| `term-dl`  | `term-dl`    | helper run inside the shell to ship a file from the agent host to the browser as a download |

```sh
cargo build --release
```

Binaries land at `target/release/{term-hub,term-agent,hub-admin,term-dl}`.
The SPA is embedded into `term-hub` (no separate static-asset directory
to ship); each binary is fully self-contained. Install `term-dl`
anywhere on the agent's shell `$PATH` (e.g. `/usr/local/bin/`) so users
can run `term-dl ~/build.log` from their session.

## Wire protocol

One persistent connection per agent carries any number of session
streams. The same framing is used between browser and hub over WS,
with `stream_id` pinned to 0 (the WS itself demultiplexes).

```
[stream_id:u32 BE][type:u8][len:u32 BE][payload:len]    (9-byte header)

type 0  = data               (raw PTY bytes, both directions, stream > 0)
type 1  = resize             (rows:u16 BE, cols:u16 BE; hub->agent; stream > 0)
type 2  = open               (session_id + rows:u16 + cols:u16; hub->agent; FIRST frame of stream)
type 3  = close              (no payload; either direction; signals stream end)
type 4  = ping               (<= 64B; either direction; stream = 0)
type 5  = pong               (echo of ping payload; stream = 0)
type 6  = hello              (json; agent->hub; FIRST frame; stream = 0)
type 7  = paste-begin        (browser->agent; stream > 0; starts a chunked paste)
type 8  = paste-chunk        (browser->agent; stream > 0; one chunk of a paste)
type 9  = paste-end          (browser->agent; stream > 0; finalize or cancel)
type 10 = paste-reject       (agent->browser; stream > 0; agent rejected a paste)
type 11 = download-begin     (agent->browser; stream > 0; starts a chunked download)
type 12 = download-chunk     (agent->browser; stream > 0; one chunk of a download)
type 13 = download-end       (agent->browser; stream > 0; finalize or cancel)
type 14 = acquire-control    (browser->agent; stream > 0; ask to become controller)
type 15 = release-control    (browser->agent; stream > 0; relinquish control)
type 16 = take-control       (browser->agent; stream > 0; force preemption)
type 17 = controller-changed (agent->browser; stream > 0; per-receiver status: 0=none, 1=self, 2=other)
type 18 = list-sessions      (hub->agent; stream = 0; admin RPC request)
type 19 = session-list       (agent->hub; stream = 0; admin RPC response)
type 20 = kill-session       (hub->agent; stream = 0; admin RPC request)
type 21 = kill-session-ack   (agent->hub; stream = 0; admin RPC response)
```

Caps: data ≤ 64 KiB, resize == 4 bytes, open ≤ 64 + 4 bytes of
`[A-Za-z0-9_-]` + initial size, hello ≤ 1 KiB, ping/pong ≤ 64 bytes,
acquire/release/take-control 0 bytes, controller-changed 1 byte,
list-sessions 4 bytes, session-list ≤ 256 KiB JSON, kill-session ≤
4 + 1 + 64 bytes, kill-session-ack 5 bytes. Unknown types rejected.
Reserve 22..=31 for future admin extensions.

The hub→agent socket writer, the agent→hub socket writer, and the
agent's per-stream input all use a two-priority channel so interactive
frames (Data/Resize/Ping/etc.) never sit behind a 1 MiB Paste/Download
chunk. Outbound writers are byte-bounded (hi=4 MiB, lo=16 MiB);
per-stream input is item-bounded (hi=8, lo=8).

### Paste (chunked file upload)

Pasting a file (clipboard, right-click, or drag-and-drop) on a tab
streams the bytes browser → hub → agent over the same mux:

```
paste-begin: [paste_id:u32 BE][total_size:u64 BE][group_id:u32 BE]
             [group_size:u32 BE][name_len:u8][name UTF-8]
paste-chunk: [paste_id:u32 BE][bytes ≤ 1 MiB]   × ceil(total_size / 1 MiB)
paste-end:   [paste_id:u32 BE][status:u8]       // 0 = ok, 1 = cancel
paste-reject:[paste_id:u32 BE][reason:u8]       // agent → browser; aborts the paste
```

PasteReject reasons (`u8`): 0 = registry full, 1 = open failed,
2 = size mismatch, 3 = write failed, 4 = duplicate paste id,
5 = group aggregate over 4 GiB.

### Download (agent → browser, via `term-dl`)

Mirror of paste, opposite direction, triggered by the `term-dl <path>`
helper running inside a shell on the agent host:

```
term-dl  →  ESC ] 5111 ; dl ; <absolute path> BEL   (on its stdout, into the PTY)
agent    →  download-begin / download-chunk × N / download-end(0)   (on the same mux stream)
browser  →  builds a Blob, triggers `<a download>` save
```

The agent's PTY-output OSC scanner consumes our application-private
`5111;` OSCs without forwarding them to the browser (so the user
doesn't see the escape echo); other OSCs (window title, OSC 52
clipboard, …) pass through unchanged. Caps: 4 GiB per file on the
wire, but the browser-side Blob buffer is capped at 256 MiB until
streaming-to-disk is wired up. Per-stream concurrent downloads are
capped at 16. Bracketed-paste and download tasks are bound to their
stream's lifetime — closing the browser tab cancels in-flight
downloads instead of letting them keep streaming bytes into the void.

`paste_id` is browser-allocated and unique among that stream's
in-flight pastes. `group_id` ties N pastes together as one "paste
action" (Ctrl-V on a multi-file clipboard, multi-file drag-and-drop);
`group_size` is N. The agent buffers finished paths per `group_id` and
injects them all in one bracketed-paste block once all `group_size`
pastes complete. Cap is 4 GiB per file, 1 MiB per chunk, ≤ 32
concurrent pastes / 32 concurrent groups per stream. The agent writes
each file into `$XDG_RUNTIME_DIR/term-agent/paste/` (or
`/tmp/term-agent-<uid>/paste/`) with mode `0600`, sanitizes the
browser-supplied filename to `[A-Za-z0-9._-]`, and types the absolute
path(s) back into the PTY on completion.

Hello payload (JSON):

```json
{ "version": 1, "machine_id": "alpha", "psk_b64": "<base64-32>" }
```

## Authentication & trust

**Browser ↔ Hub.** WebAuthn with the `SecurityKey` flow and
`danger_set_user_presence_only_security_keys(true)` so there is no
PIN/biometric prompt — touch only. Platform authenticators may still
enforce verification regardless; if so, fall back to a hardware key.

After login, the hub returns a 32-byte random bearer token in JSON.
The SPA keeps it in a JS variable for the lifetime of the page; a
refresh discards it and forces re-auth. Sent via:

- `Authorization: Bearer <tok>` on HTTP
- `Sec-WebSocket-Protocol: bearer.<tok>` on WS upgrade

**No cookies, no localStorage.** Tab layout lives in the URL fragment.

**Agent ↔ Hub.** Per-machine PSK (32 random bytes, base64). The agent
sends it in the Hello frame; the hub constant-time compares it against
the `[[machines]]` config. Anyone with the PSK *and* network access to
`agent_bind` can register as that machine, so treat PSKs as service
credentials. The TLS layer encrypts the PSK in transit and verifies
the agent is talking to the right hub.

### Registration (out-of-band paste)

The landing page can start a registration ceremony. The hub returns a
`CreationChallengeResponse` plus an **HMAC-signed envelope** containing
the registration state. The page calls `navigator.credentials.create()`,
packages the envelope + the credential + an optional label into a
single base64 blob, and prompts the operator to paste it on the hub
host:

```sh
hub-admin add-passkey '<blob>'
```

`hub-admin` verifies the HMAC against `/var/lib/term-hub/secret.key`,
checks the TTL (≤ 10 minutes), validates the credential, rejects
duplicates, and appends to `credentials.json` under `flock(2)`.

```
hub-admin add-passkey <BLOB | ->     register a new credential
hub-admin list                       list registered credentials
hub-admin remove <LABEL_OR_CRED_ID>  remove a credential
hub-admin secret-info                show data_dir + HMAC fingerprint
```

## Terminal persistence + multi-attach

Each tab maps to a *session* on its agent. Sessions are owned by an
in-agent session manager (no tmux required): on the first attach the
agent spawns `$SHELL` in a fresh PTY; on subsequent attaches with the
same `session_id` the existing PTY is reused and its scrollback ring
(default 8 MiB) is replayed to the new client. Multiple browsers can
attach to the same session at the same time.

Tab layout lives in the URL fragment:

```
https://term.xyz.com/#alpha:web-1,alpha:logs,wsl-laptop:root
```

### Controller / viewer model

When more than one browser is attached to a session, exactly one is
the **controller** (input + resize go through) and the rest are
**viewers** (read-only). Each tab strip shows a pill — `● controlling
— release`, `👁 viewing — take`, or `— no controller — acquire` —
that reflects the per-receiver status broadcast by the agent. Wire
support: types 14–17 (`AcquireControl` / `ReleaseControl` /
`TakeControl` / `ControllerChanged`).

- First attacher of a fresh session = automatic controller.
- `Acquire` succeeds only when nobody currently controls.
- `Take` always succeeds; the prior controller becomes a viewer.
- `Release` returns control to nobody (next attach or `Acquire`
  picks it up).
- When the controller changes, the PTY is resized to the new
  controller's last-reported geometry; viewers see whatever the
  controller has (no lowest-common-denominator shrinking).

### Reattach + idle TTL

Refresh = re-auth + reattach. Bookmarks save layouts. If an agent
disconnects, the browser auto-reconnects with exponential backoff
(500ms → 30s, with jitter) and the tab status pulses orange until the
agent reappears.

Sessions survive having no clients attached. After **24 h** with
zero attached clients (configurable later via `agent.toml`) the
session is garbage-collected and the shell is killed.

### Listing / killing sessions

Each machine row in the sidebar has a `sessions ▾` toggle that opens
a panel showing the agent's live sessions with attached counts, idle
time, and a `× kill` button. Backed by HTTP:

```
GET    /api/machines/{id}/sessions               // returns {"sessions":[…]}
DELETE /api/machines/{id}/sessions/{session_id}  // returns {"killed":true|false}
```

Both require the bearer token from login. Under the hood the hub runs
a stream-0 RPC to the agent (request_id + oneshot wait, 5s timeout)
to ask for the live state — the hub doesn't cache, so what you see
is what the agent has *right now*.

## Install (one-host quick start)

There are wrapper scripts under `scripts/` for the common paths.
Everything below is what they automate, in case you want to do it by
hand.

### Scripted (recommended)

```sh
# 1. Build once.
./scripts/build.sh

# 2. On the hub host.
sudo ./scripts/install-hub.sh \
    --domain term.xyz.com \
    --email  ops@xyz.com
# (defaults to ACME staging; pass --prod once it works)

# 3. For every machine you want to reach, on the hub host:
sudo ./scripts/add-machine.sh --id alpha --label alpha.lan --reload
# -> prints an install-agent.sh command containing the fresh PSK.

# 4. On each agent host, paste the printed command:
sudo ./scripts/install-agent.sh --hub term.xyz.com:7700 \
    --machine-id alpha --psk '<the printed psk>'
# Optional: --user youruser to run the agent unprivileged.
```

Then browse to `https://term.<your-domain>/`, register a passkey,
paste the blob into `hub-admin add-passkey` on the hub host, log in.

### By hand

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin term-hub
sudo install -m 755 target/release/term-hub   /usr/local/bin/
sudo install -m 755 target/release/hub-admin  /usr/local/bin/
sudo install -m 755 target/release/term-agent /usr/local/bin/

sudo mkdir -p /etc/term-hub /etc/term-agent
sudo install -m 640 systemd/hub.toml.example   /etc/term-hub/hub.toml
sudo install -m 640 systemd/agent.toml.example /etc/term-agent/agent.toml
sudo chown -R term-hub:term-hub /etc/term-hub

# Generate a PSK per agent on the hub host and copy it to both configs.
head -c 32 /dev/urandom | base64

# The SPA is embedded into the term-hub binary; nothing to copy.
sudo install -m 644 systemd/term-hub.service   /etc/systemd/system/
sudo install -m 644 systemd/term-agent.service /etc/systemd/system/

# Edit /etc/term-hub/hub.toml (domain, rp_id, acme_email, machines + psks).
# Edit /etc/term-agent/agent.toml (hub address, machine_id, psk).

sudo systemctl daemon-reload
sudo systemctl enable --now term-hub.service       # on the hub host
sudo systemctl enable --now term-agent.service     # on each agent host
```

Then browse to `https://term.<your-domain>/`, register a passkey,
paste the blob on the hub host, log in.

## Security notes

- **Trust model.** The hub trusts whoever presents the right PSK. The
  agent trusts whoever serves a valid cert for the hub's domain. The
  WebAuthn flow protects the browser ↔ hub side. Anyone with a PSK
  *and* TCP reachability to the hub's `agent_bind` can register as
  that machine and serve any tab the operator opens for it.
- **rp_id scope.** `rp_id = xyz.com` shares credentials across sibling
  subdomains. Set `rp_id = term.xyz.com` for stricter scoping.
- **SecurityKey vs Passkey.** We use `SecurityKey` so login is touch
  only, no PIN. The trade-off: a stolen key is enough to log in.
- **HMAC secret.** `/var/lib/term-hub/secret.key` is 0600 and rotates
  manually — delete the file and the hub regenerates it on next start.
  Existing credentials keep working (the secret only protects
  registration envelopes).
- **PSK strength.** 32 random bytes from `/dev/urandom`. The hub warns
  if a configured PSK decodes to fewer than 16 bytes.

## What's not built yet

File upload / download. Frame types 7..=15 are reserved so the
existing multiplexed connection can carry transfers later without a
protocol change. The next iteration will likely add `upload-meta`/
`upload-chunk` and `download-req`/`download-chunk` plus a small SPA
pane.

## Layout

```
.
├── Cargo.toml                 workspace
├── common/                    wire frame, store types, envelope, flock
├── agent/                     term-agent binary
├── hub/
│   ├── src/                   term-hub binary (SPA embedded via rust-embed)
│   └── static/                index.html, app.js, style.css, vendor/xterm/
├── hub-admin/                 hub-admin binary
└── systemd/                   unit files + *.toml.example
```
