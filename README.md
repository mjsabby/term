# term

Web terminal hub: passkey-gated, xterm.js front-end, one or more agents
running on the machines you want to reach. Tabs survive refresh via tmux
on the agent and a URL fragment in the browser.

```
Browser  --HTTPS/WSS-->  Hub  --TCP-->  Agent  --PTY-->  tmux -- $SHELL
        (WebAuthn, tabs)        (frame)
```

## Crates

| crate      | binary       | role                                         |
|------------|--------------|----------------------------------------------|
| `common`   | —            | wire frame, credential store, HMAC envelope  |
| `agent`    | `term-agent` | TCP listener per machine; spawns tmux+PTY    |
| `hub`      | `term-hub`   | HTTPS + ACME + WebAuthn + WS<->TCP proxy     |
| `hub-admin`| `hub-admin`  | OOB passkey registration CLI on the hub      |

```
cargo build --release
```

Binaries land at `target/release/{term-hub,term-agent,hub-admin}`.

## Wire protocol

Both hub<->agent (raw TCP) and browser<->hub (WS binary messages) use:

```
[type:u8][len:u32 BE][payload:len]
type 0 = pty data
type 1 = resize (payload: rows:u16 BE, cols:u16 BE)
type 2 = open   (payload: utf-8 session_id; first frame only)
```

Frame caps: data ≤ 64 KiB, resize == 4 bytes, session_id matches
`[A-Za-z0-9_-]{1,64}`. Unknown types are rejected. Types 3..7 are
reserved for the upload/download bolt-on.

## Authentication

WebAuthn with the `SecurityKey` flow and
`danger_set_user_presence_only_security_keys(true)` so there is no PIN /
biometric prompt — touch only. Platform authenticators (Touch ID, Windows
Hello) may still enforce user verification regardless; if so, fall back
to a hardware key with PIN disabled, or accept the prompt.

**No cookies.** A successful login returns a 32-byte random bearer
token in JSON. The SPA keeps the token in a JS variable for the lifetime
of the page; a refresh discards it and forces re-auth. The token is sent
via:

- `Authorization: Bearer <tok>` on HTTP
- `Sec-WebSocket-Protocol: bearer.<tok>` on WS upgrade (browsers can't
  set custom headers on WS)

### Registration (out-of-band paste)

The landing page lets anyone start a registration ceremony. The hub
returns the `CreationChallengeResponse` plus an **HMAC-signed envelope**
containing the registration state. The page calls
`navigator.credentials.create()`, packages the envelope + the resulting
credential + an optional label into a single base64 blob, and tells the
operator to paste it on the hub host:

```sh
hub-admin add-passkey '<blob>'
```

`hub-admin` verifies the HMAC against `/var/lib/term-hub/secret.key`,
checks the TTL (≤ 10 minutes), validates the credential, rejects
duplicates, and appends to `credentials.json` under an advisory
`flock(2)`. Nothing is stored on the hub between registration start and
the operator's paste — the blob is the only handoff.

`hub-admin` subcommands:

```sh
hub-admin add-passkey <BLOB | ->     register a new credential
hub-admin list                       list registered credentials
hub-admin remove <LABEL_OR_CRED_ID>  remove a credential
hub-admin secret-info                show data_dir + HMAC fingerprint
```

## Terminal persistence

Each tab in the UI maps to a tmux session on its agent. The agent runs
`tmux new-session -A -s <id> -- <shell>`, so reconnecting reattaches and
tmux replays scrollback. Tab layout lives in the URL fragment:

```
https://term.xyz.com/#alpha:web-1,alpha:logs,beta:root
```

Refresh = re-auth + reattach. Bookmarks save layouts.

## Install (one-host quick start)

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin term-hub
sudo install -m 755 target/release/term-hub   /usr/local/bin/
sudo install -m 755 target/release/hub-admin  /usr/local/bin/
sudo install -m 755 target/release/term-agent /usr/local/bin/

sudo mkdir -p /etc/term-hub /etc/term-agent
sudo install -m 640 systemd/hub.toml.example   /etc/term-hub/hub.toml
sudo install -m 640 systemd/agent.toml.example /etc/term-agent/agent.toml
sudo chown -R term-hub:term-hub /etc/term-hub

# Bundle static assets next to the hub binary (or set TERM_HUB_STATIC_DIR).
sudo cp -r hub/static /usr/local/share/term-hub-static
sudo tee -a /etc/systemd/system/term-hub.service.d/static.conf <<EOF >/dev/null
[Service]
Environment=TERM_HUB_STATIC_DIR=/usr/local/share/term-hub-static
EOF

sudo install -m 644 systemd/term-hub.service   /etc/systemd/system/
sudo install -m 644 systemd/term-agent.service /etc/systemd/system/

# Edit /etc/term-hub/hub.toml (domain, rp_id, acme_email, machines).
# Edit /etc/term-agent/agent.toml (bind to your internal interface).

sudo systemctl daemon-reload
sudo systemctl enable --now term-agent.service     # on each agent host
sudo systemctl enable --now term-hub.service       # on the hub host
```

Then browse to `https://term.<your-domain>/`, register a passkey, paste
the blob on the hub host, log in.

## Security notes

- **No auth between hub and agent.** The agent's TCP port must be
  unreachable from the public internet. Default bind is `127.0.0.1`; use
  WireGuard, a VPC subnet, or a firewalled LAN interface.
- **rp_id scope.** If `rp_id = xyz.com`, credentials registered for
  `term.xyz.com` are valid for any sibling of `xyz.com`. Set
  `rp_id = term.xyz.com` for the strictest scope.
- **SecurityKey vs Passkey.** We use `SecurityKey` so authentication is
  "touch only", no PIN. The trade-off: a stolen key is enough to log in.
  If that's not acceptable, switch to the `Passkey` flow in `webauthn.rs`
  (will prompt for PIN/biometric on every login).
- **HMAC secret.** `/var/lib/term-hub/secret.key` is 0600 and rotates
  manually — delete the file and the hub will regenerate on next start.
  Existing credentials keep working (the secret only protects
  registration envelopes).

## What's not built yet

File upload / download. Frame types 3..7 are reserved for it so the
existing WS connection can multiplex transfers without a protocol
change. The next iteration will likely add `upload-meta`/`upload-chunk`
and `download-req`/`download-chunk` plus a minimal SPA pane.

## Layout

```
.
├── Cargo.toml                 workspace
├── common/                    wire frame, store types, envelope, flock
├── agent/                     term-agent binary
├── hub/
│   ├── src/                   term-hub binary
│   └── static/                index.html, app.js, style.css, vendor/xterm/
├── hub-admin/                 hub-admin binary
└── systemd/                   unit files + *.toml.example
```
