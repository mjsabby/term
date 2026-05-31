# term

Web terminal hub: passkey-gated, xterm.js front-end, **agents dial the
hub** so they work behind NAT, in WSL, in VMs with internal-only IPs,
or anywhere outbound TCP works. Tabs survive refresh via tmux on the
agent and a URL fragment in the browser.

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
| `agent`    | `term-agent` | dials hub, runs mux, tmux+PTY per stream        |
| `hub`      | `term-hub`   | HTTPS+ACME, WebAuthn, agent acceptor, WS proxy  |
| `hub-admin`| `hub-admin`  | OOB passkey registration CLI on the hub host    |

```sh
cargo build --release
```

Binaries land at `target/release/{term-hub,term-agent,hub-admin}`.

## Wire protocol

One persistent connection per agent carries any number of session
streams. The same framing is used between browser and hub over WS,
with `stream_id` pinned to 0 (the WS itself demultiplexes).

```
[stream_id:u32 BE][type:u8][len:u32 BE][payload:len]    (9-byte header)

type 0 = data    (raw PTY bytes, both directions, stream > 0)
type 1 = resize  (rows:u16 BE, cols:u16 BE; hub->agent; stream > 0)
type 2 = open    (utf-8 session_id; hub->agent; FIRST frame of stream)
type 3 = close   (no payload; either direction; signals stream end)
type 4 = ping    (<= 64B; either direction; stream = 0)
type 5 = pong    (echo of ping payload; stream = 0)
type 6 = hello   (json; agent->hub; FIRST frame; stream = 0)
```

Caps: data ≤ 64 KiB, resize == 4 bytes, open ≤ 64 bytes of
`[A-Za-z0-9_-]`, hello ≤ 1 KiB, ping/pong ≤ 64 bytes. Unknown types
rejected. Reserve 7..=15 for the upload/download bolt-on.

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

## Terminal persistence

Each tab maps to a tmux session on its agent. The agent runs
`tmux new-session -A -s <id> -- <shell>`, so reconnecting reattaches
and tmux replays scrollback. Tab layout lives in the URL fragment:

```
https://term.xyz.com/#alpha:web-1,alpha:logs,wsl-laptop:root
```

Refresh = re-auth + reattach. Bookmarks save layouts. If an agent
disconnects, the browser auto-reconnects with exponential backoff
(500ms → 30s, with jitter) and the tab status pulses orange until the
agent reappears.

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

# Bundle static assets next to the hub binary (or set TERM_HUB_STATIC_DIR).
sudo cp -r hub/static /usr/local/share/term-hub-static
sudo mkdir -p /etc/systemd/system/term-hub.service.d
sudo tee /etc/systemd/system/term-hub.service.d/static.conf <<EOF >/dev/null
[Service]
Environment=TERM_HUB_STATIC_DIR=/usr/local/share/term-hub-static
EOF

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
│   ├── src/                   term-hub binary
│   └── static/                index.html, app.js, style.css, vendor/xterm/
├── hub-admin/                 hub-admin binary
└── systemd/                   unit files + *.toml.example
```
