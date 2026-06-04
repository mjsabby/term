# term

Web terminal hub: passkey-gated, xterm.js front-end, **agents dial the
hub** so they work behind NAT, in WSL, in VMs with internal-only IPs,
or anywhere outbound TCP works. Tabs survive refresh via an in-agent
session manager (no tmux required) and a URL fragment in the browser;
multiple browsers can attach to the same session, with one *controller*
holding the input/resize lease and the rest as read-only viewers.

```
Browser  --HTTPS/WSS-->  Hub  <==mTLS+mux==  Agent  --PTY-->  $SHELL
       (WebAuthn, tabs)        ^                ^
                          accepts on       dials hub on
                          agent_bind       agent_bind
                          (reuses ACME     (verifies hub
                           cert + agent     hostname,
                           CA verifier)     presents
                                            client cert)
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

The agent↔hub link runs over either a length-delimited TCP/TLS byte
stream (raw `agent_bind`) or, when the agent dials a `wss://…` hub, one
frame per binary WebSocket message — same frames, full mux (`stream_id`
not pinned), so the rest of the protocol is identical on both
transports.

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
5 = group aggregate over 4 GiB, 6 = stream is a viewer, not the
session's controller (paste is an input action — see below).

### Download (agent → browser, via `term-dl`)

Mirror of paste, opposite direction, triggered by the `term-dl <path>`
helper running inside a shell on the agent host:

```
term-dl  →  ESC ] 5111 ; dl ; <token> ; <absolute path> BEL   (on its stdout, into the PTY)
agent    →  download-begin / download-chunk × N / download-end(0)   (on the same mux stream)
browser  →  builds a Blob, triggers `<a download>` save
```

`<token>` is the value of `TERM_DL_TOKEN`, a 16-byte random secret
the agent sets in the session shell's environment at spawn time and
keeps for the life of the session. The agent compares the token on
the OSC against the session's stored token and silently drops the
download request on any mismatch. This prevents a hostile process
(or a stray `cat /etc/motd` on an untrusted host) from spoofing the
OSC to exfiltrate files — without the env var, no process running
inside the shell can know the right token.

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
{ "version": 2 }
```

The Hello frame is version-only as of `HELLO_VERSION = 2`. The agent's
identity (`machine_id`) is bound at the transport layer — by the
client cert's `urn:term-agent:<machine_id>` SAN URN on the raw mTLS
path, or by the `X-Agent-Cert` + `X-Agent-Auth` upgrade headers on
the WSS-perimeter path. v1 (PSK auth) is wire-incompatible.

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

**Agent ↔ Hub.** Mutual TLS with a private per-deployment CA. The
hub creates the CA explicitly via `hub-admin init-ca`; per-machine
certs are minted with `hub-admin issue-cert --id <machine_id>` and
signed by that CA. The agent presents its leaf cert during the TLS
handshake; the hub verifies (a) the chain to its CA, (b) the
fingerprint against an allow-list in `<data_dir>/issued-certs.json`,
and (c) the SAN URN `urn:term-agent:<machine_id>` — all three live
inside a custom `rustls::ClientCertVerifier`, so a mismatch tears
down the TCP connection at the TLS-handshake layer before any
application bytes flow.

The hub never holds the CA's private key — `agent-ca.key` is owned
0600 by whoever ran `init-ca` (typically root), so a hub-process
compromise cannot mint new agent certs.

Revoke a stolen cert with `hub-admin revoke-cert --serial <hex>`
(or `--id <machine_id>` to revoke all certs for a machine). The hub
reloads `issued-certs.json` every 30 seconds, so revocations take
effect without a hub restart.

When the agent dials the hub through a TLS-terminating perimeter
(`wss://…/agent/connect` via a Microsoft Dev Tunnel, SSO reverse
proxy, …) the hub can't see the client cert, so the agent attaches
two HTTP upgrade headers carrying the equivalent assertion:

- `X-Agent-Cert: <base64-no-pad of leaf cert DER>`
- `X-Agent-Auth: <unix_secs>.<nonce_b64u>.<ECDSA-P256 sig>`

The signature covers a domain-separated payload that includes the
`Host:` header, so a tunnel-eavesdropper can't replay the assertion
against a different hub. A `(fingerprint, nonce)` replay cache
defeats replay against the same hub within the timestamp skew window
(±5 minutes).

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
the **controller** (input, resize, and file paste/drop go through) and
the rest are **viewers** (read-only — keystrokes, resize, and paste are
all dropped/rejected by the agent for non-controllers). Each tab strip shows a pill — `● controlling
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

# 2b. One-shot: create the agent CA. The hub refuses to start without
#     this. The CA private key is owned 0600 by the running user; the
#     hub service user does NOT get read access, so a hub compromise
#     can't mint new agent certs.
sudo hub-admin init-ca

# 3. For every machine you want to reach, on the hub host:
sudo ./scripts/add-machine.sh --id alpha --label alpha.lan --reload
# -> writes alpha.crt + alpha.key in $PWD and prints the install-agent
#    command. Copy the two files to the agent host.

# 4. On each agent host, paste the printed command:
sudo ./scripts/install-agent.sh --hub term.xyz.com:7700 \
    --cert alpha.crt --key alpha.key
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

# Create the agent CA (one-shot; writes to /var/lib/term-hub/agent-ca.*).
sudo hub-admin init-ca

# Per agent: issue a cert, copy the .crt + .key to the agent host.
sudo hub-admin issue-cert --id alpha --label alpha.lan
# -> writes alpha.crt + alpha.key in $PWD

# The SPA is embedded into the term-hub binary; nothing to copy.
sudo install -m 644 systemd/term-hub.service   /etc/systemd/system/
sudo install -m 644 systemd/term-agent.service /etc/systemd/system/

# Edit /etc/term-hub/hub.toml (domain, rp_id, acme_email, machines).
# Edit /etc/term-agent/agent.toml (hub address, cert_path, key_path).

sudo systemctl daemon-reload
sudo systemctl enable --now term-hub.service       # on the hub host
sudo systemctl enable --now term-agent.service     # on each agent host
```

Then browse to `https://term.<your-domain>/`, register a passkey,
paste the blob on the hub host, log in.

### Windows agent

`term-agent.exe` + `term-dl.exe` run on Windows 10 / 11 / Server 2019+
(ConPTY required). The full workspace — including `term-hub.exe` +
`hub-admin.exe` — also builds on Windows now that the webauthn stack
is hand-rolled (no `openssl-sys`).

```powershell
# 1. Build (release, MSVC toolchain — install Rust via https://rustup.rs).
.\scripts\build.ps1

# 2. From an elevated PowerShell on the agent host. The .crt + .key
#    files come from `hub-admin issue-cert --id win-laptop` on your
#    hub host; scp them over first.
.\scripts\install-agent.ps1 `
    -Hub        term.xyz.com:7700 `
    -Cert       'win-laptop.crt' `
    -Key        'win-laptop.key' `
    -Shell      'C:\Windows\System32\cmd.exe'
```

The script:

- Installs `term-agent.exe` (and `term-dl.exe` if built) to
  `%ProgramFiles%\term-agent\`.
- Copies the cert + key into `%ProgramData%\term-agent\agent.{crt,key}`
  (key 0600 / Administrators + run-as-user read).
- Writes `%ProgramData%\term-agent\agent.toml` with a tight ACL
  (SYSTEM + Administrators full control, the run-as user read-only).
- Registers a Scheduled Task `term-agent` that runs at the run-as
  user's logon, restarts on failure, and keeps running for the life
  of the session.

Single-user model: one agent per Windows user account. `-RunAsUser`
defaults to the user invoking the installer (which is almost always
what you want); pass it explicitly only if you're installing for a
different account. If you want multiple users on the same machine to
expose shells, issue a separate cert per user (`hub-admin issue-cert
--id win-alice` / `--id win-bob`) and run the installer once per
user with `-TaskName` overridden.

To uninstall: `.\scripts\uninstall-agent.ps1` (stops + unregisters
the scheduled task, removes the binary dir, preserves the cert + key
unless `-PurgeConfig` is also passed).

### Windows hub

The hub can be installed the same way on Windows when you'd rather
run it as a Scheduled Task than under systemd. `term-hub.exe` is
fully self-contained — the SPA is embedded.

```powershell
# Elevated PowerShell on the hub host.
.\scripts\install-hub.ps1 `
    -Domain    term.xyz.com `
    -AcmeEmail ops@xyz.com `
    -TlsMode   acme
```

To run the hub on a corporate network behind Microsoft Dev Tunnel —
the second listener mode described below — pass `-NoAuthBind` +
`-NoAuthOrigin`:

```powershell
.\scripts\install-hub.ps1 `
    -Domain        term.xyz.com `
    -TlsMode       off `
    -NoAuthBind    "[::]:8080" `
    -NoAuthOrigin  "https://abc-8080.usw2.devtunnels.ms"
```

The hub binds 8080 in plain HTTP; Dev Tunnel terminates TLS upstream
and you reach it at the `-NoAuthOrigin` URL. Open the Windows Firewall
port if loopback isn't enough:

```powershell
New-NetFirewallRule -DisplayName 'term-hub no-auth' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
```

### Dev Tunnel deployment (corporate networks)

For machines that live in a corporate network where the public hub
can't reach them, run the hub locally and front it with a
[Microsoft Dev Tunnel](https://learn.microsoft.com/azure/developer/dev-tunnels/).
The `[no_auth]` listener section in `hub.toml` enables a second port
that skips WebAuthn — Dev Tunnel's own AAD-backed access policy is
the perimeter.

```toml
## hub.toml
domain          = "irrelevant.example.com"   # still required, but unused
rp_id           = "irrelevant.example.com"
tls             = "off"
data_dir        = "/var/lib/term-hub"

[no_auth]
bind          = "[::]:8080"
public_origin = "https://abc-8080.usw2.devtunnels.ms"   # your tunnel URL

[[machines]]
id    = "alpha"
label = "alpha.lan"
```

Then create the tunnel and forward port 8080:

```sh
devtunnel host -p 8080 --allow-anonymous false
```

(or run with `--allow-anonymous true` if your tenant policy allows
it and you accept that the perimeter is open). The hub trusts every
request it sees on the no-auth port, so anyone who passes the
tunnel's access check sees every configured machine.

Runtime overrides:

- `TERM_HUB_NO_AUTH=off` — force the no-auth listener off even if
  `[no_auth]` is present (useful on systemd / `sc.exe` without
  editing the config file).
- `TERM_HUB_NO_AUTH=on` — require the `[no_auth]` block; fail to
  start if it's missing.

The authed listener (443 or whatever `bind` is) and the no-auth
listener can run side-by-side on the same hub process — you don't
have to choose.

#### Agents anywhere: dialing the hub over WebSocket

The raw `agent_bind` (7700) is a plain TCP/mux socket, so it only works
when the agent shares a network with the hub — a Dev Tunnel forwards
HTTP/WebSocket, not arbitrary TCP. To put an agent on a machine that
can only reach the hub *through* the tunnel, point its `hub` at the
tunnel's `wss://…/agent/connect` URL instead of a `host:port`. The hub
serves the same agent mux over a WebSocket route (`GET /agent/connect`,
exposed on both listeners); each frame is one binary message. One
tunnel-fronted hub can then serve agents on any machine that can reach
the tunnel and present its access token.

```toml
## agent.toml on a remote machine
hub               = "wss://abc-8080.usw2.devtunnels.ms/agent/connect"
cert_path         = "/etc/term-agent/agent.crt"
key_path          = "/etc/term-agent/agent.key"
## Perimeter (tunnel) token. Sent as `X-Tunnel-Authorization: tunnel
## <token>` on the WS upgrade. Tunnel tokens lapse hourly, so the agent
## caches it and only re-reads this file when it's near expiry (parsed
## from the token's JWT `exp`) — keep an out-of-band rotator writing a
## fresh token here.
tunnel_token_file = "/run/term-agent/tunnel.token"
```

Transport is chosen by the `hub` value's scheme: `ws://` / `wss://`
⇒ WebSocket; a bare `host:port` ⇒ the original raw mTLS path. Auth
is layered: the **tunnel's** access policy gates who can reach
`/agent/connect`, and the agent's **client cert + signed assertion**
(in the `X-Agent-Cert` + `X-Agent-Auth` headers) gates which
`machine_id` it may register as — exactly the same allowlist /
revocation logic as the raw mTLS path, just bridged across the
TLS-terminating perimeter. Because the WS route carries no browser
`Origin` header, it isn't affected by the hub's origin check; and
unlike the browser `WebSocket` API, the agent's native client *can*
set custom headers, so no query-string token is needed.

The token is read only from `tunnel_token_file` (an env var would be no
use — tunnel tokens expire hourly and a process's environment can't be
updated from outside once it's running). It's cached in memory and
re-read only when within a minute of its `exp`; a token whose expiry
can't be parsed (not a JWT) is re-read on every reconnect. Omit the file
for an anonymous tunnel.

Header name and scheme are configurable for non-Dev-Tunnel perimeters
(`tunnel_auth_header`, `tunnel_auth_scheme`) — e.g. an SSO proxy
expecting `Authorization: Bearer <token>` would set
`tunnel_auth_header = "Authorization"` and `tunnel_auth_scheme = "Bearer"`.

## Uninstall / clean reinstall

Each installer has a matching uninstall script; both default to
**preserving** state (cert + key on the agent; CA + credentials +
issued-certs + ACME cache on the hub) so re-installs reuse it.
Opt-in flags wipe state when you really want a fresh slate.

```sh
# Linux
sudo ./scripts/uninstall-agent.sh                        # keeps /etc/term-agent
sudo ./scripts/uninstall-agent.sh --purge-config         # also nukes cert+key+agent.toml

sudo ./scripts/uninstall-hub.sh                          # keeps /etc/term-hub + /var/lib/term-hub + user
sudo ./scripts/uninstall-hub.sh --purge-data             # DESTROYS the CA + passkeys + issued-certs
sudo ./scripts/uninstall-hub.sh --purge-config --purge-data --remove-user
```

```powershell
# Windows (elevated)
.\scripts\uninstall-agent.ps1                            # keeps %ProgramData%\term-agent
.\scripts\uninstall-agent.ps1 -PurgeConfig

.\scripts\uninstall-hub.ps1                              # keeps the data dir
.\scripts\uninstall-hub.ps1 -PurgeData                   # DESTROYS the CA + passkeys + issued-certs
```

For a true clean reinstall, the install scripts accept `--clean` /
`-Clean`, which invokes the matching uninstall script first (with
the same data-preservation defaults; pass `--purge-data` /
`-PurgeData` to also wipe state):

```sh
sudo ./scripts/install-agent.sh --hub … --cert alpha.crt --key alpha.key --clean
sudo ./scripts/install-hub.sh   --domain … --email …                    --clean
sudo ./scripts/install-hub.sh   --domain … --email …  --clean --purge-data  # full reset
```

## Security notes

- **Trust model.** The hub trusts agents that present a leaf cert
  signed by its agent CA AND whose SHA-256 fingerprint is in
  `<data_dir>/issued-certs.json` AND whose SAN URN matches the entry.
  All three checks run inside a custom `rustls::ClientCertVerifier`,
  so any mismatch tears down the TCP connection at the TLS-handshake
  layer. The agent trusts whoever serves a valid cert for the hub's
  domain. The WebAuthn flow protects the browser ↔ hub side.
- **CA key isolation.** `<data_dir>/agent-ca.key` is created by
  `hub-admin init-ca` running as root, mode 0600. The hub service
  user (`term-hub`) reads only `agent-ca.crt`, never the key — so
  a hub-process compromise cannot mint new agent certs.
- **Cert revocation.** `hub-admin revoke-cert --serial <hex>` (or
  `--id <machine_id>`) removes entries from `issued-certs.json`. The
  hub polls that file every 30s and the new policy applies to all
  subsequent TLS handshakes without a restart. Active connections
  using the now-revoked cert keep running until the agent
  reconnects — restart `term-hub.service` (or kill the agent) to
  force immediate cutoff.
- **No-auth listener.** When `[no_auth]` is configured, anyone who
  reaches the listener has full hub access. *Always* front it with a
  perimeter (Dev Tunnel access policy, SSO reverse proxy, private
  network). The hub itself does not authenticate callers on this
  socket. The `Origin:` check is still enforced. (The agent-side
  `/agent/connect` route on this listener is still authenticated by
  client cert via the `X-Agent-Cert` + `X-Agent-Auth` headers.)
- **rp_id scope.** `rp_id = xyz.com` shares credentials across sibling
  subdomains. Set `rp_id = term.xyz.com` for stricter scoping.
- **SecurityKey vs Passkey.** We use `SecurityKey` so login is touch
  only, no PIN. The trade-off: a stolen key is enough to log in.
- **HMAC secret.** `/var/lib/term-hub/secret.key` is 0600 and rotates
  manually — delete the file and the hub regenerates it on next start.
  Existing credentials keep working (the secret only protects
  registration envelopes).
- **WS-perimeter replay window.** ±5 minutes of clock skew, defeated
  by a `(fingerprint, nonce)` cache held for 10 minutes. Within that
  window, a captured `X-Agent-Auth` can't be replayed against the
  same hub (cached nonce) or against a different hub (signed payload
  binds the `Host:` header).

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
