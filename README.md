# tsproxy — A tsnet-based Tailscale SOCKS5 / HTTP Proxy Gateway

> **Why this exists.** `tsproxy` is a minimal, self-contained Tailscale client
> built for emulated/sandboxed Linux environments (Alpine-based containers,
> iSH-style userspace kernels, AI-agent sandboxes, CI runners, etc.) where the
> official `tailscaled` daemon often cannot run — full `tun` device access,
> `AF_NETLINK` sockets, or `CAP_NET_ADMIN` may be unavailable or restricted.
> Because it's built on the [tsnet](https://pkg.go.dev/tailscale.com/tsnet)
> library instead of the system daemon, it only needs plain outbound socket
> access to join a tailnet. This makes it a practical way to get an AI agent
> (or any other sandboxed process) authorized onto your Tailscale network in
> seconds, and reach your other tailnet devices through a local SOCKS5/HTTP
> proxy — no root, no kernel modules, no system-level `tailscaled` install.

Built on the [tsnet](https://pkg.go.dev/tailscale.com/tsnet) library, `tsproxy`
is a standalone Tailscale client that **does not require installing or
depending on the `tailscaled` system daemon**. It runs a userspace Tailscale
node directly inside its own process, and exposes that node's network
connectivity as local **SOCKS5** and **HTTP/HTTPS** forward proxies, so any
other program (browsers, `curl`, other CLI tools, etc.) can reach your tailnet
simply by pointing at the proxy.

It's especially well suited to sandboxed environments running minimal
distros like Alpine (userspace kernel emulators such as iSH, AI-agent
sandboxes, container CI runners) — environments that often lack full `tun`
device access, `AF_NETLINK` sockets, or `CAP_NET_ADMIN` capability, making
the official `tailscaled` daemon hard or impossible to run. `tsproxy` only
needs ordinary outbound socket access to join a tailnet, letting a process
running inside such a sandbox (e.g. an AI agent) get authorized in seconds.

## Features

- Single static binary, zero system dependencies (no root, no `tailscaled` install)
- Runs both a SOCKS5 and an HTTP/HTTPS proxy simultaneously, each with optional
  username/password or Basic Auth authentication
- **Friendly interactive auth flow**: on first run it prints a clickable
  hyperlink (OSC 8 — clickable in iTerm2, Windows Terminal, and most modern
  terminals), renders a terminal ASCII QR code, **and generates a PNG QR code
  image** (handy to send/display for phone scanning), and attempts to open
  your system's default browser automatically — everything happens in the
  terminal, no digging through logs for the auth URL
- Supports silent login via a pre-authorized Auth Key, ideal for
  servers/CI/container use cases
- Supports a self-hosted control plane such as Headscale (`-control-url`)
- **Supports exit nodes**: `-exit-node` routes all non-tailnet public traffic
  through a chosen tailnet device (the target must have already run
  `tailscale set --advertise-exit-node` and been approved by the tailnet admin)
- Supports accepting subnet routes and other advanced Tailscale features
- Node identity is persisted in a local state directory, so restarting the
  process doesn't require re-authorization

## Installation

### Download a prebuilt binary

See the release artifacts (`tsproxy-<os>-<arch>`); download and `chmod +x` to run.

### Build from source

```bash
git clone <this-repo>
cd tsnet-proxy
go build -o tsproxy ./cmd/tsproxy
```

Requires Go 1.23+ (the latest `tsnet` requires Go 1.26+; if your Go toolchain
is older, `go.mod` is pinned to `tailscale.com v1.102.4`, which is compatible
with Go 1.23).

## Quick Start

```bash
# Start the proxy (first run walks you through authorization)
./tsproxy up

# Customize listen addresses / node name
./tsproxy up -hostname my-laptop -socks5 127.0.0.1:1080 -http 127.0.0.1:8080

# Silent login with a pre-authorized key (no interaction needed)
TS_AUTHKEY=tskey-auth-xxxxx ./tsproxy up

# Add authentication to the proxies
./tsproxy up -socks5-user alice -socks5-pass s3cret -http-user alice -http-pass s3cret

# Check node status
./tsproxy status

# Log out (clears the local node identity)
./tsproxy logout
```

On startup you'll see output like:

```
🧦 SOCKS5 proxy ready: socks5://127.0.0.1:1055
🌐 HTTP/HTTPS proxy ready: http://127.0.0.1:1056
```

Other programs can then use it like this:

```bash
curl -x socks5h://127.0.0.1:1055 http://some-tailnet-host/
curl -x http://127.0.0.1:1056 https://some-tailnet-host/
export ALL_PROXY=socks5h://127.0.0.1:1055
export HTTP_PROXY=http://127.0.0.1:1056
export HTTPS_PROXY=http://127.0.0.1:1056
```

## Authorization Flow

On first run of `tsproxy up` (or if local state was cleared / the key
expired), the program will:

1. Request a one-time authorization URL from the Tailscale control plane
   (looks like `https://login.tailscale.com/a/xxxxxxxxxxxx`)
2. Print that URL in the terminal and render a QR code
3. Try to open the URL automatically in your system's default browser
4. Poll authorization status in the background; once you complete login in
   the browser/phone, the program detects it and continues starting the proxy

If your tailnet has device approval enabled, an admin may also need to
approve the device manually in the
[Tailscale admin console](https://login.tailscale.com/admin/machines) after
the auth link is used — the program will prompt you about this step.

## Security Notes

The `-state-dir` (default `~/.tsproxy/state`) holds this device's **node
identity key** in your tailnet. Anyone who obtains this file can impersonate
this device on your network — treat it like an SSH private key or a cloud
credential.

- The directory is created automatically by the `tsnet` library with `0700`
  permissions (directory) / `0600` (files), readable/writable only by the
  current user. This has been verified experimentally; no extra hardening
  is needed on top of it.
- **Never** commit the `-state-dir` directory to Git, bake it into a Docker
  image, or share it in any way.
- For a one-off trial or CI usage, pass `-ephemeral`: the node is
  automatically removed from your tailnet when the process exits, leaving
  no long-lived credential behind.

## Command-Line Flags (`tsproxy up -h`)

| flag | default | description |
|---|---|---|
| `-hostname` | local hostname | Node name shown in the tailnet |
| `-state-dir` | `~/.tsproxy/state` | Directory for persisting node identity/keys |
| `-authkey` | `$TS_AUTHKEY` | Pre-authorized key, skips interactive login |
| `-control-url` | `$TS_CONTROL_URL` | Self-hosted control plane (e.g. Headscale) address |
| `-ephemeral` | false | Ephemeral node; automatically removed from the tailnet on exit |
| `-socks5` | `127.0.0.1:1055` | SOCKS5 listen address; empty disables it |
| `-http` | `127.0.0.1:1056` | HTTP/HTTPS proxy listen address; empty disables it |
| `-socks5-user` / `-socks5-pass` | empty | SOCKS5 username/password authentication |
| `-http-user` / `-http-pass` | empty | HTTP proxy Basic Auth authentication |
| `-exit-node` | empty | Use the given exit node; all outbound traffic routes through it (requires the target to advertise it and be approved by the admin) |
| `-exit-node-allow-lan-access` | false | Still allow access to the local LAN while using an exit node |
| `-accept-routes` | true | Accept subnet routes advertised by other nodes |
| `-verbose` | false | Print verbose logs, including tsnet's internal logs |
| `-qr-file` | `state-dir/auth-qr.png` | Path to save the auth QR code image; pass `-` to disable |

## Project Layout

```
cmd/tsproxy/            CLI entry point (up/status/logout/version subcommands)
internal/config/        Command-line flag parsing and defaults
internal/tsclient/      tsnet.Server wrapper + interactive auth flow (link/QR/auto-open browser)
internal/proxy/         SOCKS5 and HTTP/HTTPS forward proxy implementation (stdlib only, dials out via tsnet.Dial)
```

## Cross-Compiling

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/tsproxy-linux-amd64   ./cmd/tsproxy
GOOS=linux   GOARCH=arm64 go build -o dist/tsproxy-linux-arm64   ./cmd/tsproxy
GOOS=darwin  GOARCH=amd64 go build -o dist/tsproxy-darwin-amd64  ./cmd/tsproxy
GOOS=darwin  GOARCH=arm64 go build -o dist/tsproxy-darwin-arm64  ./cmd/tsproxy
GOOS=windows GOARCH=amd64 go build -o dist/tsproxy-windows-amd64.exe ./cmd/tsproxy
```

## License

MIT — see [LICENSE](LICENSE). `tsproxy` itself only uses MIT-licensed
dependencies ([qrterminal](https://github.com/mdp/qrterminal),
[go-qrcode](https://github.com/skip2/go-qrcode)); the upstream
[tailscale.com](https://github.com/tailscale/tailscale) module it embeds via
`tsnet` is licensed under BSD-3-Clause.
