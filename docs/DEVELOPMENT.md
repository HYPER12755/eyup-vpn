# Development and testing

## Build

```bash
go build ./...                    # everything
go build -o /usr/local/bin/sshproxy ./cmd/sshproxy
```

Requires Go 1.27. Dependencies are limited to `github.com/google/uuid` and
`golang.org/x/crypto`.

## Checks

```bash
gofmt -l ./cmd ./internal     # must print nothing
go vet ./...
go test ./...
go test -race ./...
```

`-race` is worth running on `cmd/sshproxy`: it relays every connection from two
goroutines and shares a `bufio.Reader` between them.

## Test layout

50 tests, no mocks — `handleConn` is exercised over real loopback sockets
against a local listener.

| Package | Tests | Covers |
|---|---|---|
| `cmd/sshproxy` | 19 | header parsing, target validation, loopback guard, framing detection, pipelined and split requests, frame length encodings, close-frame echo, connection limiter |
| `cmd/vpnlimit` | 3 | usage/quota file helpers |
| `internal/singbox` | 10 | public-key derivation, link building (vless/vmess/trojan/tuic/hysteria2), add/remove user |
| `internal/appconfig` | 6 | env var fallback, public host resolution, menu.conf precedence (path injectable) |
| `internal/accounts` | 3 | username validation, random credentials, client payloads |
| `internal/limit` | 9 | marker parsing, removal, stats value parsing, quota/expiry decisions |

Note: `internal/singbox`'s tests stub `Validate`, so they do not exercise the
real `sing-box check` path. That needs the binary present at
`/usr/local/bin/sing-box`.

### Security regression tests

Four tests in `cmd/sshproxy/main_test.go` pin the guard conditions. They fail
against the pre-fix code and are the reason to keep them:

| Test | Pins |
|---|---|
| `TestFindHeaderIsCaseInsensitive` | `x-real-host` must not be ignored |
| `TestFindHeaderIgnoresInjectionInValue` | a target inside a `Referer` value must not be used |
| `TestIsLocalHost` | `localhost.attacker.example`, `127.0.0.1.evil` rejected; `[::1]` accepted |
| `TestTargetAddress` | `host:` / `0` / `> 65535` rejected; `[::1]:109` accepted |
| `TestOnlyFirstRequestIsParsed` | a `Sec-WebSocket-Key` in a *second* request must not enable framing |

To confirm a test still bites, revert the function it covers and watch it fail:

```bash
go test ./cmd/sshproxy/ -run TestFindHeaderIgnoresInjectionInValue
```

## Manual smoke test

`docs/PROTOCOL.md` describes a manual check against a real `sshd`. For a
full end-to-end run — real key exchange, publickey auth, and command execution
through WebSocket framing — you need a ProxyCommand that wraps the stream in
RFC 6455 frames; `nc` cannot, because the client must speak framed protocol
after the `101`.

## Where things live

```
cmd/sshproxy/main.go     connection handling, header parsing, target guard
cmd/sshproxy/ws.go       RFC 6455 framing, ping/pong, close
cmd/vpnctl/ops.go        status/doctor/links/users, backup, restore
internal/singbox/        config load/save, REALITY keys, link building
internal/accounts/       SSH user creation and client payloads
internal/limit/          legacy limit.* port: quota/expiry parsing and decisions
internal/appconfig/      paths and env var resolution
cmd/vpnlimit/main.go     quota/expiry enforcer daemon (stats API, Telegram, removal)
scripts/vpnmenu.sh        baba terminal menu (SSH accounts, services)
scripts/xraymenu.sh       Turkish Xray menu (delegates edits to xraycfg)
scripts/xraycfg.py        marker-based Xray config editor + link builder
scripts/v2ray-agent/     vendored Xray panel (UPSTREAM.md pins commit + sha256)
```

## Conventions

- **CLI output is Turkish**, docs are English. This is a known, deliberate
  mismatch: `vpnctl` and the menus print Turkish strings while the docs
  describe them in English. `docs/OPERATIONS.md` keeps the literal
  `port çakışması` because that is the exact text `vpnctl doctor` emits.
- Comments explain *why*, not *what*, and only where the reasoning is not
  obvious from the code.