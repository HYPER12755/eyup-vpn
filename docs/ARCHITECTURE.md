# Architecture

```
Client ──(80, HTTP+WS)──► haproxy http_frontend ──► sshproxy :10015 ──► dropbear :109 / sshd :22
                             │ (no Upgrade)           (raw or WS framed)
                             └──────────────────────► dropbear :143

Client ──(443, TLS ClientHello)──► haproxy reality_frontend (SNI passthrough)
                                       ├─ whatsapp.net   → sing-box :1443
                                       ├─ speedtest.net  → sing-box :1444
                                       ├─ chatgpt.com    → sing-box :1445
                                       ├─ m.youtube.com  → sing-box :1446
                                       └─ i.instagram.com→ sing-box :1447
```

## Components

- **sshproxy (Go):** the equivalent of `ws.py`. On the first packet it reads the `X-Real-Host`, `X-Split` and `X-Pass` headers and replies `101`. If `Sec-WebSocket-Key` is present it uses a real WebSocket frame (Cloudflare compatible), otherwise it relays raw TCP. Two instances: `ws.service` (10015) and `ws-ovpn.service` (10012).
- **haproxy:** the configuration is installed from the `deploy/haproxy.cfg` source to `/etc/haproxy/haproxy.cfg`.
  - `http_frontend` (80/8080): **pure TCP**. The first bytes are inspected with `tcp-request content accept if HTTP`; requests starting with `GET`/`CONNECT` go to `ws_backend` (10015), the rest (raw `SSH-2.0-...`) to `dropbear_backend` (143). Since headers are not parsed, `X-Real-Host`/`X-Split` pass through untouched.
  - `reality_frontend` (443): TCP passthrough to the REALITY nodes based on the TLS ClientHello SNI. Unknown SNI → the whatsapp node (camouflage is preserved).
- **SSH backend:** dropbear listens on `127.0.0.1:109` and `127.0.0.1:143` under the `dropbear-vpnstack` unit (installed by `install.sh`). haproxy sends raw SSH to 143; `sshproxy` defaults to 109. `openssh-server` stays on `:22` as a rescue path — **keep an active session open while changing SSH config**.
- **sing-box:** `/usr/local/etc/sing-box/config.json`; nodes listen on `127.0.0.1` only. Each REALITY node's `handshake.server` field is its own SNI. The `sing-box` binary is expected at `/usr/local/bin/sing-box` (if it lives elsewhere, `/usr/bin/sing-box` is symlinked).
- **Linux accounts:** in the `sshvpn` group, shell `/bin/false`, expiry set with `chage`. The `baba` menu generates random usernames/passwords.

The client side of this path — request headers, the loopback-only target rule,
and how framing is chosen — is in [PROTOCOL.md](PROTOCOL.md).

## Services

| Unit | ExecStart | Hardening |
|---|---|---|
| `ws.service` | `sshproxy 10015` | Empty CapabilityBoundingSet, ProtectSystem=strict, PrivateTmp/Devices, RestrictAddressFamilies |
| `ws-ovpn.service` | `sshproxy 10012` | same |
| `sing-box.service` | managed by the sing-box manager | — |
| `haproxy.service` | 80/443 frontend | — |
| `fail2ban.service` | sshd (+dropbear) jails | — |

## Data and backups

- sing-box config: `/usr/local/etc/sing-box/config.json`
- Client settings: `/etc/sshvpn/menu.conf` (`FAKE_HOST`, `EXTRA_HEADER`)
- Backup: `vpnctl backup` → `/root/vpnstack-backup/vpnstack-*.tar.gz` (config + menu.conf + SSH user list + meta)
