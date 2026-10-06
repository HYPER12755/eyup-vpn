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
  - `reality_frontend` (443): TCP passthrough to the REALITY nodes based on the TLS ClientHello SNI. Unknown SNI → the whatsapp node (camouflage is preserved). With `VPNSTACK_HAPROXY_PROFILE=legacy`, `deploy/haproxy.legacy.cfg` replaces this with the pre-existing multi-protocol layout: TLS is terminated by haproxy on 443 (needs `/etc/haproxy/hap.pem`) and additional ports are published. With `VPNSTACK_HAPROXY_PROFILE=hybrid`, 443 stops terminating TLS and becomes pure SNI routing: REALITY node SNIs pass through to sing-box, the real domain passes through to Xray's `tls-fallback` inbound (10443), which routes WebSocket paths, gRPC by ALPN and defaults to dropbear for SSH-over-TLS; 8443/2096/2087 keep the terminated layout.
- **SSH backend:** dropbear listens on `127.0.0.1:109` and `127.0.0.1:143`. `install.sh` adopts a dropbear that already holds both ports and otherwise installs one under the `dropbear-vpnstack` unit. haproxy sends raw SSH to 143; `sshproxy` defaults to 109. `openssh-server` stays on `:22` as a rescue path — **keep an active session open while changing SSH config**.
- **sing-box:** `/usr/local/etc/sing-box/config.json`; nodes listen on `127.0.0.1` only. Each REALITY node's `handshake.server` field is its own SNI. The `sing-box` binary is expected at `/usr/local/bin/sing-box` (if it lives elsewhere, `/usr/bin/sing-box` is symlinked).
- **xray:** the multi-protocol core of the legacy profile. Config `/etc/xray/config.json` is marker-based (users sit between `#& user` lines, each protocol has an insertion marker), binary `/usr/local/bin/xray`, unit `xray.service`. Inbounds bind `127.0.0.1` only: `10000` (stats API), `10001-10003` (VLESS/VMess/Trojan WebSocket), `10005-10007` (gRPC); the legacy haproxy frontend publishes them. `install.sh` adopts a running Xray and only installs a pinned release when none exists. Management is via the vendored `va` panel, which the installer places on disk but never runs. Domain/TLS live in `/etc/xray/domain` and `/etc/xray/xray.crt|key`; the legacy haproxy profile consumes the same pair as `/etc/haproxy/hap.pem`.
- **Linux accounts:** in the `sshvpn` group, shell `/bin/false`, expiry set with `chage`. The `baba` menu generates random usernames/passwords.

The client side of this path — request headers, the loopback-only target rule,
and how framing is chosen — is in [PROTOCOL.md](PROTOCOL.md).

## Services

| Unit | ExecStart | Hardening |
|---|---|---|
| `ws.service` | `sshproxy 10015` | Empty CapabilityBoundingSet, ProtectSystem=strict, PrivateTmp/Devices, RestrictAddressFamilies |
| `ws-ovpn.service` | `sshproxy 10012` | same |
| `dropbear-vpnstack.service` | `dropbear -F -R -p 127.0.0.1:109 -p 127.0.0.1:143` | — (skipped when an existing dropbear is adopted) |
| `sing-box.service` | managed by the sing-box manager | — |
| `xray.service` | `/usr/local/bin/xray run -config /etc/xray/config.json` | — (adopted when already running) |
| `haproxy.service` | 80/443 frontend | — |
| `fail2ban.service` | sshd (+dropbear) jails | — |

## Data and backups

- sing-box config: `/usr/local/etc/sing-box/config.json`
- Xray: `/etc/xray/config.json`, `/etc/xray/domain`, `/etc/xray/xray.crt|key`
- Client settings: `/etc/sshvpn/menu.conf` (`FAKE_HOST`, `EXTRA_HEADER`)
- Backup: `vpnctl backup` → `/root/vpnstack-backup/vpnstack-*.tar.gz` (config + menu.conf + SSH user list + meta)
