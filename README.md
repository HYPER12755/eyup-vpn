# VpnStack

A lightweight VPN management stack written in Go, consisting of an SSH WebSocket/payload bridge, sing-box (VLESS/REALITY) management, and a terminal menu.

## Components

| Component | Task | Location |
|---|---|---|
| `sshproxy` | Go port of the legacy `ws.py`: SSH bridge supporting X-Real-Host / X-Split / X-Pass + real WebSocket (Cloudflare compatible) | `/usr/local/bin/sshproxy` |
| `baba` (`vpnmenu`) | Terminal menu: automatic SSH account setup, list/delete, client settings | `/usr/local/bin/baba` |
| `singbox` | Community sing-box manager (add node/user) | `/usr/local/bin/singbox` |
| `sblink` | Derives the REALITY public key (`tag=pbk`) | `/usr/local/bin/sblink` |
| `vpnctl` | Health check, status, links, backup/restore | `/usr/local/bin/vpnctl` |
| `xray` | Multi-protocol core (VLESS/VMess/Trojan WS+gRPC) used by the legacy profile | `/usr/local/bin/xray` |
| `xraymenu` | Turkish Xray menu: add/list/delete users, links, config test | `/usr/local/bin/xraymenu` |
| `va` | Vendored upstream panel ([mack-a/v2ray-agent](scripts/v2ray-agent/UPSTREAM.md), Chinese UI) | `/usr/local/bin/va` |
| `haproxy` | 80: WS/SSH frontend · 443: SNI passthrough (REALITY) | system |
| `dropbear`/`sshd` | SSH authentication | system |

## Installation

```bash
sudo bash install.sh
```

Requirements: Ubuntu 22.04/24.04, root. The script installs dependencies, sets up sing-box + Go, deploys the haproxy configuration (`deploy/haproxy.cfg` → `/etc/haproxy/haproxy.cfg`), and installs the services (ws, ws-ovpn, haproxy, sing-box, dropbear-vpnstack, fail2ban).

The SSH backend is handled without assuming a clean server: if a dropbear already listens on `127.0.0.1:109` and `:143`, it is adopted untouched; otherwise the `dropbear` package is installed (apt is retried) and run as `dropbear-vpnstack`. If dropbear cannot be installed, the install fails instead of leaving raw SSH on port 80 silently broken (`VPNSTACK_SKIP_DROPBEAR=1` overrides deliberately).

On a server that already runs a legacy multi-protocol layout (TLS terminated by haproxy on 443, extra ports), install that profile instead of the REALITY passthrough:

```bash
sudo VPNSTACK_HAPROXY_PROFILE=legacy bash install.sh
```

The installer resolves the domain and TLS certificate automatically when they
already exist on the server: `/etc/xray/xray.crt|key`, `/etc/haproxy/hap.pem`
(split into cert+key), `/etc/letsencrypt/live/*`, `~/.acme.sh/*` and
`/etc/v2ray-agent/tls/*` are searched in that order, and the domain comes from
`/etc/xray/domain` or the certificate CN. `VPNSTACK_DOMAIN`,
`VPNSTACK_CERT_PATH` and `VPNSTACK_KEY_PATH` override the search; if nothing is
found the installer prompts (interactive runs) and finally generates a
self-signed pair. The pair lands in `/etc/xray/xray.crt|key` and, in the legacy
profile, is bundled into `/etc/haproxy/hap.pem`. Legacy SSH bridge files
(`ws.py`) and old `ws` units are backed up to `/etc/sshvpn/legacy/` and
`*.vpnstack-backup` before being replaced. Xray is adopted when already present
and otherwise installed from a pinned release; the vendored panel is only
placed on disk (`va`), never run by the installer.

Downloads are checksum-verified: sing-box and Go come from pinned releases with
pinned hashes, and a mismatch aborts the install. To pin a different sing-box
version, supply its hash:

```bash
SINGBOX_VERSION=1.15.0 SINGBOX_SHA256=<sha256> sudo -E bash install.sh
```

If the repo already contains `scripts/singbox-manager.sh`, install.sh uses
that copy and skips the third-party download. Otherwise it fetches
`Install.sh` from upstream and requires `SINGBOX_MANAGER_SHA256` — set it, or
vendor the script, rather than letting an unverified script run as root.

## Usage

```bash
baba                  # terminal menu (SSH accounts + client settings)
xraymenu              # Turkish Xray menu (users, links, config test); baba → [6]
va                    # advanced upstream panel (v2ray-agent, Chinese; optional)
singbox               # sing-box node/user management
vpnctl status         # overall status
vpnctl doctor         # health check (exit code 1 if anything is wrong)
vpnctl links          # all inbound user links
vpnctl users          # SSH + sing-box users
vpnctl backup         # backup to /root/vpnstack-backup
vpnctl restore <file> # restore from a backup (--yes to skip confirmation)
```

## Ports

| Port | What |
|---|---|
| 80 | haproxy → routes `GET`/`CONNECT` requests to 10015 (WS), other SSH traffic to dropbear (143) |
| 443 | haproxy SNI passthrough → REALITY nodes (localhost 1443-1447) |
| 10015 | `sshproxy` (SSH bridge, localhost) |
| 10012 | `sshproxy` (OpenVPN-over-WS, localhost) |
| 10000-10007 | `xray`: stats API + VLESS/VMess/Trojan WS and gRPC inbounds (localhost, legacy profile) |

With `VPNSTACK_HAPROXY_PROFILE=legacy` the haproxy frontend additionally publishes 8080/8880/2082 (HTTP) and 8443/2096/2087 (TLS).

## Security model

`sshproxy` is reachable through the public port 80, so it enforces a
**loopback-only target rule**: unless the binary is built with a shared
password, `X-Real-Host` must resolve to loopback (`127.0.0.0/8`, `::1`,
`localhost`), otherwise the connection is refused with `403`. Without this it
would be an open relay reachable by anyone.

Loopback is decided by parsing the address, not by string prefix, so
`localhost.attacker.example` and `127.0.0.1.evil` are rejected. Header names
are matched against a line's own name field only, so a target smuggled inside
another header's value (`Referer: .../X-Real-Host: evil`) is ignored.

`sshproxy` and the REALITY inbounds bind `127.0.0.1` only — the public side is
haproxy. SSH accounts live in the `sshvpn` group with shell `/bin/false`, so
they can be used for tunneling but not for a login shell.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full target-validation table.

## Client

- SSH Host: `http://<host>` · Port: `80` · payload: copy it from the `baba` menu
- REALITY: import the link from `vpnctl links <tag>` output (SNI depends on the node; the connection is made directly to IP:443)

For more details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/OPERATIONS.md](docs/OPERATIONS.md), [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
