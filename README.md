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
| `haproxy` | 80: WS/SSH frontend · 443: SNI passthrough (REALITY) | system |
| `dropbear`/`sshd` | SSH authentication | system |

## Installation

```bash
sudo bash install.sh
```

Requirements: Ubuntu 22.04/24.04, root. The script installs dependencies, sets up sing-box + Go, deploys the haproxy configuration (`deploy/haproxy.cfg` → `/etc/haproxy/haproxy.cfg`), and installs the services (ws, ws-ovpn, haproxy, sing-box, dropbear-vpnstack, fail2ban).

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
