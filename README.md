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

Requirements: Ubuntu 22.04/24.04, root. The script installs dependencies, sets up sing-box + Go, deploys the haproxy configuration (`deploy/haproxy.cfg` → `/etc/haproxy/haproxy.cfg`), and installs the services (ws, ws-ovpn, haproxy, sing-box, fail2ban).

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

## Client

- SSH Host: `http://<host>` · Port: `80` · payload: copy it from the `baba` menu
- REALITY: import the link from `vpnctl links <tag>` output (SNI depends on the node; the connection is made directly to IP:443)

For more details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/OPERATIONS.md](docs/OPERATIONS.md).
