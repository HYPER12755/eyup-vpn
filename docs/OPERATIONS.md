# Operations

## Routine tasks

```bash
baba                # create / list / delete SSH accounts, set the client host+header
singbox             # sing-box node (protocol+SNI) and user management
vpnctl doctor       # service/port/config/REALITY checks
vpnctl status       # summary
```

## Backup and restore

```bash
vpnctl backup                 # /root/vpnstack-backup/vpnstack-<date>.tar.gz
vpnctl restore <file>         # asks for confirmation
vpnctl restore <file> --yes   # no confirmation
```

Backup contents: `sing-box/config.json`, `sing-box/phone_client.json`, `sshvpn/menu.conf`, the SSH user list, and version metadata. On restore, the config is not put in place unless `sing-box check` passes.

## Adding a REALITY node (summary)

1. Pick the protocol from the `singbox` menu (VLESS + REALITY) and give it a **free localhost port in the 1443-1499 range**. The menu suggests a free port in that range, validates the one you pick, and makes the node listen on `127.0.0.1` (not exposed externally).
2. Enter the target domain as the SNI (e.g. `m.youtube.com`).
3. Get the link with `vpnctl links <tag>`; the client connects directly to **IP:443** (a Cloudflare-proxied domain cannot carry REALITY). The menu generates the link this way as well.

To route a new SNI to 443, add this line to the `reality_frontend` section of `/etc/haproxy/haproxy.cfg`: `use_backend re_<name>_backend if { req.ssl_sni -i <sni> }`, define the matching backend with `127.0.0.1:<port>`, then run `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy`.

## Xray (legacy profile)

- `/etc/xray/config.json` is marker-based: `#& <user> <expiry>` lines mark user entries, and `#vless` / `#vmess` / `#trojanws` / `#vlessgrpc` / ... are the insertion markers the manager writes to.
- Manage users with the Turkish menu: `xraymenu` (also `baba` → `[6] Xray Yönetimi`). It adds/removes users on the marker lines, validates every change with `xray run -test` (reverting on failure), rebuilds links and restarts the service. The vendored upstream panel `va` (mack-a/v2ray-agent, Chinese UI) is reachable from the same menu for advanced work; it manages its own Xray/nginx/TLS layout and running it can change haproxy, sing-box and sshproxy behaviour, so take a backup first (`vpnctl backup`).
- Domain and certificate live in `/etc/xray/domain` and `/etc/xray/xray.crt` + `xray.key`. `install.sh` searches for an existing pair first (`/etc/xray`, `hap.pem`, Let's Encrypt, `~/.acme.sh`, v2ray-agent TLS), reads the domain from `/etc/xray/domain` or the certificate CN, and only then prompts or generates a self-signed pair. `VPNSTACK_DOMAIN`, `VPNSTACK_CERT_PATH`, `VPNSTACK_KEY_PATH` override the search. In the legacy profile the same pair is rebuilt into `/etc/haproxy/hap.pem`.
- Before replacing anything from an older layout, the installer backs up the legacy SSH bridge to `/etc/sshvpn/legacy/ws.py` and old `ws`/`ws-ovpn` units to `*.vpnstack-backup`, so the previous working system stays recoverable.

## Domains, DuckDNS and Cloudflare

- **SSH without a domain works.** Raw SSH goes to `IP:80` (or 8080/8880/2052/2082/2086/2095) and haproxy hands it to dropbear; WebSocket payloads only put the domain in the `Host` header, which is plain text and needs no DNS. A domain is required for the TLS modes (443/TLS payloads, Cloudflare proxying, certificate validation) — or the client must accept a self-signed certificate.
- **DuckDNS is fine.** Point a free `name.duckdns.org` A record at the server, then issue a Let's Encrypt certificate with acme.sh's DNS-01 module (`dns_duckdns`, `DuckDNS_Token`), which does not need port 80. Set the domain in `baba` → `[8] İstemci Ayarları` so payloads use it as the host.
- **Cloudflare (proxied/orange cloud) can carry the WebSocket paths**, not raw SSH or REALITY:
  - HTTP ports: 80, 8080, 8880, 2052, 2082, 2086, 2095
  - HTTPS ports: 443, 2053, 2083, 2087, 2096, 8443
  - For SSH over Cloudflare use the WebSocket/TLS payload (path `/` → Xray fallback → dropbear, or the SSH-WS bridge); raw SSH and REALITY need a DNS-only (grey cloud) record.
  - The haproxy profiles publish every port in that list, so any Cloudflare-compatible port reaches the same backends.

## haproxy configuration

`/etc/haproxy/haproxy.cfg` comes from the `deploy/haproxy.cfg` version in the repo. `install.sh` only replaces the existing file if it is **absent** or is the distribution's stock template, so REALITY/SNI lines you added by hand are preserved (if the stock template is replaced, a `.vpnstack-backup` copy is taken first). When an existing custom configuration is kept, `install.sh` still verifies that it routes WebSocket to `127.0.0.1:10015` and raw SSH to `127.0.0.1:143`, and names whatever is missing instead of leaving a silent gap.

Servers that already run a multi-protocol layout (TLS terminated by haproxy on 443, extra ports, xray/OpenVPN backends) can install that layout instead of the REALITY passthrough:

```bash
sudo VPNSTACK_HAPROXY_PROFILE=legacy bash install.sh
```

The legacy profile comes from `deploy/haproxy.legacy.cfg`; an existing config is backed up to `.vpnstack-backup` first. It needs `/etc/haproxy/hap.pem` for 443 and cannot coexist with the REALITY frontend, since both bind 443.

The hybrid profile (`VPNSTACK_HAPROXY_PROFILE=hybrid`, `deploy/haproxy.hybrid.cfg`) solves that conflict: 443 does **not** terminate TLS, it routes by SNI — REALITY node SNIs go to sing-box, the domain goes to Xray's `tls-fallback` inbound on 10443 (WS paths, gRPC by ALPN, default → dropbear for SSH-over-TLS), and 8443/2096/2087 still terminate TLS like the legacy layout. REALITY routes are generated from the sing-box config at install time; a REALITY client link just changes its port to 443 (the SNI stays the camouflage domain). Re-run the installer to regenerate the routes after adding nodes.

To derive a new config after updating the source file:

```bash
sudo cp deploy/haproxy.cfg /etc/haproxy/haproxy.cfg   # you will lose lines you added by hand
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## Direct SSH ports

`install.sh` guarantees dropbear on `127.0.0.1:109` (the sshproxy target) and `127.0.0.1:143` (haproxy's raw SSH backend) in one of two ways:

- If a dropbear already listens on both ports, it is adopted as-is: the installer does not replace, disable or restart it. A dropbear bound to `0.0.0.0` stays bound to `0.0.0.0`; the installer warns, since `127.0.0.1` is the intended scope.
- Otherwise the `dropbear` package is installed (apt is retried) and run as the `dropbear-vpnstack` unit on those two loopback ports. If it cannot be installed, the install **fails** instead of leaving raw SSH silently dead; `VPNSTACK_SKIP_DROPBEAR=1` overrides that deliberately.

The WebSocket path (10015/80) needs dropbear only when the payload's target is the default `127.0.0.1:109`; raw SSH on port 80 always does.

SSH tunnel accounts live in the `sshvpn` group by default. On servers where an older script created them under another group, run the menus with `SSH_ACCOUNT_GROUP=<group> baba` (or export it) so listing, creation and deletion target the existing accounts — both the group member list and users whose primary group is that group are recognised.

## Troubleshooting

```bash
vpnctl doctor
journalctl -u ws -n 50 --no-pager
journalctl -u sing-box -n 50 --no-pager
journalctl -u xray -n 50 --no-pager
haproxy -c -f /etc/haproxy/haproxy.cfg
```

- **Port conflict (`bind: address already in use`):** look at the "port çakışması" line in `vpnctl doctor`; the same `listen:port` cannot be used by two inbounds.
- **REALITY "invalid connection":** the `pbk`/`sid`/SNI in the client link does not match the server config. `sblink`/`vpnctl links` produce the current `pbk`; re-import the link.
- **SSH connection dropping:** check `journalctl -u ws` and `pgrep -af sshproxy`; re-fetch the client payload (including Sec-WebSocket-Key) from the `baba` menu.
- **Client connects but no data flows:** a WebSocket client must send its first frame within 2 s of the handshake, otherwise `sshproxy` falls back to raw relay. See [PROTOCOL.md](PROTOCOL.md#framing-selection).
- **`400 BadTarget`:** the `X-Real-Host` port was empty or out of range. `403 Forbidden` means the target was not loopback and no password is compiled in.
- **Raw SSH on port 80 fails but the WebSocket path works:** haproxy sends raw SSH to `127.0.0.1:143` and `sshproxy` defaults to `127.0.0.1:109`. Both must be listening — `vpnctl doctor` checks `dropbear :109` and `dropbear :143` explicitly. If they are down, re-run `install.sh` (it adopts an already-running dropbear, otherwise installs one) and verify with `ss -ltn | grep -E '109|143'`.
- **`systemctl restart dropbear-vpnstack` fails:** run it in the foreground to see the error — `/usr/sbin/dropbear -F -R -p 127.0.0.1:109 -p 127.0.0.1:143`. If it exits immediately, a host key could not be created in `/etc/dropbear/`. When an existing dropbear was adopted, this unit does not exist — check the running one instead (`pgrep -af dropbear`).
