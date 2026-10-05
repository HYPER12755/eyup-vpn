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

## haproxy configuration

`/etc/haproxy/haproxy.cfg` comes from the `deploy/haproxy.cfg` version in the repo. `install.sh` only replaces the existing file if it is **absent** or is the distribution's stock template, so REALITY/SNI lines you added by hand are preserved (if the stock template is replaced, a `.vpnstack-backup` copy is taken first).

To derive a new config after updating the source file:

```bash
sudo cp deploy/haproxy.cfg /etc/haproxy/haproxy.cfg   # you will lose lines you added by hand
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## Direct SSH ports

If `127.0.0.1:109` (the sshproxy target) and `127.0.0.1:143` (haproxy's `dropbear_backend`) are not listening, `install.sh` warns you. The WebSocket path (10015/80) does not need them; configure dropbear on these ports only if you intend to use raw SSH.

## Troubleshooting

```bash
vpnctl doctor
journalctl -u ws -n 50 --no-pager
journalctl -u sing-box -n 50 --no-pager
haproxy -c -f /etc/haproxy/haproxy.cfg
```

- **Port conflict (`bind: address already in use`):** look at the "port çakışması" line in `vpnctl doctor`; the same `listen:port` cannot be used by two inbounds.
- **REALITY "invalid connection":** the `pbk`/`sid`/SNI in the client link does not match the server config. `sblink`/`vpnctl links` produce the current `pbk`; re-import the link.
- **SSH connection dropping:** check `journalctl -u ws` and `pgrep -af sshproxy`; re-fetch the client payload (including Sec-WebSocket-Key) from the `baba` menu.
- **Client connects but no data flows:** a WebSocket client must send its first frame within 2 s of the handshake, otherwise `sshproxy` falls back to raw relay. See [PROTOCOL.md](PROTOCOL.md#framing-selection).
- **`400 BadTarget`:** the `X-Real-Host` port was empty or out of range. `403 Forbidden` means the target was not loopback and no password is compiled in.
- **Raw SSH on port 80 fails but the WebSocket path works:** haproxy sends raw SSH to `127.0.0.1:143` and `sshproxy` defaults to `127.0.0.1:109`. Both must be listening; `install.sh` runs dropbear on both via the `dropbear-vpnstack` unit. Check with `ss -ltn | grep -E '109|143'`.
- **`systemctl restart dropbear-vpnstack` fails:** run it in the foreground to see the error — `/usr/sbin/dropbear -F -R -p 127.0.0.1:109 -p 127.0.0.1:143`. If it exits immediately, a host key could not be created in `/etc/dropbear/`.
