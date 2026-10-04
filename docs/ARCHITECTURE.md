# Mimari

```
İstemci ──(80, HTTP+WS)──► haproxy http_frontend ──► sshproxy :10015 ──► dropbear :109 / sshd :22
                              │ (Upgrade yoksa)         (ham veya WS çerçeveli)
                              └──────────────────────► dropbear :143

İstemci ──(443, TLS ClientHello)──► haproxy reality_frontend (SNI passthrough)
                                        ├─ whatsapp.net   → sing-box :1443
                                        ├─ speedtest.net  → sing-box :1444
                                        ├─ chatgpt.com    → sing-box :1445
                                        ├─ m.youtube.com  → sing-box :1446
                                        └─ i.instagram.com→ sing-box :1447
```

## Bileşenler

- **sshproxy (Go):** `ws.py` muadili. İlk pakette `X-Real-Host`, `X-Split`, `X-Pass` başlıklarını okur; `101` yanıtı verir. `Sec-WebSocket-Key` varsa gerçek WebSocket çerçevesi (Cloudflare uyumlu), yoksa ham TCP aktarır. İki kopya: `ws.service` (10015) ve `ws-ovpn.service` (10012).
- **haproxy:**
  - `http_frontend` (80/8080/...): `Upgrade: websocket` içeren istekler `ws_backend` (10015); varsayılan `dropbear_backend` (143).
  - `reality_frontend` (443): TLS ClientHello SNI'sına göre REALITY düğümlerine TCP passthrough. Bilinmeyen SNI → whatsapp düğümü (maskeleme korunur).
- **sing-box:** `/usr/local/etc/sing-box/config.json`; düğümler yalnızca `127.0.0.1` üzerinde dinler. Her REALITY düğümünün `handshake.server` alanı kendi SNI'sidir.
- **Linux hesapları:** `sshvpn` grubunda, kabuk `/bin/false`, süre `chage` ile. `baba` menüsü rastgele kullanıcı adı/şifre üretir.

## Servisler

| Unit | ExecStart | Sertleştirme |
|---|---|---|
| `ws.service` | `sshproxy 10015` | CapabilityBoundingSet boş, ProtectSystem=strict, PrivateTmp/Devices, RestrictAddressFamilies |
| `ws-ovpn.service` | `sshproxy 10012` | aynı |
| `sing-box.service` | sing-box yöneticisi tarafından yönetilir | — |
| `haproxy.service` | 80/443 ön uç | — |
| `fail2ban.service` | sshd (+dropbear) jails | — |

## Veri ve yedekler

- sing-box config: `/usr/local/etc/sing-box/config.json`
- İstemci ayarları: `/etc/sshvpn/menu.conf` (`FAKE_HOST`, `EXTRA_HEADER`)
- Yedek: `vpnctl backup` → `/root/vpnstack-backup/vpnstack-*.tar.gz` (config + menu.conf + SSH kullanıcı listesi + meta)
