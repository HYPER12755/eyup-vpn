# VpnStack

Go ile yazılmış SSH WebSocket/Payload köprüsü, sing-box (VLESS/REALITY) yönetimi ve terminal menüsünden oluşan hafif VPN yönetim yığını.

## Bileşenler

| Bileşen | Görev | Konum |
|---|---|---|
| `sshproxy` | Eski `ws.py`'nin Go portu: X-Real-Host / X-Split / X-Pass destekli SSH köprüsü + gerçek WebSocket (Cloudflare uyumlu) | `/usr/local/bin/sshproxy` |
| `baba` (`vpnmenu`) | Terminal menüsü: otomatik SSH hesabı, liste/silme, istemci ayarları | `/usr/local/bin/baba` |
| `singbox` | Topluluk sing-box yöneticisi (düğüm/kullanıcı ekleme) | `/usr/local/bin/singbox` |
| `sblink` | REALITY public key türetir (`tag=pbk`) | `/usr/local/bin/sblink` |
| `vpnctl` | Sağlık kontrolü, durum, link, yedek/geri yükleme | `/usr/local/bin/vpnctl` |
| `haproxy` | 80: WS/SSH ön uç · 443: SNI passthrough (REALITY) | sistem |
| `dropbear`/`sshd` | SSH kimlik doğrulaması | sistem |

## Kurulum

```bash
sudo bash install.sh
```

Gereksinim: Ubuntu 22.04/24.04, root. Script bağımlılıkları kurar, sing-box + Go kurar, haproxy yapılandırmasını (`deploy/haproxy.cfg` → `/etc/haproxy/haproxy.cfg`) ve servisleri (ws, ws-ovpn, haproxy, sing-box, fail2ban) yerleştirir.

## Kullanım

```bash
baba                  # terminal menüsü (SSH hesapları + istemci ayarları)
singbox               # sing-box düğüm/kullanıcı yönetimi
vpnctl status         # genel durum
vpnctl doctor         # sağlık kontrolü (sorun varsa çıkış kodu 1)
vpnctl links          # tüm inbound kullanıcı linkleri
vpnctl users          # SSH + sing-box kullanıcıları
vpnctl backup         # /root/vpnstack-backup altına yedek
vpnctl restore <file> # yedekten geri yükle (--yes ile onaysız)
```

## Portlar

| Port | Ne |
|---|---|
| 80 | haproxy → `GET`/`CONNECT` istekleri 10015'e (WS), diğer SSH trafiği dropbear'a (143) |
| 443 | haproxy SNI passthrough → REALITY düğümleri (localhost 1443-1447) |
| 10015 | `sshproxy` (SSH köprüsü, localhost) |
| 10012 | `sshproxy` (OpenVPN-over-WS, localhost) |

## İstemci

- SSH Host: `http://<host>` · Port: `80` · payload: `baba` menüsünden kopyala
- REALITY: `vpnctl links <tag>` çıktısındaki linki içe aktar (SNI düğüme göre; bağlantı doğrudan IP:443'e yapılır)

Daha fazla ayrıntı: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/OPERATIONS.md](docs/OPERATIONS.md).
