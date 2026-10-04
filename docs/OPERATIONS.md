# Operasyon

## Günlük işler

```bash
baba                # SSH hesabı oluştur / listele / sil, istemci host+header ayarı
singbox             # sing-box düğüm (protocol+SNI) ve kullanıcı yönetimi
vpnctl doctor       # servis/port/config/REALITY kontrolü
vpnctl status       # özet
```

## Yedekleme ve geri yükleme

```bash
vpnctl backup                 # /root/vpnstack-backup/vpnstack-<tarih>.tar.gz
vpnctl restore <dosya>        # onay ister
vpnctl restore <dosya> --yes  # onaysız
```

Yedek içeriği: `sing-box/config.json`, `sing-box/phone_client.json`, `sshvpn/menu.conf`, SSH kullanıcı listesi, sürüm metadata'sı. Geri yüklemede config `sing-box check` ile doğrulanmadan yerine konmaz.

## REALITY düğümü ekleme (özet)

1. `singbox` menüsünden protokolü seç (VLESS + REALITY), port olarak **1443-1499 aralığında boş** bir localhost portu ver (hepsi 443'te SNI ile yayınlanır).
2. SNI olarak hedef alan adını gir (örn. `m.youtube.com`).
3. `vpnctl links <tag>` ile linki al; istemci doğrudan **IP:443** ile bağlanır (Cloudflare proxy'li alan adı REALITY taşımaz).

Yeni SNI'yı 443'e yönlendirmek için `/etc/haproxy/haproxy.cfg` içindeki `reality_frontend` bölümüne ekleyin: `use_backend re_<ad>_backend if { req.ssl_sni -i <sni> }` ve ilgili backend'i `127.0.0.1:<port>` ile tanımlayın; sonra `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy`.

## Sorun giderme

```bash
vpnctl doctor
journalctl -u ws -n 50 --no-pager
journalctl -u sing-box -n 50 --no-pager
haproxy -c -f /etc/haproxy/haproxy.cfg
```

- **Port çakışması (`bind: address already in use`):** `vpnctl doctor` "port çakışması" satırına bakın; aynı `listen:port` iki inbound'da olamaz.
- **REALITY "invalid connection":** istemci linkindeki `pbk`/`sid`/SNI ile sunucu config'i uyuşmuyor. `sblink`/`vpnctl links` güncel `pbk` üretir; linki yeniden içe aktarın.
- **SSH bağlantısı kopuyor:** `journalctl -u ws` ve `pgrep -af sshproxy`; `baba` menüsünden istemci payload'ını (Sec-WebSocket-Key dahil) yeniden alın.
