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

1. `singbox` menüsünden protokolü seç (VLESS + REALITY), port olarak **1443-1499 aralığında boş** bir localhost portu ver. Menü bu aralıkta boş bir port önerir, seçilen portu doğrular ve düğümü `127.0.0.1` üzerinde dinler (dışarıya açılmaz).
2. SNI olarak hedef alan adını gir (örn. `m.youtube.com`).
3. `vpnctl links <tag>` ile linki al; istemci doğrudan **IP:443** ile bağlanır (Cloudflare proxy'li alan adı REALITY taşımaz). Menü de linki bu şekilde üretir.

Yeni SNI'yı 443'e yönlendirmek için `/etc/haproxy/haproxy.cfg` içindeki `reality_frontend` bölümüne ekleyin: `use_backend re_<ad>_backend if { req.ssl_sni -i <sni> }` ve ilgili backend'i `127.0.0.1:<port>` ile tanımlayın; sonra `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy`.

## haproxy yapılandırması

`/etc/haproxy/haproxy.cfg`, depodaki `deploy/haproxy.cfg` sürümünden gelir. `install.sh` mevcut dosyayı yalnızca **yoksa** ya da paketin stok şablonuysa değiştirir; elle eklediğiniz REALITY/SNI satırları korunur (stok şablon değiştirilirse `.vpnstack-backup` yedeği alınır).

Kaynak dosya güncellendikten sonra türetmek için:

```bash
sudo cp deploy/haproxy.cfg /etc/haproxy/haproxy.cfg   # elle eklediğiniz satırları kaybedersiniz
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## Doğrudan SSH portları

`127.0.0.1:109` (sshproxy hedefi) ve `127.0.0.1:143` (haproxy `dropbear_backend`) dinlemiyorsa `install.sh` uyarı verir. WebSocket yolu (10015/80) bunlara ihtiyaç duymaz; yalnızca ham SSH kullanacaksanız dropbear'ı bu portlarda yapılandırın.

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
