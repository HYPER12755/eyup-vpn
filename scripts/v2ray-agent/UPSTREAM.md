# v2ray-agent (vendored)

Terminal tabanlı Xray yönetim paneli.

- Upstream: https://github.com/mack-a/v2ray-agent
- Pinlenen commit: `5c5e2b72a394356fb1d53ed05785d407b8743758` (master, 2026-09-15)
- Lisans: AGPL-3.0 — tam metin `LICENSE` dosyasında.

## Vendored files

| File | sha256 |
|---|---|
| `install.sh` | `fca0ad30d335b05b4e99fc5de848aeaff6c32d4b97f01ae84497dfad2978bfeb` |
| `LICENSE` | `db1a87ba81e885b6bb82971964ab4e202463cde2ac4003571bc5a857d577e4a3` |

Upstream'den yalnızca bu iki dosya alındı; geri kalan bileşenler `install.sh`
çalıştırıldığında upstream'in kendi kaynaklarından indirilir.

## Nasıl kullanılıyor

`install.sh` (bizim) bu dosyayı `/usr/local/bin/va` olarak yerleştirir, **çalıştırmaz**.
`baba` menüsündeki "Xray Yönetimi" girdisi `va`'yı başlatır.

## Uyarı

Upstream script kendi Xray/nginx/TLS kurulumunu yönetir. Çalıştırıldığında
mevcut haproxy (80/443), sing-box (REALITY) ve sshproxy düzenini
değiştirebilir; üretim sunucusunda önce yedek alın (`vpnctl backup`).
