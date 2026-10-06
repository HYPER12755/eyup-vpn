#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# verify_sha256 <file> <expected> — refuses to continue on mismatch. An empty
# expected value means "no published checksum is available"; callers must decide
# explicitly whether that is acceptable rather than silently trusting the bytes.
verify_sha256() {
  local file="$1" expected="$2" label="$3" actual
  if [[ -z "${expected}" ]]; then
    warn "${label}: yayımlanmış sağlama özeti yok, indirilen dosya doğrulanmadı."
    return 0
  fi
  actual="$(sha256sum "${file}" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] || die "${label} sağlama özeti uyuşmuyor (beklenen ${expected}, gelen ${actual})."
  ok "${label} sağlama özeti doğrulandı."
}

[[ "${EUID}" -eq 0 ]] || die "Bu script root olarak çalıştırılmalıdır."
command -v apt-get >/dev/null 2>&1 || die "Bu script Ubuntu 22.04/24.04 için tasarlandı."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="/opt/vpnstack"
GO_VERSION="1.27.1"
VERSION="1.0.0"

export DEBIAN_FRONTEND=noninteractive

log "Sistem bağımlılıkları kuruluyor..."
apt-get update -y -qq
apt-get install -y -qq curl wget git sudo ufw ca-certificates openssl jq unzip tar haproxy net-tools fail2ban python3 >/dev/null
ok "Bağımlılıklar kuruldu."

ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

SINGBOX_DIR="/usr/local/etc/sing-box"
SINGBOX_CONFIG="${SINGBOX_DIR}/config.json"
SINGBOX_BIN="/usr/local/bin/sing-box"

log "Sing-box kuruluyor..."
if ! command -v sing-box >/dev/null 2>&1; then
  # Upstream publishes no checksum file, so pin the release hashes here. This
  # replaces "curl … | bash" against a moving "main" branch: the download is now
  # a pinned release, verified before anything is extracted or executed.
  SB_VERSION="${SINGBOX_VERSION:-1.14.2}"
  # The hashes below belong to 1.14.2. Allowing a version override without
  # supplying its hashes would compare the wrong bytes and fail confusingly, so
  # an override must carry its own expected checksum.
  case "${SB_VERSION}" in
    1.14.2)
      case "$(dpkg --print-architecture)" in
        amd64) SB_ARCH="amd64"; SB_SHA="a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6" ;;
        arm64) SB_ARCH="arm64"; SB_SHA="b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f" ;;
        *) die "Desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
      esac
      ;;
    *)
      [[ -n "${SINGBOX_SHA256:-}" ]] || die "SINGBOX_VERSION=${SB_VERSION} için SINGBOX_SHA256 belirtilmeli."
      case "$(dpkg --print-architecture)" in
        amd64) SB_ARCH="amd64" ;;
        arm64) SB_ARCH="arm64" ;;
        *) die "Desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
      esac
      SB_SHA="${SINGBOX_SHA256}"
      ;;
  esac
  SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${SB_ARCH}.tar.gz"
  curl -fsSL "${SB_URL}" -o /tmp/sing-box.tar.gz || die "Sing-box arşivi indirilemedi: ${SB_URL}"
  verify_sha256 /tmp/sing-box.tar.gz "${SB_SHA}" "sing-box-${SB_VERSION}-linux-${SB_ARCH}.tar.gz"

  tar -C /tmp -xzf /tmp/sing-box.tar.gz
  install -m 0755 "/tmp/sing-box-${SB_VERSION}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
  rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${SB_VERSION}-linux-${SB_ARCH}"
fi
mkdir -p "${SINGBOX_DIR}"
# Yığın sing-box dosyalarını /usr/local altında bekler (singbox yöneticisi ve Go araçları).
if [[ ! -x "${SINGBOX_BIN}" ]]; then
  SINGBOX_REAL="$(command -v sing-box)"
  if [[ "${SINGBOX_REAL}" != "${SINGBOX_BIN}" ]]; then
    ln -sf "${SINGBOX_REAL}" "${SINGBOX_BIN}"
  fi
fi
if [[ ! -s "${SINGBOX_CONFIG}" ]]; then
  printf '%s\n' '{"log":{"level":"info","timestamp":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}' > "${SINGBOX_CONFIG}"
fi
if [[ ! -f /etc/systemd/system/sing-box.service ]] || ! grep -q "${SINGBOX_CONFIG}" /etc/systemd/system/sing-box.service; then
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=${SINGBOX_BIN} run -c ${SINGBOX_CONFIG}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1 || true
systemctl restart sing-box >/dev/null 2>&1 || warn "Sing-box servisi başlatılamadı."
ok "Sing-box hazır: $("${SINGBOX_BIN}" version 2>/dev/null | head -n1)"

log "Sing-box Manager kuruluyor..."
if [[ -f "${SCRIPT_DIR}/scripts/singbox-manager.sh" ]]; then
  install -m 0755 "${SCRIPT_DIR}/scripts/singbox-manager.sh" /root/singbox.sh
else
  # Upstream publishes no checksum for this file. Rather than trust the bytes,
  # require the operator to pin one:
  #   git clone the upstream repo, then
  #   sha256sum Install.sh
  # Refusing here is deliberate — this script runs as root, so an unverified
  # download is arbitrary code execution. Set SINGBOX_MANAGER_SHA256 to the
  # reviewed hash, or vendor scripts/singbox-manager.sh into the repo and
  # re-run to take the verified path above.
  : "${SINGBOX_MANAGER_SHA256:?set SINGBOX_MANAGER_SHA256 to the reviewed sha256 of Install.sh, or vendor scripts/singbox-manager.sh}"
  wget -N -q -O /root/singbox.sh https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/Install.sh || die "Sing-box Manager indirilemedi."
  verify_sha256 /root/singbox.sh "${SINGBOX_MANAGER_SHA256}" "sing-box-manager Install.sh"
  chmod +x /root/singbox.sh 2>/dev/null || true
fi
ln -sf /root/singbox.sh /usr/local/bin/singbox
ok "Sing-box Manager hazır: singbox"

log "Go ${GO_VERSION} kuruluyor..."
case "$(dpkg --print-architecture)" in
  amd64) GO_ARCH="amd64" ;;
  arm64) GO_ARCH="arm64" ;;
  *) die "Desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
esac
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
  # go.dev publishes one checksum per release file; fetch it rather than pinning a
  # copy here, so a compromised mirror cannot redefine the expected value. A
  # missing checksum file is fatal: verifying against an empty string is worse
  # than not verifying at all.
  GO_SHA="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" 2>/dev/null \
    | jq -r --arg v "go${GO_VERSION}" --arg f "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
        '.[] | select(.version == $v) | .files[] | select(.filename == $f) | .sha256' 2>/dev/null || true)"
  [[ -n "${GO_SHA}" ]] || die "Go ${GO_VERSION} sağlama özeti alınamadı; kurulum durduruldu."
  verify_sha256 /tmp/go.tar.gz "${GO_SHA}" "go${GO_VERSION}.tar.gz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
fi
printf '%s\n' 'export PATH="$PATH:/usr/local/go/bin"' > /etc/profile.d/go.sh
chmod +x /etc/profile.d/go.sh
export PATH="${PATH}:/usr/local/go/bin"
ok "Go kuruldu: $(go version)"

log "Proje derleniyor..."
if [[ "${SCRIPT_DIR}" != "${STACK_DIR}" ]]; then
  if [[ -f "${SCRIPT_DIR}/go.mod" ]]; then
    mkdir -p "${STACK_DIR}"
    tar -C "${SCRIPT_DIR}" --exclude=.git --exclude=.env -cf - . | tar -C "${STACK_DIR}" -xf -
  elif [[ -n "${REPO_URL:-}" ]]; then
    rm -rf "${STACK_DIR}"
    git clone --depth 1 "${REPO_URL}" "${STACK_DIR}" >/dev/null 2>&1
  else
    die "go.mod bulunamadı. Script'i proje kök dizininden çalıştırın veya REPO_URL tanımlayın."
  fi
fi

cd "${STACK_DIR}"
COMMIT="$(git -C "${SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X vpnstack/internal/version.Version=${VERSION} -X vpnstack/internal/version.Commit=${COMMIT} -X vpnstack/internal/version.Date=${DATE}"

go mod download
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /usr/local/bin/sshproxy ./cmd/sshproxy
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /usr/local/bin/sblink ./cmd/sblink
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /usr/local/bin/vpnctl ./cmd/vpnctl
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o /usr/local/bin/vpnlimit ./cmd/vpnlimit
install -m 0755 "${STACK_DIR}/scripts/vpnmenu.sh" /usr/local/bin/vpnmenu
ln -sf /usr/local/bin/vpnmenu /usr/local/bin/baba
install -m 0755 "${STACK_DIR}/scripts/xraymenu.sh" /usr/local/bin/xraymenu
install -m 0755 "${STACK_DIR}/scripts/xraycfg.py" /usr/local/bin/xraycfg
ok "Kuruldu: sshproxy + sblink + vpnctl + vpnmenu (baba) + xraymenu/xraycfg"

# ---------------------------------------------------------- Keşif ve sahiplenme
# Üzerine kurulum yapılan sunucuda sertifika ve SSH tüneli dosyaları zaten
# olabilir (eski VPN scriptleri, acme.sh, certbot, v2ray-agent, hap.pem). Bu
# bölüm her şeyi otomatik tarar: bulduğunu sahiplenir, bulamadığını sorar ya da
# üretir. Sıra: VPNSTACK_* ortam değişkenleri > otomatik keşif > soru > üretim.
log "Sertifika ve SSH tüneli dosyaları taranıyor..."

mkdir -p /etc/sshvpn
if [[ ! -f /etc/sshvpn/menu.conf ]]; then
  printf 'FAKE_HOST=\nEXTRA_HEADER=\n' > /etc/sshvpn/menu.conf
  chmod 600 /etc/sshvpn/menu.conf
fi

# Bilinen kurulumların sertifika konumlarını sırayla dener; bulduğunda
# "cert|key|kaynak" basar. hap.pem birleşik bir dosyadır: iki alan da aynı
# yolu gösterir ve bölüm aşağıda onu cert+key olarak ikiye ayırır.
find_cert_pair() {
  if [[ -s /etc/xray/xray.crt && -s /etc/xray/xray.key ]]; then
    echo "/etc/xray/xray.crt|/etc/xray/xray.key|Xray düzeni"
    return 0
  fi
  if [[ -s /etc/haproxy/hap.pem ]] && grep -q "PRIVATE KEY" /etc/haproxy/hap.pem; then
    echo "/etc/haproxy/hap.pem|/etc/haproxy/hap.pem|haproxy hap.pem (birleşik)"
    return 0
  fi
  local dir name
  for dir in /etc/letsencrypt/live/*/; do
    [[ -s "${dir}fullchain.pem" && -s "${dir}privkey.pem" ]] || continue
    echo "${dir}fullchain.pem|${dir}privkey.pem|Let's Encrypt"
    return 0
  done
  for dir in /root/.acme.sh/*/; do
    name="${dir%/}"; name="${name##*/}"; name="${name%_ecc}"
    [[ -s "${dir}${name}.key" ]] || continue
    if [[ -s "${dir}fullchain.cer" ]]; then
      echo "${dir}fullchain.cer|${dir}${name}.key|acme.sh"
      return 0
    fi
    if [[ -s "${dir}${name}.cer" ]]; then
      echo "${dir}${name}.cer|${dir}${name}.key|acme.sh"
      return 0
    fi
  done
  for dir in /etc/v2ray-agent/tls/*.crt; do
    [[ -s "${dir}" && -s "${dir%.crt}.key" ]] || continue
    echo "${dir}|${dir%.crt}.key|v2ray-agent TLS"
    return 0
  done
  return 1
}

# Domaini önce dosyadan, yoksa bulunan sertifikanın CN alanından çıkarır.
discover_domain() {
  local domain="" pair
  if [[ -s /etc/xray/domain ]]; then
    domain="$(head -n1 /etc/xray/domain)"
  fi
  if [[ -z "${domain}" ]]; then
    pair="$(find_cert_pair || true)"
    if [[ -n "${pair}" ]]; then
      domain="$(openssl x509 -in "${pair%%|*}" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' | head -n1)"
    fi
  fi
  [[ -n "${domain}" ]] || return 1
  echo "${domain}"
}

DOMAIN="${VPNSTACK_DOMAIN:-}"
if [[ -z "${DOMAIN}" ]]; then
  DOMAIN="$(discover_domain || true)"
  [[ -n "${DOMAIN}" ]] && log "Domain sistemde bulundu: ${DOMAIN}"
fi
if [[ -z "${DOMAIN}" && -t 0 ]]; then
  read -r -p "Sunucu alan adı (örn. vpn.example.com, boş = atla): " DOMAIN || true
fi
if [[ -n "${DOMAIN}" ]]; then
  mkdir -p /etc/xray
  printf '%s\n' "${DOMAIN}" > /etc/xray/domain
  # FAKE_HOST is the decoy Host header in client payloads; only fill it in when
  # the operator has not set one deliberately.
  if ! grep -qE '^FAKE_HOST=.+' /etc/sshvpn/menu.conf; then
    sed -i "s|^FAKE_HOST=.*|FAKE_HOST=${DOMAIN}|" /etc/sshvpn/menu.conf
  fi
  ok "Domain kaydedildi: ${DOMAIN} (/etc/xray/domain)"
fi

# --------------------------------------------------------- DuckDNS (opsiyonel)
# Token verilirse: DuckDNS A kaydı bu sunucuya yönlendirilir ve DNS-01
# doğrulamasıyla Let's Encrypt sertifikası alınır (80 portu meşgul edilmez).
# Boş geçilirse hiçbir şey yapılmaz. acme.sh doğrulanmamış bir boru hattıyla
# değil, pinlenmiş commit + sha256 ile kurulur.
ACME_HOME="/root/.acme.sh"
ACME_BIN="${ACME_HOME}/acme.sh"

ensure_acme() {
  local commit="807da6498377ee5e0cf43a78091f46f12dc59a89"
  local acme_sha="c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7"
  local dnsapi_sha="8be535b8d6270b7a37671da954d89c896df7af29c2f38d5029054ec315fe77af"
  if [[ -x "${ACME_BIN}" && -f "${ACME_HOME}/dnsapi/dns_duckdns.sh" ]]; then
    return 0
  fi
  mkdir -p "${ACME_HOME}/dnsapi"
  curl -fsSL "https://raw.githubusercontent.com/acmesh-official/acme.sh/${commit}/acme.sh" -o "${ACME_BIN}" || return 1
  curl -fsSL "https://raw.githubusercontent.com/acmesh-official/acme.sh/${commit}/dnsapi/dns_duckdns.sh" -o "${ACME_HOME}/dnsapi/dns_duckdns.sh" || return 1
  verify_sha256 "${ACME_BIN}" "${acme_sha}" "acme.sh" || return 1
  verify_sha256 "${ACME_HOME}/dnsapi/dns_duckdns.sh" "${dnsapi_sha}" "dns_duckdns.sh" || return 1
  chmod 0755 "${ACME_BIN}"
  # Günlük yenileme; --install-cert yolları kaydedildiği için cron yenilemesi
  # sertifikayı doğrudan /etc/xray'e geri kurar.
  cat > /etc/cron.d/vpnstack-acme <<EOF
0 3 * * * root ${ACME_BIN} --cron --home ${ACME_HOME} >/dev/null 2>&1
EOF
  return 0
}

DUCKDNS_TOKEN="${DUCKDNS_TOKEN:-}"
if [[ -z "${DUCKDNS_TOKEN}" && -t 0 ]]; then
  read -r -p "DuckDNS tokeni (boş = atla, DNS-01 sertifikası alınmaz): " DUCKDNS_TOKEN || true
fi
DUCKDNS_CERT=false
DUCKDNS_SOURCE=""
if [[ -n "${DUCKDNS_TOKEN}" ]]; then
  mkdir -p /etc/xray
  if [[ -z "${DOMAIN}" && -t 0 ]]; then
    read -r -p "DuckDNS alt alan adı (örn. adiniz.duckdns.org): " DOMAIN || true
    if [[ -n "${DOMAIN}" ]]; then
      printf '%s\n' "${DOMAIN}" > /etc/xray/domain
      ok "Domain kaydedildi: ${DOMAIN} (/etc/xray/domain)"
    fi
  fi
  if [[ "${DOMAIN}" != *".duckdns.org" ]]; then
    warn "DuckDNS tokeni verildi ama domain .duckdns.org değil; DuckDNS adımı atlandı."
  else
    DUCKDNS_SUB="${DOMAIN%.duckdns.org}"
    DUCKDNS_IP="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${DUCKDNS_IP}" ]]; then
      DUCKDNS_RESULT="$(curl -fsSL --max-time 10 "https://www.duckdns.org/update?domains=${DUCKDNS_SUB}&token=${DUCKDNS_TOKEN}&ip=${DUCKDNS_IP}" 2>/dev/null || true)"
      if [[ "${DUCKDNS_RESULT}" == "OK" ]]; then
        ok "DuckDNS A kaydı güncellendi: ${DOMAIN} → ${DUCKDNS_IP}"
      else
        warn "DuckDNS A kaydı güncellenemedi (${DUCKDNS_RESULT:-yanıt yok}); mevcut kayıt kullanılacak."
      fi
    fi
    if ensure_acme; then
      if DuckDNS_Token="${DUCKDNS_TOKEN}" "${ACME_BIN}" --home "${ACME_HOME}" --issue --dns dns_duckdns -d "${DOMAIN}" --keylength ec-256 >/dev/null 2>&1 \
        && DuckDNS_Token="${DUCKDNS_TOKEN}" "${ACME_BIN}" --home "${ACME_HOME}" --install-cert -d "${DOMAIN}" --ecc \
             --fullchain-file /etc/xray/xray.crt --key-file /etc/xray/xray.key >/dev/null 2>&1; then
        chmod 0644 /etc/xray/xray.crt
        chmod 0600 /etc/xray/xray.key
        DUCKDNS_CERT=true
        DUCKDNS_SOURCE="DuckDNS + Let's Encrypt (acme.sh)"
        ok "DuckDNS sertifikası alındı: ${DOMAIN}"
      else
        warn "DuckDNS sertifikası alınamadı (token/alan adı?); mevcut sertifikaya düşülecek."
      fi
    else
      warn "acme.sh indirilemedi/doğrulanamadı; DuckDNS sertifikası atlandı."
    fi
  fi
fi

CERT_PATH="${VPNSTACK_CERT_PATH:-}"
KEY_PATH="${VPNSTACK_KEY_PATH:-}"
CERT_SOURCE=""
if [[ "${DUCKDNS_CERT}" == true && -z "${CERT_PATH}" ]]; then
  CERT_PATH=/etc/xray/xray.crt
  KEY_PATH=/etc/xray/xray.key
  CERT_SOURCE="${DUCKDNS_SOURCE}"
fi
if [[ -z "${CERT_PATH}" ]]; then
  CERT_PAIR="$(find_cert_pair || true)"
  if [[ -n "${CERT_PAIR}" ]]; then
    IFS='|' read -r CERT_PATH KEY_PATH CERT_SOURCE <<< "${CERT_PAIR}"
    log "Sertifika bulundu: ${CERT_SOURCE}"
  fi
fi
if [[ -z "${CERT_PATH}" && -t 0 ]]; then
  read -r -p "TLS sertifika (fullchain) yolu (boş = mevcut/self-signed): " CERT_PATH || true
  if [[ -n "${CERT_PATH}" ]]; then
    read -r -p "TLS özel anahtar yolu: " KEY_PATH || true
  fi
fi
if [[ -n "${CERT_PATH}" ]]; then
  if [[ "${CERT_PATH}" == "${KEY_PATH}" ]]; then
    # Birleşik PEM (hap.pem): sertifika zinciri ile anahtarı ikiye ayır.
    grep -q "PRIVATE KEY" "${CERT_PATH}" || die "Birleşik PEM anahtar içermiyor: ${CERT_PATH}"
    mkdir -p /etc/xray
    awk '/PRIVATE KEY/ { exit } { print }' "${CERT_PATH}" > /etc/xray/xray.crt
    awk 'found || /PRIVATE KEY/ { found=1; print }' "${CERT_PATH}" > /etc/xray/xray.key
    chmod 0644 /etc/xray/xray.crt
    chmod 0600 /etc/xray/xray.key
    CERT_SOURCE="${CERT_SOURCE:-birleşik PEM}"
    ok "Sertifika ayrıştırıldı: ${CERT_PATH} → /etc/xray/xray.crt + xray.key"
  elif [[ "${CERT_PATH}" == /etc/xray/xray.crt && "${KEY_PATH}" == /etc/xray/xray.key ]]; then
    ok "Xray sertifikası hazır: /etc/xray/xray.crt${CERT_SOURCE:+ (${CERT_SOURCE})}"
  else
    [[ -f "${CERT_PATH}" && -f "${KEY_PATH}" ]] || die "Sertifika/anahtar bulunamadı: cert='${CERT_PATH}' key='${KEY_PATH}'"
    install -m 0644 "${CERT_PATH}" /etc/xray/xray.crt
    install -m 0600 "${KEY_PATH}" /etc/xray/xray.key
    CERT_SOURCE="${CERT_SOURCE:-verilen yol}"
    ok "TLS sertifikası kuruldu: ${CERT_PATH} → /etc/xray/xray.crt"
  fi
fi
if [[ ! -f /etc/xray/xray.crt || ! -f /etc/xray/xray.key ]]; then
  CERT_CN="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
  mkdir -p /etc/xray
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${CERT_CN}" \
    -keyout /etc/xray/xray.key -out /etc/xray/xray.crt >/dev/null 2>&1
  chmod 600 /etc/xray/xray.key
  CERT_SOURCE="self-signed (CN=${CERT_CN})"
  ok "Self-signed sertifika üretildi (CN=${CERT_CN}); gerçek sertifika için VPNSTACK_CERT_PATH/KEY_PATH verin."
fi
# Xray bazı kurulumlarda www-data olarak çalışır (legacy unit); anahtarı grup
# okunur yap ki hem root hem www-data birimleri sertifikayı okuyabilsin.
if id -u www-data >/dev/null 2>&1; then
  chown root:www-data /etc/xray/xray.key 2>/dev/null || true
  chmod 0640 /etc/xray/xray.key
fi

# SSH tüneli destek dosyaları: grup ve eski köprünün yedeği.
getent group sshvpn >/dev/null 2>&1 || groupadd -f sshvpn >/dev/null 2>&1 || true
ok "sshvpn grubu hazır."

# Eski panelin SSH hesap grubunu sahiplen: sshvpn boşken /bin/false kabuklu
# kullanıcıların en kalabalık grubu o panelin grubudur; menu.conf'a yazılır ve
# baba/vpnctl bu grubu yönetir.
detect_legacy_group() {
  local gid group count best="" best_count=0
  while IFS= read -r gid; do
    [[ -n "${gid}" ]] || continue
    (( gid >= 1000 )) || continue
    group="$(getent group "${gid}" 2>/dev/null | cut -d: -f1)"
    [[ -n "${group}" && "${group}" != "sshvpn" ]] || continue
    count="$(awk -F: -v g="${gid}" '$4==g && $7=="/bin/false" {c++} END {print c+0}' /etc/passwd)"
    if (( count > best_count )); then
      best="${group}"
      best_count="${count}"
    fi
  done < <(awk -F: '$7=="/bin/false" {print $4}' /etc/passwd | sort -u)
  [[ -n "${best}" ]] && echo "${best}"
}

if grep -qE '^ACCOUNT_GROUP=.+' /etc/sshvpn/menu.conf 2>/dev/null; then
  ok "SSH hesap grubu ayarlı: $(grep -E '^ACCOUNT_GROUP=' /etc/sshvpn/menu.conf | cut -d= -f2)"
else
  OWN_SSHVPN_USERS="$(awk -F: -v g="$(getent group sshvpn | cut -d: -f3)" '$4==g {c++} END {print c+0}' /etc/passwd)"
  LEGACY_GROUP=""
  [[ "${OWN_SSHVPN_USERS}" -eq 0 ]] && LEGACY_GROUP="$(detect_legacy_group || true)"
  if [[ -n "${LEGACY_GROUP}" ]]; then
    printf 'ACCOUNT_GROUP=%s\n' "${LEGACY_GROUP}" >> /etc/sshvpn/menu.conf
    ok "Mevcut panelin SSH grubu sahiplenildi: ${LEGACY_GROUP} (baba/vpnctl artık bunu yönetir)."
  else
    ok "SSH hesap grubu: sshvpn"
  fi
fi
for legacy in /etc/whoiamluna/ws.py /usr/local/bin/ws.py /root/ws.py /etc/ws.py; do
  if [[ -f "${legacy}" ]]; then
    mkdir -p /etc/sshvpn/legacy
    cp -a "${legacy}" /etc/sshvpn/legacy/ws.py
    chmod 600 /etc/sshvpn/legacy/ws.py
    ok "Eski SSH köprüsü yedeklendi: ${legacy} → /etc/sshvpn/legacy/ws.py"
    break
  fi
done
for legacy_unit in /etc/systemd/system/ws.service /etc/systemd/system/ws-ovpn.service; do
  if [[ -f "${legacy_unit}" ]] && ! grep -q "sshproxy" "${legacy_unit}" 2>/dev/null; then
    # Bilinen yollarda köprü bulunamadıysa, eski birimin çalıştırdığı
    # Python dosyasını ExecStart'tan çıkar ve onu da yedekle.
    if [[ ! -f /etc/sshvpn/legacy/ws.py ]]; then
      legacy_exec="$(grep -E '^ExecStart=' "${legacy_unit}" | grep -oE '/[^ ]+\.py' | head -n1)"
      if [[ -n "${legacy_exec}" && -f "${legacy_exec}" ]]; then
        mkdir -p /etc/sshvpn/legacy
        cp -a "${legacy_exec}" /etc/sshvpn/legacy/ws.py
        chmod 600 /etc/sshvpn/legacy/ws.py
        ok "Eski SSH köprüsü birimden bulundu ve yedeklendi: ${legacy_exec} → /etc/sshvpn/legacy/ws.py"
      fi
    fi
    cp -a "${legacy_unit}" "${legacy_unit}.vpnstack-backup"
    log "Eski birim yedeklendi: ${legacy_unit}.vpnstack-backup"
  fi
done

log "Servisler yapılandırılıyor..."
install -m 0644 "${STACK_DIR}/deploy/ws.service" /etc/systemd/system/ws.service
install -m 0644 "${STACK_DIR}/deploy/ws-ovpn.service" /etc/systemd/system/ws-ovpn.service

# Profil seçimi: reality (varsayılan: 443'te SNI passthrough → sing-box) veya
# legacy (üzerine kurulum yapılan sunuculardaki TLS sonlandırmalı, ek portlu,
# çoklu protokollü eski düzen).
HAPROXY_PROFILE="${VPNSTACK_HAPROXY_PROFILE:-reality}"
case "${HAPROXY_PROFILE}" in
  reality) HAPROXY_SRC="${STACK_DIR}/deploy/haproxy.cfg" ;;
  legacy)  HAPROXY_SRC="${STACK_DIR}/deploy/haproxy.legacy.cfg" ;;
  hybrid)  HAPROXY_SRC="${STACK_DIR}/deploy/haproxy.hybrid.cfg" ;;
  *) die "VPNSTACK_HAPROXY_PROFILE=${HAPROXY_PROFILE} geçersiz (reality|legacy|hybrid)." ;;
esac

# hybrid profil: 443'ü SNI'ye göre dağıtır. REALITY rotaları sing-box
# yapılandırmasından üretilir; alan adı TLS'ı Xray sonlandırır.
render_hybrid_haproxy() {
  python3 - "${SINGBOX_CONFIG}" "$1" "$2" "${DOMAIN:-}" <<'PY'
import json, sys
config_path, src, dst, domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    with open(config_path) as handle:
        config = json.load(handle)
except Exception:
    config = {}
entries = []
for inbound in config.get("inbounds", []):
    tls = inbound.get("tls") or {}
    reality = tls.get("reality") or {}
    sni = (reality.get("handshake") or {}).get("server") or tls.get("server_name") or ""
    port = inbound.get("listen_port")
    tag = str(inbound.get("tag") or "")
    if not sni or not port:
        continue
    # Aynı SNI'yı paylaşan düğümlerden REALITY olan kazanır; düz TLS düğümü
    # aksi halde 443'ü gereksizce kapardı.
    priority = 0 if "reality" in tls else 1
    entries.append((priority, sni, port, tag))
routes, backends, seen = [], [], set()
for _priority, sni, port, tag in sorted(entries, key=lambda item: item[0]):
    if sni in seen:
        continue
    seen.add(sni)
    safe = "".join(ch if ch.isalnum() else "_" for ch in tag) or ("node_%s" % port)
    routes.append("    acl sni_%s req.ssl_sni -i %s" % (safe, sni))
    routes.append("    use_backend re_%s_backend if sni_%s" % (safe, safe))
    backends.append("backend re_%s_backend\n    mode tcp\n    server %s_node 127.0.0.1:%s check\n" % (safe, safe, port))
text = open(src).read()
if domain:
    text = text.replace("#__DOMAIN_ROUTE__", "    use_backend xray_tls_backend if { req.ssl_sni -i %s }" % domain)
else:
    text = text.replace("#__DOMAIN_ROUTE__", "    # domain bilinmiyor; 443 doğrudan Xray TLS'e gider")
text = text.replace("#__REALITY_ROUTES__", "\n".join(routes) if routes else "    # REALITY düğümü yok; 443 doğrudan Xray TLS'e gider")
text = text.replace("#__REALITY_BACKENDS__", "\n".join(backends) if backends else "# REALITY düğümü yok")
with open(dst, "w") as handle:
    handle.write(text)
PY
}

HAPROXY_DST="/etc/haproxy/haproxy.cfg"
if [[ "${HAPROXY_PROFILE}" == "hybrid" ]]; then
  if [[ -f "${HAPROXY_DST}" ]]; then
    cp -a "${HAPROXY_DST}" "${HAPROXY_DST}.vpnstack-backup"
    log "Mevcut haproxy.cfg yedeklendi: ${HAPROXY_DST}.vpnstack-backup"
  fi
  HAPROXY_RENDERED="$(mktemp)"
  render_hybrid_haproxy "${HAPROXY_SRC}" "${HAPROXY_RENDERED}"
  install -m 0644 "${HAPROXY_RENDERED}" "${HAPROXY_DST}"
  rm -f "${HAPROXY_RENDERED}"
  # 443 passthrough olduğu için hap.pem yalnızca 8443/2096/2087 içindir.
  if [[ -f /etc/xray/xray.crt && -f /etc/xray/xray.key ]]; then
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    chmod 600 /etc/haproxy/hap.pem
    ok "hap.pem üretildi (8443/2096/2087 TLS)."
  fi
  ok "haproxy.cfg hybrid profille kuruldu (443: SNI paylaşımı, Xray TLS + REALITY)."
elif [[ "${HAPROXY_PROFILE}" == "legacy" ]]; then
  if [[ -f "${HAPROXY_DST}" ]]; then
    cp -a "${HAPROXY_DST}" "${HAPROXY_DST}.vpnstack-backup"
    log "Mevcut haproxy.cfg yedeklendi: ${HAPROXY_DST}.vpnstack-backup"
  fi
  install -m 0644 "${HAPROXY_SRC}" "${HAPROXY_DST}"
  # The legacy frontend terminates TLS on 443, so haproxy needs the cert and key
  # in one file. It is derived from the /etc/xray pair the installer just
  # ensured, which is also what makes the same certificate usable for SSH.
  if [[ -f /etc/xray/xray.crt && -f /etc/xray/xray.key ]]; then
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    chmod 600 /etc/haproxy/hap.pem
    ok "hap.pem üretildi (443 TLS): /etc/haproxy/hap.pem."
  else
    warn "legacy profil 443 için hap.pem gerekli; /etc/xray sertifikası bulunamadı."
  fi
  ok "haproxy.cfg legacy profille kuruldu (80/8080/8880/2082 · 443 TLS · WS 10015 · SSH 143)."
elif [[ ! -f "${HAPROXY_DST}" ]] || grep -q "# example config for haproxy" "${HAPROXY_DST}"; then
  if [[ -f "${HAPROXY_DST}" ]]; then
    cp -a "${HAPROXY_DST}" "${HAPROXY_DST}.vpnstack-backup"
    log "Stok haproxy.cfg yedeklendi: ${HAPROXY_DST}.vpnstack-backup"
  fi
  install -m 0644 "${HAPROXY_SRC}" "${HAPROXY_DST}"
  ok "haproxy.cfg kuruldu (80: WS/SSH · 443: REALITY SNI)."
elif ! grep -q "# vpnstack" "${HAPROXY_DST}"; then
  # Elle düzenlenmiş ya da başka bir kurulumdan gelen yapılandırma korunur,
  # ama vpnstack SSH yolunun iki bacağı yine de aranır; eksik olan tam olarak
  # söylenir, çünkü sessiz kalan bir eksiklik SSH'ı çalışmaz bırakır.
  HAPROXY_MISSING=""
  grep -q "10015" "${HAPROXY_DST}" || HAPROXY_MISSING="${HAPROXY_MISSING} WebSocket→127.0.0.1:10015"
  grep -qE 'server[^#]*:143\b' "${HAPROXY_DST}" || HAPROXY_MISSING="${HAPROXY_MISSING} ham SSH→127.0.0.1:143"
  if [[ -n "${HAPROXY_MISSING}" ]]; then
    warn "${HAPROXY_DST} elle düzenlenmiş görünüyor; dokunulmadı. Eksik yönlendirme:${HAPROXY_MISSING}."
    warn "deploy/haproxy.cfg'yi örnek alın ya da VPNSTACK_HAPROXY_PROFILE=legacy ile çalışan düzeni kurun."
  else
    ok "Mevcut haproxy.cfg korundu; vpnstack yolları (WS 10015, SSH 143) doğrulandı."
  fi
else
  ok "Mevcut haproxy.cfg korundu (düzenlemeleriniz silinmedi)."
fi

mkdir -p /etc/sshvpn
if [[ ! -f /etc/sshvpn/menu.conf ]]; then
  printf 'FAKE_HOST=\nEXTRA_HEADER=\n' > /etc/sshvpn/menu.conf
  chmod 600 /etc/sshvpn/menu.conf
fi

systemctl daemon-reload
systemctl enable --now ws.service >/dev/null 2>&1 || warn "ws.service başlatılamadı."
systemctl enable --now ws-ovpn.service >/dev/null 2>&1 || warn "ws-ovpn.service başlatılamadı."
if haproxy -c -f "${HAPROXY_DST}" >/dev/null 2>&1; then
  systemctl enable haproxy >/dev/null 2>&1 || true
  systemctl reload-or-restart haproxy >/dev/null 2>&1 || systemctl enable --now haproxy >/dev/null 2>&1 || warn "haproxy başlatılamadı."
else
  warn "haproxy yapılandırması geçersiz; haproxy yeniden yüklenmedi."
  haproxy -c -f "${HAPROXY_DST}" 2>&1 | tail -5 || true
fi
ok "ws.service, ws-ovpn.service yapılandırıldı."

log "SSH arka ucu kuruluyor..."
# haproxy routes raw SSH on port 80 to 127.0.0.1:143 and sshproxy defaults to
# 127.0.0.1:109, so dropbear has to listen on both or that path is dead. Without
# this the failure is silent: haproxy accepts the connection and the backend
# refuses it.
#
# Kurulum iki sunucu tipini ayırt eder:
#   1. dropbear zaten 109 ve 143'ü dinliyor (üzerine kurulum yapılan eski/mevcut
#      VPN düzeni): dokunulmaz, olduğu gibi sahiplenilir.
#   2. hiç yok: apt ile kurulur; kurulamazsa sessizce devam etmek yerine hata
#      verilir, çünkü eksik dropbear SSH-80 yolunu ölü bırakır.

listening_on() {
  ss -ltnH "sport = :$1" 2>/dev/null | grep -q .
}

dropbear_binary() {
  if [[ -x /usr/sbin/dropbear ]]; then
    echo /usr/sbin/dropbear
  elif command -v dropbear >/dev/null 2>&1; then
    command -v dropbear
  else
    # Boş döner ama başarılı sayılır: `set -e` altında bulunamayan bir ikili
    # yüzünden betiğin burada ölmesi yerine kurulum akışı devam etmeli.
    echo ""
  fi
}

listening_process_name() {
  ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -n1
}

if listening_on 109 && listening_on 143; then
  OWNER_109="$(listening_process_name 109)"
  OWNER_143="$(listening_process_name 143)"
  ok "Mevcut dinleyiciler sahiplenildi — :109 ${OWNER_109:-?} · :143 ${OWNER_143:-?}"
  for pair in "109:${OWNER_109}" "143:${OWNER_143}"; do
    PORT="${pair%%:*}"; OWNER="${pair#*:}"
    if [[ -n "${OWNER}" && "${OWNER}" != *dropbear* ]]; then
      warn "port ${PORT} dropbear değil (${OWNER}) tarafından tutuluyor; SSH-80 yolu beklendiği gibi çalışmayabilir."
    fi
  done
  if ss -ltnH "sport = :143" 2>/dev/null | grep -qE '0\.0\.0\.0|\*|\[::\]'; then
    warn "dropbear :143 tüm arayüzlerde dinliyor; yalnızca 127.0.0.1 olması önerilir."
  fi
else
  DROPBEAR_BIN="$(dropbear_binary)"
  if [[ -z "${DROPBEAR_BIN}" ]]; then
    log "dropbear kuruluyor (apt)…"
    for attempt in 1 2 3; do
      apt-get update -qq >/dev/null 2>&1 || true
      if apt-get install -y -qq dropbear >/dev/null 2>&1 || apt-get install -y -qq dropbear-bin >/dev/null 2>&1; then
        break
      fi
      warn "dropbear kurulum denemesi ${attempt}/3 başarısız."
      sleep 2
    done
    DROPBEAR_BIN="$(dropbear_binary)"
  fi

  if [[ -z "${DROPBEAR_BIN}" ]]; then
    if [[ "${VPNSTACK_SKIP_DROPBEAR:-0}" == "1" ]]; then
      warn "dropbear kurulamadı; VPNSTACK_SKIP_DROPBEAR=1 ile yoksayıldı (SSH-80 yolu çalışmaz)."
    else
      die "dropbear kurulamadı (apt). SSH-80 yolu (haproxy → 127.0.0.1:143) çalışmaz. apt durumunu düzeltip yeniden deneyin; bilerek yoksaymak için VPNSTACK_SKIP_DROPBEAR=1."
    fi
  else
    # -R makes dropbear generate any missing host key on startup, so there is no
    # need to run dropbearkey here (note: -f is the keygen output flag, and the
    # type is "ecdsa", not "ecdsa-sha2-nistp256"). -p is repeatable, up to 10
    # ports. openssh-server on :22 is left running as a rescue path.
    cat > /etc/systemd/system/dropbear-vpnstack.service <<EOF
[Unit]
Description=dropbear (vpnstack backends 109/143)
After=network.target

[Service]
Type=simple
ExecStart=${DROPBEAR_BIN} -F -R -p 127.0.0.1:109 -p 127.0.0.1:143
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable dropbear-vpnstack >/dev/null 2>&1 || true
    # Ubuntu's packaged unit also binds :22 and writes the same pidfile; keep it
    # off so the two do not collide.
    systemctl disable --now dropbear >/dev/null 2>&1 || true
    systemctl restart dropbear-vpnstack >/dev/null 2>&1 || true
    DROPBEAR_STARTED=false
    for _ in $(seq 1 10); do
      if listening_on 109 && listening_on 143; then
        DROPBEAR_STARTED=true
        break
      fi
      sleep 0.5
    done
    if [[ "${DROPBEAR_STARTED}" == true ]]; then
      ok "dropbear 127.0.0.1:109 ve :143 dinliyor."
    else
      warn "dropbear-vpnstack başlatılamadı ya da portları tutamadı: journalctl -u dropbear-vpnstack"
      ss -ltnp 2>/dev/null | grep -E ':(109|143)\b' || true
    fi
  fi
fi

# ---------------------------------------------------------------- Xray core
# Adopt-first, like dropbear: a server that already runs Xray (the legacy
# multi-protocol layout keeps the binary in /usr/local/bin and the config in
# /etc/xray) is left running exactly as it is. Only a missing install is added,
# from a pinned, checksum-verified release.
log "Xray kuruluyor..."
XRAY_BIN="/usr/local/bin/xray"
if command -v xray >/dev/null 2>&1 || [[ -x "${XRAY_BIN}" ]]; then
  XRAY_REAL="$(command -v xray 2>/dev/null || echo "${XRAY_BIN}")"
  if [[ "${XRAY_REAL}" != "${XRAY_BIN}" ]]; then
    ln -sf "${XRAY_REAL}" "${XRAY_BIN}"
  fi
  ok "Mevcut Xray sahiplenildi: $("${XRAY_BIN}" version 2>/dev/null | head -n1)"
else
  XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
  # The hashes below are the published .dgst values for v26.3.27. A version
  # override must carry its own sha256; otherwise the download would be
  # compared against the pins of a different release and fail confusingly.
  case "${XRAY_VERSION}" in
    v26.3.27)
      case "$(dpkg --print-architecture)" in
        amd64) XRAY_ARCH="64"; XRAY_SHA="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae" ;;
        arm64) XRAY_ARCH="arm64-v8a"; XRAY_SHA="4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c" ;;
        *) die "Desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
      esac
      ;;
    *)
      [[ -n "${XRAY_SHA256:-}" ]] || die "XRAY_VERSION=${XRAY_VERSION} için XRAY_SHA256 belirtilmeli."
      case "$(dpkg --print-architecture)" in
        amd64) XRAY_ARCH="64" ;;
        arm64) XRAY_ARCH="arm64-v8a" ;;
        *) die "Desteklenmeyen mimari: $(dpkg --print-architecture)" ;;
      esac
      XRAY_SHA="${XRAY_SHA256}"
      ;;
  esac
  XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
  curl -fsSL "${XRAY_URL}" -o /tmp/xray.zip || die "Xray arşivi indirilemedi: ${XRAY_URL}"
  verify_sha256 /tmp/xray.zip "${XRAY_SHA}" "Xray-linux-${XRAY_ARCH}.zip"
  rm -rf /tmp/xray-extract
  mkdir -p /tmp/xray-extract
  unzip -oq /tmp/xray.zip -d /tmp/xray-extract
  install -m 0755 /tmp/xray-extract/xray "${XRAY_BIN}"
  rm -rf /tmp/xray.zip /tmp/xray-extract
  ok "Xray kuruldu: $("${XRAY_BIN}" version 2>/dev/null | head -n1)"
fi

mkdir -p /etc/xray /var/log/xray
XRAY_CONFIG_CHANGED=false
if [[ ! -s /etc/xray/config.json ]]; then
  # The template is the marker-based layout the legacy manager expects: users
  # live between #& user lines and each protocol has an insertion marker
  # (#vless, #vmess, ...). It also carries the tls-fallback inbound (10443)
  # that the hybrid profile routes 443 traffic into.
  install -m 0644 "${STACK_DIR}/deploy/xray.config.json" /etc/xray/config.json
  XRAY_CONFIG_CHANGED=true
  ok "Xray config şablonu kuruldu: /etc/xray/config.json"
fi
if [[ "${HAPROXY_PROFILE}" == "hybrid" ]] && ! grep -q '"tls-fallback"' /etc/xray/config.json 2>/dev/null; then
  warn "hybrid profilde 443 için /etc/xray/config.json içinde tls-fallback inbound'u (port 10443) gerekir; deploy/xray.config.json'daki bloğu ekleyip xray'i yeniden başlatın."
fi
if [[ ! -f /etc/systemd/system/xray.service ]]; then
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_BIN} run -config /etc/xray/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "xray.service kuruldu."
fi
systemctl enable xray >/dev/null 2>&1 || true
if systemctl is-active --quiet xray && [[ "${XRAY_CONFIG_CHANGED}" != true ]]; then
  ok "xray.service zaten çalışıyor; dokunulmadı."
elif systemctl restart xray >/dev/null 2>&1 && listening_on 10000; then
  ok "xray.service çalışıyor (stats API 127.0.0.1:10000)."
else
  warn "xray.service başlatılamadı ya da 10000 dinlemiyor: journalctl -u xray"
fi

log "Xray paneli yerleştiriliyor (v2ray-agent)…"
VA_SRC="${STACK_DIR}/scripts/v2ray-agent/install.sh"
if [[ -f "${VA_SRC}" ]]; then
  install -m 0755 "${VA_SRC}" /usr/local/bin/va
  ok "Panel hazır: va (baba menüsünde 'Xray Yönetimi'); çalıştırılana kadar sisteme dokunmaz."
else
  warn "scripts/v2ray-agent/install.sh bulunamadı; panel kurulmadı."
fi

log "Kota/süre denetleyicisi kuruluyor…"
# Eski panelin limit* daemon'ları aynı sayaçları okuyup aynı dosyalara yazar;
# ikisi birlikte çalışırsa kullanım çift sayılır. vpnlimit devralır.
for legacy_unit in limitvless limitvmess limittrojan limitshadowsocks; do
  if systemctl is-enabled "${legacy_unit}" >/dev/null 2>&1 || systemctl is-active --quiet "${legacy_unit}" 2>/dev/null; then
    systemctl disable --now "${legacy_unit}" >/dev/null 2>&1 || true
    log "Eski ${legacy_unit} daemon'u kapatıldı (vpnlimit devraldı)."
  fi
done
install -m 0644 "${STACK_DIR}/deploy/vpnlimit.service" /etc/systemd/system/vpnlimit.service
systemctl daemon-reload
systemctl enable vpnlimit >/dev/null 2>&1 || true
systemctl restart vpnlimit >/dev/null 2>&1 || true
if systemctl is-active --quiet vpnlimit; then
  ok "vpnlimit çalışıyor (Xray kotaları ve süresi her turda denetlenir)."
else
  warn "vpnlimit başlatılamadı: journalctl -u vpnlimit"
fi

log "fail2ban yapılandırılıyor..."
JAILS=""
if [[ -f /etc/fail2ban/filter.d/dropbear.conf ]]; then
  JAILS="[dropbear]
enabled = true
"
fi
cat > /etc/fail2ban/jail.d/vpnstack.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

${JAILS}
EOF
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban başlatılamadı."
ok "fail2ban hazır (sshd${JAILS:+, dropbear})."

SERVER_IP="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
[[ -n "${SERVER_IP}" ]] || SERVER_IP="$(hostname -I | awk '{print $1}')"

echo
echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}          VPN STACK KURULUMU TAMAMLANDI        ${NC}"
echo -e "${GREEN}===============================================${NC}"
echo -e " Sürüm           : ${GREEN}${VERSION}${NC}"
echo -e " Terminal Menü   : ${GREEN}baba${NC} (veya vpnmenu)"
echo -e " Xray Menü       : ${GREEN}baba [6]${NC} · ${GREEN}xraymenu${NC} · panel: ${GREEN}va${NC}"
echo -e " Kota Denetimi   : ${GREEN}vpnlimit${NC} (kota + süre)"
echo -e " Sing-box Menü   : ${GREEN}singbox${NC}"
echo -e " Sağlık Kontrolü : ${GREEN}vpnctl doctor${NC}"
echo -e " Sunucu IP       : ${GREEN}${SERVER_IP}${NC}"
echo -e " Domain          : ${GREEN}${DOMAIN:-$(cat /etc/xray/domain 2>/dev/null || echo '-')}${NC} · TLS: ${GREEN}/etc/xray/xray.crt${NC}"
echo -e " Sertifika       : ${GREEN}${CERT_SOURCE:-mevcut}${NC}"
echo -e " SSH Portları    : ${GREEN}80${NC} (haproxy) / ${GREEN}10015${NC} (sshproxy)"
echo -e " SSH Hedefi      : ${GREEN}127.0.0.1:109${NC}"
echo -e " Sing-box Config : ${GREEN}${SINGBOX_CONFIG}${NC}"
echo -e " Servisler       : ${GREEN}systemctl status ws ws-ovpn haproxy sing-box xray${NC}"
echo -e "${GREEN}===============================================${NC}"
