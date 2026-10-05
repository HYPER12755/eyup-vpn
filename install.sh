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
apt-get install -y -qq curl wget git sudo ufw ca-certificates openssl jq unzip tar haproxy net-tools fail2ban >/dev/null
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
install -m 0755 "${STACK_DIR}/scripts/vpnmenu.sh" /usr/local/bin/vpnmenu
ln -sf /usr/local/bin/vpnmenu /usr/local/bin/baba
ok "Kuruldu: sshproxy + sblink + vpnctl + vpnmenu (baba)"

log "Servisler yapılandırılıyor..."
install -m 0644 "${STACK_DIR}/deploy/ws.service" /etc/systemd/system/ws.service
install -m 0644 "${STACK_DIR}/deploy/ws-ovpn.service" /etc/systemd/system/ws-ovpn.service

HAPROXY_SRC="${STACK_DIR}/deploy/haproxy.cfg"
HAPROXY_DST="/etc/haproxy/haproxy.cfg"
if [[ ! -f "${HAPROXY_DST}" ]] || grep -q "# example config for haproxy" "${HAPROXY_DST}"; then
  if [[ -f "${HAPROXY_DST}" ]]; then
    cp -a "${HAPROXY_DST}" "${HAPROXY_DST}.vpnstack-backup"
    log "Stok haproxy.cfg yedeklendi: ${HAPROXY_DST}.vpnstack-backup"
  fi
  install -m 0644 "${HAPROXY_SRC}" "${HAPROXY_DST}"
  ok "haproxy.cfg kuruldu (80: WS/SSH · 443: REALITY SNI)."
elif ! grep -q "# vpnstack" "${HAPROXY_DST}"; then
  warn "${HAPROXY_DST} elle düzenlenmiş görünüyor; dokunulmadı. Eksik REALITY/SNI ve WS yönlendirmesini elle ekleyin."
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
if ! command -v dropbear >/dev/null 2>&1; then
  apt-get install -y -qq dropbear >/dev/null 2>&1 || warn "dropbear kurulamadı."
fi
if [[ -x /usr/sbin/dropbear ]]; then
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
ExecStart=/usr/sbin/dropbear -F -R -p 127.0.0.1:109 -p 127.0.0.1:143
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
  if systemctl restart dropbear-vpnstack >/dev/null 2>&1; then
    ok "dropbear 127.0.0.1:109 ve :143 dinliyor."
  else
    warn "dropbear-vpnstack başlatılamadı; journalctl -u dropbear-vpnstack"
  fi
else
  warn "dropbear kurulu değil; yalnızca openssh-server (:22) kullanılabilir."
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
echo -e " Sing-box Menü   : ${GREEN}singbox${NC}"
echo -e " Sağlık Kontrolü : ${GREEN}vpnctl doctor${NC}"
echo -e " Sunucu IP       : ${GREEN}${SERVER_IP}${NC}"
echo -e " SSH Portları    : ${GREEN}80${NC} (haproxy) / ${GREEN}10015${NC} (sshproxy)"
echo -e " SSH Hedefi      : ${GREEN}127.0.0.1:109${NC}"
echo -e " Sing-box Config : ${GREEN}${SINGBOX_CONFIG}${NC}"
echo -e " Servisler       : ${GREEN}systemctl status ws ws-ovpn haproxy sing-box${NC}"
echo -e "${GREEN}===============================================${NC}"
