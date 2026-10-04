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
  curl -fsSL https://sing-box.app/install.sh | bash >/dev/null 2>&1 || die "Sing-box kurulumu başarısız."
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
  wget -N -q -O /root/singbox.sh https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/Install.sh || warn "Sing-box Manager indirilemedi."
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

for p in 109 143; do
  if ! (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then
    warn "127.0.0.1:${p} dinlemiyor — doğrudan SSH için dropbear'ı bu portta yapılandırın."
  fi
done

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
