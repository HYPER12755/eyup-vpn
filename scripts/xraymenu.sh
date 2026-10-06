#!/usr/bin/env bash
# Xray yönetim menüsü — Türkçe arayüz.
# Config işlemleri xraycfg (scripts/xraycfg.py) üzerinden yapılır; o araç
# marker tabanlı düzeni korur ve her değişikliği `xray -test` ile doğrular.
set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

XRAY_CFG="/etc/xray/config.json"
DOMAIN_FILE="/etc/xray/domain"
XRAYCFG_BIN="/usr/local/bin/xraycfg"
VA_BIN="/usr/local/bin/va"
BOX_WIDTH=56

[[ "${EUID}" -eq 0 ]] || { echo -e "${RED}Bu menü root olarak çalıştırılmalıdır.${NC}"; exit 1; }

# --- kutu çizimi: Türkçe karakterler bayt değil karakter sayılır, aksi halde
# --- hizalama kayar (printf %-Ns bayta göre dolgu yapar).
box_rule() {
  local left="$1" mid="$2" right="$3" i
  printf '  %s' "${left}"
  for ((i = 0; i < BOX_WIDTH; i++)); do printf '%s' "${mid}"; done
  printf '%s\n' "${right}"
}

box_top()    { box_rule "┌" "─" "┐"; }
box_mid()    { box_rule "├" "─" "┤"; }
box_bottom() { box_rule "└" "─" "┘"; }

# Görünen uzunluk: ANSI renk kodları düşülür; aksi halde renkli satırların
# hizası kayar.
visible_len() {
  local clean
  clean="$(printf '%s' "$1" | sed -r 's/\x1b\[[0-9;]*m//g')"
  echo "${#clean}"
}

box_line() {
  local text="$1" pad len
  len="$(visible_len "${text}")"
  pad=$((BOX_WIDTH - 1 - len))
  ((pad < 0)) && pad=0
  printf '  │ %s%*s│\n' "${text}" "${pad}" ""
}

box_center() {
  local text="$1" left right len
  len="$(visible_len "${text}")"
  left=$(( (BOX_WIDTH - len) / 2 ))
  ((left < 1)) && left=1
  right=$((BOX_WIDTH - len - left))
  ((right < 0)) && right=0
  printf '  │%*s%s%*s│\n' "${left}" "" "${text}" "${right}" ""
}

find_xraycfg() {
  if [[ -x "${XRAYCFG_BIN}" ]]; then
    echo "${XRAYCFG_BIN}"
  elif [[ -f "$(dirname "${BASH_SOURCE[0]}")/xraycfg.py" ]]; then
    echo "python3 $(dirname "${BASH_SOURCE[0]}")/xraycfg.py"
  else
    echo ""
  fi
}

server_domain() {
  local domain=""
  [[ -f "${DOMAIN_FILE}" ]] && domain="$(head -n1 "${DOMAIN_FILE}" 2>/dev/null)"
  echo "${domain}"
}

user_counts() {
  local xcfg out
  xcfg="$(find_xraycfg)"
  if [[ -z "${xcfg}" ]]; then
    echo "0 0 0"
    return
  fi
  out="$(${xcfg} list --tsv 2>/dev/null)"
  printf '%s %s %s' \
    "$(echo "${out}" | grep -c '^vless' || true)" \
    "$(echo "${out}" | grep -c '^vmess' || true)" \
    "$(echo "${out}" | grep -c '^trojan' || true)"
}

print_banner() {
  local domain tls_expiry counts vless vmess trojan state
  domain="$(server_domain)"
  counts="$(user_counts)"
  vless="${counts%% *}"; counts="${counts#* }"
  vmess="${counts%% *}"; trojan="${counts#* }"
  tls_expiry=""
  if [[ -f /etc/xray/xray.crt ]]; then
    tls_expiry="$(openssl x509 -in /etc/xray/xray.crt -noout -enddate 2>/dev/null | cut -d= -f2)"
  fi

  echo
  box_top
  box_center "$(echo -e "${BOLD}XRAY YÖNETİM PANELİ${NC}")"
  box_mid
  if systemctl is-active --quiet xray 2>/dev/null; then
    state="${GREEN}● açık${NC}"
  else
    state="${RED}● kapalı${NC}"
  fi
  box_line "$(echo -e "Servis    : ${state}")"
  box_line "$(echo -e "Domain    : ${GREEN}${domain:-<tanımsız>}${NC}")"
  box_line "$(echo -e "Sertifika : ${GREEN}${tls_expiry:-<yok>}${NC}")"
  box_line "$(echo -e "Kullanıcı : VLESS ${GREEN}${vless}${NC} · VMess ${GREEN}${vmess}${NC} · Trojan ${GREEN}${trojan}${NC}")"
  box_line "$(echo -e "${DIM}/vless /vmess /trojan-ws · grpc 443${NC}")"
  box_bottom
}

menu() {
  echo
  box_top
  box_center "$(echo -e "${BOLD}İŞLEM MENÜSÜ${NC}")"
  box_mid
  box_line "[1] Kullanıcı Ekle"
  box_line "[2] Kullanıcıları Listele"
  box_line "[3] Kullanıcı Sil"
  box_line "[4] Kullanıcı Detayı / Linkler"
  box_line "[5] Config Test + Servisi Yenile"
  box_line "[6] Gelişmiş Panel (v2ray-agent)"
  box_line "[0] Geri"
  box_bottom
}

random_name() {
  openssl rand -base64 24 2>/dev/null | tr -dc 'a-z0-9' | cut -c1-6
}

restart_xray() {
  echo
  if systemctl restart xray >/dev/null 2>&1 && systemctl is-active --quiet xray; then
    echo -e "${GREEN}Xray yeniden başlatıldı ve çalışıyor.${NC}"
  else
    echo -e "${RED}Xray yeniden başlatılamadı!${NC} journalctl -u xray"
  fi
}

create_user() {
  local xcfg proto_choice proto name days input
  xcfg="$(find_xraycfg)"
  [[ -n "${xcfg}" ]] || { echo -e "${RED}xraycfg bulunamadı (install.sh çalıştırın).${NC}"; return 1; }

  echo
  echo -e " Protokol: ${BOLD}[1]${NC} VLESS  ${BOLD}[2]${NC} VMess  ${BOLD}[3]${NC} Trojan"
  read -r -p "$(echo -e "${CYAN}Seçim (varsayılan 1):${NC} ")" proto_choice
  case "${proto_choice:-1}" in
    1) proto="vless" ;;
    2) proto="vmess" ;;
    3) proto="trojan" ;;
    *) echo -e "${RED}Geçersiz seçim.${NC}"; return 1 ;;
  esac

  name="$(random_name)"
  read -r -p "$(echo -e "${CYAN}Kullanıcı adı (varsayılan ${name}):${NC} ")" input
  [[ -n "${input}" ]] && name="${input}"
  [[ "${name}" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo -e "${RED}Geçersiz ad (harf, rakam, _ -).${NC}"; return 1; }

  read -r -p "$(echo -e "${CYAN}Süre, gün (varsayılan 30, 0 = süresiz):${NC} ")" days
  days="${days:-30}"
  [[ "${days}" =~ ^[0-9]+$ ]] || days=30

  echo
  if ${xcfg} add "${proto}" "${name}" --days "${days}"; then
    echo
    echo -e "${GREEN}==============================================${NC}"
    echo -e "${GREEN}            KULLANICI OLUŞTURULDU              ${NC}"
    echo -e "${GREEN}==============================================${NC}"
    echo -e " Proto : ${GREEN}${proto}${NC}"
    echo -e " Süre  : ${GREEN}$([[ "${days}" == "0" ]] && echo süresiz || date -d "+${days} days" +%Y-%m-%d)${NC}"
    echo
    echo -e "${YELLOW}Bağlantı linkleri:${NC}"
    XRAY_DOMAIN="$(server_domain)" ${xcfg} links "${name}" || true
    echo -e "${GREEN}==============================================${NC}"
    restart_xray
  else
    echo -e "${RED}Kullanıcı eklenemedi.${NC}"
  fi
}

list_users() {
  local xcfg
  xcfg="$(find_xraycfg)"
  [[ -n "${xcfg}" ]] || { echo -e "${RED}xraycfg bulunamadı.${NC}"; return 1; }
  echo
  ${xcfg} list
}

user_detail() {
  local xcfg name
  xcfg="$(find_xraycfg)"
  read -r -p "$(echo -e "${CYAN}Kullanıcı adı:${NC} ")" name
  [[ -n "${name}" ]] || return
  echo
  ${xcfg} list | awk -v u="${name}" 'NR==1 || $2==u'
  echo
  XRAY_DOMAIN="$(server_domain)" ${xcfg} links "${name}" || true
}

delete_user() {
  local xcfg name proto_choice proto
  xcfg="$(find_xraycfg)"
  list_users
  echo
  read -r -p "$(echo -e "${CYAN}Silinecek kullanıcı adı:${NC} ")" name
  [[ -n "${name}" ]] || return
  echo -e " Protokol: ${BOLD}[1]${NC} VLESS  ${BOLD}[2]${NC} VMess  ${BOLD}[3]${NC} Trojan"
  read -r -p "$(echo -e "${CYAN}Seçim (varsayılan 1):${NC} ")" proto_choice
  case "${proto_choice:-1}" in
    1) proto="vless" ;;
    2) proto="vmess" ;;
    3) proto="trojan" ;;
    *) echo -e "${RED}Geçersiz seçim.${NC}"; return ;;
  esac
  ${xcfg} del "${proto}" "${name}" || return
  restart_xray
}

test_and_restart() {
  local xcfg
  xcfg="$(find_xraycfg)"
  echo
  if ${xcfg} test; then
    echo -e "${GREEN}Config geçerli.${NC}"
  else
    echo -e "${RED}Config geçersiz! Düzeltmeden yeniden başlatmayın.${NC}"
    return 1
  fi
  restart_xray
}

run_va_panel() {
  if [[ ! -x "${VA_BIN}" ]]; then
    echo -e "${RED}Gelişmiş panel kurulu değil (${VA_BIN}).${NC}"
    return 1
  fi
  echo -e "${YELLOW}Not: v2ray-agent (mack-a) arayüzü Çince'dir ve kendi kurulum düzenini yönetir;${NC}"
  echo -e "${YELLOW}mevcut haproxy/sing-box/sshproxy yapılandırmasını değiştirebilir.${NC}"
  echo -e "${YELLOW}Üretimde önce: vpnctl backup${NC}"
  local answer
  read -r -p "$(echo -e "${CYAN}Panel açılsın mı? (e/H):${NC} ")" answer
  [[ "${answer}" =~ ^[eEyY]$ ]] && bash "${VA_BIN}"
}

while true; do
  print_banner
  menu
  read -r -p "$(echo -e "${CYAN}Seçim:${NC} ")" choice
  case "${choice}" in
    1) create_user ;;
    2) list_users ;;
    3) delete_user ;;
    4) user_detail ;;
    5) test_and_restart ;;
    6) run_va_panel ;;
    0) exit 0 ;;
    *) echo -e "${RED}Geçersiz seçim.${NC}" ;;
  esac
  echo
  read -r -p "$(echo -e "${YELLOW}Devam etmek için Enter...${NC}")" _
done
