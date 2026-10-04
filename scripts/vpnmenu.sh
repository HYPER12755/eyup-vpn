#!/usr/bin/env bash
set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

GROUP="sshvpn"
SSH_PORT_PUBLIC="80"
SSH_PORT_DIRECT="10015"
SSH_TARGET="127.0.0.1:109"
SINGBOX_DIR="/usr/local/etc/sing-box"
SINGBOX_CONFIG="${SINGBOX_DIR}/config.json"
SINGBOX_CERT_DIR="${SINGBOX_DIR}"
REALITY_PORT_MIN=1443
REALITY_PORT_MAX=1499
MENU_CONF="/etc/sshvpn/menu.conf"
DEFAULT_HOST="can.vps-mosto.site"
FAKE_HOST=""
EXTRA_HEADER=""

[[ "${EUID}" -eq 0 ]] || { echo -e "${RED}Bu menü root olarak çalıştırılmalıdır.${NC}"; exit 1; }

load_menu_conf() {
  if [[ -f "${MENU_CONF}" ]]; then
    local key value
    while IFS='=' read -r key value; do
      case "${key}" in
        FAKE_HOST) [[ -n "${value}" ]] && FAKE_HOST="${value}" ;;
        EXTRA_HEADER) EXTRA_HEADER="${value}" ;;
      esac
    done < "${MENU_CONF}"
  fi
}

save_menu_conf() {
  mkdir -p "$(dirname "${MENU_CONF}")"
  printf 'FAKE_HOST=%s\nEXTRA_HEADER=%s\n' "${FAKE_HOST}" "${EXTRA_HEADER}" > "${MENU_CONF}"
  chmod 600 "${MENU_CONF}"
}

client_host() {
  echo "${FAKE_HOST:-${DEFAULT_HOST}}"
}

server_ip() {
  local ip
  ip="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "${ip}" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "${ip}" ]] || ip="127.0.0.1"
  echo "${ip}"
}

ensure_group() {
  getent group "${GROUP}" >/dev/null 2>&1 || groupadd -f "${GROUP}" >/dev/null 2>&1
}

random_username() {
  local name
  command -v openssl >/dev/null 2>&1 || { echo -e "${RED}openssl bulunamadı.${NC}" >&2; return 1; }
  for _ in $(seq 1 20); do
    name="$(openssl rand -base64 24 2>/dev/null | tr -dc 'a-z0-9' | cut -c1-6)"
    if [[ "${name}" =~ ^[a-z] ]] && ! id -u "${name}" >/dev/null 2>&1; then
      echo "${name}"
      return 0
    fi
  done
  return 1
}

random_password() {
  local password
  password="$(openssl rand -base64 24 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-8)"
  [[ -n "${password}" ]] || return 1
  echo "${password}"
}

random_free_port() {
  local port
  for _ in $(seq 1 50); do
    port=$(( (RANDOM % 50001) + 10000 ))
    ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN || { echo "${port}"; return; }
  done
  echo "$(( (RANDOM % 50001) + 10000 ))"
}

random_free_port_range() {
  local lo="$1" hi="$2" port
  for _ in $(seq 1 50); do
    port=$(( lo + RANDOM % (hi - lo + 1) ))
    ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN || { echo "${port}"; return; }
  done
  echo "${lo}"
}

account_expiry() {
  local user="$1"
  chage -l "${user}" 2>/dev/null | awk -F': ' '/Account expires/ {print $2}'
}

payload_get() {
  local host="$1"
  local extra=""
  [[ -n "${EXTRA_HEADER}" ]] && extra="${EXTRA_HEADER}[crlf]"
  printf 'GET / HTTP/1.1[crlf]Host: %s[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]%s[crlf]' \
    "${host}" "${extra}"
}

payload_connect() {
  local host="$1"
  local extra=""
  [[ -n "${EXTRA_HEADER}" ]] && extra="${EXTRA_HEADER}[crlf]"
  printf 'CONNECT %s HTTP/1.1[crlf]Host: %s[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]X-Real-Host: %s[crlf]X-Split: 1[crlf]%s[crlf]' \
    "${SSH_TARGET}" "${host}" "${SSH_TARGET}" "${extra}"
}

create_account() {
  ensure_group
  load_menu_conf

  local days username password expiry host_input header_input
  read -r -p "$(echo -e "${CYAN}Süre (gün, varsayılan 30, 0 = süresiz):${NC} ")" days
  days="${days:-30}"
  [[ "${days}" =~ ^[0-9]+$ ]] || days=30

  read -r -p "$(echo -e "${CYAN}SSH Host / alan adı (varsayılan: ${FAKE_HOST:-${DEFAULT_HOST}}):${NC} ")" host_input
  [[ -n "${host_input}" ]] && FAKE_HOST="${host_input}"

  read -r -p "$(echo -e "${CYAN}Ek header (örn. Backend: elsanor, boş = yok):${NC} ")" header_input
  [[ -n "${header_input}" ]] && EXTRA_HEADER="${header_input}"

  save_menu_conf

  username="$(random_username)" || { echo -e "${RED} kullanıcı adı üretilemedi.${NC}"; return 1; }
  password="$(random_password)" || { echo -e "${RED}Şifre üretilemedi.${NC}"; return 1; }

  if [[ "${days}" -eq 0 ]]; then
    expiry="-1"
  else
    expiry="$(date -d "+${days} days" +%Y-%m-%d)"
  fi

  if ! useradd -M -s /bin/false -G "${GROUP}" "${username}" 2>/dev/null; then
    echo -e "${RED}Hesap oluşturulamadı.${NC}"
    return 1
  fi
  # chpasswd/chage başarısız olursa hesap yarım kalmasın: geri al.
  if ! echo "${username}:${password}" | chpasswd 2>/dev/null; then
    userdel "${username}" 2>/dev/null
    echo -e "${RED}Şifre atanamadı, hesap oluşturulmadı.${NC}"
    return 1
  fi
  if ! chage -E "${expiry}" -M 99999 "${username}" >/dev/null 2>&1; then
    userdel "${username}" 2>/dev/null
    echo -e "${RED}Süre atanamadı, hesap oluşturulmadı.${NC}"
    return 1
  fi

  local host expires_text
  host="$(client_host)"
  expires_text="Süresiz"
  [[ "${expiry}" != "-1" ]] && expires_text="${expiry}"

  echo
  echo -e "${GREEN}==============================================${NC}"
  echo -e "${GREEN}            SSH HESABI OLUŞTURULDU             ${NC}"
  echo -e "${GREEN}==============================================${NC}"
  echo -e " SSH Host    : ${GREEN}http://${host}${NC}"
  echo -e " Port        : ${GREEN}${SSH_PORT_PUBLIC}${NC} (alternatif: ${SSH_PORT_DIRECT})"
  echo -e " Kullanıcı   : ${GREEN}${username}${NC}"
  echo -e " Şifre       : ${GREEN}${password}${NC}"
  echo -e " Bitiş       : ${GREEN}${expires_text}${NC}"
  [[ -n "${EXTRA_HEADER}" ]] && echo -e " Ek Header   : ${GREEN}${EXTRA_HEADER}${NC}"
  echo -e "${CYAN}----------------------------------------------${NC}"
  echo -e "${YELLOW}Payload 1 (GET):${NC}"
  echo -e "${CYAN}$(payload_get "${host}")${NC}"
  echo -e "${YELLOW}Payload 2 (CONNECT):${NC}"
  echo -e "${CYAN}$(payload_connect "${host}")${NC}"
  echo -e "${GREEN}==============================================${NC}"
  echo
}

client_settings() {
  load_menu_conf
  echo
  echo -e " Mevcut SSH Host : ${GREEN}${FAKE_HOST:-${DEFAULT_HOST}}${NC}"
  echo -e " Mevcut Header   : ${GREEN}${EXTRA_HEADER:-<yok>}${NC}"
  echo
  local host_input header_input
  read -r -p "$(echo -e "${CYAN}Yeni SSH Host / alan adı (boş = değişmez):${NC} ")" host_input
  [[ -n "${host_input}" ]] && FAKE_HOST="${host_input}"
  read -r -p "$(echo -e "${CYAN}Yeni ek header (boş = değişmez, '-' = temizle):${NC} ")" header_input
  if [[ "${header_input}" == "-" ]]; then
    EXTRA_HEADER=""
  elif [[ -n "${header_input}" ]]; then
    EXTRA_HEADER="${header_input}"
  fi
  save_menu_conf
  echo -e "${GREEN}Kaydedildi.${NC}"
}

list_accounts() {
  local members
  members="$(getent group "${GROUP}" 2>/dev/null | awk -F: '{print $4}')"
  if [[ -z "${members}" ]]; then
    echo -e "${YELLOW}Henüz SSH hesabı yok.${NC}"
    return
  fi

  echo
  printf "${BOLD}%-12s %-12s %-10s %s${NC}\n" "KULLANICI" "DURUM" "ŞİFRE" "BİTİŞ"
  echo "------------------------------------------------------------"
  local user status
  for user in ${members//,/ }; do
    status="$(passwd -S "${user}" 2>/dev/null | awk '{print $2}')"
    [[ "${status}" == "P" ]] && status="${GREEN}aktif${NC}" || status="${RED}kilitli${NC}"
    printf "%-12s %-22s %-10s %s\n" "${user}" "${status}" "***" "$(account_expiry "${user}")"
  done
  echo
}

delete_account() {
  local members
  members="$(getent group "${GROUP}" 2>/dev/null | awk -F: '{print $4}')"
  if [[ -z "${members}" ]]; then
    echo -e "${YELLOW}Silinecek hesap yok.${NC}"
    return
  fi

  local username
  read -r -p "$(echo -e "${CYAN}Silinecek kullanıcı adı:${NC} ")" username
  [[ -n "${username}" ]] || return
  if ! id -u "${username}" >/dev/null 2>&1; then
    echo -e "${RED}Kullanıcı bulunamadı: ${username}${NC}"
    return
  fi
  # Yalnızca ${GROUP} üyesi silinebilir; aksi halde bir yazım hatası sistem
  # hesabını siler.
  if [[ ",${members// /}," != *",${username},"* ]]; then
    echo -e "${RED}${username}, ${GROUP} grubunda değil — silinmedi.${NC}"
    return
  fi

  local answer
  read -r -p "$(echo -e "${YELLOW}${username} silinsin mi? (e/H):${NC} ")" answer
  if [[ "${answer}" =~ ^[eEyY]$ ]]; then
    userdel "${username}" 2>/dev/null && echo -e "${GREEN}${username} silindi.${NC}" || echo -e "${RED}Silinemedi.${NC}"
  fi
}

service_menu() {
  echo
  systemctl is-active ws.service >/dev/null 2>&1 && echo -e " ws.service      : ${GREEN}aktif${NC}" || echo -e " ws.service      : ${RED}kapalı${NC}"
  systemctl is-active haproxy.service >/dev/null 2>&1 && echo -e " haproxy.service : ${GREEN}aktif${NC}" || echo -e " haproxy.service : ${RED}kapalı${NC}"
  systemctl is-active sing-box.service >/dev/null 2>&1 && echo -e " sing-box.service: ${GREEN}aktif${NC}" || echo -e " sing-box.service: ${RED}kapalı${NC}"
  echo
  local answer
  read -r -p "$(echo -e "${CYAN}Servisleri yeniden başlat? (e/H):${NC} ")" answer
  if [[ "${answer}" =~ ^[eEyY]$ ]]; then
    systemctl restart ws.service 2>/dev/null
    systemctl restart haproxy.service 2>/dev/null
    systemctl restart sing-box.service 2>/dev/null
    echo -e "${GREEN}Servisler yeniden başlatıldı.${NC}"
  fi
}

system_info() {
  echo
  echo -e " Sunucu IP : ${GREEN}$(server_ip)${NC}"
  echo -e " SSH Port  : ${GREEN}${SSH_PORT_PUBLIC}${NC} (haproxy) / ${GREEN}${SSH_PORT_DIRECT}${NC} (ws)"
  echo -e " Hedef     : ${GREEN}${SSH_TARGET}${NC}"
  echo -e " SSH Host  : ${GREEN}${FAKE_HOST:-${DEFAULT_HOST}}${NC}"
  echo -e " Sing-box  : ${GREEN}${SINGBOX_CONFIG}${NC}"
  echo
}

run_singbox_manager() {
  if [[ ! -f /usr/local/bin/singbox ]]; then
    echo -e "${RED}Sing-box Manager bulunamadı (/usr/local/bin/singbox).${NC}"
    return
  fi
  bash /usr/local/bin/singbox
}

singbox_ensure_config() {
  mkdir -p "${SINGBOX_DIR}"
  [[ -s "${SINGBOX_CONFIG}" ]] || printf '%s\n' '{"log":{"level":"info","timestamp":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}' > "${SINGBOX_CONFIG}"
}

resolve_tls_cert() {
  local domain="$1"
  if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
    echo "/etc/letsencrypt/live/${domain}/fullchain.pem:/etc/letsencrypt/live/${domain}/privkey.pem"
    return
  fi
  mkdir -p "${SINGBOX_CERT_DIR}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${SINGBOX_CERT_DIR}/${domain}.key" \
    -out "${SINGBOX_CERT_DIR}/${domain}.crt" \
    -days 3650 -subj "/CN=${domain}" >/dev/null 2>&1
  echo "${SINGBOX_CERT_DIR}/${domain}.crt:${SINGBOX_CERT_DIR}/${domain}.key"
}

singbox_apply_inbound() {
  local inbound="$1"
  singbox_ensure_config

  local tmp
  # Hedefle aynı dosya sisteminde olmalı: /tmp ayrı bir mount ise mv kopyalayıp
  # siler ve kesinti sonrası kırpık config.json bırakır.
  tmp="$(mktemp "${SINGBOX_CONFIG}.XXXXXX")"
  if ! jq --argjson inb "${inbound}" '.inbounds = ((.inbounds // []) + [$inb])' "${SINGBOX_CONFIG}" > "${tmp}"; then
    echo -e "${RED}Config güncellenemedi.${NC}"
    rm -f "${tmp}"
    return 1
  fi
  if ! sing-box check -c "${tmp}" >/dev/null 2>&1; then
    echo -e "${RED}Config doğrulaması başarısız:${NC}"
    sing-box check -c "${tmp}" 2>&1 | tail -3
    rm -f "${tmp}"
    return 1
  fi

  cp -f "${SINGBOX_CONFIG}" "${SINGBOX_CONFIG}.bak"
  mv -f "${tmp}" "${SINGBOX_CONFIG}"
  systemctl reload sing-box >/dev/null 2>&1 || systemctl restart sing-box >/dev/null 2>&1
}

singbox_create_inbound() {
  echo
  echo -e " Protokol: ${BOLD}[1]${NC} VLESS  ${BOLD}[2]${NC} Hysteria2  ${BOLD}[3]${NC} TUIC"
  local proto_choice protocol
  read -r -p "$(echo -e "${CYAN}Seçim (varsayılan 1):${NC} ")" proto_choice
  proto_choice="${proto_choice:-1}"
  case "${proto_choice}" in
    1) protocol="vless" ;;
    2) protocol="hysteria2" ;;
    3) protocol="tuic" ;;
    *) echo -e "${RED}Geçersiz seçim.${NC}"; return ;;
  esac

  local security="tls" domain="" sni="" cert="" key="" certpair=""
  if [[ "${protocol}" == "vless" ]]; then
    local sec_choice
    echo -e " Güvenlik: ${BOLD}[1]${NC} TLS (alan adı)  ${BOLD}[2]${NC} REALITY (SNI)"
    read -r -p "$(echo -e "${CYAN}Seçim (varsayılan 1):${NC} ")" sec_choice
    sec_choice="${sec_choice:-1}"
    [[ "${sec_choice}" == "2" ]] && security="reality"
  fi

  local port listen_addr link_port
  if [[ "${security}" == "reality" ]]; then
    read -r -p "$(echo -e "${CYAN}Port (boş = ${REALITY_PORT_MIN}-${REALITY_PORT_MAX} arası boş, haproxy 443 SNI ile yayınlar):${NC} ")" port
    if [[ -z "${port}" ]]; then
      port="$(random_free_port_range "${REALITY_PORT_MIN}" "${REALITY_PORT_MAX}")"
    elif [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < REALITY_PORT_MIN || port > REALITY_PORT_MAX )); then
      echo -e "${RED}REALITY portu ${REALITY_PORT_MIN}-${REALITY_PORT_MAX} aralığında olmalı.${NC}"
      return 1
    fi
    listen_addr="127.0.0.1"
    link_port=443
  else
    read -r -p "$(echo -e "${CYAN}Port (boş = rastgele 10000-60000):${NC} ")" port
    [[ -n "${port}" ]] || port="$(random_free_port)"
    listen_addr="::"
    link_port="${port}"
  fi

  if [[ "${security}" == "reality" ]]; then
    read -r -p "$(echo -e "${CYAN}REALITY SNI (örn. www.microsoft.com):${NC} ")" sni
    [[ -n "${sni}" ]] || { echo -e "${RED}SNI zorunlu.${NC}"; return; }
  else
    read -r -p "$(echo -e "${CYAN}TLS alan adı (örn. bedavakralik.duckdns.org):${NC} ")" domain
    [[ -n "${domain}" ]] || { echo -e "${RED}Alan adı zorunlu.${NC}"; return; }
    certpair="$(resolve_tls_cert "${domain}")"
    cert="${certpair%%:*}"
    key="${certpair##*:}"
  fi

  local tag uuid password inbound link ip
  ip="$(server_ip)"
  tag="${protocol}-$(date +%s)"
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  password="$(random_password)"

  case "${protocol}" in
    vless)
      if [[ "${security}" == "reality" ]]; then
        local keypair priv pub sid
        keypair="$(sing-box generate reality-keypair)"
        priv="$(echo "${keypair}" | awk -F': ' '/PrivateKey/{print $2}')"
        pub="$(echo "${keypair}" | awk -F': ' '/PublicKey/{print $2}')"
        sid="$(sing-box generate rand --hex 8)"
        inbound="$(jq -n --arg tag "${tag}" --arg listen "${listen_addr}" --argjson port "${port}" --arg uuid "${uuid}" --arg sni "${sni}" --arg priv "${priv}" --arg sid "${sid}" \
          '{type:"vless",tag:$tag,listen:$listen,listen_port:$port,users:[{name:"user1",uuid:$uuid,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$sni,reality:{enabled:true,handshake:{server:$sni,server_port:443},private_key:$priv,short_id:[$sid]}}}')"
        link="vless://${uuid}@${ip}:${link_port}?type=tcp&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${sid}&flow=xtls-rprx-vision#${tag}"
      else
        inbound="$(jq -n --arg tag "${tag}" --arg listen "${listen_addr}" --argjson port "${port}" --arg uuid "${uuid}" --arg domain "${domain}" --arg cert "${cert}" --arg key "${key}" \
          '{type:"vless",tag:$tag,listen:$listen,listen_port:$port,users:[{name:"user1",uuid:$uuid,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$domain,certificate_path:$cert,key_path:$key}}')"
        link="vless://${uuid}@${ip}:${link_port}?type=tcp&security=tls&sni=${domain}&flow=xtls-rprx-vision#${tag}"
      fi
      ;;
    hysteria2)
      inbound="$(jq -n --arg tag "${tag}" --arg listen "${listen_addr}" --argjson port "${port}" --arg pass "${password}" --arg domain "${domain}" --arg cert "${cert}" --arg key "${key}" \
        '{type:"hysteria2",tag:$tag,listen:$listen,listen_port:$port,users:[{name:"user1",password:$pass}],tls:{enabled:true,server_name:$domain,certificate_path:$cert,key_path:$key,alpn:["h3"]}}')"
      link="hysteria2://${password}@${ip}:${link_port}/?sni=${domain}#${tag}"
      ;;
    tuic)
      inbound="$(jq -n --arg tag "${tag}" --arg listen "${listen_addr}" --argjson port "${port}" --arg uuid "${uuid}" --arg pass "${password}" --arg domain "${domain}" --arg cert "${cert}" --arg key "${key}" \
        '{type:"tuic",tag:$tag,listen:$listen,listen_port:$port,users:[{name:"user1",uuid:$uuid,password:$pass}],congestion_control:"bbr",tls:{enabled:true,server_name:$domain,certificate_path:$cert,key_path:$key,alpn:["h3"]}}')"
      link="tuic://${uuid}:${password}@${ip}:${link_port}/?sni=${domain}&congestion_control=bbr#${tag}"
      ;;
  esac

  singbox_apply_inbound "${inbound}" || return

  echo
  echo -e "${GREEN}==============================================${NC}"
  echo -e "${GREEN}           INBOUND OLUŞTURULDU                 ${NC}"
  echo -e "${GREEN}==============================================${NC}"
  echo -e " Tag       : ${GREEN}${tag}${NC}"
  echo -e " Protokol  : ${GREEN}${protocol}${NC}"
  if [[ "${security}" == "reality" ]]; then
    echo -e " Port      : ${GREEN}${port}${NC} (yalnızca ${listen_addr} · haproxy 443 SNI ile yayınlanır)"
  else
    echo -e " Port      : ${GREEN}${port}${NC}"
  fi
  if [[ "${security}" == "reality" ]]; then
    echo -e " Güvenlik  : ${GREEN}REALITY${NC} (SNI: ${sni})"
  else
    echo -e " Güvenlik  : ${GREEN}TLS${NC} (alan adı: ${domain})"
  fi
  echo -e " Bağlantı  : ${CYAN}${link}${NC}"
  echo -e "${GREEN}==============================================${NC}"
  echo
}

singbox_list_inbounds() {
  singbox_ensure_config
  local count
  count="$(jq '.inbounds | length' "${SINGBOX_CONFIG}" 2>/dev/null || echo 0)"
  if [[ "${count}" == "0" ]]; then
    echo -e "${YELLOW}Inbound yok.${NC}"
    return
  fi
  echo
  printf "${BOLD}%-26s %-11s %-8s %s${NC}\n" "TAG" "PROTOKOL" "PORT" "GÜVENLİK"
  echo "-------------------------------------------------------------------"
  jq -r '.inbounds[] | [.tag, .type, (.listen_port|tostring), (if .tls.reality.enabled then "reality" elif .tls.enabled then "tls" else "yok" end)] | @tsv' "${SINGBOX_CONFIG}" |
    while IFS=$'\t' read -r tag proto port sec; do
      printf "%-26s %-11s %-8s %s\n" "${tag}" "${proto}" "${port}" "${sec}"
    done
  echo
}

singbox_delete_inbound() {
  singbox_ensure_config
  singbox_list_inbounds
  local tag tmp
  read -r -p "Silinecek tag: " tag
  [[ -n "${tag}" ]] || return

  tmp="$(mktemp "${SINGBOX_CONFIG}.XXXXXX")"
  if ! jq --arg tag "${tag}" '.inbounds |= map(select(.tag != $tag))' "${SINGBOX_CONFIG}" > "${tmp}"; then
    rm -f "${tmp}"
    return
  fi
  if ! sing-box check -c "${tmp}" >/dev/null 2>&1; then
    echo -e "${RED}Doğrulama başarısız.${NC}"
    rm -f "${tmp}"
    return
  fi
  cp -f "${SINGBOX_CONFIG}" "${SINGBOX_CONFIG}.bak"
  mv -f "${tmp}" "${SINGBOX_CONFIG}"
  systemctl reload sing-box >/dev/null 2>&1 || systemctl restart sing-box >/dev/null 2>&1
  echo -e "${GREEN}${tag} silindi.${NC}"
}

singbox_menu() {
  while true; do
    echo
    echo -e "${CYAN}${BOLD}  [1] Inbound oluştur   [2] Inbound listele   [3] Inbound sil${NC}"
    echo -e "${CYAN}${BOLD}  [4] Servis yeniden başlat   [0] Geri${NC}"
    local choice
    read -r -p "$(echo -e "${CYAN}Seçim:${NC} ")" choice
    case "${choice}" in
      1) singbox_create_inbound ;;
      2) singbox_list_inbounds ;;
      3) singbox_delete_inbound ;;
      4) systemctl restart sing-box >/dev/null 2>&1 && echo -e "${GREEN}sing-box yeniden başlatıldı.${NC}" ;;
      0) return ;;
      *) echo -e "${RED}Geçersiz seçim.${NC}" ;;
    esac
  done
}

menu() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔════════════════════════════════════════╗"
  echo "  ║            BABA YÖNETİM MENÜSÜ         ║"
  echo "  ╠════════════════════════════════════════╣"
  echo "  ║  [1] SSH Hesabı Oluştur (otomatik)     ║"
  echo "  ║  [2] Hesapları Listele                 ║"
  echo "  ║  [3] Hesap Sil                         ║"
  echo "  ║  [4] Servis Durumu / Yeniden Başlat    ║"
  echo "  ║  [5] Sistem Bilgisi                    ║"
  echo "  ║  [6] Sing-box Manager                 ║"
  echo "  ║  [7] İstemci Ayarları (Host/Header)    ║"
  echo "  ║  [0] Çıkış                             ║"
  echo "  ╚════════════════════════════════════════╝"
  echo -e "${NC}"
}

while true; do
  menu
  read -r -p "$(echo -e "${CYAN}Seçim:${NC} ")" choice
  case "${choice}" in
    1) create_account ;;
    2) list_accounts ;;
    3) delete_account ;;
    4) service_menu ;;
    5) system_info ;;
    6) run_singbox_manager ;;
    7) client_settings ;;
    0) echo -e "${GREEN}Çıkılıyor.${NC}"; exit 0 ;;
    *) echo -e "${RED}Geçersiz seçim.${NC}" ;;
  esac
  echo
  read -r -p "$(echo -e "${YELLOW}Devam etmek için Enter...${NC}")" _
done
