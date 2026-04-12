#!/usr/bin/env bash
# =============================================================================
#  MTProxy installer
#  Copies pre-built binary, creates config, installs systemd service.
# =============================================================================
set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n"; }
ask()     { echo -e "${YELLOW}[?]${RESET} $*"; }

# ── constants ────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/mtproxy"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
BINARY_NAME="mtproxy"
SERVICE_NAME="mtproxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="mtproxy"

# ── helpers ──────────────────────────────────────────────────────────────────
require_root() {
    [[ "$EUID" -eq 0 ]] || error "Run as root: sudo bash install.sh"
}

require_cmd() {
    command -v "$1" &>/dev/null || error "'$1' not found. Install it first."
}

gen_hex16() {
    # 16 random bytes → 32 hex chars
    if command -v openssl &>/dev/null; then
        openssl rand -hex 16
    else
        cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32
    fi
}

str_to_hex() {
    echo -n "$1" | xxd -p | tr -d '\n'
}

detect_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipecho.net/plain" "https://ifconfig.me"; do
        ip=$(curl -s --max-time 4 "$url" 2>/dev/null || true)
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
    done
    echo "YOUR_SERVER_IP"
}

make_tg_link() {
    local ip="$1" port="$2" secret="$3"
    echo "tg://proxy?server=${ip}&port=${port}&secret=${secret}"
    echo "https://t.me/proxy?server=${ip}&port=${port}&secret=${secret}"
}

# ── find binary ──────────────────────────────────────────────────────────────
find_binary() {
    # 1. same dir as this script
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    local candidates=(
        "${script_dir}/target/release/${BINARY_NAME}"
        "${script_dir}/${BINARY_NAME}"
        "./${BINARY_NAME}"
    )
    for f in "${candidates[@]}"; do
        [[ -x "$f" ]] && { echo "$f"; return 0; }
    done
    return 1
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════
require_root
require_cmd xxd
require_cmd curl

clear
echo -e "${BOLD}${CYAN}"
echo "  ███╗   ███╗████████╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗"
echo "  ████╗ ████║╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝"
echo "  ██╔████╔██║   ██║   ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ "
echo "  ██║╚██╔╝██║   ██║   ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  "
echo "  ██║ ╚═╝ ██║   ██║   ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   "
echo "  ╚═╝     ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  "
echo -e "${RESET}"
echo -e "  ${BOLD}MTProto Proxy Installer${RESET}  (Rust edition)\n"

# ── locate binary ────────────────────────────────────────────────────────────
header "Locate binary"

BINARY_SRC=""
if BINARY_SRC=$(find_binary); then
    info "Found binary: ${BINARY_SRC}"
else
    ask "Binary not found automatically."
    read -rp "    Enter full path to the mtproxy binary: " BINARY_SRC
    [[ -x "$BINARY_SRC" ]] || error "File '${BINARY_SRC}' does not exist or is not executable."
fi

# ── listen port ──────────────────────────────────────────────────────────────
header "Listening port"

ask "Port to listen on [default: 443]:"
read -rp "    > " INPUT_PORT
PORT="${INPUT_PORT:-443}"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] \
    || error "Invalid port: ${PORT}"
info "Port: ${PORT}"

# ── secret mode ──────────────────────────────────────────────────────────────
header "Secret / obfuscation mode"

echo "  1) FakeTLS  — wraps traffic in fake TLS 1.3  [recommended, harder to block]"
echo "  2) Secure   — dd-prefix obfuscation"
echo "  3) Classic  — plain obfuscated"
echo ""
ask "Choose mode [1/2/3, default: 1]:"
read -rp "    > " MODE_INPUT
MODE="${MODE_INPUT:-1}"

SECRET_RAW=""
SECRET_DISPLAY=""
TG_SECRET=""

case "$MODE" in
# ── FakeTLS ──
1)
    ask "TLS domain to mimic [default: cloudflare.com]:"
    read -rp "    > " DOMAIN_INPUT
    TLS_DOMAIN="${DOMAIN_INPUT:-cloudflare.com}"

    ask "Secret hex (32 chars, leave empty to generate):"
    read -rp "    > " HEX_INPUT
    if [[ -z "$HEX_INPUT" ]]; then
        HEX_INPUT=$(gen_hex16)
        info "Generated secret: ${HEX_INPUT}"
    fi
    [[ ${#HEX_INPUT} -eq 32 && "$HEX_INPUT" =~ ^[0-9a-fA-F]+$ ]] \
        || error "Secret must be exactly 32 hex characters."

    DOMAIN_HEX=$(str_to_hex "$TLS_DOMAIN")
    TG_SECRET="ee${HEX_INPUT}${DOMAIN_HEX}"
    SECRET_RAW="${TG_SECRET}"
    SECRET_DISPLAY="FakeTLS  domain=${TLS_DOMAIN}  secret=${HEX_INPUT}"
    ;;
# ── Secure ──
2)
    ask "Secret hex (32 chars, leave empty to generate):"
    read -rp "    > " HEX_INPUT
    if [[ -z "$HEX_INPUT" ]]; then
        HEX_INPUT=$(gen_hex16)
        info "Generated secret: ${HEX_INPUT}"
    fi
    [[ ${#HEX_INPUT} -eq 32 && "$HEX_INPUT" =~ ^[0-9a-fA-F]+$ ]] \
        || error "Secret must be exactly 32 hex characters."

    TG_SECRET="dd${HEX_INPUT}"
    SECRET_RAW="${TG_SECRET}"
    SECRET_DISPLAY="Secure (dd)  secret=${HEX_INPUT}"
    ;;
# ── Classic ──
3)
    ask "Secret hex (32 chars, leave empty to generate):"
    read -rp "    > " HEX_INPUT
    if [[ -z "$HEX_INPUT" ]]; then
        HEX_INPUT=$(gen_hex16)
        info "Generated secret: ${HEX_INPUT}"
    fi
    [[ ${#HEX_INPUT} -eq 32 && "$HEX_INPUT" =~ ^[0-9a-fA-F]+$ ]] \
        || error "Secret must be exactly 32 hex characters."

    TG_SECRET="${HEX_INPUT}"
    SECRET_RAW="${HEX_INPUT}"
    SECRET_DISPLAY="Classic  secret=${HEX_INPUT}"
    ;;
*)
    error "Unknown mode: ${MODE}"
    ;;
esac

info "Mode: ${SECRET_DISPLAY}"

# ── optional: add more users ─────────────────────────────────────────────────
declare -A USERS
USERS["user1"]="${SECRET_RAW}"

header "Additional users (optional)"
echo "  You can add more users now, or press Enter to skip."

while true; do
    ask "Add another user? [y/N]:"
    read -rp "    > " ADD_MORE
    [[ "$ADD_MORE" =~ ^[Yy]$ ]] || break

    ask "  Username:"
    read -rp "    > " UNAME
    [[ -n "$UNAME" ]] || { warn "Empty username, skipping."; continue; }

    echo "  Secret mode: 1=FakeTLS  2=Secure  3=Classic  4=Paste full secret"
    read -rp "    > " UMODE

    case "$UMODE" in
    1)
        ask "  TLS domain [cloudflare.com]:"
        read -rp "    > " UDOMAIN
        UDOMAIN="${UDOMAIN:-cloudflare.com}"
        USECRET=$(gen_hex16)
        UHEX=$(str_to_hex "$UDOMAIN")
        USERS["$UNAME"]="ee${USECRET}${UHEX}"
        info "  ${UNAME}: ee${USECRET}${UHEX}"
        ;;
    2)
        USECRET=$(gen_hex16)
        USERS["$UNAME"]="dd${USECRET}"
        info "  ${UNAME}: dd${USECRET}"
        ;;
    3)
        USECRET=$(gen_hex16)
        USERS["$UNAME"]="${USECRET}"
        info "  ${UNAME}: ${USECRET}"
        ;;
    4)
        ask "  Full secret string:"
        read -rp "    > " UFULL
        USERS["$UNAME"]="${UFULL}"
        ;;
    *)
        warn "Unknown mode, skipping."
        ;;
    esac
done

# ── mask host ────────────────────────────────────────────────────────────────
header "Mask host (for non-proxy clients)"
ask "Host to forward non-proxy clients to [default: www.google.com]:"
read -rp "    > " MASK_INPUT
MASK_HOST="${MASK_INPUT:-www.google.com}"
info "Mask host: ${MASK_HOST}"

# ── summary ──────────────────────────────────────────────────────────────────
header "Summary"
echo -e "  Install dir : ${BOLD}${INSTALL_DIR}${RESET}"
echo -e "  Binary      : ${BOLD}${BINARY_SRC}${RESET}"
echo -e "  Port        : ${BOLD}${PORT}${RESET}"
echo -e "  Mask host   : ${BOLD}${MASK_HOST}${RESET}"
echo -e "  Users       : ${BOLD}${#USERS[@]}${RESET}"
for u in "${!USERS[@]}"; do
    echo -e "    ${CYAN}${u}${RESET} = ${USERS[$u]}"
done
echo ""
ask "Proceed with installation? [Y/n]:"
read -rp "    > " CONFIRM
[[ "${CONFIRM:-Y}" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ── install ──────────────────────────────────────────────────────────────────
header "Installing"

# create system user
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    info "Created system user '${SERVICE_USER}'"
fi

# create install dir
mkdir -p "${INSTALL_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

# copy binary
cp "${BINARY_SRC}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
chown root:root "${INSTALL_DIR}/${BINARY_NAME}"
info "Binary installed → ${INSTALL_DIR}/${BINARY_NAME}"

# give capability to bind port < 1024 without root
if command -v setcap &>/dev/null && [[ "$PORT" -lt 1024 ]]; then
    setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/${BINARY_NAME}"
    info "Set cap_net_bind_service on binary (needed for port ${PORT})"
fi

# ── write config.toml ────────────────────────────────────────────────────────
{
    echo "# MTProxy config — generated by install.sh on $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo ""
    echo "listen    = \"0.0.0.0:${PORT}\""
    echo "mask_host = \"${MASK_HOST}\""
    echo ""
    echo "[users]"
    for u in "${!USERS[@]}"; do
        echo "${u} = \"${USERS[$u]}\""
    done
} > "${CONFIG_FILE}"
chmod 640 "${CONFIG_FILE}"
chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
info "Config written → ${CONFIG_FILE}"

# ── write systemd unit ───────────────────────────────────────────────────────
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=MTProto Proxy (Rust)
Documentation=https://github.com/alexbers/mtprotoproxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# Allow binding to port ${PORT} (net capability set on binary)
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
info "Systemd unit written → ${SERVICE_FILE}"

# ── firewall ─────────────────────────────────────────────────────────────────
header "Firewall"
if command -v ufw &>/dev/null; then
    ufw allow "${PORT}/tcp" &>/dev/null && info "ufw: opened port ${PORT}/tcp"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="${PORT}/tcp" &>/dev/null
    firewall-cmd --reload &>/dev/null
    info "firewalld: opened port ${PORT}/tcp"
elif command -v iptables &>/dev/null; then
    iptables -C INPUT -p tcp --dport "${PORT}" -j ACCEPT &>/dev/null \
        || iptables -A INPUT -p tcp --dport "${PORT}" -j ACCEPT
    info "iptables: opened port ${PORT}/tcp"
else
    warn "No firewall manager found — open port ${PORT} manually if needed."
fi

# ── enable & start service ───────────────────────────────────────────────────
header "Service"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
sleep 1

if systemctl is-active --quiet "${SERVICE_NAME}"; then
    info "Service '${SERVICE_NAME}' is running ✓"
else
    warn "Service may not have started. Check: journalctl -u ${SERVICE_NAME} -n 30"
fi

# ── print proxy links ────────────────────────────────────────────────────────
header "Proxy links"

PUBLIC_IP=$(detect_public_ip)
echo -e "  ${BOLD}Server IP:${RESET} ${PUBLIC_IP}"
echo -e "  ${BOLD}Port:${RESET} ${PORT}"
echo ""

for u in "${!USERS[@]}"; do
    S="${USERS[$u]}"
    echo -e "  ${BOLD}${CYAN}── ${u} ──${RESET}"
    echo -e "  Secret : ${S}"
    echo -e "  tg://proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${S}"
    echo -e "  https://t.me/proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${S}"
    echo ""
done

# ── save links to file ───────────────────────────────────────────────────────
LINKS_FILE="${INSTALL_DIR}/proxy_links.txt"
{
    echo "# MTProxy links — generated $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "# Server: ${PUBLIC_IP}:${PORT}"
    echo ""
    for u in "${!USERS[@]}"; do
        S="${USERS[$u]}"
        echo "## ${u}"
        echo "tg://proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${S}"
        echo "https://t.me/proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${S}"
        echo ""
    done
} > "${LINKS_FILE}"
chmod 640 "${LINKS_FILE}"
chown root:"${SERVICE_USER}" "${LINKS_FILE}"
info "Links saved → ${LINKS_FILE}"

# ── done ─────────────────────────────────────────────────────────────────────
header "Done"
echo -e "  ${GREEN}${BOLD}MTProxy successfully installed!${RESET}"
echo ""
echo -e "  Useful commands:"
echo -e "    ${CYAN}systemctl status ${SERVICE_NAME}${RESET}          — service status"
echo -e "    ${CYAN}journalctl -u ${SERVICE_NAME} -f${RESET}           — live logs"
echo -e "    ${CYAN}systemctl restart ${SERVICE_NAME}${RESET}          — restart"
echo -e "    ${CYAN}cat ${LINKS_FILE}${RESET}  — proxy links"
echo ""
