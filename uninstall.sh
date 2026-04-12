#!/usr/bin/env bash
# =============================================================================
#  MTProxy uninstaller
#  Stops & disables the service, removes binary, config, systemd unit, user.
# =============================================================================
set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()   { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*"; }
error()  { echo -e "${RED}[✘]${RESET} $*" >&2; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n"; }
ask()    { echo -e "${YELLOW}[?]${RESET} $*"; }

# ── constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/mtproxy"
BINARY_NAME="mtproxy"
SERVICE_NAME="mtproxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="mtproxy"

# ── guards ────────────────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || error "Run as root: sudo bash uninstall.sh"

# ── detect installed port for firewall cleanup ────────────────────────────────
PORT=""
CONFIG_FILE="${INSTALL_DIR}/config.toml"
if [[ -f "$CONFIG_FILE" ]]; then
    PORT=$(grep -E '^listen\s*=' "$CONFIG_FILE" | grep -oE '[0-9]{1,5}"?$' | tr -d '"' || true)
fi

# ── confirm ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${RED}  MTProto Proxy — Uninstaller${RESET}\n"
echo -e "  This will remove:"
echo -e "    • systemd service  ${CYAN}${SERVICE_NAME}${RESET}"
echo -e "    • install dir      ${CYAN}${INSTALL_DIR}${RESET}"
echo -e "    • systemd unit     ${CYAN}${SERVICE_FILE}${RESET}"
echo -e "    • system user      ${CYAN}${SERVICE_USER}${RESET}"
[[ -n "$PORT" ]] && echo -e "    • firewall rule    ${CYAN}port ${PORT}/tcp${RESET}"
echo ""
ask "Proceed? [y/N]:"
read -rp "    > " CONFIRM
[[ "${CONFIRM}" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ── stop & disable service ────────────────────────────────────────────────────
header "Service"

if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}"
    info "Service stopped"
else
    warn "Service was not running"
fi

if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}"
    info "Service disabled"
fi

# ── remove systemd unit ───────────────────────────────────────────────────────
if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    info "Systemd unit removed → ${SERVICE_FILE}"
else
    warn "Systemd unit not found: ${SERVICE_FILE}"
fi

# ── remove install directory ──────────────────────────────────────────────────
header "Files"

if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    info "Removed ${INSTALL_DIR}"
else
    warn "Install dir not found: ${INSTALL_DIR}"
fi

# ── remove system user ────────────────────────────────────────────────────────
header "System user"

if id "${SERVICE_USER}" &>/dev/null; then
    userdel "${SERVICE_USER}"
    info "Removed system user '${SERVICE_USER}'"
else
    warn "User '${SERVICE_USER}' not found"
fi

# ── firewall ──────────────────────────────────────────────────────────────────
if [[ -n "$PORT" ]]; then
    header "Firewall"
    if command -v ufw &>/dev/null; then
        ufw delete allow "${PORT}/tcp" &>/dev/null && info "ufw: closed port ${PORT}/tcp"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --remove-port="${PORT}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        info "firewalld: closed port ${PORT}/tcp"
    elif command -v iptables &>/dev/null; then
        if iptables -C INPUT -p tcp --dport "${PORT}" -j ACCEPT &>/dev/null; then
            iptables -D INPUT -p tcp --dport "${PORT}" -j ACCEPT
            info "iptables: closed port ${PORT}/tcp"
        fi
    else
        warn "No firewall manager found — close port ${PORT} manually if needed."
    fi
fi

# ── done ──────────────────────────────────────────────────────────────────────
header "Done"
echo -e "  ${GREEN}${BOLD}MTProxy successfully removed.${RESET}\n"
