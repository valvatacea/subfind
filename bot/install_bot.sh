#!/usr/bin/env bash
# ============================================================================
# subfind - Comprehensive Telegram Bot Installer
# Instalasi + service systemd untuk bot/ (D2IP / SubFind / CDNScan / SNIScan)
# Jalankan sebagai root: sudo bash bot/install_bot.sh
# ============================================================================
set -euo pipefail

INSTALL_DIR="${SUBFIND_INSTALL_DIR:-/root/subfind}"
BOT_DIR="$INSTALL_DIR/bot"
VENV_DIR="$INSTALL_DIR/.venv"
SERVICE_NAME="subfind-bot"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="$BOT_DIR/.env"
REQ_FILE="$BOT_DIR/requirements.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; NC='\033[0m'
log_info(){ echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok(){ echo -e "${GREEN}[OK]${NC}  $*"; }
log_warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error(){ echo -e "${RED}[ERR]${NC}  $*" >&2; }

# ---------- helpers ----------
need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Jalankan sebagai root (sudo)."
        exit 1
    fi
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "Python3 tidak ditemukan."
        exit 1
    fi
    log_ok "Python $(python3 --version) ditemukan"
}

install_system_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        log_info "Menginstal dependensi sistem (python3-venv, python3-pip)..."
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true
        log_ok "Dependensi sistem siap"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 python3-pip >/dev/null 2>&1 || true
    else
        log_warn "Package manager tidak dikenal, lewati instalasi sistem"
    fi
}

setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Membuat virtualenv di $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
    fi
    log_ok "Virtualenv siap"
    if [ -f "$REQ_FILE" ]; then
        log_info "Menginstal requirements bot..."
        "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
        "$VENV_DIR/bin/pip" install -r "$REQ_FILE"
        log_ok "Dependensi bot terinstal"
    else
        log_warn "requirements.txt tidak ditemukan, lewati"
    fi
}

setup_env() {
    if [ ! -f "$ENV_FILE" ] && [ -f "$BOT_DIR/.env.example" ]; then
        cp "$BOT_DIR/.env.example" "$ENV_FILE"
        log_ok "bot/.env dibuat dari .env.example"
    fi

    # Pastikan BOT_TOKEN terisi
    _token_val="$(grep -E '^BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    if [ ! -f "$ENV_FILE" ] || [ -z "$_token_val" ] || [ "$_token_val" = "isi_token_bot_anda_disini" ] || [[ "$_token_val" == isi_token* ]]; then
        log_warn "BOT_TOKEN belum terisi di $ENV_FILE"
        read -rp "Masukkan BOT_TOKEN: " token
        if [ -z "$token" ]; then
            log_error "BOT_TOKEN kosong, instalasi dibatalkan"
            exit 1
        fi
        if grep -q '^BOT_TOKEN=' "$ENV_FILE" 2>/dev/null; then
            sed -i "s|^BOT_TOKEN=.*|BOT_TOKEN=$token|" "$ENV_FILE"
        else
            echo "BOT_TOKEN=$token" >> "$ENV_FILE"
        fi
        log_ok "BOT_TOKEN disimpan"
    else
        log_ok "BOT_TOKEN sudah ada di .env"
    fi
    chmod 600 "$ENV_FILE"
}

setup_profile() {
    if [ -f "$BOT_DIR/setup_profile.py" ]; then
        log_info "Menjalankan setup profil bot (commands, description, foto)..."
        "$VENV_DIR/bin/python" "$BOT_DIR/setup_profile.py" || log_warn "Setup profil gagal (boleh dijalankan manual nanti)"
    fi
}

create_service() {
    log_info "Membuat systemd service $SERVICE_NAME..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Subfind Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$VENV_DIR/bin/python -m bot.main
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    log_ok "Service $SERVICE_NAME dibuat & di-enable"
}

start_service() {
    log_info "Menjalankan service $SERVICE_NAME..."
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_ok "Service $SERVICE_NAME aktif"
    else
        log_error "Service gagal start. Cek: journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

verify() {
    log_info "Verifikasi..."
    if "$VENV_DIR/bin/python" -c "import telebot; print('telebot ok')" >/dev/null 2>&1; then
        log_ok "Import telebot OK"
    else
        log_warn "Import telebot gagal"
    fi
    systemctl is-active --quiet "$SERVICE_NAME" && log_ok "Service aktif" || log_warn "Service tidak aktif"
}

main() {
    echo ""
    echo "============================================================"
    echo "  subfind - Comprehensive Telegram Bot Installer"
    echo "============================================================"
    echo ""

    need_root
    check_python

    if [ ! -d "$INSTALL_DIR" ]; then
        log_info "Clone repo..."
        git clone --depth 1 https://github.com/valvatacea/subfind.git "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"

    setup_venv
    setup_env
    setup_profile
    create_service
    start_service
    verify

    echo ""
    echo "============================================================"
    echo "  Instalasi bot selesai!"
    echo "============================================================"
    echo ""
    echo "  Service : $SERVICE_NAME"
    echo "  Status  : systemctl status $SERVICE_NAME"
    echo "  Log     : journalctl -u $SERVICE_NAME -f"
    echo "  Env     : $ENV_FILE"
    echo "  Venv    : $VENV_DIR"
    echo ""
    echo "  Untuk stop:    systemctl stop $SERVICE_NAME"
    echo "  Untuk restart: systemctl restart $SERVICE_NAME"
    echo ""
}

main "$@"
