#!/usr/bin/env bash
# ============================================================================
# subfind - Web UI installer (nginx + PHP-FPM) untuk folder web/
# Menjalankan index.php / scan.php via HTTP.
# Jalankan sebagai root: sudo bash web/install_web.sh
# ============================================================================
set -euo pipefail

INSTALL_DIR="${SUBFIND_INSTALL_DIR:-/root/subfind}"
WEB_DIR="$INSTALL_DIR/web"
# Port: dari env WEB_PORT, atau tanya user
if [ -z "${WEB_PORT:-}" ]; then
    read -rp "Port web UI [8080]: " PORT
    PORT="${PORT:-8080}"
else
    PORT="$WEB_PORT"
fi
SERVICE_NGINX="nginx"
PHP_FPM_SERVICE=""

RED='\033[0;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info(){ echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok(){ echo -e "${GREEN}[OK]${NC}  $*"; }
log_warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error(){ echo -e "${RED}[ERR]${NC}  $*"; } >&2

need_root() { [ "$(id -u)" -eq 0 ] || { log_error "Jalankan sebagai root (sudo)."; exit 1; }; }

detect_php_fpm() {
    for svc in $(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -E '^php[0-9.]+-fpm\.service$'); do
        PHP_FPM_SERVICE="${svc%.service}"
        return 0
    done
    if command -v php-fpm >/dev/null 2>&1; then
        PHP_FPM_SERVICE="php-fpm"
        return 0
    fi
    return 1
}

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        log_info "Menginstal nginx + php-fpm via apt..."
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y nginx php-fpm php-cli php-curl php-json >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y nginx php php-fpm php-cli >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y nginx php php-fpm php-cli >/dev/null 2>&1 || true
    else
        log_warn "Package manager tidak dikenal"
    fi
    if ! detect_php_fpm; then
        log_error "php-fpm tidak ditemukan setelah instalasi."
        exit 1
    fi
    log_ok "nginx + $PHP_FPM_SERVICE siap"
}

setup_dirs() {
    mkdir -p "$WEB_DIR"
    mkdir -p "$INSTALL_DIR/output" "$INSTALL_DIR/output/states" "$INSTALL_DIR/output/ipranges"
    chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || true
    chmod 755 "$WEB_DIR"
    chown -R www-data:www-data "$INSTALL_DIR/output" 2>/dev/null || true
    # Pastikan www-data bisa traverse ke WEB_DIR (parent /root sering 700)
    chmod 755 /root 2>/dev/null || true
    chmod 755 "$INSTALL_DIR" 2>/dev/null || true
    # Pastikan www-data bisa eksekusi venv python (untuk scan.php)
    if [ -d "$INSTALL_DIR/.venv" ]; then
        chmod 755 "$INSTALL_DIR" "$INSTALL_DIR/.venv" "$INSTALL_DIR/.venv/bin" 2>/dev/null || true
        chmod 755 "$INSTALL_DIR/.venv/bin/python"* 2>/dev/null || true
    fi
    log_ok "Direktori siap"
}

find_php_socket() {
    for sock in /run/php/php*-fpm.sock /var/run/php/php*-fpm.sock; do
        if [ -S "$sock" ]; then
            echo "$sock"
            return 0
        fi
    done
    echo "/run/php/php-fpm.sock"
}

create_nginx_conf() {
    local sock
    sock="$(find_php_socket)"
    local conf="/etc/nginx/sites-available/subfind-web"
    log_info "Membuat nginx config (port $PORT, socket $sock)..."

    cat > "$conf" <<EOF
server {
    listen $PORT;
    listen [::]:$PORT;

    server_name _;
    root $WEB_DIR;
    index index.php;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \\.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\\.ht {
        deny all;
    }
}
EOF

    if [ -d /etc/nginx/sites-enabled ]; then
        ln -sf "$conf" /etc/nginx/sites-enabled/subfind-web
        # JANGAN hapus default site (bisa dipakai natssh/dll). subfind-web listen di port terpisah.
    fi
    log_ok "Nginx config dibuat"
}

test_and_restart() {
    log_info "Test konfigurasi nginx..."
    if ! nginx -t 2>&1 | tail -3; then
        log_error "Konfigurasi nginx invalid."
        exit 1
    fi
    log_ok "Config valid"

    log_info "Restart php-fpm + nginx..."
    systemctl restart "$PHP_FPM_SERVICE" 2>/dev/null || true
    systemctl enable "$PHP_FPM_SERVICE" >/dev/null 2>&1 || true
    systemctl restart nginx
    systemctl enable nginx >/dev/null 2>&1 || true
    log_ok "Service restarted"
}

verify() {
    log_info "Verifikasi..."
    if systemctl is-active --quiet nginx; then
        log_ok "nginx aktif"
    else
        log_warn "nginx tidak aktif"
    fi
    if systemctl is-active --quiet "$PHP_FPM_SERVICE"; then
        log_ok "$PHP_FPM_SERVICE aktif"
    else
        log_warn "$PHP_FPM_SERVICE tidak aktif"
    fi
    echo ""
    echo "  Web UI: http://<IP-server>:$PORT/"
    echo "  (pastikan firewall membuka port $PORT)"
}

main() {
    echo ""
    echo "============================================================"
    echo "  subfind - Web UI installer (nginx + PHP-FPM)"
    echo "============================================================"
    echo ""
    need_root

    # Reinstall otomatis: bersihkan config site lama + hasil scan lama (kecuali ipranges cache)
    log_info "Membersihkan config site lama (reinstall)..."
    rm -f /etc/nginx/sites-enabled/subfind-web /etc/nginx/sites-available/subfind-web
    if [ -d "$INSTALL_DIR/output" ]; then
        find "$INSTALL_DIR/output" -maxdepth 2 -type f \( -name '*.txt' -o -name '*.json' \) ! -path '*/ipranges/*' -delete 2>/dev/null || true
    fi
    log_ok "Config lama dibersihkan"

    install_deps
    setup_dirs
    create_nginx_conf
    test_and_restart
    verify
    echo ""
    echo "Selesai. Ubah port via env: WEB_PORT=8081 sudo bash web/install_web.sh"
    echo ""
}

main "$@"
