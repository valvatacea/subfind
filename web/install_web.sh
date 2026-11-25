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
SSL_ENABLED="${SSL_ENABLED:-0}"
SSL_DOMAIN="${SSL_DOMAIN:-}"
SSL_CERT="/etc/nginx/ssl/subfind_fullchain.pem"
SSL_KEY="/etc/nginx/ssl/subfind_key.pem"
SSL_CHAIN="/etc/nginx/ssl/subfind.pem"

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
        apt-get install -y nginx php-fpm php-cli php-curl php-json acl >/dev/null 2>&1 || true
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
    # Pastikan www-data bisa traverse ke WEB_DIR.
    # Utamakan ACL (izin hanya untuk www-data). Set mask r-x agar efektif.
    if ! command -v setfacl >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y acl >/dev/null 2>&1 || true
        fi
    fi
    if command -v setfacl >/dev/null 2>&1; then
        setfacl -m u:www-data:rx,m::rx /root 2>/dev/null || true
        setfacl -m u:www-data:rx,m::rx "$INSTALL_DIR" 2>/dev/null || true
        chmod 750 /root 2>/dev/null || true
        chmod 750 "$INSTALL_DIR" 2>/dev/null || true
        log_ok "ACL www-data:rx diterapkan (mode aman, /root 750)"
    else
        chmod 755 /root 2>/dev/null || true
        chmod 755 "$INSTALL_DIR" 2>/dev/null || true
        log_warn "acl tidak tersedia; fallback chmod 755 /root"
    fi
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

extract_root_domain() {
    local domain="$1"
    local psl_file="$2"
    local parts count best_len line trimmed
    local best_suffix="" best_len=0
    local ddots="${domain//[^.]/}"
    parts=${#ddots}
    parts=$((parts + 1))
    local line_count=0
    while IFS= read -r line; do
        line_count=$((line_count + 1))
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        line="$trimmed"
        [[ -z "$line" || "$line" == //* ]] && continue
        if [[ "$line" == \*.* ]]; then
            line="${line#*.}"
        fi
        [[ "$line" == !* ]] && continue
        [[ -z "$line" ]] && continue
        local sdots="${line//[^.]/}"
        count=${#sdots}
        count=$((count + 1))
        if [[ "$domain" == "$line" || "$domain" == *".$line" ]]; then
            if [ "$count" -gt "$best_len" ] && [ "$parts" -gt "$count" ]; then
                best_suffix="$line"
                best_len="$count"
            fi
        fi
    done < "$psl_file"
    if [ -n "$best_suffix" ]; then
        local start=$((parts - best_len))
        local remaining="$domain"
        local idx=1
        while [ $idx -lt $start ]; do
            remaining="${remaining#*.}"
            idx=$((idx + 1))
        done
        echo "$remaining"
        return 0
    fi
    return 1
}

setup_ssl() {
    # Jika SSL_DOMAIN tidak di-set via env, tanya user
    if [ -z "$SSL_DOMAIN" ]; then
        echo ""
        read -rp "Aktifkan SSL (HTTPS) via acme.sh + Cloudflare DNS? (y/N): " _ssl_ans
        case "${_ssl_ans:-N}" in
            y|Y) ;;
            *) log_info "SSL dinonaktifkan (HTTP only)."; SSL_ENABLED=0; return 0 ;;
        esac
        read -rp "Domain/Host untuk SSL (contoh: subfind.example.com): " SSL_DOMAIN
        [ -z "$SSL_DOMAIN" ] && { log_error "Domain kosong, SSL dibatalkan."; SSL_ENABLED=0; return 0; }
    fi
    SSL_ENABLED=1
    export SSL_DOMAIN

    # Ekstraksi root domain via Public Suffix List (tiru natssh)
    INSTALL_DIR_SSL="${SUBFIND_INSTALL_DIR:-/root/subfind}"
    PSL_DIR="$INSTALL_DIR_SSL/config"
    mkdir -p "$PSL_DIR"
    PSL_FILE="$PSL_DIR/public_suffix_list.dat"
    if [ ! -s "$PSL_FILE" ]; then
        log_info "Mengunduh Public Suffix List..."
        wget -q "https://publicsuffix.org/list/public_suffix_list.dat" -O "$PSL_FILE" 2>/dev/null || true
    fi
    ROOT_DOMAIN=""
    if [ -s "$PSL_FILE" ]; then
        ROOT_DOMAIN="$(extract_root_domain "$SSL_DOMAIN" "$PSL_FILE")" || ROOT_DOMAIN=""
    fi
    if [ -z "$ROOT_DOMAIN" ]; then
        ROOT_DOMAIN="$SSL_DOMAIN"
    fi
    if [ "$ROOT_DOMAIN" = "$SSL_DOMAIN" ]; then
        log_warn "Suffix domain '$SSL_DOMAIN' tidak ditemukan di PSL."
        read -rp "Lanjutkan terbitkan sertifikat untuk $ROOT_DOMAIN? (y/N): " _c
        case "${_c:-N}" in y|Y) ;; *) log_warn "SSL dibatalkan."; SSL_ENABLED=0; return 0 ;; esac
    fi
    log_ok "Root domain untuk sertifikat (wildcard): $ROOT_DOMAIN"
    export ROOT_DOMAIN

    # Kredensial Cloudflare
    if [ -z "${CF_Token:-}" ] && [ -z "${CF_Key:-}" ]; then
        echo ""
        echo -e "${YELLOW}Pilih jenis kredensial Cloudflare:${NC}"
        echo "  1) API Token"
        echo "  2) API Key + Email"
        read -rp "Pilihan (1-2, 0 = batal SSL): " cf_pilih
        case "$cf_pilih" in
            1) read -rp "Cloudflare API Token: " CF_Token; export CF_Token ;;
            2) read -rp "Cloudflare API Key: " CF_Key; read -rp "Cloudflare Account Email: " CF_Email; export CF_Key CF_Email ;;
            0|"") log_warn "SSL dibatalkan."; SSL_ENABLED=0; return 0 ;;
            *) log_warn "Pilihan tidak valid, SSL dibatalkan."; SSL_ENABLED=0; return 0 ;;
        esac
    fi
    [ -n "${CF_Token:-}" ] && export CF_Token
    [ -n "${CF_Key:-}" ] && export CF_Key
    [ -n "${CF_Email:-}" ] && export CF_Email

    if [ -z "${CF_Token:-}" ] && [ -z "${CF_Key:-}" ]; then
        log_error "Kredensial Cloudflare kosong, SSL dibatalkan."
        SSL_ENABLED=0
        return 0
    fi

    # Install acme.sh jika belum ada
    if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
        log_info "Memasang acme.sh..."
        curl -fsSL https://get.acme.sh | sh -s email="${CF_Email:-admin@example.com}" >/dev/null 2>&1 || true
    fi
    if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
        log_error "acme.sh tidak tersedia, SSL dibatalkan."
        SSL_ENABLED=0
        return 0
    fi

    mkdir -p /etc/nginx/ssl
    log_info "Menerbitkan sertifikat SSL untuk $SSL_DOMAIN via acme.sh (Cloudflare DNS)..."
    "$HOME/.acme.sh/acme.sh" --issue --force --dns dns_cf -d "*.${ROOT_DOMAIN}" -d "${ROOT_DOMAIN}" \
        --cert-file "$SSL_CHAIN" \
        --key-file "$SSL_KEY" \
        --fullchain-file "$SSL_CERT" \
        --reloadcmd "systemctl reload nginx" || {
            log_error "Gagal menerbitkan sertifikat. SSL dibatalkan."
            SSL_ENABLED=0
            return 0
        }
    log_ok "Sertifikat SSL diterbitkan."

    # Cron auto-renew
    if ! crontab -l 2>/dev/null | grep -q "acme.sh --cron"; then
        (crontab -l 2>/dev/null; echo "0 2 * * * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh >> /var/log/acme-renew.log 2>&1") | crontab -
        log_ok "Cron auto-renew acme.sh ditambahkan."
    fi
}

create_nginx_conf() {
    local sock
    sock="$(find_php_socket)"
    local conf="/etc/nginx/sites-available/subfind-web"
    log_info "Membuat nginx config (port $PORT, socket $sock)..."

    if [ "$SSL_ENABLED" = "1" ]; then
        cat > "$conf" <<EOF
server {
    listen $PORT ssl;
    listen [::]:$PORT ssl;

    server_name $SSL_DOMAIN;
    root $WEB_DIR;
    index index.php;

    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;

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
    else
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
    fi

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
    if [ "$SSL_ENABLED" = "1" ]; then
        echo "  Web UI: https://$SSL_DOMAIN:$PORT/"
    else
        echo "  Web UI: http://<IP-server>:$PORT/"
    fi
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
    setup_ssl
    create_nginx_conf
    test_and_restart
    verify
    echo ""
    echo "Selesai. Ubah port via env: WEB_PORT=8081 sudo bash web/install_web.sh"
    echo ""
}

main "$@"
