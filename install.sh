#!/usr/bin/env bash
# ============================================================================
# subfind - Installer Script
# Instalasi Subdomain & CDN Scanner Toolkit (CLI + Telegram Bot + Web UI)
# ============================================================================
set -euo pipefail

REPO_URL="https://github.com/valvatacea/subfind.git"
INSTALL_DIR="${SUBFIND_INSTALL_DIR:-$HOME/subfind}"
BIN_DIR="${SUBFIND_BIN_DIR:-$HOME/bin}"
REQUIRED_PYTHON="3"

# Warna output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERR]${NC}  $*" >&2; }

# -----------------------------------------------------------------------------
# Cek Python 3
# -----------------------------------------------------------------------------
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "Python 3 tidak ditemukan. Silakan install terlebih dahulu:"
        echo "  Debian/Ubuntu: sudo apt update && sudo apt install python3 python3-pip"
        echo "  Termux:        pkg install python"
        echo "  CentOS/RHEL:   sudo yum install python3"
        exit 1
    fi

    local py_ver
    py_ver=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
    local py_major="${py_ver%%.*}"
    local py_minor="${py_ver#*.}"

    if [ "$py_major" -lt "$REQUIRED_PYTHON" ]; then
        log_error "Python $REQUIRED_PYTHON+ diperlukan, ditemukan $py_ver"
        exit 1
    fi

    log_ok "Python $py_ver ditemukan"
}

# -----------------------------------------------------------------------------
# Clone atau update repo
# -----------------------------------------------------------------------------
setup_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        log_info "Repo sudah ada di $INSTALL_DIR, mengupdate..."
        cd "$INSTALL_DIR"
        git pull --rebase origin main || {
            log_warn "Gagal pull, coba reset ke origin/main"
            git fetch origin
            git reset --hard origin/main
        }
    else
        log_info "Meng-clone repo $REPO_URL ke $INSTALL_DIR ..."
        git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    fi

    cd "$INSTALL_DIR"
    log_ok "Repo siap di $INSTALL_DIR"
}

# -----------------------------------------------------------------------------
# Buat direktori output, states, dan web
# -----------------------------------------------------------------------------
setup_dirs() {
    mkdir -p "$INSTALL_DIR/output"
    mkdir -p "$INSTALL_DIR/output/states"
    mkdir -p "$INSTALL_DIR/output/ipranges"
    mkdir -p "$INSTALL_DIR/web"
    log_ok "Direktori output dan web siap di $INSTALL_DIR"
}

# -----------------------------------------------------------------------------
# Buat file skrip executable
# -----------------------------------------------------------------------------
make_executable() {
    chmod +x "$INSTALL_DIR/d2ip.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/cdnscan.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/subfind.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/sniscan.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/etc/git-rebase.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/etc/update_subfind.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/bot/setup_profile.py" 2>/dev/null || true
    log_ok "File skrip dibuat executable"
}

# -----------------------------------------------------------------------------
# Buat symlink di BIN_DIR untuk akses cepat
# -----------------------------------------------------------------------------
create_symlinks() {
    mkdir -p "$BIN_DIR"

    local items=(
        "cdnscan.py:cdnscan"
        "subfind.py:subfind"
        "d2ip.py:d2ip"
        "sniscan.py:sniscan"
    )

    for item in "${items[@]}"; do
        local src="${item%%:*}"
        local name="${item##*:}"
        local src_path="$INSTALL_DIR/$src"
        local link_path="$BIN_DIR/$name"

        if [ ! -e "$src_path" ]; then
            log_warn "$src_path tidak ditemukan, dilewati"
            continue
        fi

        if [ -e "$link_path" ] || [ -L "$link_path" ]; then
            log_warn "$BIN_DIR/$name sudah ada, dilewati"
        else
            ln -sf "$src_path" "$link_path"
            log_ok "Symlink $name -> $BIN_DIR/$name"
        fi
    done
}

# -----------------------------------------------------------------------------
# Setup bot (opsional)
# -----------------------------------------------------------------------------
setup_bot() {
    local bot_dir="$INSTALL_DIR/bot"
    local env_file="$INSTALL_DIR/.env"
    local env_example="$INSTALL_DIR/.env.example"

    if [ ! -d "$bot_dir" ]; then
        log_warn "Folder bot/ tidak ditemukan, dilewati setup bot"
        return 0
    fi

    # Buat .env dari contoh jika belum ada
    if [ ! -f "$env_file" ] && [ -f "$env_example" ]; then
        cp "$env_example" "$env_file"
        log_ok "File .env dibuat dari contoh (isi BOT_TOKEN Anda)"
    elif [ ! -f "$env_file" ]; then
        log_warn ".env.example tidak ditemukan, buat .env manual"
    fi

    # Install dependensi bot jika pip tersedia
    if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
        local pip_cmd
        command -v pip3 >/dev/null 2>&1 && pip_cmd="pip3" || pip_cmd="pip"
        log_info "Menginstal dependensi bot ($pip_cmd install -r bot/requirements.txt)..."
        $pip_cmd install -r "$bot_dir/requirements.txt" >/dev/null 2>&1 && log_ok "Dependensi bot terinstal" || log_warn "Gagal instal dependensi bot (install manual)"
    else
        log_warn "pip tidak ditemukan, install dependensi bot manual:"
        echo "  pip3 install -r $bot_dir/requirements.txt"
    fi

    echo ""
    echo "  Jalankan bot dengan: cd $INSTALL_DIR && python3 -m bot.main"
    echo "  Setup profil bot:    python3 $INSTALL_DIR/bot/setup_profile.py"
    echo ""
}

# -----------------------------------------------------------------------------
# Setup web UI (opsional)
# -----------------------------------------------------------------------------
setup_web() {
    local web_dir="$INSTALL_DIR/web"

    if [ ! -d "$web_dir" ]; then
        log_warn "Folder web/ tidak ditemukan, dilewati setup web"
        return 0
    fi

    log_info "Folder web UI tersedia di $web_dir"
    echo ""
    echo "  Untuk menjalankan antarmuka web:"
    echo "  cd $INSTALL_DIR/web"
    echo "  php -S 0.0.0.0:8080"
    echo "  Buka: http://<ip-vps>:8080"
    echo ""
}

# -----------------------------------------------------------------------------
# Cek PATH
# -----------------------------------------------------------------------------
check_path() {
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
        log_warn "$BIN_DIR belum ada di PATH"
        echo ""
        echo "Tambahkan ke ~/.bashrc atau ~/.zshrc:"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
        echo ""
        echo "Atau jalankan langsung dengan path lengkap:"
        echo "  $INSTALL_DIR/cdnscan.py 104.16.0.0/24"
        echo "  $INSTALL_DIR/d2ip.py example.com"
    else
        log_ok "$BIN_DIR sudah ada di PATH"
    fi
}

# -----------------------------------------------------------------------------
# Verifikasi instalasi
# -----------------------------------------------------------------------------
verify() {
    log_info "Memverifikasi instalasi ..."

    if python3 "$INSTALL_DIR/cdnscan.py" --help >/dev/null 2>&1; then
        log_ok "cdnscan.py berfungsi"
    else
        log_error "cdnscan.py gagal diuji"
        return 1
    fi

    if python3 "$INSTALL_DIR/subfind.py" --help >/dev/null 2>&1; then
        log_ok "subfind.py berfungsi"
    else
        log_error "subfind.py gagal diuji"
        return 1
    fi

    if python3 "$INSTALL_DIR/sniscan.py" --help >/dev/null 2>&1; then
        log_ok "sniscan.py berfungsi"
    else
        log_error "sniscan.py gagal diuji"
        return 1
    fi

    if python3 "$INSTALL_DIR/d2ip.py" --help >/dev/null 2>&1; then
        log_ok "d2ip.py berfungsi"
    fi

    # Cek modul common
    if python3 -c "import sys; sys.path.insert(0, '$INSTALL_DIR'); from common.validators import validate_domain; print('ok')" >/dev/null 2>&1; then
        log_ok "Modul common berfungsi"
    else
        log_warn "Modul common gagal diuji (periksa struktur folder)"
    fi

    # Cek folder output dan web
    if [ -d "$INSTALL_DIR/output" ]; then
        log_ok "Folder output siap"
    fi

    if [ -d "$INSTALL_DIR/web" ]; then
        log_ok "Folder web UI siap"
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    echo ""
    echo "============================================================"
    echo "  subfind - Installer"
    echo "  Subdomain & CDN Scanner Toolkit (CLI + Bot + Web UI)"
    echo "============================================================"
    echo ""

    check_python
    setup_repo
    setup_dirs
    make_executable
    create_symlinks
    setup_bot
    setup_web
    check_path
    verify

    echo ""
    echo "============================================================"
    echo "  Instalasi selesai!"
    echo "============================================================"
    echo ""
    echo "Contoh penggunaan CLI:"
    echo "  cdnscan.py 104.16.0.0/24 -l 100 -d 0.3 -y"
    echo "  subfind.py example.com"
    echo "  sniscan.py instagram.com"
    echo "  d2ip example.com"
    echo ""
    echo "Contoh penggunaan Bot Telegram:"
    echo "  cd $INSTALL_DIR && python3 -m bot.main"
    echo "  python3 $INSTALL_DIR/bot/setup_profile.py"
    echo ""
    echo "Contoh Web UI:"
    echo "  cd $INSTALL_DIR/web && php -S 0.0.0.0:8080"
    echo ""
    echo "Lokasi file:   $INSTALL_DIR"
    echo "Symlink:       $BIN_DIR"
    echo "Hasil scan:    $INSTALL_DIR/output/"
    echo "Web UI:        $INSTALL_DIR/web/"
    echo "Bot env:       $INSTALL_DIR/.env"
    echo ""
}

main "$@"
