#!/usr/bin/env bash
# =============================================================================
# subfind - Installer Script
# Instalasi skrip cdnscan.py, subfind.py, dan d2ip.sh ke sistem
# =============================================================================
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
        echo "  Debian/Ubuntu: sudo apt update && sudo apt install python3"
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
# Buat direktori output & states
# -----------------------------------------------------------------------------
setup_dirs() {
    mkdir -p "$INSTALL_DIR/output"
    mkdir -p "$INSTALL_DIR/output/states"
    mkdir -p "$INSTALL_DIR/output/ipranges"
    log_ok "Direktori output siap di $INSTALL_DIR/output"
}

# -----------------------------------------------------------------------------
# Buat executable
# -----------------------------------------------------------------------------
make_executable() {
    chmod +x "$INSTALL_DIR/d2ip.sh"
    chmod +x "$INSTALL_DIR/cdnscan.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/subfind.py" 2>/dev/null || true
    log_ok "File skrip dibuat executable"
}

# -----------------------------------------------------------------------------
# Buat symlink di BIN_DIR untuk akses cepat
# -----------------------------------------------------------------------------
create_symlinks() {
    mkdir -p "$BIN_DIR"

    if [ ! -e "$BIN_DIR/cdnscan" ]; then
        ln -sf "$INSTALL_DIR/cdnscan.py" "$BIN_DIR/cdnscan"
        log_ok "Symlink cdnscan -> $BIN_DIR/cdnscan"
    else
        log_warn "$BIN_DIR/cdnscan sudah ada, dilewati"
    fi

    if [ ! -e "$BIN_DIR/subfind" ]; then
        ln -sf "$INSTALL_DIR/subfind.py" "$BIN_DIR/subfind"
        log_ok "Symlink subfind -> $BIN_DIR/subfind"
    else
        log_warn "$BIN_DIR/subfind sudah ada, dilewati"
    fi

    if [ ! -e "$BIN_DIR/d2ip" ]; then
        ln -sf "$INSTALL_DIR/d2ip.sh" "$BIN_DIR/d2ip"
        log_ok "Symlink d2ip -> $BIN_DIR/d2ip"
    else
        log_warn "$BIN_DIR/d2ip sudah ada, dilewati"
    fi
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
        echo "  $INSTALL_DIR/d2ip.sh example.com"
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

    if bash "$INSTALL_DIR/d2ip.sh" 2>&1 | grep -qi "usage\|usage:" || true; then
        log_ok "d2ip.sh berfungsi"
    fi

    # Cek file output
    if [ -d "$INSTALL_DIR/output" ]; then
        log_ok "Folder output siap"
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    echo ""
    echo "============================================================"
    echo "  subfind - Installer"
    echo "  Subdomain & CDN Scanner Toolkit"
    echo "============================================================"
    echo ""

    check_python
    setup_repo
    setup_dirs
    make_executable
    create_symlinks
    check_path
    verify

    echo ""
    echo "============================================================"
    echo "  Instalasi selesai!"
    echo "============================================================"
    echo ""
    echo "Contoh penggunaan:"
    echo "  cdnscan.py 104.16.0.0/24 -l 100 -d 0.3 -y"
    echo "  subfind.py example.com"
    echo "  d2ip example.com"
    echo ""
    echo "Lokasi file:   $INSTALL_DIR"
    echo "Symlink:       $BIN_DIR"
    echo "Hasil scan:    $INSTALL_DIR/output/"
    echo ""
}

main "$@"
