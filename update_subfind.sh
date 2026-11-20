#!/system/bin/sh
# update_subfind.sh - Update subfind.py dari GitHub via wget atau curl
# Cocok untuk Termux (J5) dan OpenWrt (STB)

REPO_RAW="https://raw.githubusercontent.com/valvatacea/subfind/main/subfind.py"
TARGET="$HOME/subfind/subfind.py"
BACKUP_DIR="$HOME/subfind/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="$BACKUP_DIR/subfind_${TIMESTAMP}.py"

# Cek tool download (wget atau curl)
if command -v wget >/dev/null 2>&1; then
    DOWNLOAD="wget"
elif command -v curl >/dev/null 2>&1; then
    DOWNLOAD="curl"
else
    echo "[ERR] wget atau curl tidak ditemukan. Install salah satunya dulu."
    exit 1
fi

echo "[INFO] Mengunduh subfind.py terbaru dari GitHub ..."

mkdir -p "$BACKUP_DIR"

# Backup file lama jika ada
if [ -f "$TARGET" ]; then
    cp "$TARGET" "$BACKUP"
    echo "[INFO] Backup lama disimpan ke: $BACKUP"
fi

# Unduh file baru
if [ "$DOWNLOAD" = "wget" ]; then
    wget -q -O "$TARGET.tmp" "$REPO_RAW"
else
    curl -s -L -o "$TARGET.tmp" "$REPO_RAW"
fi

if [ ! -s "$TARGET.tmp" ]; then
    echo "[ERR] Gagal mengunduh file (kosong atau error jaringan)."
    rm -f "$TARGET.tmp"
    exit 1
fi

# Verifikasi sintaks Python
if python3 -m py_compile "$TARGET.tmp" >/dev/null 2>&1; then
    mv "$TARGET.tmp" "$TARGET"
    chmod +x "$TARGET"
    echo "[OK] subfind.py berhasil diperbarui di: $TARGET"
else
    echo "[ERR] File yang diunduh tidak valid (sintaks Python error)."
    rm -f "$TARGET.tmp"
    exit 1
fi

echo "[Selesai] Jalankan dengan: python3 $TARGET <domain>"
