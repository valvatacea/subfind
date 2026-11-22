#!/system/bin/sh
# update_subfind.sh - Update subfind.py dari GitHub via wget atau curl
# Cocok untuk Termux (J5) dan OpenWrt (STB)

REPO_RAW="https://raw.githubusercontent.com/valvatacea/subfind/main/subfind.py"
TARGET="$HOME/subfind/subfind.py"
BACKUP_DIR="$HOME/subfind/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="$BACKUP_DIR/subfind_${TIMESTAMP}.py"
TMP="$HOME/subfind/subfind.py.tmp"

# Cek tool download (wget atau curl)
if command -v wget >/dev/null 2>&1; then
    DOWNLOAD="wget"
elif command -v curl >/dev/null 2>&1; then
    DOWNLOAD="curl"
else
    echo "[ERR] wget atau curl tidak ditemukan. Install salah satunya dulu."
    exit 1
fi

echo "[INFO] Mengecek update subfind.py ..."

mkdir -p "$BACKUP_DIR"

# Unduh ke file sementara
if [ "$DOWNLOAD" = "wget" ]; then
    wget -q -O "$TMP" "$REPO_RAW"
else
    curl -s -L -o "$TMP" "$REPO_RAW"
fi

if [ ! -s "$TMP" ]; then
    echo "[ERR] Gagal mengunduh file (kosong atau error jaringan)."
    rm -f "$TMP"
    exit 1
fi

# Jika target belum ada, langsung pakai yang baru
if [ ! -f "$TARGET" ]; then
    mv "$TMP" "$TARGET"
    chmod +x "$TARGET"
    echo "[OK] subfind.py dibuat baru di: $TARGET"
    echo "[Selesai] Jalankan dengan: python3 $TARGET <domain>"
    exit 0
fi

# Bandingkan isi file remote dengan lokal
if cmp -s "$TMP" "$TARGET"; then
    echo "[INFO] subfind.py sudah terbaru, tidak ada perubahan."
    rm -f "$TMP"
    exit 0
fi

# File berbeda: backup, verifikasi sintaks, lalu ganti
cp "$TARGET" "$BACKUP"
echo "[INFO] Backup lama disimpan ke: $BACKUP"

if python3 -m py_compile "$TMP" >/dev/null 2>&1; then
    mv "$TMP" "$TARGET"
    chmod +x "$TARGET"
    echo "[OK] subfind.py berhasil diperbarui di: $TARGET"
else
    echo "[ERR] File yang diunduh tidak valid (sintaks Python error)."
    rm -f "$TMP"
    exit 1
fi

echo "[Selesai] Jalankan dengan: python3 $TARGET <domain>"
