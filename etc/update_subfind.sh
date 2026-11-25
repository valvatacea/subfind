#!/system/bin/sh
# update_subfind.sh - Update seluruh repo subfind dari GitHub via zip
# Cocok untuk Termux (J5) dan OpenWrt (STB)

REPO_ZIP="https://github.com/valvatacea/subfind/archive/refs/heads/main.zip"
TARGET_DIR="$HOME/subfind"
BACKUP_DIR="$HOME/subfind/backup"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="$BACKUP_DIR/subfind_${TIMESTAMP}"
TMP_ZIP="$HOME/subfind/subfind_update.zip"
TMP_DIR="$HOME/subfind/subfind_update_tmp"

# Cek tool download (wget atau curl)
if command -v wget >/dev/null 2>&1; then
    DOWNLOAD="wget"
elif command -v curl >/dev/null 2>&1; then
    DOWNLOAD="curl"
else
    echo "[ERR] wget atau curl tidak ditemukan. Install salah satunya dulu."
    exit 1
fi

# Cek tool unzip
if ! command -v unzip >/dev/null 2>&1; then
    echo "[ERR] unzip tidak ditemukan. Install unzip dulu."
    exit 1
fi

echo "[INFO] Mengunduh zip repo subfind ..."

mkdir -p "$BACKUP_DIR"

if [ "$DOWNLOAD" = "wget" ]; then
    wget -q -O "$TMP_ZIP" "$REPO_ZIP"
else
    curl -s -L -o "$TMP_ZIP" "$REPO_ZIP"
fi

if [ ! -s "$TMP_ZIP" ]; then
    echo "[ERR] Gagal mengunduh zip (kosong atau error jaringan)."
    rm -f "$TMP_ZIP"
    exit 1
fi

# Ekstrak ke direktori sementara
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
unzip -q -o "$TMP_ZIP" -d "$TMP_DIR"

# Folder hasil unzip biasanya subfind-main/
EXTRACTED_DIR=$(ls -d "$TMP_DIR"/subfind-* 2>/dev/null | head -1)
if [ -z "$EXTRACTED_DIR" ]; then
    echo "[ERR] Struktur zip tidak dikenal (tidak ada folder subfind-*)."
    rm -rf "$TMP_DIR" "$TMP_ZIP"
    exit 1
fi

# Backup direktori target jika ada
if [ -d "$TARGET_DIR" ]; then
    cp -a "$TARGET_DIR" "$BACKUP"
    echo "[INFO] Backup lama disimpan ke: $BACKUP"
fi

# Cadangkan bot/state.db (state persisten) agar tidak ikut terhapus saat update
STATE_DB_BACKUP=""
if [ -f "$TARGET_DIR/bot/state.db" ]; then
    STATE_DB_BACKUP="$BACKUP_DIR/state_${TIMESTAMP}.db"
    cp -a "$TARGET_DIR/bot/state.db" "$STATE_DB_BACKUP"
    echo "[INFO] Cadangkan bot/state.db ke: $STATE_DB_BACKUP"
fi

# Salin file baru (kecuali .git, .venv, output, backup, __pycache__, .gitignore, bot.log)
echo "[INFO] Menyalin file baru ke $TARGET_DIR ..."
for item in "$EXTRACTED_DIR"/*; do
    name=$(basename "$item")
    case "$name" in
        .git|.venv|output|backup|__pycache__|.gitignore|bot.log)
            echo "[SKIP] $name"
            ;;
        *)
            rm -rf "$TARGET_DIR/$name"
            cp -a "$item" "$TARGET_DIR/"
            ;;
    esac
done

# Pulihkan bot/state.db jika ada backup
if [ -n "$STATE_DB_BACKUP" ] && [ -f "$STATE_DB_BACKUP" ]; then
    mkdir -p "$TARGET_DIR/bot"
    cp -a "$STATE_DB_BACKUP" "$TARGET_DIR/bot/state.db"
    echo "[INFO] Pulihkan bot/state.db dari backup"
fi

# Bersihkan
rm -rf "$TMP_DIR" "$TMP_ZIP"

echo "[OK] Repo subfind berhasil diperbarui di: $TARGET_DIR"
echo "[Selesai] Jalankan dengan: python3 $TARGET_DIR/bot/main.py"
