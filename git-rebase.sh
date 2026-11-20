#!/bin/bash
# Skrip commit + rebase untuk subfind
# Penggunaan: bash git-rebase.sh "pesan commit"

set -e

REMOTE_BRANCH="origin/main"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
COMMIT_MSG="${1:-update subfind}"

echo "=== Branch saat ini: $CURRENT_BRANCH ==="

# 1. Cek apakah ada perubahan yang belum di-commit
if ! git diff-index --quiet HEAD --; then
    echo "Ada perubahan lokal yang belum di-commit. Men-commit dulu..."
    git add -A
    git commit -m "$COMMIT_MSG"
else
    echo "Tidak ada perubahan lokal. Lewati commit."
fi

# 2. Fetch terbaru dari remote
echo "Mengambil update dari remote..."
git fetch origin

# 3. Cek apakah branch diverge
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse "$REMOTE_BRANCH")
BASE=$(git merge-base @ "$REMOTE_BRANCH")

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "Branch sudah sinkron dengan $REMOTE_BRANCH. Tidak perlu rebase."
    exit 0
elif [ "$LOCAL" = "$BASE" ]; then
    echo "Local ada di belakang remote. Fast-forward..."
    git merge --ff-only "$REMOTE_BRANCH"
    exit 0
elif [ "$REMOTE" = "$BASE" ]; then
    echo "Local ada di depan remote. Tidak ada yang perlu di-rebase."
    exit 0
else
    echo "Branch diverge. Melakukan rebase ke $REMOTE_BRANCH..."
    git rebase "$REMOTE_BRANCH"
    echo "Rebase selesai."
fi