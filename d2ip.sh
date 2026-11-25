#!/bin/bash
# d2ip.sh - Resolve domain ke IP address
# Output disimpan ke output/<domain>.txt (dan juga ditampilkan di layar)

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 google.com"
    exit 1
fi

DOMAIN=$1
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Validasi domain + filter NSFW (opsional, via Python)
if ! python3 - "$DOMAIN" "$BASE_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
from common.validators import validate_domain
from common.nsfw_filter import is_blocked

domain = sys.argv[1]
if not validate_domain(domain):
    print("Domain tidak valid.")
    sys.exit(1)

blocked, kata = is_blocked(domain)
if blocked:
    print(f"Domain diblokir: {kata}")
    sys.exit(1)
PY
then
    echo "Domain tidak valid atau diblokir (NSFW)."
    exit 1
fi

{
echo "Domain: $DOMAIN"
echo ""

# Coba dengan dig
if command -v dig &>/dev/null; then
    echo "=== dig ==="
    dig +short "$DOMAIN"
fi

# Coba dengan host
if command -v host &>/dev/null; then
    echo "=== host ==="
    host "$DOMAIN" | awk '/has (IPv6 )?address/ {print $NF}'
fi

# Coba dengan getent (bawaan glibc)
if command -v getent &>/dev/null; then
    echo "=== getent ==="
    getent hosts "$DOMAIN" | awk '{print $1}'
fi

# Coba dengan nslookup
if command -v nslookup &>/dev/null; then
    echo "=== nslookup ==="
    nslookup "$DOMAIN" | awk '/^Address:/ {print $2}' | tail -n +2
fi

echo ""
echo "Selesai."
}
