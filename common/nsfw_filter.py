# common/nsfw_filter.py - Pemblokir domain yang mengandung kata kunci tidak pantas
# Digunakan sebelum proses scan dimulai (input domain saja, tidak memindai isi website).

import html
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKLIST_FILE = os.path.join(BASE_DIR, "nsfw_blocklist.txt")
SHALLALIST_FILE = os.path.join(BASE_DIR, "nsfw_blocklist_shallalist.txt")

_blocklist = None


def _load_blocklist():
    """Baca blocklist dari dua file, disimpan cache di memori."""
    global _blocklist
    if _blocklist is not None:
        return _blocklist
    kata = set()
    for path in (BLOCKLIST_FILE, SHALLALIST_FILE):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for baris in f:
                    k = baris.strip().lower()
                    if k and not k.startswith("#"):
                        kata.add(k)
    _blocklist = kata
    return kata


def is_blocked(domain):
    """Cek apakah domain mengandung kata kunci dari blocklist.
    Return (True, kata_kunci) jika terblokir, (None, None) jika aman.

    Entri dengan titik (domain) dicocokkan secara utuh/suffix domain,
    bukan substring bebas, agar tidak false positive (mis. youtube.com vs tube.com).
    Entri tanpa titik (kata kunci) tetap dicocokkan sebagai substring.
    """
    if not domain:
        return None, None
    d = domain.lower().strip().rstrip('.')
    for kata in _load_blocklist():
        if not kata:
            continue
        k = kata.lower()
        if '.' in k:
            # domain-like: exact match atau subdomain
            if d == k or d.endswith('.' + k):
                return True, kata
        else:
            if k in d:
                return True, kata
    return None, None


def blocked_message(domain, kata):
    """Bentuk pesan peringatan untuk domain yang diblokir."""
    return (
        f"🚫 <b>Scan dibatalkan.</b>\n"
        f"Domain <b>{html.escape(domain)}</b> mengandung kata \"<b>{html.escape(kata)}</b>\" yang termasuk kata tidak pantas / NSFW.\n"
        f"Silakan gunakan domain lain."
    )
