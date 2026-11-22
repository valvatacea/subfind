#!/usr/bin/env python3
# update_nsfw_blocklist.py - Unduh daftar domain NSFW dari Shallalist mirror (GitHub)
# dan gabungkan ke common/nsfw_blocklist.txt tanpa duplikasi.
# Shallalist asli (shallalist.de) sudah tidak aktif; mirror ini gratis dan tetap tersedia.

import os
import sys
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKLIST_FILE = os.path.join(BASE_DIR, "nsfw_blocklist_shallalist.txt")

# Sumber Shallalist mirror (gratis). Tambah kategori lain di sini jika diperlukan.
# Kategori yang direkomendasikan untuk NSFW: porn. Kategori lain boleh diaktifkan.
SOURCES = {
    "porn": "https://raw.githubusercontent.com/Azothyran/ShallalistMirror/master/porn/domains",
    # "dating": "https://raw.githubusercontent.com/Azothyran/ShallalistMirror/master/dating/domains",
    # "gamble": "https://raw.githubusercontent.com/Azothyran/ShallalistMirror/master/gamble/domains",
    # "drugs":  "https://raw.githubusercontent.com/Azothyran/ShallalistMirror/master/drugs/domains",
}

from common.http_status import HEADERS_WITHOUT_COMPRESSION


def fetch_domains(url):
    """Ambil daftar domain dari URL. Return list string, atau [] jika gagal."""
    try:
        req = urllib.request.Request(url, headers=HEADERS_WITHOUT_COMPRESSION)
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] Gagal unduh {url}: {e}")
        return []

    domains = []
    for baris in text.splitlines():
        d = baris.strip().lower()
        if not d or d.startswith("#"):
            continue
        if d.startswith("www."):
            d = d[4:]
        domains.append(d)
    return domains


def load_existing(path):
    """Baca blocklist yang sudah ada. Return set (tanpa baris komentar)."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {baris.strip().lower() for baris in f if baris.strip() and not baris.strip().startswith("#")}


def save_blocklist(path, entries):
    """Tulis blocklist: header komentar + entri yang sudah diurutkan."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Daftar kata kunci/domain yang tidak diperbolehkan discan (NSFW / tidak pantas)\n")
        f.write("# Satu entri per baris. Pencocokan case-insensitive substring.\n")
        f.write("# Beberapa entri diunduh otomatis dari Shallalist mirror (gratis).\n")
        f.write("#\n")
        for e in sorted(entries):
            f.write(e + "\n")


def main():
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    existing = load_existing(BLOCKLIST_FILE)
    before = len(existing)

    added = 0
    for kategori, url in SOURCES.items():
        domains = fetch_domains(url)
        new_domains = set()
        for d in domains:
            if d not in existing:
                new_domains.add(d)
        existing |= new_domains
        added += len(new_domains)
        print(f"[OK] {kategori}: {len(domains)} domain, {len(new_domains)} baru ditambahkan")

    save_blocklist(BLOCKLIST_FILE, existing)
    print(f"\n[Selesai] Sebelum: {before}, Sesudah: {len(existing)}, Ditambahkan: {added}")
    print(f"File: {BLOCKLIST_FILE}")


if __name__ == "__main__":
    main()
