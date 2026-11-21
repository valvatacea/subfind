#!/usr/bin/env python3
# subfind-telegram-bot — D2IP / SubFind / CDNScan via tombol inline
# Jalankan: python3 -m bot.main   (dari /root/subfind/)
import os
import sys
import re
import socket
import json
import threading
import queue
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed

# Folder root repo (induk folder bot/) — semua path dinamis dari lokasi file ini
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOT_DIR = os.path.dirname(os.path.abspath(__file__))

from dotenv import load_dotenv
load_dotenv(os.path.join(BOT_DIR, '.env'))

import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Impor logika scan dari skrip asli (tidak ada duplikasi kode)
sys.path.insert(0, BASE_DIR)
from subfind import (
    enumerate_domain, resolve_ip,
    crt_sh, hackertarget, wordlist_fallback,
    CACHE_MAX_AGE_SECONDS as SUBFIND_CACHE_AGE,
    get_cache_path, load_cache, save_cache,
    scan_ports_summary, COMMON_PORTS as SUBFIND_PORTS,
    CF_PREFIXES as SUBFIND_CF_PREFIXES, detect_cdn as subfind_detect_cdn,
)
from common.validators import validate_domain
from common.progress import format_elapsed, calculate_eta, build_bar, SPINNER
from sniscan import (
    enumerate_hosts,
)
from cdnscan import (
    parse_ip_range, process_ip,
    PROVIDER_URLS, get_provider_ips,
    format_ports, save_state, load_state, count_existing_ips,
    SCAN_PORTS as CDN_PORTS, MAX_IPS_PER_SCAN, SCAN_DELAY,
    IPRANGE_DIR, STATE_DIR, CACHE_MAX_AGE_SECONDS as CDN_CACHE_AGE,
    detect_cdn_and_status, scan_open_ports,
)

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("BOT_TOKEN belum di-set. Buat .env dengan BOT_TOKEN=isi_token")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

# Antrian thread-safe untuk edit_message_text dari worker thread.
# Worker thread (scan progres) hanya memasukkan permintaan ke antrian;
# thread dispatcher (berjalan di latar belakang) yang mengeksekusinya,
# sehingga semua panggilan Telebot dilakukan dari satu thread saja.
_edit_queue = queue.Queue()


def _edit_dispatcher():
    """Thread pemroses antrian: mengeksekusi edit_message_text satu per satu."""
    while True:
        try:
            item = _edit_queue.get()
            if item is None:  # sentinel untuk berhenti
                break
            chat_id, message_id, text, kwargs = item
            try:
                bot.edit_message_text(text, chat_id, message_id, **kwargs)
            except Exception:
                pass
            _edit_queue.task_done()
        except Exception:
            pass


_edit_dispatcher_thread = threading.Thread(target=_edit_dispatcher, daemon=True)
_edit_dispatcher_thread.start()


# ===================== KONFIG =====================
HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
socket.setdefaulttimeout(10)
MAX_MESSAGE = 3800  # batas aman per pesan Telegram
ITEM_PER_PAGE = 10  # data per halaman untuk pagination
CDN_LIMIT_DEFAULT = MAX_IPS_PER_SCAN  # 1000 dari CLI

# ===================== STATE USER =====================
# user_state[chat_id] = {"mode": "...", "awaiting": "...", ...}
user_state = {}
state_lock = threading.Lock()


def set_state(chat_id, **kw):
    with state_lock:
        st = user_state.get(chat_id, {})
        st.update(kw)
        user_state[chat_id] = st


def get_state(chat_id):
    with state_lock:
        return user_state.get(chat_id, {})


def clear_state(chat_id):
    with state_lock:
        user_state.pop(chat_id, None)


# ===================== ESCAPE HTML =====================
def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pad_label(label, width=12):
    """Tanpa padding - label langsung diikuti titik dua."""
    return label


# ===================== SPINNER & WAKTU =====================
# SPINNER, format_elapsed diimpor dari common.progress


def build_progress_text(title, target, current, total, start_time, spinner_idx):
    """Bangun teks progres dengan spinner, bar, persentase, elapsed time, dan ETA.

    Tidak ada rate limiting di sini — spinner thread mengontrol timing (setiap 0,4 detik).
    Output format HTML untuk Telegram, menggunakan emoji 🟦⬜ untuk progress bar.
    """
    import time
    now = time.time()
    elapsed = now - start_time

    if current > 0 and total > 0:
        eta = calculate_eta(elapsed, current, total)
    else:
        eta = 0

    # Progress bar: 10 blok, emoji kotak biru terisi dan kosong
    bar = build_bar(current, total, width=10,
                    filled_char="🟦", empty_char="⬜")
    pct = int(current / total * 100) if total > 0 else 0

    # Spinner dari spinner_idx yang dikelola oleh spinner thread (independen dari progres)
    spinner = SPINNER[spinner_idx % len(SPINNER)]

    return (f"{spinner} <b>{title}</b>\n"
            f"Memindai <b>{esc(target)}</b>...\n"
            f"{bar} {pct}% ({current}/{total})\n"
            f"Elapsed: {format_elapsed(elapsed)} | ETA: {format_elapsed(eta)}")


# ===================== KEYBOARD =====================
def kb_main():
    m = InlineKeyboardMarkup(row_width=2)
    m.add(
        InlineKeyboardButton("🌐 D2IP (Domain ➜ IP)", callback_data="menu:d2ip"),
        InlineKeyboardButton("🔍 SubFind (Subdomain)", callback_data="menu:subfind"),
        InlineKeyboardButton("🛡️ CDNScan (CDN/IP)", callback_data="menu:cdnscan"),
        InlineKeyboardButton("🔍 SNIScan (TLS/IP)", callback_data="menu:sniscan"),
        InlineKeyboardButton("❓ Bantuan", callback_data="menu:help"),
    )
    return m


def kb_back(prev_menu="menu:main"):
    m = InlineKeyboardMarkup(row_width=1)
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev_menu}"))
    return m


def kb_confirm_scan(callback_prefix, target, prev_menu="menu:main"):
    m = InlineKeyboardMarkup(row_width=2)
    m.add(
        InlineKeyboardButton("✅ Mulai scan", callback_data=f"{callback_prefix}:start:{target}"),
        InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev_menu}"),
    )
    return m


PROVIDER_DISPLAY = {
    "cloudflare": "Cloudflare",
    "cloudfront": "CloudFront",
}

def kb_provider():
    m = InlineKeyboardMarkup(row_width=2)
    for name in PROVIDER_URLS:
        m.add(InlineKeyboardButton(f"🌐 {PROVIDER_DISPLAY[name]}", callback_data=f"cdnscan:provider:{name}"))
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:cdnscan"))
    return m


def kb_ranges(ranges, page=1, per_page=8, selected=None):
    """Tombol pilihan rentang IP dari provider, dengan paginasi."""
    m = InlineKeyboardMarkup(row_width=2)
    total = len(ranges)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    selected = selected or []
    for cidr in ranges[start:end]:
        label = f"✅ {cidr}" if cidr in selected else cidr
        m.add(InlineKeyboardButton(label, callback_data=f"cdnscan:range:{cidr}"))
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"cdnscan:ranges:page:{page-1}"))
    nav.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="cdnscan:ranges:noop"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ⏭️", callback_data=f"cdnscan:ranges:page:{page+1}"))
    m.add(*nav)
    m.add(InlineKeyboardButton("✅ Scan yang dipilih", callback_data="cdnscan:range:confirm"))
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:cdnscan"))
    return m


def kb_limit(prev_menu="cdnscan:ranges:page"):
    m = InlineKeyboardMarkup(row_width=3)
    m.add(
        InlineKeyboardButton("500", callback_data="cdnscan:limit:500"),
        InlineKeyboardButton("1000", callback_data="cdnscan:limit:1000"),
        InlineKeyboardButton("🔢 Custom", callback_data="cdnscan:limit:custom"),
        InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev_menu}"),
    )
    return m


def kb_next_target(prev_menu="menu:cdnscan", show_view=False):
    m = InlineKeyboardMarkup(row_width=2)
    if show_view:
        m.add(
            InlineKeyboardButton("👁️ Lihat", callback_data="cdnscan:view"),
            InlineKeyboardButton("▶️ Next", callback_data="cdnscan:next"),
        )
    else:
        m.add(
            InlineKeyboardButton("▶️ Next", callback_data="cdnscan:next"),
        )
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev_menu}"))
    return m


def kb_cdnscan_menu():
    m = InlineKeyboardMarkup(row_width=2)
    for name in PROVIDER_URLS:
        m.add(InlineKeyboardButton(f"🌐 {PROVIDER_DISPLAY[name]}", callback_data=f"cdnscan:provider:{name}"))
    m.add(InlineKeyboardButton("✏️ Masukkan IP/CIDR sendiri", callback_data="cdnscan:manual"))
    m.add(InlineKeyboardButton("📜 Riwayat Scan", callback_data="cdnscan:history:1"))
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:main"))
    return m


def kb_sniscan_menu():
    m = InlineKeyboardMarkup(row_width=2)
    m.add(InlineKeyboardButton("🔍 Scan SNI Host", callback_data="sniscan:search"))
    m.add(InlineKeyboardButton("📜 Riwayat Scan", callback_data="sniscan:history:1"))
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:main"))
    return m


# ===================== PAGINATION HELPER =====================
def build_page_text(results, page, mode, title):
    """Bangun teks halaman dalam format normal (bukan <pre>).
    Label kolom renggang dengan spasi di sekitar '|', garis pembatas
    menyesuaikan lebar tiap kolom agar nyaman di layar HP.
    Hanya IP dan PORTS yang <code> (monospace).
    """
    total = len(results)
    per_page = 50 if mode == "d2ip" else ITEM_PER_PAGE
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page
    chunk = results[start:end]

    title_line = f"{title} — Halaman {page}/{total_pages} ({total} data)"
    underline = "_" * 40

    lines = [underline, title_line, underline, ""]

    if mode == "subfind":
        for i, (sub, ip, ports, status, cdn) in enumerate(chunk, start=start + 1):
            lines.append(f"{pad_label('Subdomain', 12)}: {esc(sub)}")
            lines.append(f"{pad_label('IP', 12)}: {esc(ip)}")
            lines.append(f"{pad_label('PORTS', 12)}: {esc(ports)}")
            lines.append(f"{pad_label('Status', 12)}: {esc(status)}")
            lines.append(f"{pad_label('CDN', 12)}: {esc(cdn)}")
            lines.append("----------------------------------------------")
    elif mode == "cdnscan":
        for i, (ip, ports, cdn, status) in enumerate(chunk, start=start + 1):
            lines.append(f"{pad_label('IP', 12)}: {esc(ip)}")
            lines.append(f"{pad_label('PORTS', 12)}: {esc(format_ports(ports))}")
            lines.append(f"{pad_label('CDN', 12)}: {esc(cdn)}")
            lines.append(f"{pad_label('Status', 12)}: {esc(status)}")
            lines.append("----------------------------------------------")
    elif mode == "sniscan":
        for i, r in enumerate(chunk, start=start + 1):
            lines.append(f"{pad_label('SNI Host', 12)}: {esc(r[0])}")
            lines.append(f"{pad_label('Direct IP', 12)}: {esc(r[1])} ({r[6]}ms)")
            lines.append(f"{pad_label('TLS/ALPN', 12)}: {esc(r[2])} | ALPN: {esc(r[3])}")
            lines.append(f"{pad_label('Port TLS', 12)}: {esc(r[4])}({esc(r[2])})")
            lines.append(f"{pad_label('Port Lain', 12)}: {esc(r[5])}")
            lines.append("----------------------------------------------")
    elif mode == "d2ip":
        for line in chunk:
            lines.append(line)
        return "\n".join(lines), page, total_pages

    return "\n".join(lines), page, total_pages


def kb_page(mode, page, total_pages, back_target=None):
    """Tombol prev / halaman / next + kembali ke menu."""
    m = InlineKeyboardMarkup(row_width=3)
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"page:{mode}:{page - 1}"))
    buttons.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="page:noop"))
    if page < total_pages:
        buttons.append(InlineKeyboardButton("Next ⏭️", callback_data=f"page:{mode}:{page + 1}"))
    m.add(*buttons)
    prev = back_target or {"subfind": "menu:subfind", "cdnscan": "menu:cdnscan", "d2ip": "menu:d2ip"}.get(mode, "menu:main")
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev}"))
    return m




# ===================== HISTORY =====================
def get_cdnscan_history():
    """Baca daftar file hasil scan CDNScan JSON dari output/."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    if not os.path.exists(OUT_DIR):
        return []
    files = []
    for fname in os.listdir(OUT_DIR):
        if fname.startswith("cdnscan_") and fname.endswith(".json"):
            try:
                with open(os.path.join(OUT_DIR, fname), 'r') as f:
                    data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    target = first.get("target", fname.replace("cdnscan_", "").replace(".json", ""))
                    provider = first.get("provider", "-")
                    count = len(data)
                else:
                    target = fname.replace("cdnscan_", "").replace(".json", "")
                    provider = "-"
                    count = 0
                files.append({
                    "type": "cdnscan",
                    "target": target,
                    "provider": provider,
                    "count": count,
                    "file": fname,
                })
            except Exception:
                files.append({
                    "type": "cdnscan",
                    "target": fname,
                    "provider": "-",
                    "count": 0,
                    "file": fname,
                })
    files.sort(key=lambda x: x["file"], reverse=True)
    return files


def build_cdnscan_history_page(page=1, per_page=10):
    """Bangun teks halaman riwayat CDNScan dengan tombol inline per entri."""
    files = get_cdnscan_history()
    total = len(files)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    chunk = files[start:end]

    lines = ["_" * 40, "📜 Riwayat CDNScan", "_" * 40, ""]
    if not files:
        lines.append("Belum ada hasil scan CDNScan.")
    else:
        lines.append(f"Total: {total} hasil scan")

    lines.append("")
    return "\n".join(lines), page, total_pages


def show_cdnscan_history_page(chat_id, message_id, page, edit=True):
    """Tampilkan halaman riwayat CDNScan dengan tombol inline per entri."""
    text, page, total_pages = build_cdnscan_history_page(page)
    kb = InlineKeyboardMarkup(row_width=2)

    files = get_cdnscan_history()
    per_page = 10
    start = (page - 1) * per_page
    end = start + 10
    chunk = files[start:end]
    for item in chunk:
        label = f"{item['target']} ({item['provider']})"
        kb.add(InlineKeyboardButton(label, callback_data=f"cdnscan:history:detail:{item['file']}"))

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"cdnscan:history:{page - 1}"))
    nav.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="cdnscan:history:noop"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ⏭️", callback_data=f"cdnscan:history:{page + 1}"))
    kb.add(*nav)

    kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:cdnscan"))

    try:
        if edit:
            bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
        else:
            bot.send_message(chat_id, text, reply_markup=kb)
    except Exception:
        bot.send_message(chat_id, text, reply_markup=kb)


def show_cdnscan_history_detail(chat_id, message_id, filename, edit=True):
    """Tampilkan seluruh data dalam satu list hasil scan CDNScan (dengan paginasi)."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    fpath = os.path.join(OUT_DIR, filename)
    try:
        with open(fpath, 'r') as f:
            data = json.load(f)
    except Exception:
        text = "❌ Gagal membaca file hasil scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="cdnscan:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    if not data or not isinstance(data, list):
        text = "❌ Tidak ada data dalam file scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="cdnscan:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    target = data[0].get("target", filename) if data else filename
    provider = data[0].get("provider", "-") if data else "-"

    results = [(item.get("ip", "-"), item.get("ports", "-"), item.get("cdn", "-"), item.get("status", "-")) for item in data]
    save_scan_state(chat_id, "cdnscan", target, results, "CDNScan", page=1)
    info_text = f"✅ <b>Target sudah discan sebelumnya.</b>\nProvider: {provider}\nTotal: {len(data)} data"
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target="cdnscan:history:1")


def get_subfind_history():
    """Baca daftar file hasil scan SubFind JSON dari output/."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    if not os.path.exists(OUT_DIR):
        return []
    files = []
    for fname in os.listdir(OUT_DIR):
        if fname.startswith("subfind_") and fname.endswith(".json"):
            try:
                with open(os.path.join(OUT_DIR, fname), 'r') as f:
                    data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    target = first.get("target", fname.replace("subfind_", "").replace(".json", ""))
                    count = len(data)
                else:
                    target = fname.replace("subfind_", "").replace(".json", "")
                    count = 0
                files.append({
                    "type": "subfind",
                    "target": target,
                    "count": count,
                    "file": fname,
                })
            except Exception:
                files.append({
                    "type": "subfind",
                    "target": fname,
                    "count": 0,
                    "file": fname,
                })
    files.sort(key=lambda x: x["file"], reverse=True)
    return files


def build_subfind_history_page(page=1, per_page=10):
    """Bangun teks halaman riwayat SubFind dengan tombol inline per entri."""
    files = get_subfind_history()
    total = len(files)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    chunk = files[start:end]

    lines = ["_" * 40, "📜 Riwayat SubFind", "_" * 40, ""]
    if not files:
        lines.append("Belum ada hasil scan SubFind.")
    else:
        lines.append(f"Total: {total} hasil scan")

    lines.append("")
    return "\n".join(lines), page, total_pages


def show_subfind_history_page(chat_id, message_id, page, edit=True):
    """Tampilkan halaman riwayat SubFind dengan tombol inline per entri."""
    text, page, total_pages = build_subfind_history_page(page)
    kb = InlineKeyboardMarkup(row_width=2)

    files = get_subfind_history()
    per_page = 10
    start = (page - 1) * per_page
    end = start + 10
    chunk = files[start:end]
    for item in chunk:
        label = f"{item['target']} ({item['count']} subdomain)"
        kb.add(InlineKeyboardButton(label, callback_data=f"subfind:history:detail:{item['file']}"))

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"subfind:history:{page - 1}"))
    nav.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="subfind:history:noop"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ⏭️", callback_data=f"subfind:history:{page + 1}"))
    kb.add(*nav)

    kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:subfind"))

    try:
        if edit:
            bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
        else:
            bot.send_message(chat_id, text, reply_markup=kb)
    except Exception:
        bot.send_message(chat_id, text, reply_markup=kb)


def show_subfind_history_detail(chat_id, message_id, filename, edit=True):
    """Tampilkan seluruh data dalam satu list hasil scan SubFind (dengan paginasi)."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    fpath = os.path.join(OUT_DIR, filename)
    try:
        with open(fpath, 'r') as f:
            data = json.load(f)
    except Exception:
        text = "❌ Gagal membaca file hasil scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="subfind:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    if not data or not isinstance(data, list):
        text = "❌ Tidak ada data dalam file scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="subfind:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    target = data[0].get("target", filename) if data else filename

    results = [(item.get("subdomain", "-"), item.get("ip", "-"), item.get("ports", "-"), item.get("status", "-"), item.get("cdn", "-")) for item in data]
    save_scan_state(chat_id, "subfind", target, results, "SubFind", page=1)
    info_text = f"✅ <b>Target sudah discan sebelumnya.</b>\nTotal: {len(data)} subdomain"
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target="subfind:history:1")


def save_scan_state(chat_id, mode, target, results, title, page=1):
    """Simpan hasil scan ke state agar bisa di-paging dan dibaca ulang dari JSON."""
    set_state(chat_id,
              mode="scan_view",
              scan_mode=mode,
              scan_target=target,
              scan_results=results,
              scan_page=page,
              scan_title=title)


def show_scan_page(chat_id, message_id, edit=True, info_text=None, back_target=None):
    """Tampilkan halaman scan saat ini dari state.
    info_text: teks tambahan yang ditampilkan di atas tabel (misal "sudah discan").
    back_target: callback_data untuk tombol Kembali (override default).
    """
    st = get_state(chat_id)
    results = st.get("scan_results", [])
    mode = st.get("scan_mode", "subfind")
    page = st.get("scan_page", 1)
    target = st.get("scan_target", "-")
    title = st.get("scan_title", "Hasil Scan")

    if not results:
        text = f"⚠️ <b>{title}</b>\nTidak ada data untuk ditampilkan."
        if info_text:
            text = f"{info_text}\n\n{text}"
        prev = back_target or {"subfind": "menu:subfind", "cdnscan": "menu:cdnscan", "d2ip": "menu:d2ip"}.get(mode, "menu:main")
        try:
            if edit:
                _edit_queue.put((
                    chat_id, message_id, text,
                    {"reply_markup": kb_back(prev)}
                ))
            else:
                bot.send_message(chat_id, text, reply_markup=kb_back(prev))
        except Exception:
            bot.send_message(chat_id, text, reply_markup=kb_back(prev))
        return

    text, page, total_pages = build_page_text(results, page, mode, title)
    set_state(chat_id, scan_page=page)
    if info_text:
        text = f"{info_text}\n\n{text}"
    try:
        if edit:
            _edit_queue.put((
                chat_id, message_id, text,
                {"reply_markup": kb_page(mode, page, total_pages, back_target=back_target)}
            ))
        else:
            bot.send_message(chat_id, text, reply_markup=kb_page(mode, page, total_pages, back_target=back_target))
    except Exception:
        bot.send_message(chat_id, text, reply_markup=kb_page(mode, page, total_pages, back_target=back_target))


# ===================== SNISCAN HISTORY =====================
def get_sniscan_history():
    """Baca daftar file hasil scan SNIScan JSON dari output/."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    if not os.path.exists(OUT_DIR):
        return []
    files = []
    for fname in os.listdir(OUT_DIR):
        if fname.startswith("sniscan_") and fname.endswith(".json"):
            try:
                with open(os.path.join(OUT_DIR, fname), 'r') as f:
                    data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    target = first.get("target", fname.replace("sniscan_", "").replace(".json", ""))
                    count = len(data)
                elif isinstance(data, dict):
                    target = data.get("target", data.get("domain", fname.replace("sniscan_", "").replace(".json", "")))
                    count = len(data.get("results", []))
                else:
                    target = fname.replace("sniscan_", "").replace(".json", "")
                    count = 0
                files.append({
                    "type": "sniscan",
                    "target": target,
                    "count": count,
                    "file": fname,
                })
            except Exception:
                files.append({
                    "type": "sniscan",
                    "target": fname,
                    "count": 0,
                    "file": fname,
                })
    files.sort(key=lambda x: x["file"], reverse=True)
    return files


def build_sniscan_history_page(page=1, per_page=10):
    """Bangun teks halaman riwayat SNIScan dengan tombol inline per entri."""
    files = get_sniscan_history()
    total = len(files)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    chunk = files[start:end]

    lines = ["_" * 40, "📜 Riwayat SNIScan", "_" * 40, ""]
    if not files:
        lines.append("Belum ada hasil scan SNIScan.")
    else:
        lines.append(f"Total: {total} hasil scan")
    lines.append("")
    return "\n".join(lines), page, total_pages


def show_sniscan_history_page(chat_id, message_id, page, edit=True):
    """Tampilkan halaman riwayat SNIScan dengan tombol inline per entri."""
    text, page, total_pages = build_sniscan_history_page(page)
    kb = InlineKeyboardMarkup(row_width=2)

    files = get_sniscan_history()
    start = (page - 1) * 10
    end = start + 10
    chunk = files[start:end]
    for item in chunk:
        label = f"{item['target']} ({item['count']} host)"
        kb.add(InlineKeyboardButton(label, callback_data=f"sniscan:history:detail:{item['file']}"))

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"sniscan:history:{page - 1}"))
    nav.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="sniscan:history:noop"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ⏭️", callback_data=f"sniscan:history:{page + 1}"))
    kb.add(*nav)

    kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:sniscan"))

    try:
        if edit:
            bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
        else:
            bot.send_message(chat_id, text, reply_markup=kb)
    except Exception:
        bot.send_message(chat_id, text, reply_markup=kb)


def show_sniscan_history_detail(chat_id, message_id, filename, edit=True):
    """Tampilkan seluruh data dalam satu list hasil scan SNIScan (dengan paginasi)."""
    OUT_DIR = os.path.join(BASE_DIR, "output")
    fpath = os.path.join(OUT_DIR, filename)
    try:
        with open(fpath, 'r') as f:
            data = json.load(f)
    except Exception:
        text = "❌ Gagal membaca file hasil scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="sniscan:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    if not data:
        text = "❌ Tidak ada data dalam file scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="sniscan:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    if isinstance(data, list):
        target = data[0].get("target", filename) if data else filename
        results = [
            (
                item.get("sni_host", "-"),
                item.get("ip", "-"),
                item.get("tls_version", "-"),
                item.get("alpn", "-"),
                item.get("tls_port", "-"),
                ",".join(str(p) for p in item.get("extra_ports", [])) if item.get("extra_ports") else "-",
                item.get("response_time_ms", 0),
            )
            for item in data
        ]
    elif isinstance(data, dict):
        target = data.get("target", data.get("domain", filename))
        results = [
            (
                item.get("sni_host", "-"),
                item.get("ip", "-"),
                item.get("tls_version", "-"),
                item.get("alpn", "-"),
                item.get("tls_port", "-"),
                ",".join(str(p) for p in item.get("extra_ports", [])) if item.get("extra_ports") else "-",
                item.get("response_time_ms", 0),
            )
            for item in data.get("results", [])
        ]
    else:
        text = "❌ Tidak ada data dalam file scan."
        kb = InlineKeyboardMarkup(row_width=1)
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="sniscan:history:1"))
        try:
            if edit:
                bot.edit_message_text(text, chat_id, message_id, reply_markup=kb)
            else:
                bot.send_message(chat_id, text, reply_markup=kb)
        except Exception:
            pass
        return

    save_scan_state(chat_id, "sniscan", target, results, "SNIScan", page=1)
    info_text = f"✅ <b>Target sudah discan sebelumnya.</b>\nTotal: {len(results)} host"
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target="sniscan:history:1")


# ===================== D2IP (dari d2ip.sh) =====================
def d2ip_resolve_multi(domain):
    """Resolve domain menggunakan multiple resolver seperti d2ip.sh CLI.
    Return dict: {resolver: [ips]}
    """
    results = {}
    resolvers = {
        "dig": ["dig", "+short", domain],
        "host": ["host", domain],
        "getent": ["getent", "hosts", domain],
        "nslookup": ["nslookup", domain],
    }
    for name, cmd in resolvers.items():
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = out.stdout.strip().splitlines()
            ips = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Ambil IP saja (skip hostname)
                parts = line.split()
                for p in parts:
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', p):
                        ips.append(p)
            if ips:
                results[name] = ips
        except Exception:
            pass
    return results


def run_d2ip(chat_id, message_id, domain):
    # Coba socket dulu (cepat)
    ip, err = socket.gethostbyname(domain), None
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        ip = None
        err = str(e)

    # Coba multiple resolver
    multi = d2ip_resolve_multi(domain)

    lines = [f"✅ <b>D2IP selesai</b>\nDomain: <b>{esc(domain)}</b>\n"]
    if ip:
        lines.append(f"Socket: <code>{esc(ip)}</code>")
    else:
        lines.append(f"Socket: gagal ({esc(err)})")

    for name, ips in multi.items():
        lines.append(f"<b>{name}</b>")
        for x in ips:
            lines.append(f"  <code>{esc(x)}</code>")
        lines.append("")

    # Simpan ke file output (mirip d2ip.sh)
    OUT_DIR = os.path.join(BASE_DIR, "output")
    os.makedirs(OUT_DIR, exist_ok=True)
    fname = f"{OUT_DIR}/{domain}.txt"
    try:
        with open(fname, 'w') as f:
            f.write(f"Domain: {domain}\n\n")
            if ip:
                f.write(f"Socket: {ip}\n")
            else:
                f.write(f"Socket: gagal ({err})\n")
            for name, ips in multi.items():
                f.write(f"{name}:\n")
                for x in ips:
                    f.write(f"  {x}\n")
            f.write("\nSelesai.\n")
    except Exception:
        pass

    # Tampilkan dengan pagination jika terlalu panjang
    set_state(chat_id,
              mode="scan_view",
              scan_mode="d2ip",
              scan_target=domain,
              scan_results=lines,
              scan_page=1,
              scan_title="D2IP")
    show_scan_page(chat_id, message_id, edit=True)


# ===================== SUBFIND (impor dari subfind.py) =====================
def run_subfind(chat_id, message_id, domain):
    if message_id is None:
        sent = bot.send_message(chat_id, f"🔍 <b>SubFind</b>\nMempersiapkan scan untuk <b>{esc(domain)}</b>...")
        message_id = sent.message_id
    else:
        sent = type('obj', (object,), {'message_id': message_id})()

    import time
    start_time = time.time()

    # State progres yang dibagikan antara spinner thread dan progress callback
    scan_state = {
        "active": True,
        "chat_id": chat_id,
        "message_id": message_id,
        "title": "SubFind",
        "target": domain,
        "current": 0,
        "total": 0,
        "start_time": start_time,
        "spinner_idx": 0,
    }
    scan_lock = threading.Lock()

    def _spinner_loop():
        """Thread mandiri: memutar spinner dan mengupdate progres ke antrian."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            text = build_progress_text(
                state["title"], state["target"],
                state["current"], state["total"],
                state["start_time"], state["spinner_idx"],
            )
            _edit_queue.put((state["chat_id"], state["message_id"], text, {}))

            with scan_lock:
                scan_state["spinner_idx"] += 1

            time.sleep(0.4)

    # Jalankan spinner thread terpisah (independen dari progres scan)
    spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
    spinner_thread.start()

    def progress_callback(current, total):
        with scan_lock:
            scan_state["current"] = current
            scan_state["total"] = total

    results, errors = enumerate_domain(domain, progress_callback=progress_callback)

    # Matikan spinner thread
    with scan_lock:
        scan_state["active"] = False

    if errors:
        _edit_queue.put((
            chat_id, message_id,
            f"[!] Provider gagal: {'; '.join(errors)}",
            {}
        ))

    if not results:
        _edit_queue.put((
            chat_id, message_id,
            f"⚠️ <b>SubFind</b>\nTidak ada subdomain ditemukan untuk <b>{esc(domain)}</b>.",
            {"reply_markup": kb_back("menu:subfind")}
        ))
        clear_state(chat_id)
        return

    # Simpan hasil ke JSON (output/subfind_<domain>.json)
    OUT_DIR = os.path.join(BASE_DIR, "output")
    os.makedirs(OUT_DIR, exist_ok=True)
    jname = f"{OUT_DIR}/subfind_{domain}.json"
    json_data = [{"subdomain": r[0], "ip": r[1], "ports": r[2], "status": r[3], "cdn": r[4], "target": domain} for r in results]
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    # Simpan ke state dan tampilkan halaman 1 (pagination)
    save_scan_state(chat_id, "subfind", domain, results, "SubFind")
    show_scan_page(chat_id, sent.message_id, edit=True)


# ===================== SNISCAN (impor dari sniscan.py) =====================
def run_sniscan(chat_id, message_id, domain):
    if message_id is None:
        sent = bot.send_message(chat_id, f"🔍 <b>SNIScan</b>\nMempersiapkan scan untuk <b>{esc(domain)}</b>...")
        message_id = sent.message_id
    else:
        sent = type('obj', (object,), {'message_id': message_id})()

    import time
    start_time = time.time()

    # State progres yang dibagikan antara spinner thread dan progress callback
    scan_state = {
        "active": True,
        "chat_id": chat_id,
        "message_id": message_id,
        "title": "SNIScan",
        "target": domain,
        "current": 0,
        "total": 0,
        "start_time": start_time,
        "spinner_idx": 0,
    }
    scan_lock = threading.Lock()

    def _spinner_loop():
        """Thread mandiri: memutar spinner dan mengupdate progres ke antrian."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            text = build_progress_text(
                state["title"], state["target"],
                state["current"], state["total"],
                state["start_time"], state["spinner_idx"],
            )
            _edit_queue.put((state["chat_id"], state["message_id"], text, {}))

            with scan_lock:
                scan_state["spinner_idx"] += 1

            time.sleep(0.4)

    # Jalankan spinner thread terpisah (independen dari progres scan)
    spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
    spinner_thread.start()

    def progress_callback(current, total):
        with scan_lock:
            scan_state["current"] = current
            scan_state["total"] = total

    results, errors = enumerate_hosts(domain, progress_callback=progress_callback)

    # Matikan spinner thread
    with scan_lock:
        scan_state["active"] = False

    if errors:
        _edit_queue.put((
            chat_id, message_id,
            f"[!] Provider gagal: {'; '.join(errors)}",
            {}
        ))

    if not results:
        _edit_queue.put((
            chat_id, message_id,
            f"⚠️ <b>SNIScan</b>\nTidak ada SNI host ditemukan untuk <b>{esc(domain)}</b>.",
            {"reply_markup": kb_back("menu:sniscan")}
        ))
        clear_state(chat_id)
        return

    # Simpan hasil ke JSON (output/sniscan_<domain>.json)
    OUT_DIR = os.path.join(BASE_DIR, "output")
    os.makedirs(OUT_DIR, exist_ok=True)
    jname = f"{OUT_DIR}/sniscan_{domain}.json"
    json_data = [
        {
            "sni_host": r["sni_host"],
            "ip": r["ip"],
            "response_time_ms": r["response_time_ms"],
            "tls_version": r["tls_version"],
            "alpn": r["alpn"],
            "tls_port": r["tls_port"],
            "extra_ports": r["extra_ports"],
            "target": domain
        }
        for r in results
    ]
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    # Konversi ke tuple untuk pagination (sama pola dengan subfind)
    results_tuples = [
        (
            r["sni_host"],
            r["ip"],
            r["tls_version"],
            r["alpn"],
            r["tls_port"],
            ",".join(str(p) for p in r["extra_ports"]) if r["extra_ports"] else "-",
            r["response_time_ms"],
        )
        for r in results
    ]

    # Simpan ke state dan tampilkan halaman 1 (pagination)
    save_scan_state(chat_id, "sniscan", domain, results_tuples, "SNIScan")
    show_scan_page(chat_id, sent.message_id, edit=True)


# ===================== HELP =====================
HELP_TEXT = (
    "🤖 <b>Surfinder — Panduan Singkat</b>\n\n"
    "<b>Menu:</b>\n"
    "🌐 D2IP — Resolve domain ke IP. Ketik domain (contoh: google.com).\n"
    "🔍 SubFind — Cari subdomain + IP + port + status + CDN. Ketik domain (contoh: example.com).\n"
    "🛡️ CDNScan — Deteksi CDN dari IP/CIDR/range atau provider (cloudflare/cloudfront).\n"
    "🔍 SNIScan — Scan SNI host via TLS handshake + deteksi port. Ketik domain (contoh: instagram.com).\n\n"
    "<b>Cara pakai:</b>\n"
    "1. Klik tombol menu yang diinginkan (D2IP / SubFind / CDNScan / SNIScan)\n"
    "2. Ketik domain atau IP/CIDR sesuai yang diminta\n"
    "3. Tunggu scan selesai\n"
    "4. Lihat hasil per halaman dengan tombol Prev / Next\n\n"
    "<b>Perintah:</b>\n"
    "/start — Mulai bot & lihat menu\n"
    "/menu — Kembali ke menu utama\n"
    "/help — Tampilkan bantuan ini\n"
)


# ===================== HANDLERS =====================
@bot.message_handler(commands=['start', 'menu', 'help'])
def cmd_start(message):
    clear_state(message.chat.id)
    if message.text.strip().lower() == '/help':
        bot.send_message(message.chat.id, HELP_TEXT, reply_markup=kb_back("menu:main"))
        return
    bot.send_message(
        message.chat.id,
        "👋 <b>Surfinder</b>\nPilih menu di bawah:",
        reply_markup=kb_main()
    )


@bot.callback_query_handler(func=lambda call: True)
def cb_handler(call):
    chat_id = call.message.chat.id
    message_id = call.message.message_id
    data = call.data

    # Jawab callback agar tombol tidak "loading" selamanya
    try:
        bot.answer_callback_query(call.id)
    except Exception:
        pass

    if data == "menu:main":
        clear_state(chat_id)
        bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main())

    elif data == "menu:help":
        bot.edit_message_text(HELP_TEXT, chat_id, message_id, reply_markup=kb_back("menu:main"))

    elif data == "menu:d2ip":
        set_state(chat_id, mode="d2ip", awaiting="domain", prev_menu="menu:main")
        bot.edit_message_text(
            "🌐 <b>D2IP — Domain ➜ IP</b>\n\nKirim domain yang mau di-resolve (contoh: google.com).",
            chat_id, message_id, reply_markup=kb_back("menu:main")
        )

    elif data == "menu:subfind":
        set_state(chat_id, mode="subfind", awaiting=None, prev_menu="menu:main")
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(InlineKeyboardButton("🔍 Cari Subdomain", callback_data="subfind:search"))
        kb.add(InlineKeyboardButton("📜 Riwayat Scan", callback_data="subfind:history:1"))
        kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:main"))
        bot.edit_message_text(
            "🔍 <b>SubFind — Subdomain Enumeration</b>\n\nPilih opsi di bawah:",
            chat_id, message_id, reply_markup=kb
        )

    elif data == "subfind:search":
        set_state(chat_id, mode="subfind", awaiting="domain", prev_menu="menu:subfind")
        bot.edit_message_text(
            "🔍 <b>SubFind — Domain ➜ Subdomain</b>\n\nKirim domain yang mau dicari subdomain-nya (contoh: example.com).",
            chat_id, message_id, reply_markup=kb_back("menu:subfind")
        )

    elif data == "menu:cdnscan":
        set_state(chat_id, mode="cdnscan", awaiting="target", prev_menu="menu:main")
        bot.edit_message_text(
            "🛡️ <b>CDNScan — Deteksi CDN</b>\n\nPilih provider atau masukkan IP/CIDR/range secara manual:",
            chat_id, message_id, reply_markup=kb_cdnscan_menu()
        )

    elif data == "menu:sniscan":
        set_state(chat_id, mode="sniscan", awaiting=None, prev_menu="menu:main")
        bot.edit_message_text(
            "🔍 <b>SNIScan — TLS Handshake & Multi-Port</b>\n\nPilih opsi di bawah:",
            chat_id, message_id, reply_markup=kb_sniscan_menu()
        )

    elif data == "sniscan:search":
        set_state(chat_id, mode="sniscan", awaiting="domain", prev_menu="menu:sniscan")
        bot.edit_message_text(
            "🔍 <b>SNIScan — Domain ➜ SNI</b>\n\nKirim domain yang mau discan SNI-nya (contoh: instagram.com).",
            chat_id, message_id, reply_markup=kb_back("menu:sniscan")
        )

    elif data.startswith("d2ip:start:"):
        target = data.split(":", 2)[2]
        set_state(chat_id, mode="d2ip", awaiting=None, prev_menu="menu:d2ip")
        threading.Thread(target=run_d2ip, args=(chat_id, message_id, target), daemon=True).start()

    elif data.startswith("subfind:start:"):
        target = data.split(":", 2)[2]
        set_state(chat_id, mode="subfind", awaiting=None, prev_menu="menu:subfind")
        threading.Thread(target=run_subfind, args=(chat_id, message_id, target), daemon=True).start()

    elif data == "cdnscan:manual":
        set_state(chat_id, mode="cdnscan", awaiting="target", prev_menu="menu:cdnscan")
        bot.edit_message_text(
            "🛡️ <b>CDNScan — Masukkan target</b>\n\nKirim IP, CIDR (contoh 104.16.0.0/20), atau range (104.16.0.0-104.0.255).",
            chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
        )

    elif data.startswith("cdnscan:provider:"):
        provider = data.split(":", 2)[2]
        set_state(chat_id, mode="cdnscan_provider", awaiting=provider, cdn_provider=provider, prev_menu="menu:cdnscan")
        try:
            bot.edit_message_text(
                f"🛡️ <b>CDNScan — Provider {provider}</b>\nMengunduh daftar rentang IP...",
                chat_id, message_id
            )
        except Exception:
            pass
        threading.Thread(target=fetch_provider_ranges, args=(chat_id, message_id, provider), daemon=True).start()

    elif data.startswith("cdnscan:ranges:page:"):
        page = int(data.split(":")[-1])
        st = get_state(chat_id)
        ranges = st.get("cdn_ranges", [])
        selected = st.get("cdn_selected", [])
        provider = st.get("cdn_provider", "")
        prev_menu = st.get("prev_menu", "menu:cdnscan")
        set_state(chat_id, cdn_range_page=page)
        bot.edit_message_text(
            f"🛡️ <b>Pilih rentang IP — {provider}</b>\nHalaman {page}",
            chat_id, message_id, reply_markup=kb_ranges(ranges, page=page, selected=selected)
        )

    elif data.startswith("cdnscan:range:"):
        parts = data.split(":")
        # cdnscan:range:<cidr>  atau  cdnscan:range:confirm
        if len(parts) == 3 and parts[2] != "confirm":
            cidr = parts[2]
            st = get_state(chat_id)
            selected = st.get("cdn_selected", [])
            if cidr in selected:
                selected.remove(cidr)
            else:
                selected.append(cidr)
            set_state(chat_id, cdn_selected=selected)
            provider = st.get("cdn_provider", "")
            ranges = st.get("cdn_ranges", [])
            # Tampilkan ulang halaman saat ini
            page = st.get("cdn_range_page", 1)
            bot.edit_message_text(
                f"🛡️ <b>Pilih rentang IP — {provider}</b>\nTerpilih: {len(selected)}",
                chat_id, message_id, reply_markup=kb_ranges(ranges, page=page, selected=selected)
            )
        elif parts[2] == "confirm":
            st = get_state(chat_id)
            selected = st.get("cdn_selected", [])
            if not selected:
                try:
                    bot.answer_callback_query(call.id, "Pilih minimal satu rentang.")
                except Exception:
                    pass
                return
            set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_targets=selected, prev_menu="cdnscan:ranges:page")
            target_display = ", ".join(selected[:3]) + (f" (+{len(selected)-3} lebih)" if len(selected) > 3 else "")
            bot.edit_message_text(
                f"🛡️ <b>CDNScan — Limit IP</b>\nTarget: {esc(target_display)}\nBerapa IP maksimal per batch? (maksimal 1000)",
                chat_id, message_id, reply_markup=kb_limit()
            )

    elif data.startswith("cdnscan:history:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[2].isdigit():
            page = int(parts[2])
            show_cdnscan_history_page(chat_id, message_id, page, edit=True)
        elif len(parts) == 4 and parts[2] == "detail":
            filename = parts[3]
            show_cdnscan_history_detail(chat_id, message_id, filename, edit=True)

    elif data.startswith("subfind:history:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[2].isdigit():
            page = int(parts[2])
            show_subfind_history_page(chat_id, message_id, page, edit=True)
        elif len(parts) == 4 and parts[2] == "detail":
            filename = parts[3]
            show_subfind_history_detail(chat_id, message_id, filename, edit=True)

    elif data.startswith("sniscan:history:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[2].isdigit():
            page = int(parts[2])
            show_sniscan_history_page(chat_id, message_id, page, edit=True)
        elif len(parts) == 4 and parts[2] == "detail":
            filename = parts[3]
            show_sniscan_history_detail(chat_id, message_id, filename, edit=True)

    elif data.startswith("cdnscan:limit:"):
        parts = data.split(":")
        # cdnscan:limit:<n>  (targets sudah disimpan di state oleh cdnscan:range:confirm)
        if parts[2] == "custom":
            set_state(chat_id, mode="cdnscan_limit", awaiting="custom_limit", prev_menu="cdnscan:ranges:page")
            bot.edit_message_text(
                "🔢 <b>Masukkan limit IP custom</b>\nMasukkan angka maksimal IP per batch (1-1000):",
                chat_id, message_id, reply_markup=kb_back("cdnscan:ranges:page")
            )
            return
        limit = int(parts[2])
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
        # Mulai scan target pertama
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()

    elif data == "cdnscan:next":
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        index = st.get("cdn_target_index", 0)

        # Skip target yang sudah selesai (completed) — cari target berikutnya yang belum dipindai
        while index < len(targets):
            target = targets[index]
            state = load_state(target)
            if state and state.get("completed"):
                index += 1
                set_state(chat_id, cdn_target_index=index)
            else:
                break

        if index < len(targets):
            threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()
        else:
            try:
                bot.edit_message_text(
                    "✅ <b>CDNScan selesai</b>\nSemua target telah discan.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                bot.send_message(chat_id, "✅ CDNScan selesai — semua target telah discan.", reply_markup=kb_back("menu:cdnscan"))
            clear_state(chat_id)

    elif data == "cdnscan:view":
        # Tampilkan hasil gabungan dari semua target yang sudah discan
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        all_results = []
        for t in targets:
            safe_name = t.replace("/", "_").replace("-", "_").replace(".", "_")
            jname = f"{BASE_DIR}/output/cdnscan_{safe_name}.json"
            try:
                with open(jname, 'r') as f:
                    saved = json.load(f)
                if saved and isinstance(saved, list):
                    for item in saved:
                        all_results.append((
                            item.get("ip", "-"),
                            item.get("ports", "-"),
                            item.get("cdn", "-"),
                            item.get("status", "-"),
                        ))
            except Exception:
                pass

        if not all_results:
            try:
                bot.edit_message_text(
                    "❌ <b>Tidak ada hasil scan</b>\nBelum ada data yang tersimpan.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                bot.send_message(chat_id, "❌ Tidak ada hasil scan.", reply_markup=kb_back("menu:cdnscan"))
            return

        # Simpan hasil gabungan dan tampilkan via pagination
        set_state(chat_id,
                  mode="scan_view",
                  scan_mode="cdnscan",
                  scan_target=", ".join(targets[:3]) + (f" (+{len(targets)-3} lebih)" if len(targets) > 3 else ""),
                  scan_results=all_results,
                  scan_page=1,
                  scan_title="Hasil Gabungan CDNScan")
        show_scan_page(chat_id, message_id, edit=True)

    elif data.startswith("cdnscan:start:"):
        target = data.split(":", 2)[2]
        set_state(chat_id, mode="cdnscan", awaiting=None, cdn_targets=[target], cdn_limit=0, cdn_target_index=0, prev_menu="menu:cdnscan")
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()

    elif data.startswith("page:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[2].isdigit():
            target_page = int(parts[2])
            mode = parts[1]
            st = get_state(chat_id)
            if st.get("mode") == "scan_view" and st.get("scan_mode") == mode:
                set_state(chat_id, scan_page=target_page)
                show_scan_page(chat_id, message_id, edit=True)
            else:
                try:
                    bot.answer_callback_query(call.id, "Sesi scan sudah kedaluwarsa.")
                except Exception:
                    pass
        else:
            try:
                bot.answer_callback_query(call.id, "Tombol tidak dikenal.")
            except Exception:
                pass

    elif data.startswith("back:"):
        prev_menu = data.split(":", 1)[1]
        st = get_state(chat_id)
        if prev_menu == "menu:main":
            clear_state(chat_id)
            bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main())
        elif prev_menu == "menu:d2ip":
            set_state(chat_id, mode="d2ip", awaiting="domain", prev_menu="menu:main")
            bot.edit_message_text(
                "🌐 <b>D2IP — Domain ➜ IP</b>\n\nKirim domain yang mau di-resolve (contoh: google.com).",
                chat_id, message_id, reply_markup=kb_back("menu:main")
            )
        elif prev_menu == "menu:subfind":
            set_state(chat_id, mode="subfind", awaiting=None, prev_menu="menu:main")
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(InlineKeyboardButton("🔍 Cari Subdomain", callback_data="subfind:search"))
            kb.add(InlineKeyboardButton("📜 Riwayat Scan", callback_data="subfind:history:1"))
            kb.add(InlineKeyboardButton("↩️ Kembali", callback_data="back:menu:main"))
            bot.edit_message_text(
                "🔍 <b>SubFind — Subdomain Enumeration</b>\n\nPilih opsi di bawah:",
                chat_id, message_id, reply_markup=kb
            )
        elif prev_menu == "menu:cdnscan":
            set_state(chat_id, mode="cdnscan", awaiting="target", prev_menu="menu:main")
            bot.edit_message_text(
                "🛡️ <b>CDNScan — Deteksi CDN</b>\n\nPilih provider atau masukkan IP/CIDR/range secara manual:",
                chat_id, message_id, reply_markup=kb_cdnscan_menu()
            )
        elif prev_menu == "menu:sniscan":
            set_state(chat_id, mode="sniscan", awaiting=None, prev_menu="menu:main")
            bot.edit_message_text(
                "🔍 <b>SNIScan — TLS Handshake & Multi-Port</b>\n\nPilih opsi di bawah:",
                chat_id, message_id, reply_markup=kb_sniscan_menu()
            )
        elif prev_menu == "cdnscan_provider":
            provider = st.get("cdn_provider", "")
            set_state(chat_id, mode="cdnscan_provider", awaiting=provider, cdn_provider=provider, prev_menu="menu:cdnscan")
            try:
                bot.edit_message_text(
                    f"🛡️ <b>CDNScan — Provider {provider}</b>\nMengunduh daftar rentang IP...",
                    chat_id, message_id
                )
            except Exception:
                pass
            threading.Thread(target=fetch_provider_ranges, args=(chat_id, message_id, provider), daemon=True).start()
        elif prev_menu == "cdnscan:ranges:page":
            provider = st.get("cdn_provider", "")
            ranges = st.get("cdn_ranges", [])
            selected = st.get("cdn_selected", [])
            page = st.get("cdn_range_page", 1)
            set_state(chat_id, mode="cdnscan_provider", awaiting=provider, cdn_provider=provider, prev_menu="menu:cdnscan")
            try:
                bot.edit_message_text(
                    f"🛡️ <b>Pilih rentang IP — {provider}</b>\nDitemukan {len(ranges)} rentang.\nPilih satu atau lebih:",
                    chat_id, message_id, reply_markup=kb_ranges(ranges, page=page, selected=selected)
                )
            except Exception:
                pass
        elif prev_menu == "cdnscan:history:1":
            show_cdnscan_history_page(chat_id, message_id, 1, edit=True)
        elif prev_menu == "subfind:history:1":
            show_subfind_history_page(chat_id, message_id, 1, edit=True)
        elif prev_menu == "sniscan:history:1":
            show_sniscan_history_page(chat_id, message_id, 1, edit=True)
        else:
            # Fallback ke menu utama
            clear_state(chat_id)
            bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main())

    else:
        try:
            bot.answer_callback_query(call.id, "Tombol tidak dikenal.")
        except Exception:
            pass


def run_cdnscan_target_batch(chat_id, message_id):
    """Proses daftar target CDNScan satu per satu (dengan resume)."""
    st = get_state(chat_id)
    targets = st.get("cdn_targets", []) or []
    limit = st.get("cdn_limit", 0)
    index = st.get("cdn_target_index", 0)

    if index >= len(targets):
        # Semua target selesai, tampilkan pesan selesai dengan tombol Lihat
        _edit_queue.put((
            chat_id, message_id,
            "✅ <b>CDNScan selesai</b>\nSemua target telah discan.",
            {"reply_markup": kb_next_target("menu:cdnscan", show_view=True)}
        ))
        clear_state(chat_id)
        return

    # Hitung total IP di semua target (untuk progress gabungan)
    total_all_ips = 0
    scanned_all_ips = 0
    for t in targets:
        t_state = load_state(t)
        t_offset = t_state.get('scanned_count', 0) if t_state else 0
        t_all = parse_ip_range(t)
        t_total = len(t_all) if t_all else 0
        total_all_ips += t_total
        scanned_all_ips += t_offset  # Sudah discan dari target sebelumnya

    target = targets[index]
    import time
    start_time = time.time()

    # State progres gabungan yang dibagikan antara spinner thread dan progress callback
    scan_state = {
        "active": True,
        "chat_id": chat_id,
        "message_id": message_id,
        "title": "CDNScan",
        "target": f"Target [{index + 1}/{len(targets)}]: {esc(target)}",
        "current": scanned_all_ips,  # Kumulatif dari target sebelumnya
        "total": total_all_ips,      # Total semua target
        "start_time": start_time,
        "spinner_idx": 0,
        "target_index": index,
        "target_current": 0,
        "target_total": 0,
    }
    scan_lock = threading.Lock()

    try:
        _edit_queue.put((
            chat_id, message_id,
            f"🛡️ <b>CDNScan</b>\nTarget [{index + 1}/{len(targets)}]: <b>{esc(target)}</b>\nMemulai scan...",
            {}
        ))
    except Exception:
        pass

    # Cek state resume untuk target ini
    state = load_state(target)
    state_offset = state.get('scanned_count', 0) if state else 0
    if state and state.get("completed"):
        # Sudah selesai, tampilkan hasil scan dari file JSON
        OUT_DIR = os.path.join(BASE_DIR, "output")
        safe_name = target.replace("/", "_").replace("-", "_").replace(".", "_")
        jname = f"{OUT_DIR}/cdnscan_{safe_name}.json"
        try:
            with open(jname, 'r') as f:
                saved = json.load(f)
        except Exception:
            saved = []

        if saved and isinstance(saved, list):
            results = [(item.get("ip", "-"), item.get("ports", "-"), item.get("cdn", "-"), item.get("status", "-")) for item in saved]
            save_scan_state(chat_id, "cdnscan", target, results, "CDNScan", page=1)
            show_scan_page(chat_id, message_id, edit=True, info_text="✅ <b>Target sudah discan sebelumnya.</b>")
        else:
            try:
                bot.edit_message_text(
                    f"🛡️ <b>CDNScan</b>\nTarget: <b>{esc(target)}</b>\nSudah discan sepenuhnya, tidak ada data yang tersimpan.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                pass
        return

    ips = parse_ip_range(target, offset=state_offset, max_ips=limit if limit > 0 else None)
    if not ips:
        # Target tidak punai IP yang bisa dipindai, lanjut ke target berikutnya otomatis
        set_state(chat_id, cdn_target_index=index + 1)
        # Rekursi untuk memproses target berikutnya
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()
        return

    results = []
    max_workers = min(30, len(ips))
    c = 0

    # Jalankan spinner thread terpisah (independen dari progres scan)
    def _spinner_loop():
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state_copy = dict(scan_state)

            text = build_progress_text(
                state_copy["title"], state_copy["target"],
                state_copy["current"], state_copy["total"],
                state_copy["start_time"], state_copy["spinner_idx"],
            )
            _edit_queue.put((state_copy["chat_id"], state_copy["message_id"], text, {}))

            with scan_lock:
                scan_state["spinner_idx"] += 1

            time.sleep(0.4)

    spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
    spinner_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_ip, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    results.append((ip, "-", "-", "-"))
                c += 1
                with scan_lock:
                    scan_state["target_current"] = c
                    scan_state["current"] = scanned_all_ips + c  # Kumulatif semua target
                    scan_state["total"] = total_all_ips          # Total semua target

    finally:
        # Matikan spinner thread
        with scan_lock:
            scan_state["active"] = False

    results.sort(key=lambda x: ipaddress.ip_address(x[0].split('/')[0] if '/' in x[0] else x[0]))

    # Simpan JSON
    OUT_DIR = os.path.join(BASE_DIR, "output")
    os.makedirs(OUT_DIR, exist_ok=True)
    safe_name = target.replace("/", "_").replace("-", "_").replace(".", "_")
    jname = f"{OUT_DIR}/cdnscan_{safe_name}.json"
    json_data = [{"ip": r[0], "ports": r[1], "cdn": r[2], "status": r[3], "target": target, "provider": st.get("cdn_provider", "manual")} for r in results]
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    # Update state resume
    new_offset = state_offset + len(results)
    next_check = parse_ip_range(target, offset=new_offset, max_ips=1)
    completed = len(next_check) == 0
    save_state(target, new_offset, completed)

    if not completed:
        # Target belum selesai (dijeda), tampilkan progres dan opsi lanjut
        # Hitung sisa IP untuk ditampilkan
        all_ips = parse_ip_range(target)
        total_ips = len(all_ips) if all_ips else 0
        sisa_ips = max(0, total_ips - new_offset)

        set_state(chat_id, cdn_target_index=index)
        _edit_queue.put((
            chat_id, message_id,
            f"⏸️ <b>CDNScan jeda</b>\nTarget [{index + 1}/{len(targets)}]: <b>{esc(target)}</b>\n"
            f"Sudah discan: {new_offset} IP, sisa: {sisa_ips} IP.\nKlik Next untuk melanjutkan target ini.",
            {"reply_markup": kb_next_target("menu:cdnscan")}
        ))
        return

    # Target selesai, lanjut ke target berikutnya otomatis (tanpa jeda)
    set_state(chat_id, cdn_target_index=index + 1)
    scanned_all_ips += len(results)

    if index + 1 < len(targets):
        # Ada target lagi, lanjut otomatis tanpa jeda
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()
        return
    else:
        # Semua target selesai, tampilkan tombol Lihat
        save_scan_state(chat_id, "cdnscan", targets[-1] if targets else [], [], "CDNScan")
        _edit_queue.put((
            chat_id, message_id,
            "✅ <b>CDNScan selesai</b>\nSemua target telah discan.",
            {"reply_markup": kb_next_target("menu:cdnscan", show_view=True)}
        ))
        clear_state(chat_id)
        return


def fetch_provider_ranges(chat_id, message_id, provider):
    """Unduh daftar rentang IP dari provider dan tampilkan untuk dipilih."""
    ips, err = get_provider_ips(provider)
    if err:
        _edit_queue.put((
            chat_id, message_id,
            f"❌ <b>CDNScan</b>\nGagal unduh rentang {provider}: {esc(err)}",
            {"reply_markup": kb_back("menu:cdnscan")}
        ))
        clear_state(chat_id)
        return
    ips = ips or []

    set_state(chat_id, cdn_ranges=ips, cdn_provider=provider, cdn_selected=[], cdn_range_page=1)
    _edit_queue.put((
        chat_id, message_id,
        f"🛡️ <b>Pilih rentang IP — {provider}</b>\nDitemukan {len(ips)} rentang.\nPilih satu atau lebih:",
        {"reply_markup": kb_ranges(ips, page=1)}
    ))

@bot.message_handler(func=lambda message: True)
def text_handler(message):
    chat_id = message.chat.id
    text = message.text.strip()
    st = get_state(chat_id)
    mode = st.get("mode")
    awaiting = st.get("awaiting")

    if not mode or mode == "main":
        bot.send_message(chat_id, "Pilih menu dulu dengan /start.", reply_markup=kb_main())
        return

    if mode == "d2ip" and awaiting == "domain":
        domain = text.lower().strip()
        if not validate_domain(domain):
            bot.send_message(chat_id, "Domain tidak valid. Coba lagi (contoh: google.com).")
            return
        sent = bot.send_message(chat_id, f"🌐 <b>D2IP</b>\nMeng-resolve <b>{esc(domain)}</b>...")
        set_state(chat_id, mode="d2ip", awaiting=None)
        threading.Thread(target=run_d2ip, args=(chat_id, sent.message_id, domain), daemon=True).start()
        return

    if mode == "subfind" and awaiting == "domain":
        domain = text.lower().strip()
        if not validate_domain(domain):
            bot.send_message(chat_id, "Domain tidak valid. Coba lagi (contoh: example.com).")
            return
        set_state(chat_id, mode="subfind", awaiting=None)
        threading.Thread(target=run_subfind, args=(chat_id, None, domain), daemon=True).start()
        return

    if mode == "cdnscan_limit" and awaiting == "custom_limit":
        try:
            limit = int(text)
        except ValueError:
            bot.send_message(chat_id, "Masukkan angka yang valid.")
            return
        if limit < 1 or limit > 1000:
            bot.send_message(chat_id, "Limit harus antara 1 dan 1000. Coba lagi.")
            return
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
        sent = bot.send_message(
            chat_id,
            f"🔢 <b>Limit IP diset: {limit}</b>\nSedang memproses scan...",
        )
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, sent.message_id), daemon=True).start()
        return

    if mode == "cdnscan" and awaiting == "target":
        target = text.strip()
        # Cek apakah nama provider
        if target.lower() in PROVIDER_URLS:
            set_state(chat_id, mode="cdnscan_provider", awaiting=target.lower(), cdn_provider=target.lower())
            sent = bot.send_message(chat_id, f"🛡️ <b>CDNScan — Provider {target}</b>\nMengunduh daftar rentang IP...")
            threading.Thread(target=fetch_provider_ranges, args=(chat_id, sent.message_id, target.lower()), daemon=True).start()
            return
        sent = bot.send_message(chat_id, f"🛡️ <b>CDNScan</b>\nMemproses target <b>{esc(target)}</b>...")
        set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_targets=[target], cdn_limit=0, cdn_target_index=0)
        bot.edit_message_text(
            f"🔢 <b>CDNScan — Limit IP</b>\nTarget: {esc(target)}\nBerapa IP maksimal per batch? (maksimal 1000)",
            chat_id, sent.message_id, reply_markup=kb_limit("menu:cdnscan")
        )
        return

    if mode == "sniscan" and awaiting == "domain":
        domain = text.lower().strip()
        if not validate_domain(domain):
            bot.send_message(chat_id, "Domain tidak valid. Coba lagi (contoh: instagram.com).")
            return
        set_state(chat_id, mode="sniscan", awaiting=None)
        threading.Thread(target=run_sniscan, args=(chat_id, None, domain), daemon=True).start()
        return

    # Fallback
    bot.send_message(chat_id, "Pilih menu dulu dengan /start.", reply_markup=kb_main())


# ===================== MAIN =====================
if __name__ == '__main__':
    print("Surfinder Telegram Bot sedang berjalan...")
    bot.infinity_polling()