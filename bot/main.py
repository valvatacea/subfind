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
import logging
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed

# Folder root repo (induk folder bot/) — semua path dinamis dari lokasi file ini
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOT_DIR = os.path.dirname(os.path.abspath(__file__))

from dotenv import load_dotenv
load_dotenv(os.path.join(BOT_DIR, '.env'))

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('surfinder')

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
    detect_cdn as subfind_detect_cdn,
)
from common.validators import validate_domain
from common.nsfw_filter import is_blocked, blocked_message
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

ADMIN_IDS = set()
for part in (os.environ.get("ADMIN_IDS", "") or "").split(","):
    part = part.strip()
    if part.isdigit():
        ADMIN_IDS.add(int(part))


def is_admin(user_id):
    try:
        return int(user_id) in ADMIN_IDS
    except (TypeError, ValueError):
        return False

# ===================== BATASAN SCAN SIMULTAN =====================
MAX_ACTIVE_SCANS = 3          # Maksimal scan berjalan bersamaan di seluruh bot
ACTIVE_SCANS = 0              # Counter scan aktif saat ini
MAX_CONCURRENT_SCANS_PER_CHAT = 1  # Maksimal 1 scan per chat (kecuali d2ip)
# =================================================================

# Registry scan aktif untuk tombol Stop (chat_id -> scan_state dict)
ACTIVE_SCAN_STATES = {}
SCAN_STATE_LOCK = threading.Lock()


def register_scan_state(chat_id, scan_state):
    """Daftarkan scan_state ke registry agar handler scan:stop dapat mengaksesnya."""
    with SCAN_STATE_LOCK:
        ACTIVE_SCAN_STATES[chat_id] = scan_state


def unregister_scan_state(chat_id):
    """Hapus scan_state dari registry setelah scan selesai/dihentikan."""
    with SCAN_STATE_LOCK:
        ACTIVE_SCAN_STATES.pop(chat_id, None)


def request_scan_stop(chat_id):
    """Set stop_requested=True pada scan_state chat_id (active tetap True
    biar spinner tetap jalan dan tombol Stop bisa di-animate).
    Return True jika scan_state ditemukan."""
    with SCAN_STATE_LOCK:
        scan_state = ACTIVE_SCAN_STATES.get(chat_id)
        if not scan_state:
            return False
        scan_state["stop_requested"] = True
        # Propagate ke stop_event (dipakai SNIScan) jika ada
        stop_event = scan_state.get("stop_event")
        if stop_event is not None:
            try:
                stop_event.set()
            except Exception:
                pass
        return True


def kb_stop_button(stop_requested=False, spinner_idx=0):
    """Tombol Stop dengan animasi saat stop_requested=True."""
    if stop_requested:
        dots = "." * (spinner_idx % 4)
        label = f"⏳ Menghentikan{dots}"
    else:
        label = "⏹️ Stop"
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(label, callback_data="scan:stop"))
    return kb


def cek_slot_scan(chat_id):
    """Cek apakah chat boleh mulai scan (1 scan per chat).
    Return True jika slot tersedia dan sudah ditandai scanning=True."""
    st = get_state(chat_id)
    if st.get("scanning"):
        return False
    global ACTIVE_SCANS
    if ACTIVE_SCANS >= MAX_ACTIVE_SCANS:
        return False
    ACTIVE_SCANS += 1
    set_state(chat_id, scanning=True)
    return True


def bebaskan_slot_scan(chat_id):
    """Lepas slot scan setelah selesai (atau gagal)."""
    global ACTIVE_SCANS
    ACTIVE_SCANS = max(0, ACTIVE_SCANS - 1)
    set_state(chat_id, scanning=False)

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
IP_OVERALL_TIMEOUT = 5  # detik maksimum per IP sebelum dianggap gagal
MAX_TOTAL_BATCH = 1500  # batas total IP per batch multi-target

# ===================== STATE USER =====================
# In-memory flags only (scanning). Semua state lain persist di chat_state.settings (session_store).
_scan_flags = {}
_scan_flags_lock = threading.Lock()

# Session store (Fase 1). None jika import gagal.
try:
    from bot import session_store as _ss
except Exception:
    try:
        sys.path.insert(0, BOT_DIR)
        import session_store as _ss
    except Exception:
        _ss = None


def _scan_flag_get(chat_id):
    with _scan_flags_lock:
        return bool(_scan_flags.get(chat_id, False))


def _scan_flag_set(chat_id, value):
    with _scan_flags_lock:
        if value:
            _scan_flags[chat_id] = True
        else:
            _scan_flags.pop(chat_id, None)


def set_state(chat_id, **kw):
    """Persist state ke chat_state.settings. Key 'scanning' ditangani terpisah (in-memory)."""
    scanning = kw.pop("scanning", None)
    if scanning is not None:
        _scan_flag_set(chat_id, bool(scanning))
    if not kw:
        return
    if _ss is not None:
        try:
            settings = _ss.get_chat_settings(chat_id)
            settings.update(kw)
            for k, v in list(settings.items()):
                if v is None:
                    settings.pop(k, None)
            _ss.set_chat_settings(chat_id, settings)
        except Exception as e:
            log.debug("set_state failed: %s", e)
    # Dual-write session store (best-effort)
    if _ss is not None and 'mode' in kw:
        try:
            active = _ss.get_active_session(chat_id)
            if active is None:
                sid = _ss.create_session(chat_id, kw['mode'], payload=kw, status='awaiting_input')
                _ss.set_active_session(chat_id, sid)
            else:
                _ss.update_session(active['id'], payload=kw)
        except Exception as e:
            log.debug("session dual-write set_state failed: %s", e)


def get_state(chat_id):
    """Baca state dari chat_state.settings (+ scanning flag in-memory)."""
    st = {}
    if _ss is not None:
        try:
            st = dict(_ss.get_chat_settings(chat_id))
        except Exception:
            st = {}
    st["scanning"] = _scan_flag_get(chat_id)
    return st


_FLOW_KEYS = ("mode", "awaiting", "prev_menu", "scan_mode", "scan_target", "scan_title",
              "scan_page", "scan_back_target", "scan_filters", "filter_mode", "filter_field",
              "cdn_targets", "cdn_selected", "cdn_ranges", "cdn_provider", "cdn_limit",
              "cdn_range_page", "cdn_target_index", "_sid")

def clear_state(chat_id):
    """Hapus flow state (flow keys) untuk menu utama; pertahankan scanning flag & history page."""
    if _ss is not None:
        try:
            _ss.clear_active_session(chat_id)
            settings = _ss.get_chat_settings(chat_id)
            for k in _FLOW_KEYS:
                settings.pop(k, None)
            _ss.set_chat_settings(chat_id, settings)
        except Exception as e:
            log.debug("clear_state failed: %s", e)


# Subsystem 1 (Fase 3): history page disimpan di chat_state.settings, bukan user_state.
def _hist_page_get(chat_id, key):
    if _ss is not None:
        try:
            return _ss.get_chat_settings(chat_id).get(key, 1)
        except Exception:
            pass
    return get_state(chat_id).get(key, 1)


def _hist_page_set(chat_id, key, page):
    if _ss is not None:
        try:
            st = _ss.get_chat_settings(chat_id)
            st[key] = page
            _ss.set_chat_settings(chat_id, st)
            return
        except Exception:
            pass
    set_state(chat_id, **{key: page})


# Subsystem 2 (Fase 3): scan_page & scan_back_target -> chat_state.settings
def _scan_page_get(chat_id):
    if _ss is not None:
        try:
            v = _ss.get_chat_settings(chat_id).get("scan_page")
            if v is not None:
                return v
        except Exception:
            pass
    return get_state(chat_id).get("scan_page", 1)


def _scan_page_set(chat_id, page):
    if _ss is not None:
        try:
            st = _ss.get_chat_settings(chat_id)
            st["scan_page"] = page
            _ss.set_chat_settings(chat_id, st)
            return
        except Exception:
            pass
    _scan_page_set(chat_id, page)


def _scan_back_target_get(chat_id):
    if _ss is not None:
        try:
            v = _ss.get_chat_settings(chat_id).get("scan_back_target")
            if v is not None:
                return v
        except Exception:
            pass
    return get_state(chat_id).get("scan_back_target")


def _scan_back_target_set(chat_id, value):
    if _ss is not None:
        try:
            st = _ss.get_chat_settings(chat_id)
            if value is None:
                st.pop("scan_back_target", None)
            else:
                st["scan_back_target"] = value
            _ss.set_chat_settings(chat_id, st)
            return
        except Exception:
            pass
    if value is None:
        # no-op fallback
        pass
    else:
        set_state(chat_id, scan_back_target=value)


# Subsystem 3 (Fase 3): filter state -> chat_state.settings
def _cs_get(chat_id, key, default=None):
    if _ss is not None:
        try:
            settings = _ss.get_chat_settings(chat_id)
            if key in settings:
                return settings.get(key, default)
        except Exception:
            pass
    return get_state(chat_id).get(key, default)


def _cs_set(chat_id, key, value):
    if _ss is not None:
        try:
            st = _ss.get_chat_settings(chat_id)
            if value is None:
                st.pop(key, None)
            else:
                st[key] = value
            _ss.set_chat_settings(chat_id, st)
            return
        except Exception:
            pass
    if value is not None:
        set_state(chat_id, **{key: value})


# ===================== ESCAPE HTML =====================
def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pad_label(label, width=12):
    """Tanpa padding - label langsung diikuti titik dua."""
    return label


def count_total_batch_ips(targets, limit):
    """Hitung total IP yang akan discan dalam satu batch.

    limit=0 berarti unlimited (ambil semua sisa IP per target).
    """
    total = 0
    for t in targets:
        t_state = load_state(t)
        t_offset = t_state.get('scanned_count', 0) if t_state else 0
        t_all_full = parse_ip_range(t)
        t_total_full = len(t_all_full) if t_all_full else 0
        t_sisa = max(0, t_total_full - t_offset)
        if t_sisa > 0:
            ips = min(limit, t_sisa) if limit > 0 else t_sisa
            total += ips
    return total


# ===================== SPINNER & WAKTU =====================
# SPINNER, format_elapsed diimpor dari common.progress


def build_progress_text(spinner_idx, title, target, current, total, start_time,
                        elapsed=None, eta=None):
    """Bangun teks progres dengan spinner, bar, persentase, elapsed time, dan ETA.

    Tidak ada rate limiting di sini — spinner thread mengontrol timing (setiap 0,4 detik).
    Output format HTML untuk Telegram, menggunakan emoji 🟦⬜ untuk progress bar.
    elapsed/eta dapat dikirim oleh thread terpisah (elapsed_loop) agar spinner
    tidak tergantung pada event penyelesaian item.
    """
    import time
    now = time.time()
    if elapsed is None:
        elapsed = now - start_time

    # Clamp current dan pct agar tidak melebihi total (hindari >100%)
    if total > 0:
        current = min(current, total)
        pct = int(current / total * 100)
    else:
        current = 0
        pct = 0

    if eta is None:
        if current > 0 and total > 0 and elapsed > 0:
            eta = calculate_eta(elapsed, current, total)
        else:
            eta = 0

    # Progress bar: 10 blok, emoji kotak biru terisi dan kosong
    bar = build_bar(current, total, width=10,
                    filled_char="🟦", empty_char="⬜")

    # Spinner dari spinner_idx yang dikelola oleh spinner thread (independen dari progres)
    spinner = SPINNER[spinner_idx % len(SPINNER)]

    return (f"{spinner} <b>{title}</b>\n"
            f"Memindai <b>{esc(target)}</b>...\n"
            f"{bar} {pct}% ({current}/{total})\n"
            f"Elapsed: {format_elapsed(elapsed)} | ETA: {format_elapsed(eta)}")


# ===================== KEYBOARD =====================
def kb_main(user_id=None):
    m = InlineKeyboardMarkup(row_width=2)
    m.add(
        InlineKeyboardButton("🌐 D2IP (Domain ➜ IP)", callback_data="menu:d2ip"),
        InlineKeyboardButton("🔍 SubFind (Subdomain)", callback_data="menu:subfind"),
        InlineKeyboardButton("🛡️ CDNScan (CDN/IP)", callback_data="menu:cdnscan"),
        InlineKeyboardButton("🔍 SNIScan (TLS/IP)", callback_data="menu:sniscan"),
    )
    if is_admin(user_id):
        m.add(InlineKeyboardButton("🗑️ Hapus Riwayat", callback_data="admin:hapus_riwayat"))
    m.add(InlineKeyboardButton("❓ Bantuan", callback_data="menu:help"))
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
    m = InlineKeyboardMarkup(row_width=3)
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


def kb_next_target(prev_menu="menu:cdnscan", show_view=False, show_next=True):
    m = InlineKeyboardMarkup(row_width=2)
    buttons = []
    if show_view:
        buttons.append(InlineKeyboardButton("👁️ Lihat", callback_data="cdnscan:view"))
    if show_next:
        buttons.append(InlineKeyboardButton("▶️ Next", callback_data="cdnscan:next"))
    if buttons:
        m.add(*buttons)
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
            lines.append(f"{pad_label('CDN', 12)}: -")
            lines.append(f"{pad_label('Status', 12)}: {esc(r[7])}")
            lines.append("----------------------------------------------")
    elif mode == "d2ip":
        for line in chunk:
            lines.append(line)
        return "\n".join(lines), page, total_pages

    return "\n".join(lines), page, total_pages


def kb_page(mode, page, total_pages, back_target=None, filter_active=False, filter_count=0):
    """Tombol prev / halaman / next + filter + kembali ke menu."""
    m = InlineKeyboardMarkup(row_width=3)
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton("⏮️ Prev", callback_data=f"page:{mode}:{page - 1}"))
    buttons.append(InlineKeyboardButton(f"{page}/{total_pages}", callback_data="page:noop"))
    if page < total_pages:
        buttons.append(InlineKeyboardButton("Next ⏭️", callback_data=f"page:{mode}:{page + 1}"))
    m.add(*buttons)

    # Tombol filter (hanya untuk mode yang punya hasil terstruktur, bukan d2ip)
    if mode != "d2ip":
        if filter_active:
            buttons2 = [
                InlineKeyboardButton("🔍 Tambah", callback_data=f"filter:{mode}"),
                InlineKeyboardButton(f"🧹 Bersihkan ({filter_count})", callback_data=f"clearfilter:{mode}"),
            ]
        else:
            buttons2 = [InlineKeyboardButton("🔍 Filter", callback_data=f"filter:{mode}")]
        m.add(*buttons2)

    prev = back_target or {"subfind": "menu:subfind", "cdnscan": "menu:cdnscan", "d2ip": "menu:d2ip"}.get(mode, "menu:main")
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data=f"back:{prev}"))
    return m


# ===================== FILTER FIELD KEYBOARD =====================
FILTER_FIELDS = {
    "subfind": [
        ("Subdomain", "subdomain"),
        ("IP", "ip"),
        ("Ports", "ports"),
        ("Status", "status"),
        ("CDN", "cdn"),
    ],
    "cdnscan": [
        ("IP", "ip"),
        ("Ports", "ports"),
        ("CDN", "cdn"),
        ("Status", "status"),
    ],
    "sniscan": [
        ("SNI Host", "sni_host"),
        ("IP", "ip"),
        ("TLS/ALPN", "tls_version"),
        ("ALPN", "alpn"),
        ("Port TLS", "tls_port"),
        ("Port Lain", "extra_ports"),
        ("Status", "status"),
        ("Response ms", "response_time_ms"),
        ("CDN", "cdn"),
    ],
}

FIELD_LABELS = {
    "subdomain": "Subdomain",
    "ip": "IP",
    "ports": "Ports",
    "status": "Status",
    "cdn": "CDN",
    "sni_host": "SNI Host",
    "tls_version": "TLS/ALPN",
    "alpn": "ALPN",
    "tls_port": "Port TLS",
    "extra_ports": "Port Lain",
    "response_time_ms": "Response ms",
}

FIELD_FILTER_EXAMPLE = {
    "subdomain": "google.com",
    "ip": "1.2.3.4",
    "ports": "80,443",
    "status": "200",
    "cdn": "Cloudflare",
    "sni_host": "google.com",
    "tls_version": "TLSv1.3",
    "alpn": "h2",
    "tls_port": "443",
    "extra_ports": "8080",
    "response_time_ms": "120",
}


def kb_filter_fields(mode):
    """Keyboard pilih field yang akan difilter. Tidak tersedia untuk d2ip."""
    fields = FILTER_FIELDS.get(mode, [])
    m = InlineKeyboardMarkup(row_width=2)
    buttons = [
        InlineKeyboardButton(label, callback_data=f"filterfield:{mode}:{key}")
        for label, key in fields
    ]
    if buttons:
        m.add(*buttons)
    m.add(InlineKeyboardButton("↩️ Kembali", callback_data=f"filterback:{mode}"))
    return m

def filter_matches(entry, filters):
    """Cek entri (tuple) cocok semua filter. filters: dict {field_key: nilai}."""
    if not filters:
        return True
    # Map field_key -> index pada tuple hasil scan per mode
    # Index diambil dari hasil build_page_text / run_*:
    # subfind: (sub, ip, ports, status, cdn) -> 0,1,2,3,4
    # cdnscan: (ip, ports, cdn, status) -> 0,1,2,3
    # sniscan: (sni_host, ip, tls_version, alpn, tls_port, extra_ports, response_time_ms, status) -> 0..7
    index_map = {
        "subfind": {
            "subdomain": 0, "ip": 1, "ports": 2, "status": 3, "cdn": 4,
        },
        "cdnscan": {
            "ip": 0, "ports": 1, "cdn": 2, "status": 3,
        },
        "sniscan": {
            "sni_host": 0, "ip": 1, "tls_version": 2, "alpn": 3,
            "tls_port": 4, "extra_ports": 5, "response_time_ms": 6, "status": 7, "cdn": 8,
        },
    }
    # Dapatkan mode dari caller — tidak tersedia di sini, pakai heuristik berdasarkan panjang entry
    # Fallback: cocokkan semua field yang tersedia di index_map mana pun yang indeksnya valid
    for field_key, nilai in filters.items():
        found = False
        for mode_map in index_map.values():
            idx = mode_map.get(field_key)
            if idx is not None and idx < len(entry):
                cell = str(entry[idx])
                if nilai.lower() in cell.lower():
                    found = True
                    break
        if not found:
            return False
    return True




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
                elif isinstance(data, dict):
                    results = data.get("results", [])
                    if not results:
                        continue
                    first = results[0] if isinstance(results, list) and results else {}
                    target = (first.get("target") if isinstance(first, dict) else None) or data.get("target") or fname.replace("cdnscan_", "").replace(".json", "")
                    provider = (first.get("provider") if isinstance(first, dict) else None) or data.get("provider", "-")
                    count = len(results)
                else:
                    continue
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
    _hist_page_set(chat_id, "cdn_history_page", page)
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
    st_hist = get_state(chat_id)
    hist_page = _hist_page_get(chat_id, "cdn_history_page")
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target=f"cdnscan:history:{hist_page}")


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
                elif isinstance(data, dict):
                    results = data.get("results", [])
                    if not results:
                        continue
                    first = results[0] if isinstance(results, list) and results else {}
                    target = (first.get("target") if isinstance(first, dict) else None) or data.get("target") or data.get("domain") or fname.replace("subfind_", "").replace(".json", "")
                    count = len(results)
                else:
                    continue
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
    _hist_page_set(chat_id, "subfind_history_page", page)
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
    st_hist = get_state(chat_id)
    hist_page = _hist_page_get(chat_id, "subfind_history_page")
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target=f"subfind:history:{hist_page}")


def save_scan_state(chat_id, mode, target, results, title, page=1):
    """Simpan metadata scan ke state; hasil dibaca dari file output/ saat view."""
    set_state(chat_id,
              mode="scan_view",
              scan_mode=mode,
              scan_target=target,
              scan_page=page,
              scan_title=title)
    _cs_set(chat_id, "scan_filters", {})




def _load_scan_results_from_file(mode, target):
    """Coba muat hasil scan dari file output/ jika state hilang (misal setelah restart).
    Return list of tuples sesuai format build_page_text, atau None jika gagal.
    """
    if not target or target == "-":
        return None
    OUT_DIR = os.path.join(BASE_DIR, "output")
    try:
        if mode == "subfind":
            jname = os.path.join(OUT_DIR, f"subfind_{target}.json")
            with open(jname) as f:
                data = json.load(f)
            if not isinstance(data, list):
                data = data.get("results", []) if isinstance(data, dict) else []
            out = []
            for item in data:
                if isinstance(item, dict):
                    out.append((
                        item.get("subdomain", "-"),
                        item.get("ip", "-"),
                        item.get("ports", "-"),
                        item.get("status", "-"),
                        item.get("cdn", "-"),
                    ))
                elif isinstance(item, (list, tuple)):
                    out.append(tuple(item))
            return out or None

        if mode == "sniscan":
            jname = os.path.join(OUT_DIR, f"sniscan_{target}.json")
            with open(jname) as f:
                data = json.load(f)
            if not isinstance(data, list):
                data = data.get("results", []) if isinstance(data, dict) else []
            out = []
            for item in data:
                if isinstance(item, dict):
                    extra = item.get("extra_ports", [])
                    extra_str = ",".join(str(p) for p in extra) if extra else "-"
                    out.append((
                        item.get("sni_host", "-"),
                        item.get("ip", "-"),
                        item.get("tls_version", "-"),
                        item.get("alpn", "-"),
                        item.get("tls_port", "-"),
                        extra_str,
                        item.get("response_time_ms", "-"),
                        item.get("status", "-"),
                        item.get("cdn", "-"),
                    ))
                elif isinstance(item, (list, tuple)):
                    out.append(tuple(item))
            return out or None

        if mode == "cdnscan":
            # Agregasi semua file cdnscan_*.json (satu per target)
            import glob
            files = glob.glob(os.path.join(OUT_DIR, "cdnscan_*.json"))
            out = []
            for jname in files:
                try:
                    with open(jname) as f:
                        data = json.load(f)
                except Exception:
                    continue
                if not isinstance(data, list):
                    data = data.get("results", []) if isinstance(data, dict) else []
                for item in data:
                    if isinstance(item, dict):
                        out.append((
                            item.get("ip", "-"),
                            item.get("ports", "-"),
                            item.get("cdn", "-"),
                            item.get("status", "-"),
                        ))
            return out or None
    except Exception as e:
        log.debug("load scan results from file failed: %s", e)
        return None

def show_scan_page(chat_id, message_id, edit=True, info_text=None, back_target=None):
    """Tampilkan halaman scan saat ini dari state.
    info_text: teks tambahan yang ditampilkan di atas tabel (misal "sudah discan").
    back_target: callback_data untuk tombol Kembali (override default).
    Terapkan scan_filters (client-side) sebelum pagination.
    """
    st = get_state(chat_id)
    mode = st.get("scan_mode", "subfind")
    target = st.get("scan_target", "-")
    if mode == "d2ip":
        results = st.get("scan_results", []) or []
    else:
        results = _load_scan_results_from_file(mode, target) or []
    page = _scan_page_get(chat_id)
    target = st.get("scan_target", "-")
    title = st.get("scan_title", "Hasil Scan")
    filters = _cs_get(chat_id, "scan_filters", {}) or {}

    # Terapkan filter client-side (tidak rescan)
    if filters:
        filtered = [r for r in results if filter_matches(r, filters)]
    else:
        filtered = results
    results = filtered

    if not results:
        text = f"⚠️ <b>{title}</b>\nTidak ada data yang cocok dengan filter."
        if info_text:
            text = f"{info_text}\n\n{text}"
        prev = back_target or _scan_back_target_get(chat_id) or {"subfind": "menu:subfind", "cdnscan": "menu:cdnscan", "d2ip": "menu:d2ip"}.get(mode, "menu:main")
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
    if back_target:
        _scan_back_target_set(chat_id, back_target)

    # Indikator filter di atas tabel
    filter_line = ""
    if filters:
        parts = [f"{FIELD_LABELS.get(k, k)}={v}" for k, v in filters.items()]
        filter_line = f"🔍 Filter: {', '.join(parts)}\n"
    if info_text:
        text = f"{info_text}\n\n{text}"
    if filter_line:
        text = f"{filter_line}{text}"

    try:
        if edit:
            _edit_queue.put((
                chat_id, message_id, text,
                {"reply_markup": kb_page(mode, page, total_pages, back_target=back_target or st.get("scan_back_target"),
                                         filter_active=bool(filters), filter_count=len(filters))}
            ))
        else:
            bot.send_message(chat_id, text, reply_markup=kb_page(mode, page, total_pages, back_target=back_target or st.get("scan_back_target"),
                                                                 filter_active=bool(filters), filter_count=len(filters)))
    except Exception:
        bot.send_message(chat_id, text, reply_markup=kb_page(mode, page, total_pages, back_target=back_target or st.get("scan_back_target"),
                                                             filter_active=bool(filters), filter_count=len(filters)))

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
                    results = data.get("results", [])
                    if not results:
                        continue
                    first = results[0] if isinstance(results, list) and results else {}
                    target = (first.get("target") if isinstance(first, dict) else None) or data.get("target") or data.get("domain") or fname.replace("sniscan_", "").replace(".json", "")
                    count = len(results)
                else:
                    continue
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
    _hist_page_set(chat_id, "sniscan_history_page", page)
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
                item.get("status", "-"),
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
                item.get("status", "-"),
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
    st_hist = get_state(chat_id)
    hist_page = _hist_page_get(chat_id, "sniscan_history_page")
    show_scan_page(chat_id, message_id, edit=True, info_text=info_text, back_target=f"sniscan:history:{hist_page}")


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


def _run_d2ip_with_slot(chat_id, message_id, domain):
    """Jalankan D2IP dengan slot scan per chat; lepas slot di finally."""
    try:
        run_d2ip(chat_id, message_id, domain)
    finally:
        bebaskan_slot_scan(chat_id)


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
    _cs_set(chat_id, "scan_filters", {})
    show_scan_page(chat_id, message_id, edit=True)


# ===================== SUBFIND (impor dari subfind.py) =====================
def run_subfind(chat_id, message_id, domain, session_id=None):
    if message_id is None:
        sent = bot.send_message(chat_id, f"🔍 <b>SubFind</b>\nMempersiapkan scan untuk <b>{esc(domain)}</b>...")
        message_id = sent.message_id
    else:
        sent = type('obj', (object,), {'message_id': message_id})()

    import time
    start_time = time.time()

    # State progres yang dibagikan antara spinner thread, elapsed thread, dan progress callback
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
        "elapsed": 0,
        "eta": 0,
        "stop_requested": False,
        "scan_type": "subfind",
        "session_id": session_id,
    }
    scan_lock = threading.Lock()

    # Fase 2: tandai session running
    if session_id is not None and _ss is not None:
        try:
            _ss.update_session(session_id, status='running', payload={'domain': domain})
        except Exception as e:
            log.debug("session update (running) failed: %s", e)

    # Register ke registry agar tombol Stop dapat mengakses scan_state ini
    register_scan_state(chat_id, scan_state)

    # Event untuk sinyalisasi stop dari tombol Stop ke enumerate_domain
    stop_event = threading.Event()
    scan_state["stop_event"] = stop_event

    def _spinner_loop():
        """Thread mandiri: memutar spinner dan mengupdate progres ke antrian (setiap 0.5 detik)."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            text = build_progress_text(
                state["spinner_idx"], state["title"], state["target"],
                state["current"], state["total"],
                state["start_time"],
                elapsed=state["elapsed"], eta=state["eta"],
            )
            # Tambah tombol Stop saat scan masih aktif (SubFind)
            _edit_queue.put((state["chat_id"], state["message_id"], text,
                             {"reply_markup": kb_stop_button(
                                 stop_requested=state["stop_requested"],
                                 spinner_idx=state["spinner_idx"],
                             )}))

            with scan_lock:
                scan_state["spinner_idx"] += 1

            time.sleep(0.5)

    def _elapsed_loop():
        """Thread mandiri: menghitung elapsed time dan ETA (setiap 1 detik)."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            now = time.time()
            elapsed = now - state["start_time"]
            if state["current"] > 0 and state["total"] > 0 and elapsed > 0:
                eta = (elapsed / state["current"]) * (state["total"] - state["current"])
            else:
                eta = 0

            with scan_lock:
                scan_state["elapsed"] = elapsed
                scan_state["eta"] = eta

            time.sleep(1.0)

    # Jalankan spinner thread terpisah (independen dari progres scan)
    spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
    spinner_thread.start()

    # Jalankan elapsed thread terpisah (independen dari progres scan)
    elapsed_thread = threading.Thread(target=_elapsed_loop, daemon=True)
    elapsed_thread.start()

    def progress_callback(current, total):
        with scan_lock:
            scan_state["current"] = current
            scan_state["total"] = total

    results, errors = enumerate_domain(domain, progress_callback=progress_callback, stop_event=stop_event)

    # Matikan spinner dan elapsed thread
    with scan_lock:
        scan_state["active"] = False

    # Unregister dari registry
    unregister_scan_state(chat_id)

    # Jika dihentikan paksa, simpan hasil partikel dan tampilkan
    if stop_event.is_set():
        OUT_DIR = os.path.join(BASE_DIR, "output")
        os.makedirs(OUT_DIR, exist_ok=True)
        jname = f"{OUT_DIR}/subfind_{domain}.json"
        json_data = [{"subdomain": r[0], "ip": r[1], "ports": r[2], "status": r[3], "cdn": r[4], "target": domain} for r in results]
        with open(jname, 'w') as f:
            json.dump(json_data, f, indent=2)
        if results:
            save_scan_state(chat_id, "subfind", domain, results, "SubFind")
        if session_id is not None and _ss is not None:
            try:
                _ss.update_session(session_id, status='cancelled', payload={'domain': domain, 'results': len(results)})
                _ss.clear_active_session(chat_id)
            except Exception as e:
                log.debug("session update (cancelled) failed: %s", e)
        _edit_queue.put((
            chat_id, message_id,
            f"⏹️ <b>SubFind dihentikan</b>\n"
            f"Ditemukan: {len(results)} subdomain.\n"
            f"Hasil yang tersimpan dapat dilihat melalui tombol Lihat.",
            {"reply_markup": kb_back("menu:subfind")}
        ))
        return

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
        if session_id is not None and _ss is not None:
            try:
                _ss.update_session(session_id, status='done', payload={'domain': domain, 'results': 0})
                _ss.clear_active_session(chat_id)
            except Exception as e:
                log.debug("session update (empty) failed: %s", e)
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
    if session_id is not None and _ss is not None:
        try:
            _ss.update_session(session_id, status='done', payload={'domain': domain, 'results': len(results)})
            _ss.clear_active_session(chat_id)
        except Exception as e:
            log.debug("session update (done) failed: %s", e)
    show_scan_page(chat_id, sent.message_id, edit=True)


# ===================== SNISCAN (impor dari sniscan.py) =====================
def run_sniscan(chat_id, message_id, domain, session_id=None):
    log.info("SNIScan mulai: domain=%s chat_id=%s", domain, chat_id)
    if message_id is None:
        sent = bot.send_message(chat_id, f"🔍 <b>SNIScan</b>\nMempersiapkan scan untuk <b>{esc(domain)}</b>...")
        message_id = sent.message_id
    else:
        sent = type('obj', (object,), {'message_id': message_id})()

    import time
    start_time = time.time()

    # State progres yang dibagikan antara spinner thread, elapsed thread, dan progress callback
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
        "elapsed": 0,
        "eta": 0,
        "stop_requested": False,
        "scan_type": "sniscan",
        "session_id": session_id,
    }
    scan_lock = threading.Lock()

    if session_id is not None and _ss is not None:
        try:
            _ss.update_session(session_id, status='running', payload={'domain': domain})
        except Exception as e:
            log.debug("session update (running) failed: %s", e)

    # Register ke registry agar tombol Stop dapat mengakses scan_state ini
    register_scan_state(chat_id, scan_state)

    # Event untuk sinyalisasi stop dari tombol Stop ke enumerate_hosts
    stop_event = threading.Event()
    scan_state["stop_event"] = stop_event

    def _spinner_loop():
        """Thread mandiri: memutar spinner dan mengupdate progres ke antrian (setiap 0.5 detik)."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            text = build_progress_text(
                state["spinner_idx"], state["title"], state["target"],
                state["current"], state["total"],
                state["start_time"],
                elapsed=state["elapsed"], eta=state["eta"],
            )
            # Tambah tombol Stop saat scan masih aktif (SubFind)
            _edit_queue.put((state["chat_id"], state["message_id"], text,
                             {"reply_markup": kb_stop_button(
                                 stop_requested=state["stop_requested"],
                                 spinner_idx=state["spinner_idx"],
                             )}))

            with scan_lock:
                scan_state["spinner_idx"] += 1

            time.sleep(0.5)

    def _elapsed_loop():
        """Thread mandiri: menghitung elapsed time dan ETA (setiap 1 detik)."""
        while True:
            with scan_lock:
                if not scan_state["active"]:
                    break
                state = dict(scan_state)

            now = time.time()
            elapsed = now - state["start_time"]
            if state["current"] > 0 and state["total"] > 0 and elapsed > 0:
                eta = (elapsed / state["current"]) * (state["total"] - state["current"])
            else:
                eta = 0

            with scan_lock:
                scan_state["elapsed"] = elapsed
                scan_state["eta"] = eta

            time.sleep(1.0)

    # Jalankan spinner thread terpisah (independen dari progres scan)
    spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
    spinner_thread.start()

    # Jalankan elapsed thread terpisah (independen dari progres scan)
    elapsed_thread = threading.Thread(target=_elapsed_loop, daemon=True)
    elapsed_thread.start()

    def progress_callback(current, total):
        with scan_lock:
            scan_state["current"] = current
            scan_state["total"] = total

    results, errors = enumerate_hosts(domain, progress_callback=progress_callback, stop_event=stop_event)
    log.debug("SNIScan selesai: domain=%s results=%d errors=%d", domain, len(results), len(errors))

    # Matikan spinner dan elapsed thread
    with scan_lock:
        scan_state["active"] = False

    # Unregister dari registry
    unregister_scan_state(chat_id)

    # Jika dihentikan paksa, simpan hasil partikel dan tampilkan
    if stop_event.is_set():
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

        # Konversi ke tuple untuk pagination
        results_tuples = [
            (
                r["sni_host"],
                r["ip"],
                r["tls_version"],
                r["alpn"],
                r["tls_port"],
                ",".join(str(p) for p in r["extra_ports"]) if r["extra_ports"] else "-",
                r["response_time_ms"],
                r.get("status", "-"),
                r.get("cdn", "-"),
            )
            for r in results
        ]
        if results:
            save_scan_state(chat_id, "sniscan", domain, results_tuples, "SNIScan")
        if session_id is not None and _ss is not None:
            try:
                _ss.update_session(session_id, status='cancelled', payload={'domain': domain, 'results': len(results)})
                _ss.clear_active_session(chat_id)
            except Exception as e:
                log.debug("session update (cancelled) failed: %s", e)
        _edit_queue.put((
            chat_id, message_id,
            f"⏹️ <b>SNIScan dihentikan</b>\n"
            f"Ditemukan: {len(results)} SNI host.\n"
            f"Hasil yang tersimpan dapat dilihat melalui tombol Lihat.",
            {"reply_markup": kb_back("menu:sniscan")}
        ))
        return

    if errors:
        log.debug("SNIScan provider errors: %s", '; '.join(errors))
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
        if session_id is not None and _ss is not None:
            try:
                _ss.update_session(session_id, status='done', payload={'domain': domain, 'results': 0})
                _ss.clear_active_session(chat_id)
            except Exception as e:
                log.debug("session update (empty) failed: %s", e)
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
            "status": r.get("status", "-"),
            "cdn": r.get("cdn", "-"),
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
            r.get("status", "-"),
            r.get("cdn", "-"),
        )
        for r in results
    ]

    # Simpan ke state dan tampilkan halaman 1 (pagination)
    save_scan_state(chat_id, "sniscan", domain, results_tuples, "SNIScan")
    if session_id is not None and _ss is not None:
        try:
            _ss.update_session(session_id, status='done', payload={'domain': domain, 'results': len(results)})
            _ss.clear_active_session(chat_id)
        except Exception as e:
            log.debug("session update (done) failed: %s", e)
    show_scan_page(chat_id, sent.message_id, edit=True)
    log.info("SNIScan selesai: domain=%s total=%d", domain, len(results))


# ===================== WRAPPER SLOT SCAN (subfind & sniscan) ====================
def _run_subfind_with_slot(chat_id, message_id, domain, session_id=None):
    """Jalankan SubFind dengan slot scan per chat; lepas slot di finally."""
    try:
        run_subfind(chat_id, message_id, domain, session_id=session_id)
    finally:
        bebaskan_slot_scan(chat_id)


def _run_sniscan_with_slot(chat_id, message_id, domain, session_id=None):
    """Jalankan SNIScan dengan slot scan per chat; lepas slot di finally."""
    try:
        run_sniscan(chat_id, message_id, domain, session_id=session_id)
    finally:
        bebaskan_slot_scan(chat_id)


# ===================== HELP =====================
HELP_TEXT = (
    "🤖 <b>Surfinder — Bot Scanner Jaringan</b>\n\n"
    "<b>Fitur:</b>\n"
    "• D2IP — Resolve domain ke IP\n"
    "• SubFind — Enumerasi subdomain + IP + port + status + CDN\n"
    "• CDNScan — Deteksi CDN dari IP/CIDR/range atau provider\n"
    "• SNIScan — Scan SNI host via TLS handshake + deteksi port\n\n"
    "<b>Cara pakai:</b>\n"
    "1. Pilih menu dari tombol inline\n"
    "2. Masukkan domain atau IP/CIDR yang diminta\n"
    "3. Tunggu scan selesai\n"
    "4. Lihat hasil per halaman dengan tombol Prev / Next\n"
    "5. Gunakan Filter untuk menyaring hasil berdasarkan field tertentu\n\n"
    "<b>Perintah:</b>\n"
    "/start — Mulai bot & lihat menu\n"
    "/menu — Kembali ke menu utama\n"
    "/help — Tampilkan panduan ini\n"
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
        reply_markup=kb_main(user_id=message.chat.id)
    )


@bot.callback_query_handler(func=lambda call: True)
def cb_handler(call):
    chat_id = call.message.chat.id
    message_id = call.message.message_id
    data = call.data

    log.debug("callback: %s from chat %s", data, chat_id)

    # Jawab callback agar tombol tidak "loading" selamanya
    try:
        bot.answer_callback_query(call.id)
    except Exception:
        pass

    if data == "menu:main":
        clear_state(chat_id)
        bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main(user_id=chat_id))

    elif data == "menu:help":
        bot.edit_message_text(HELP_TEXT, chat_id, message_id, reply_markup=kb_back("menu:main"))

    elif data == "admin:hapus_riwayat":
        if not is_admin(chat_id):
            try:
                bot.answer_callback_query(call.id, "Tidak diizinkan", show_alert=True)
            except Exception:
                pass
            return
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("✅ Ya, hapus semua", callback_data="admin:hapus_riwayat:confirm"),
            InlineKeyboardButton("❌ Batal", callback_data="admin:hapus_riwayat:cancel"),
        )
        bot.edit_message_text(
            "⚠️ <b>Hapus semua riwayat output?</b>\n"
            "Semua file .txt dan .json di output/ akan dihapus (kecuali cache ipranges/).",
            chat_id, message_id, reply_markup=kb
        )

    elif data == "admin:hapus_riwayat:confirm":
        if not is_admin(chat_id):
            try:
                bot.answer_callback_query(call.id, "Tidak diizinkan", show_alert=True)
            except Exception:
                pass
            return
        deleted = 0
        out_dir = os.path.join(BASE_DIR, "output")
        for root, dirs, files in os.walk(out_dir):
            # jangan hapus cache ipranges
            if "ipranges" in root.split(os.sep):
                continue
            for fn in files:
                if fn.endswith(".txt") or fn.endswith(".json"):
                    try:
                        os.remove(os.path.join(root, fn))
                        deleted += 1
                    except Exception:
                        pass
        bot.edit_message_text(
            f"✅ {deleted} file output (.txt/.json) dihapus.\nCache ipranges/ tidak disentuh.",
            chat_id, message_id, reply_markup=kb_main(user_id=chat_id)
        )

    elif data == "admin:hapus_riwayat:cancel":
        bot.edit_message_text("Dibatalkan.", chat_id, message_id, reply_markup=kb_main(user_id=chat_id))

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
        sid = None
        if _ss is not None:
            try:
                sid = _ss.create_session(chat_id, "subfind", status="awaiting_input", payload={"prev_menu": "menu:subfind"})
                _ss.set_active_session(chat_id, sid)
            except Exception as e:
                log.debug("session create (subfind:search) failed: %s", e)
        set_state(chat_id, mode="subfind", awaiting="domain", prev_menu="menu:subfind", _sid=sid)
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
        sid = None
        if _ss is not None:
            try:
                sid = _ss.create_session(chat_id, "sniscan", status="awaiting_input", payload={"prev_menu": "menu:sniscan"})
                _ss.set_active_session(chat_id, sid)
            except Exception as e:
                log.debug("session create (sniscan:search) failed: %s", e)
        set_state(chat_id, mode="sniscan", awaiting="domain", prev_menu="menu:sniscan", _sid=sid)
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

        # Verifikasi total IP per batch sebelum scan dimulai
        total = count_total_batch_ips(targets, limit)
        if total > MAX_TOTAL_BATCH:
            set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
            try:
                bot.edit_message_text(
                    f"⚠️ <b>Total IP melebihi batas</b>\n"
                    f"Target: {len(targets)} rentang, total IP per batch: {total}\n"
                    f"Batas maksimal: {MAX_TOTAL_BATCH} IP per batch.\n\n"
                    f"Lanjutkan dengan membatasi ke {MAX_TOTAL_BATCH} IP?",
                    chat_id, message_id,
                    reply_markup=InlineKeyboardMarkup(row_width=2).add(
                        InlineKeyboardButton("✅ Lanjutkan", callback_data=f"cdnscan:limit:confirm:{limit}"),
                        InlineKeyboardButton("❌ Batal", callback_data="back:cdnscan:ranges:page")
                    )
                )
            except Exception:
                pass
            return

        set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
        # Mulai scan target pertama
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()

    elif data.startswith("cdnscan:limit:confirm:"):
        parts = data.split(":")
        limit = int(parts[2])
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []

        # Verifikasi total IP per batch sebelum scan dimulai
        total = count_total_batch_ips(targets, limit)
        if total > MAX_TOTAL_BATCH:
            set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
            try:
                bot.edit_message_text(
                    f"⚠️ <b>Total IP melebihi batas</b>\n"
                    f"Target: {len(targets)} rentang, total IP per batch: {total}\n"
                    f"Batas maksimal: {MAX_TOTAL_BATCH} IP per batch.\n\n"
                    f"Lanjutkan dengan membatasi ke {MAX_TOTAL_BATCH} IP?",
                    chat_id, message_id,
                    reply_markup=InlineKeyboardMarkup(row_width=2).add(
                        InlineKeyboardButton("✅ Lanjutkan", callback_data=f"cdnscan:limit:confirm:{limit}"),
                        InlineKeyboardButton("❌ Batal", callback_data="back:cdnscan:ranges:page")
                    )
                )
            except Exception:
                pass
            return

        set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()

    elif data == "cdnscan:next":
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        limit = st.get("cdn_limit", 0)

        if targets:
            # Verifikasi total IP per batch sebelum scan dimulai
            total = count_total_batch_ips(targets, limit)
            if total > MAX_TOTAL_BATCH:
                set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
                try:
                    bot.edit_message_text(
                        f"⚠️ <b>Total IP melebihi batas</b>\n"
                        f"Target: {len(targets)} rentang, total IP per batch: {total}\n"
                        f"Batas maksimal: {MAX_TOTAL_BATCH} IP per batch.\n\n"
                        f"Lanjutkan dengan membatasi ke {MAX_TOTAL_BATCH} IP?",
                        chat_id, message_id,
                        reply_markup=InlineKeyboardMarkup(row_width=2).add(
                            InlineKeyboardButton("✅ Lanjutkan", callback_data=f"cdnscan:limit:confirm:{limit}"),
                            InlineKeyboardButton("❌ Batal", callback_data="back:cdnscan:ranges:page")
                        )
                    )
                except Exception:
                    pass
                return

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

        # Jika cdn_targets tidak ada di state, coba baca dari file JSON di output/
        if not targets:
            import glob
            out_dir = os.path.join(BASE_DIR, "output")
            json_files = glob.glob(os.path.join(out_dir, "cdnscan_*.json"))
            targets = []
            for jf in json_files:
                fname = os.path.basename(jf)
                # Ubah nama file kembali ke CIDR: cdnscan_1_1_1_0_24.json -> 1.1.1.0/24
                name = fname.replace("cdnscan_", "").replace(".json", "")
                parts = name.split("_")
                if len(parts) == 5:
                    # Format: a_b_c_d_e -> a.b.c.d/e (IPv4 CIDR)
                    targets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}/{parts[4]}")
                elif len(parts) >= 8:
                    # Format range: a_b_c_d-e_f_g_h -> a.b.c.d-e.f.g.h
                    left = parts[:4]
                    right = parts[4:]
                    if len(left) == 4 and len(right) == 4:
                        targets.append(f"{left[0]}.{left[1]}.{left[2]}.{left[3]}-{right[0]}.{right[1]}.{right[2]}.{right[3]}")
                    else:
                        targets.append(name)
                else:
                    targets.append(name)

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
                    "❌ <b>Tidak ada hasil scan</b>\nBelum ada data yang tersimpan.\n\nCoba jalankan scan CDNScan terlebih dahulu.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                bot.send_message(chat_id, "❌ Tidak ada hasil scan. Coba jalankan scan CDNScan terlebih dahulu.", reply_markup=kb_back("menu:cdnscan"))
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

        # Verifikasi total IP per batch sebelum scan dimulai (limit=0 = unlimited)
        total = count_total_batch_ips([target], 0)
        if total > MAX_TOTAL_BATCH:
            set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=0, cdn_targets=[target], cdn_target_index=0, prev_menu="menu:cdnscan")
            try:
                bot.edit_message_text(
                    f"⚠️ <b>Total IP melebihi batas</b>\n"
                    f"Target: {target}, total IP: {total}\n"
                    f"Batas maksimal: {MAX_TOTAL_BATCH} IP per batch.\n\n"
                    f"Lanjutkan dengan membatasi ke {MAX_TOTAL_BATCH} IP?",
                    chat_id, message_id,
                    reply_markup=InlineKeyboardMarkup(row_width=2).add(
                        InlineKeyboardButton("✅ Lanjutkan", callback_data="cdnscan:limit:confirm:2000"),
                        InlineKeyboardButton("❌ Batal", callback_data="back:menu:cdnscan")
                    )
                )
            except Exception:
                pass
            return

        # Cek batas scan simultan
        global ACTIVE_SCANS
        if ACTIVE_SCANS >= MAX_ACTIVE_SCANS:
            try:
                bot.edit_message_text(
                    "⚠️ <b>Server penuh</b>\nSedang ada scan berjalan di bot. Coba lagi beberapa saat.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                pass
            return
        st = get_state(chat_id)
        if st.get("scanning"):
            try:
                bot.edit_message_text(
                    "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                    chat_id, message_id, reply_markup=kb_back("menu:cdnscan")
                )
            except Exception:
                pass
            return
        ACTIVE_SCANS += 1
        set_state(chat_id, scanning=True)

        threading.Thread(target=run_cdnscan_target_batch, args=(chat_id, message_id), daemon=True).start()

    elif data.startswith("page:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[2].isdigit():
            target_page = int(parts[2])
            mode = parts[1]
            st = get_state(chat_id)
            if st.get("mode") == "scan_view" and st.get("scan_mode") == mode:
                set_state(chat_id, scan_page=target_page)
                back_target = st.get("scan_back_target", None)
                show_scan_page(chat_id, message_id, edit=True, back_target=back_target)
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

    elif data.startswith("filter:"):
        parts = data.split(":")
        if len(parts) == 2:
            mode = parts[1]
            st = get_state(chat_id)
            filters = _cs_get(chat_id, "scan_filters", {}) or {}
            filter_line = ""
            if filters:
                parts_filter = [f"{FIELD_LABELS.get(k, k)}={v}" for k, v in filters.items()]
                filter_line = f"\n\nFilter aktif: {', '.join(parts_filter)}"
            try:
                bot.edit_message_text(
                    f"🔍 <b>Pilih field untuk difilter</b>{filter_line}\nPilih kolom yang ingin difilter:",
                    chat_id, message_id, reply_markup=kb_filter_fields(mode)
                )
            except Exception:
                bot.send_message(chat_id, "🔍 Pilih field untuk difilter:", reply_markup=kb_filter_fields(mode))

    elif data.startswith("filterfield:"):
        parts = data.split(":")
        if len(parts) == 3:
            mode = parts[1]
            field_key = parts[2]
            label = FIELD_LABELS.get(field_key, field_key)
            set_state(chat_id, awaiting="filter_value")
            _cs_set(chat_id, "filter_mode", mode)
            _cs_set(chat_id, "filter_field", field_key)
            try:
                bot.edit_message_text(
                    f"🔍 <b>Masukkan nilai untuk {label}</b>\nContoh: {FIELD_FILTER_EXAMPLE.get(field_key, '200')}",
                    chat_id, message_id,
                )
            except Exception:
                bot.send_message(chat_id, f"🔍 Masukkan nilai untuk {label}:")

    elif data.startswith("clearfilter:"):
        parts = data.split(":")
        if len(parts) == 2:
            mode = parts[1]
            _cs_set(chat_id, "scan_filters", {})
            st = get_state(chat_id)
            show_scan_page(chat_id, message_id, edit=True)

    elif data.startswith("filterback:"):
        parts = data.split(":")
        if len(parts) == 2:
            mode = parts[1]
            st = get_state(chat_id)
            # Kembali ke halaman hasil scan (bukan ulang ke field selection)
            show_scan_page(chat_id, message_id, edit=True)

    elif data == "scan:stop":
        # Tombol Stop ditekan saat scan sedang berjalan
        stopped = request_scan_stop(chat_id)
        try:
            if stopped:
                bot.answer_callback_query(call.id, "⏹️ Scan dihentikan, menyimpan hasil...")
            else:
                bot.answer_callback_query(call.id, "Tidak ada scan yang berjalan.")
        except Exception:
            pass

    elif data.startswith("back:"):
        prev_menu = data.split(":", 1)[1]
        st = get_state(chat_id)
        if prev_menu == "menu:main":
            clear_state(chat_id)
            bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main(user_id=chat_id))
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
            bot.edit_message_text("👋 <b>Surfinder</b>\nPilih menu di bawah:", chat_id, message_id, reply_markup=kb_main(user_id=chat_id))

    else:
        try:
            bot.answer_callback_query(call.id, "Tombol tidak dikenal.")
        except Exception:
            pass


def run_cdnscan_target_batch(chat_id, message_id):
    """Proses daftar target CDNScan secara gabungan (combined mode).

    Setiap target diambil sisa IP sesuai limit, lalu semua IP discan dalam satu batch.
    Tidak ada jeda antar target. Setelah progress 100%:
    - Jika masih ada sisa IP di mana-mana target → tampilkan "Lihat" + "Next"
    - Jika semua target 100% selesai → tampilkan hanya "Lihat"
    """
    # Cek slot scan per chat (1 scan per chat; d2ip dikecualikan)
    if not cek_slot_scan(chat_id):
        try:
            bot.edit_message_text(
                "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                chat_id, message_id, reply_markup=kb_back("menu:cdnscan"),
            )
        except Exception:
            bot.send_message(
                chat_id,
                "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                reply_markup=kb_back("menu:cdnscan"),
            )
        return

    global ACTIVE_SCANS
    try:
        st = get_state(chat_id)
        targets = st.get("cdn_targets", []) or []
        limit = st.get("cdn_limit", 0)

        if not targets:
            _edit_queue.put((
                chat_id, message_id,
                "❌ <b>CDNScan</b>\nTidak ada target yang dipilih.",
                {"reply_markup": kb_back("menu:cdnscan")}
            ))
            clear_state(chat_id)
            ACTIVE_SCANS = max(0, ACTIVE_SCANS - 1)
            set_state(chat_id, scanning=False)
            return

        # Fase 1: Kumpulkan semua sisa IP per target dengan limit
        batch_items = []  # list of (target, ip)
        total_batch_ips = 0
        target_info = {}  # target -> {"offset": int, "total_effective": int}

        for t in targets:
            t_state = load_state(t)
            t_offset = t_state.get('scanned_count', 0) if t_state else 0

            # Hitung total IP dalam range (tanpa limit) untuk mengetahui sisa sebenarnya
            t_all_full = parse_ip_range(t)
            t_total_full = len(t_all_full) if t_all_full else 0
            t_sisa = max(0, t_total_full - t_offset)

            if t_sisa > 0:
                # Ambil IP sesuai limit dari offset untuk batch ini
                ips = parse_ip_range(t, offset=t_offset, max_ips=limit if limit > 0 else None)
                for ip in ips:
                    batch_items.append((t, ip))
                    total_batch_ips += 1
                target_info[t] = {"offset": t_offset, "total_effective": t_total_full, "sisa": t_sisa}
            else:
                # Target sudah 100% selesai
                target_info[t] = {"offset": t_offset, "total_effective": t_total_full, "sisa": 0}

        if not batch_items:
            # Semua target 100% selesai
            _edit_queue.put((
                chat_id, message_id,
                "✅ <b>CDNScan selesai</b>\nSemua target telah discan.",
                {"reply_markup": kb_next_target("menu:cdnscan", show_view=False, show_next=False)}
            ))
            # JANGAN clear_state: cdn_targets dibutuhkan oleh tombol "Lihat" (cdnscan:view).
            ACTIVE_SCANS = max(0, ACTIVE_SCANS - 1)
            set_state(chat_id, scanning=False)
            return

        # Fase 2: Scan semua IP gabungan dalam satu batch
        import time
        start_time = time.time()
        scan_state = {
            "active": True,
            "chat_id": chat_id,
            "message_id": message_id,
            "title": "CDNScan",
            "target": f"Multi-Target ({len(targets)} target)",
            "current": 0,
            "total": total_batch_ips,
            "start_time": start_time,
            "spinner_idx": 0,
            "elapsed": 0,
            "eta": 0,
            "stop_requested": False,
            "scan_type": "cdnscan",
        }
        scan_lock = threading.Lock()

        # Register ke registry agar tombol Stop dapat mengakses scan_state ini
        register_scan_state(chat_id, scan_state)

        try:
            _edit_queue.put((
                chat_id, message_id,
                f"🛡️ <b>CDNScan</b>\nScan gabungan {len(targets)} target...\nMemulai scan {total_batch_ips} IP...",
                {}
            ))
        except Exception:
            pass

        def _spinner_loop():
            """Thread mandiri: memutar spinner dan mengupdate progres ke antrian (setiap 1 detik)."""
            while True:
                with scan_lock:
                    if not scan_state["active"]:
                        break
                    state_copy = dict(scan_state)

                text = build_progress_text(
                    state_copy["spinner_idx"], state_copy["title"], state_copy["target"],
                    state_copy["current"], state_copy["total"],
                    state_copy["start_time"],
                    elapsed=state_copy["elapsed"], eta=state_copy["eta"],
                )
                # Tambah tombol Stop saat scan masih aktif (CDNScan)
                _edit_queue.put((state_copy["chat_id"], state_copy["message_id"], text,
                                 {"reply_markup": kb_stop_button(
                                     stop_requested=state_copy["stop_requested"],
                                     spinner_idx=state_copy["spinner_idx"],
                                 )}))

                with scan_lock:
                    scan_state["spinner_idx"] += 1

                time.sleep(1.0)

        def _elapsed_loop():
            """Thread mandiri: menghitung elapsed time dan ETA (setiap 1 detik)."""
            while True:
                with scan_lock:
                    if not scan_state["active"]:
                        break
                    state = dict(scan_state)

                now = time.time()
                elapsed = now - state["start_time"]
                if state["current"] > 0 and state["total"] > 0 and elapsed > 0:
                    eta = (elapsed / state["current"]) * (state["total"] - state["current"])
                else:
                    eta = 0

                with scan_lock:
                    scan_state["elapsed"] = elapsed
                    scan_state["eta"] = eta

                time.sleep(1.0)

        spinner_thread = threading.Thread(target=_spinner_loop, daemon=True)
        spinner_thread.start()

        elapsed_thread = threading.Thread(target=_elapsed_loop, daemon=True)
        elapsed_thread.start()

        # Simpan hasil per-target
        target_results = {}  # target -> list of results

        # Tandai apakah scan dihentikan paksa (untuk Fase 3/4)
        scan_dihentikan = False

        try:
            with ThreadPoolExecutor(max_workers=min(15, len(batch_items))) as executor:
                futures = {executor.submit(process_ip, ip): (t, ip) for t, ip in batch_items}
                pending = set(futures.keys())
                while pending:
                    done, pending = wait(
                        pending, timeout=IP_OVERALL_TIMEOUT,
                        return_when=FIRST_COMPLETED
                    )
                    for future in done:
                        t, ip = futures[future]
                        try:
                            result = future.result()
                        except Exception:
                            result = (ip, "-", "-", "-")

                        if t not in target_results:
                            target_results[t] = []
                        target_results[t].append(result)

                        c = scan_state["current"] + 1
                        with scan_lock:
                            scan_state["current"] = c

                    # Jika tidak ada future yang selesai dalam batas waktu,
                    # lewati IP yang macet agar progres tidak nempel selamanya.
                    if not done and pending:
                        skip_now = min(3, len(pending))
                        for f in list(pending)[:skip_now]:
                            t, ip = futures[f]
                            if t not in target_results:
                                target_results[t] = []
                            target_results[t].append((ip, "-", "-", "-"))
                            pending.discard(f)

                            c = scan_state["current"] + 1
                            with scan_lock:
                                scan_state["current"] = c

                    # Cek apakah user menekan tombol Stop
                    with scan_lock:
                        if scan_state["stop_requested"]:
                            scan_dihentikan = True
                            for f in list(pending):
                                f.cancel()
                            try:
                                executor.shutdown(wait=False)
                            except Exception:
                                pass
                            break

        finally:
            # Matikan spinner dan elapsed thread
            with scan_lock:
                scan_state["active"] = False

            # Unregister dari registry (slot scan dilepas oleh outer finally)
            unregister_scan_state(chat_id)

        # Fase 3: Simpan hasil per-target dan update state
        any_has_sisa = False
        for t in targets:
            results = target_results.get(t, [])
            info = target_info[t]

            # Sortir hasil
            results.sort(key=lambda x: ipaddress.ip_address(x[0].split('/')[0] if '/' in x[0] else x[0]))

            # Simpan JSON per target
            OUT_DIR = os.path.join(BASE_DIR, "output")
            os.makedirs(OUT_DIR, exist_ok=True)
            safe_name = t.replace("/", "_").replace("-", "_").replace(".", "_")
            jname = f"{OUT_DIR}/cdnscan_{safe_name}.json"

            # Baca data lama jika ada
            existing = []
            try:
                with open(jname, 'r') as f:
                    existing = json.load(f)
            except Exception:
                existing = []

            # Gabungkan data lama dengan baru
            all_data = existing + [
                {"ip": r[0], "ports": r[1], "cdn": r[2], "status": r[3], "target": t,
                 "provider": st.get("cdn_provider", "manual")}
                for r in results
            ]
            with open(jname, 'w') as f:
                json.dump(all_data, f, indent=2)

            # Update state resume
            new_offset = info["offset"] + len(results)
            next_check = parse_ip_range(t, offset=new_offset, max_ips=1)
            completed = len(next_check) == 0
            save_state(t, new_offset, completed)

            if not completed:
                any_has_sisa = True

        # Fase 4: Tampilkan hasil
        # Kumpulkan semua hasil dari file JSON untuk ditampilkan di "Lihat"
        all_results = []
        for t in targets:
            safe_name = t.replace("/", "_").replace("-", "_").replace(".", "_")
            jname = f"{OUT_DIR}/cdnscan_{safe_name}.json"
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

        has_data = len(all_results) > 0

        # Scan dihentikan paksa via tombol Stop
        if scan_dihentikan:
            if has_data:
                save_scan_state(chat_id, "cdnscan", targets[-1] if targets else [], all_results, "CDNScan")
            _edit_queue.put((
                chat_id, message_id,
                f"⏹️ <b>CDNScan dihentikan</b>\n"
                f"Discan: {scan_state['current']} / {scan_state['total']} IP.\n"
                f"Hasil yang tersimpan dapat dilihat melalui tombol Lihat.",
                {"reply_markup": kb_next_target("menu:cdnscan", show_view=has_data, show_next=False)}
            ))
            return

        if any_has_sisa:
            # Masih ada sisa IP di mana-mana target → tampilkan "Lihat" + "Next"
            set_state(chat_id, cdn_target_index=0)  # Reset index, next akan hitung ulang sisa
            _edit_queue.put((
                chat_id, message_id,
                f"✅ <b>CDNScan batch selesai</b>\n"
                f"Discan: {total_batch_ips} IP dari {len(targets)} target.\n"
                f"Masih ada sisa IP di beberapa target.\n"
                f"Klik Next untuk batch berikutnya, atau Lihat untuk hasil gabungan.",
                {"reply_markup": kb_next_target("menu:cdnscan", show_view=has_data)}
            ))
        else:
            # Semua target 100% selesai → hanya "Lihat"
            # Simpan hasil aktual ke state agar bisa dilihat melalui tombol "Lihat"
            if has_data:
                save_scan_state(chat_id, "cdnscan", targets[-1] if targets else [], all_results, "CDNScan")
            _edit_queue.put((
                chat_id, message_id,
                "✅ <b>CDNScan selesai</b>\nSemua target telah discan.",
                {"reply_markup": kb_next_target("menu:cdnscan", show_view=has_data, show_next=False)}
            ))
            # JANGAN clear_state: cdn_targets dibutuhkan oleh tombol "Lihat" (cdnscan:view).
            ACTIVE_SCANS = max(0, ACTIVE_SCANS - 1)
            set_state(chat_id, scanning=False)
            return
    finally:
        ACTIVE_SCANS = max(0, ACTIVE_SCANS - 1)
        set_state(chat_id, scanning=False)


def fetch_provider_ranges(chat_id, message_id, provider):
    """Unduh daftar rentang IP dari provider dan tampilkan untuk dipilih."""
    import time
    last_update = [0]

    def progress_cb(downloaded, total):
        now = time.time()
        if now - last_update[0] < 1.0:
            return
        last_update[0] = now
        mb = downloaded / 1024 / 1024
        if total:
            mb_total = total / 1024 / 1024
            text = f"🛡️ <b>CDNScan — Provider {provider}</b>\nMengunduh daftar rentang IP... | {mb:.1f} MB / {mb_total:.1f} MB"
        else:
            text = f"🛡️ <b>CDNScan — Provider {provider}</b>\nMengunduh daftar rentang IP... | {mb:.1f} MB"
        try:
            _edit_queue.put((chat_id, message_id, text, {}))
        except Exception:
            pass

    ips, err = get_provider_ips(provider, progress_callback=progress_cb)
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
        bot.send_message(chat_id, "Pilih menu dulu dengan /start.", reply_markup=kb_main(user_id=chat_id))
        return

    if mode == "d2ip" and awaiting == "domain":
        domain = text.lower().strip()
        if not validate_domain(domain):
            bot.send_message(chat_id, "Domain tidak valid. Coba lagi (contoh: google.com).")
            return
        blocked, kata = is_blocked(domain)
        if blocked:
            bot.send_message(chat_id, blocked_message(domain, kata))
            return
        if not cek_slot_scan(chat_id):
            bot.send_message(
                chat_id,
                "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                reply_markup=kb_back("menu:d2ip"),
            )
            return
        sent = bot.send_message(chat_id, f"🌐 <b>D2IP</b>\nMeng-resolve <b>{esc(domain)}</b>...")
        set_state(chat_id, mode="d2ip", awaiting=None)
        threading.Thread(target=_run_d2ip_with_slot, args=(chat_id, sent.message_id, domain), daemon=True).start()
        return

    if mode == "subfind" and awaiting == "domain":
        domain = text.lower().strip()
        if not validate_domain(domain):
            bot.send_message(chat_id, "Domain tidak valid. Coba lagi (contoh: example.com).")
            return
        blocked, kata = is_blocked(domain)
        if blocked:
            bot.send_message(chat_id, blocked_message(domain, kata))
            return
        if not cek_slot_scan(chat_id):
            bot.send_message(
                chat_id,
                "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                reply_markup=kb_back("menu:subfind"),
            )
            return
        sid = None
        if _ss is not None:
            try:
                active = _ss.get_active_session(chat_id)
                if active is None:
                    sid = _ss.create_session(chat_id, "subfind", status="awaiting_input", payload={"domain": domain})
                    _ss.set_active_session(chat_id, sid)
                else:
                    sid = active['id']
                    _ss.update_session(sid, status="running", payload={"domain": domain})
            except Exception as e:
                log.debug("session ensure (subfind) failed: %s", e)
        set_state(chat_id, mode="subfind", awaiting=None, _sid=sid)
        threading.Thread(target=_run_subfind_with_slot, args=(chat_id, None, domain, sid), daemon=True).start()
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

        # Verifikasi total IP per batch sebelum scan dimulai
        total = count_total_batch_ips(targets, limit)
        if total > MAX_TOTAL_BATCH:
            set_state(chat_id, mode="cdnscan_limit", awaiting=None, cdn_limit=limit, cdn_targets=targets, cdn_target_index=0, prev_menu="cdnscan:ranges:page")
            bot.send_message(
                chat_id,
                f"⚠️ <b>Total IP melebihi batas</b>\n"
                f"Target: {len(targets)} rentang, total IP per batch: {total}\n"
                f"Batas maksimal: {MAX_TOTAL_BATCH} IP per batch.\n\n"
                f"Lanjutkan dengan membatasi ke {MAX_TOTAL_BATCH} IP?",
                reply_markup=InlineKeyboardMarkup(row_width=2).add(
                    InlineKeyboardButton("✅ Lanjutkan", callback_data=f"cdnscan:limit:confirm:{limit}"),
                    InlineKeyboardButton("❌ Batal", callback_data="back:cdnscan:ranges:page")
                )
            )
            return

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
        blocked, kata = is_blocked(domain)
        if blocked:
            bot.send_message(chat_id, blocked_message(domain, kata))
            return
        if not cek_slot_scan(chat_id):
            bot.send_message(
                chat_id,
                "⚠️ <b>Scan sedang berjalan di chat ini</b>\nTunggu selesai sebelum scan baru.",
                reply_markup=kb_back("menu:sniscan"),
            )
            return
        sid = None
        if _ss is not None:
            try:
                active = _ss.get_active_session(chat_id)
                if active is None:
                    sid = _ss.create_session(chat_id, "sniscan", status="awaiting_input", payload={"domain": domain})
                    _ss.set_active_session(chat_id, sid)
                else:
                    sid = active['id']
                    _ss.update_session(sid, status="running", payload={"domain": domain})
            except Exception as e:
                log.debug("session ensure (sniscan) failed: %s", e)
        set_state(chat_id, mode="sniscan", awaiting=None, _sid=sid)
        threading.Thread(target=_run_sniscan_with_slot, args=(chat_id, None, domain, sid), daemon=True).start()
        return

    if awaiting == "filter_value":
        mode = _cs_get(chat_id, "filter_mode")
        field_key = _cs_get(chat_id, "filter_field")
        if not mode or not field_key:
            bot.send_message(chat_id, "Sesi filter tidak valid. Pilih menu dulu dengan /start.", reply_markup=kb_main(user_id=chat_id))
            return
        label = FIELD_LABELS.get(field_key, field_key)
        filters = _cs_get(chat_id, "scan_filters", {}) or {}
        filters[field_key] = text
        set_state(chat_id, awaiting=None)
        _cs_set(chat_id, "filter_mode", None)
        _cs_set(chat_id, "filter_field", None)
        _cs_set(chat_id, "scan_filters", filters)
        # Render ulang halaman 1 (edit pesan input user)
        show_scan_page(chat_id, message.message_id, edit=False)
        return

    # Fallback
    bot.send_message(chat_id, "Pilih menu dulu dengan /start.", reply_markup=kb_main(user_id=chat_id))


# ===================== MAIN =====================
if __name__ == '__main__':
    try:
        from .session_store import init_db
        init_db()
        log.info("session_store ready")
    except Exception as e:
        log.warning("session_store init failed: %s", e)
    log.info("Surfinder Telegram Bot sedang berjalan...")
    bot.infinity_polling()