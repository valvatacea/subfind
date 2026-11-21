# common/progress.py - Utilitas progres bersama untuk skrip CLI dan bot Telegram
# Berisi logika perhitungan spinner, progress bar, elapsed time, dan ETA.
# Tidak berubah tampilan output — hanya mengekstrak duplikasi kode.

import time


SPINNER = ['⠋', '⠙', '⠹', '⠼', '⠴', '⠦', '⠧', '⠏']


def format_elapsed(seconds):
    """Format durasi detik menjadi string yang mudah dibaca.

    Args:
        seconds: Durasi dalam detik (float)

    Returns:
        String seperti '12s' atau '1m 24s'
    """
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def calculate_eta(elapsed, current, total):
    """Hitung estimated time of arrival.

    Args:
        elapsed: Waktu telah berlalu dalam detik
        current: Item yang sudah diproses
        total: Total item yang akan diproses

    Returns:
        ETA dalam detik (float), atau 0 jika belum cukup data
    """
    if current > 0 and total > 0 and elapsed > 0:
        return (elapsed / current) * (total - current)
    return 0


def build_bar(current, total, width=10, filled_char="█", empty_char="░"):
    """Bangun string progress bar.

    Args:
        current: Item yang sudah diproses
        total: Total item
        width: Lebar bar dalam jumlah karakter
        filled_char: Karakter untuk bagian terisi
        empty_char: Karakter untuk bagian kosong

    Returns:
        String seperti '████████░░'
    """
    if total > 0:
        filled = int(current / total * width)
    else:
        filled = 0
    filled = max(0, min(filled, width))
    return filled_char * filled + empty_char * (width - filled)


def build_progress_text(spinner_idx, title, target, current, total,
                        start_time, filled_char="█", empty_char="░",
                        width=10, label_prefix="Scanning",
                        target_suffix="...", count_template="({current}/{total})",
                        show_target=True, prefix="", elapsed=None, eta=None):
    """Bangun satu baris teks progres lengkap.

    Args:
        spinner_idx: Indeks spinner saat ini (diberi inkremen oleh pemanggil)
        title: Judul scan (misal 'SubFind', 'SNIScan', 'CDNScan')
        target: Target yang dipindai (domain atau IP/CIDR)
        current: Item yang sudah diproses
        total: Total item
        start_time: Waktu mulai scan (time.time())
        filled_char: Karakter bar terisi
        empty_char: Karakter bar kosong
        width: Lebar bar
        label_prefix: Prefix teks sebelum target (misal 'Scanning')
        target_suffix: Suffix teks setelah target (default '...')
        count_template: Template untuk count, gunakan {current} dan {total}.
                        Kosongkan untuk tidak menampilkan count.
        show_target: Apakah menampilkan target (default True)
        prefix: Teks di awal sebelum spinner (default '')
        elapsed: Waktu berlalu dalam detik (dikirim oleh elapsed thread)
        eta: Estimasi waktu selesai dalam detik (dikirim oleh elapsed thread)

    Returns:
        String siap dicetak (tanpa newline)
    """
    now = time.time()
    if elapsed is None:
        elapsed = now - start_time
    if eta is None and current > 0 and total > 0 and elapsed > 0:
        eta = (elapsed / current) * (total - current)
    else:
        eta = 0

    bar = build_bar(current, total, width=width,
                    filled_char=filled_char, empty_char=empty_char)
    pct = int(current / total * 100) if total > 0 else 0

    spinner = SPINNER[spinner_idx % len(SPINNER)]
    elapsed_str = format_elapsed(elapsed)
    eta_str = format_elapsed(eta)

    # Clamp pct agar tidak melebihi 100%
    if total > 0:
        pct = min(int(current / total * 100), 100)
    else:
        pct = 0

    # Bangun bagian count
    if count_template:
        count_str = count_template.format(current=min(current, total), total=total)
    else:
        count_str = ""

    # Susun bagian-bagian teks
    parts = []
    if prefix:
        parts.append(prefix)
    parts.append(spinner)
    if label_prefix:
        parts.append(label_prefix)
    if show_target and target:
        parts.append(target + target_suffix)
    parts.append(f"{bar} {pct}%")
    if count_str:
        parts.append(count_str)
    parts.append(f"Elapsed: {elapsed_str} | ETA: {eta_str}")

    return " ".join(parts)