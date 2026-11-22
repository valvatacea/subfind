#!/usr/bin/env python3
# cdnscan.py - Scan rentang IP untuk deteksi CDN
# Penggunaan:
#   python3 cdnscan.py <cidr atau range>     (manual)
#   python3 cdnscan.py <provider>            (nama provider, misal cloudflare)
# Contoh:
#   python3 cdnscan.py 104.16.0.0/20
#   python3 cdnscan.py 104.16.0.0-104.16.0.255
#   python3 cdnscan.py cloudflare
#   python3 cdnscan.py cloudfront

import sys
import os
import socket
import json
import ipaddress
import urllib.request
import urllib.error
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from common.progress import build_progress_text
from common.http_status import get_http_status_multi
from datetime import datetime

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}
def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pad_label(label, width=12):
    return label + " " * max(0, width - len(label))

# Folder dasar berdasarkan lokasi file ini
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Port yang di-scan untuk deteksi CDN (hanya port umum web)
SCAN_PORTS = [
    80, 443
]

# Batas maksimal IP yang akan di-scan per target
MAX_IPS_PER_SCAN = 1000

# Batas total IP per batch untuk multi-target
MAX_TOTAL_BATCH = 2000

# Konfirmasi otomatis (di-set dari argumen CLI -y)
AUTO_CONFIRM = False

# Jeda antar IP dalam detik (rate limiting)
SCAN_DELAY = 0.5

# Provider yang menyediakan IP range secara publik
PROVIDER_URLS = {
    'cloudflare': 'https://www.cloudflare.com/ips-v4',
    'cloudfront': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
}

# Folder untuk cache IP range provider dan hasil scan (absolut dari lokasi file ini)
IPRANGE_DIR = os.path.join(BASE_DIR, "output", "ipranges")
SCAN_DIR = os.path.join(BASE_DIR, "output")
STATE_DIR = os.path.join(BASE_DIR, "output", "states")
CACHE_MAX_AGE_SECONDS = 604800  # 7 hari untuk cache IP range provider
SCAN_CACHE_MAX_AGE_SECONDS = 604800  # 7 hari untuk skip scan ulang

# Lock thread-safe
print_lock = threading.Lock()


def fetch(url, timeout=15, progress_callback=None):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            total = r.headers.get('Content-Length')
            total = int(total) if total else None
            downloaded = 0
            chunks = []
            last_update = 0
            import time
            while True:
                chunk = r.read(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                downloaded += len(chunk)
                now = time.time()
                if progress_callback and now - last_update > 1.0:
                    progress_callback(downloaded, total)
                    last_update = now
            return b''.join(chunks).decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return f"HTTP_ERROR_{e.code}"
    except urllib.error.URLError as e:
        return f"URL_ERROR_{e.reason}"
    except Exception as e:
        return f"ERR_{type(e).__name__}"


def fetch_headers(host, port=80, scheme="http", timeout=5):
    """Ambil header response dari host:port via GET request."""
    try:
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, headers=HEADERS, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return str(r.headers).lower(), r.status
    except urllib.error.HTTPError as e:
        return str(e.headers).lower() if e.headers else "", e.code
    except Exception:
        return "", None


def detect_cdn_and_status(ip):
    """Deteksi CDN dan status HTTP.
    
    Status diambil dari get_http_status_multi (HTTP/HTTPS GET request).
    CDN dideteksi dari rentang IP Cloudflare.
    """
    cdn = "-"
    status = get_http_status_multi(ip, timeout=5)

    # Fallback: rentang IP Cloudflare
    if cdn == "-":
        cf_prefixes = (
            '104.16','104.17','104.18','104.19','104.20','104.21','104.22','104.23',
            '104.24','104.25','104.26','104.27','104.28','104.29','104.30','104.31',
            '172.64','172.65','172.66','172.67','172.68','172.69','172.70','172.71',
            '140.213','140.214','140.215','140.216','140.217','140.218','140.219',
            '140.220','140.221','140.222','140.223','140.224','140.225','140.226',
            '140.227','140.228','140.229','140.230','140.231','140.232','140.233',
            '140.234','140.235','140.236','140.237','140.238','140.239','140.240',
            '140.241','140.242','140.243','140.244','140.245','140.246','140.247',
            '140.248','140.249','140.250','140.251','140.252','140.253','140.254',
            '140.255','173.245','173.246','173.247','173.248','173.249','103.21',
            '103.22','103.23','103.24','103.25','103.26','103.27','103.28','103.29',
            '103.30','103.31','185.61','185.62','185.63','188.114','188.115','188.116',
            '188.117','188.118','188.119','188.120','188.121','188.122','188.123',
            '188.124','188.125','188.126','190.93','190.94','190.95','190.96','190.97',
            '190.98','190.99','191.96','191.97','191.98','191.99','191.100','191.101',
            '191.102','191.103','191.104','191.105','191.106','191.107','191.108',
            '191.109','191.110','191.111','197.234','197.235','198.41','198.42',
            '198.43','198.44','198.45','198.46','198.47','198.48','198.49','198.50',
            '198.51','198.52','198.53','198.54','198.55','198.56','198.57','198.58',
            '198.59','198.60','198.61','198.62','198.63','198.64','198.65','198.66',
            '198.67','198.68','198.69','198.70','198.71','198.72','198.73','198.74',
            '198.75','198.76','198.77','198.78','198.79','198.80','198.81','198.82',
            '198.83','198.84','198.85','198.86','198.87','198.88','198.89','198.90',
            '198.91','198.92','198.93','198.94','198.95','198.96','198.97','198.98',
            '198.99','198.100','198.101','198.102','198.103','198.104','198.105',
            '198.106','198.107','198.108','198.109','198.110','198.111','198.112',
            '198.113','198.114','198.115','198.116','198.117','198.118','198.119',
            '198.120','198.121','198.122','198.123','198.124','198.125','198.126',
            '198.127','199.27','199.28','199.29','199.30','199.31','199.32','199.33',
            '199.34','199.35','199.36','199.37','199.38','199.39','199.40','199.41',
            '199.42','199.43','199.44','199.45','199.46','199.47','199.48','199.49',
            '199.50','199.51','199.52','199.53','199.54','199.55','199.56','199.57',
            '199.58','199.59','199.60','199.61','199.62','199.63','199.64','199.65',
            '199.66','199.67','199.68','199.69','199.70','199.71','199.72','199.73',
            '199.74','199.75','199.76','199.77','199.78','199.79','199.80','199.81',
            '199.82','199.83','199.84','199.85','199.86','199.87','199.88','199.89',
            '199.90','199.91','199.92','199.93','199.94','199.95','199.96','199.97',
            '199.98','199.99','199.100','199.101','199.102','199.103','199.104',
            '199.105','199.106','199.107','199.108','199.109','199.110','199.111',
            '199.112','199.113','199.114','199.115','199.116','199.117','199.118',
            '199.119','199.120','199.121','199.122','199.123','199.124','199.125',
            '199.126','199.127'
        )
        if ip.startswith(cf_prefixes):
            cdn = 'Cloudflare (IP range)'

    return cdn, status


def scan_open_ports(ip, ports=SCAN_PORTS, timeout=1.5):
    """Scan port terbuka pada IP, return daftar angka port saja"""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
            s.close()
        except Exception:
            pass
    return ",".join(open_ports) if open_ports else "-"


def format_ports(ports_str):
    """Singkatkan daftar port agar kolom tidak terlalu lebar"""
    if ports_str == "-":
        return "-"
    ports = ports_str.split(",")
    if len(ports) <= 3:
        return ports_str
    return f"{','.join(ports[:3])},... ({len(ports)} port)"


def parse_ip_range(input_str, offset=0, max_ips=None):
    """Parse input CIDR atau range (start-end) ke daftar IP string.

    Args:
        input_str: String CIDR, range, atau IP tunggal.
        offset: Lewati N IP pertama (untuk resume).
        max_ips: Batas maksimal jumlah IP yang di-generate (None = tanpa batas).
    """
    ips = []
    input_str = input_str.strip()

    # Coba CIDR
    try:
        network = ipaddress.ip_network(input_str, strict=False)
        count = 0
        skipped = 0
        for ip in network.hosts():
            if skipped < offset:
                skipped += 1
                continue
            ips.append(str(ip))
            count += 1
            if max_ips is not None and count >= max_ips:
                break
        return ips
    except ValueError:
        pass

    # Coba range start-end
    if '-' in input_str:
        parts = input_str.split('-')
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                if start.version != end.version:
                    return ips
                current = start
                count = 0
                skipped = 0
                while current <= end:
                    if skipped < offset:
                        skipped += 1
                        current += 1
                        continue
                    ips.append(str(current))
                    count += 1
                    if max_ips is not None and count >= max_ips:
                        break
                    current += 1
                return ips
            except ValueError:
                return ips

    # Coba single IP
    try:
        ipaddress.ip_address(input_str)
        return [input_str] if offset == 0 else []
    except ValueError:
        return ips


def get_provider_ips(provider_name, progress_callback=None):
    """Ambil daftar IP dari provider, dengan cache 7 hari"""
    provider_name = provider_name.lower()
    if provider_name not in PROVIDER_URLS:
        return None, f"Provider '{provider_name}' tidak didukung. Tersedia: {', '.join(PROVIDER_URLS.keys())}"

    os.makedirs(IPRANGE_DIR, exist_ok=True)
    cache_file = f"{IPRANGE_DIR}/{provider_name}.json"

    # Cek apakah cache masih valid (< 7 hari)
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache = json.load(f)
            fetched_at = datetime.fromisoformat(cache.get('fetched_at', '2000-01-01'))
            age = (datetime.now() - fetched_at).total_seconds()
            if age < CACHE_MAX_AGE_SECONDS:
                return cache.get('ips', []), None
        except Exception:
            pass  # Cache rusak, akan di-fetch ulang

    # Fetch dari provider
    url = PROVIDER_URLS[provider_name]
    print(f"[*] Mengunduh IP range {provider_name} dari {url} ...")
    result = fetch(url, timeout=30, progress_callback=progress_callback)
    if result is None or result.startswith(("HTTP_ERROR_", "URL_ERROR_", "ERR_")):
        return None, f"Gagal mengunduh {provider_name}: {result}"

    ips = []
    try:
        if provider_name == 'cloudflare':
            # Text file, satu IP per baris
            for line in result.splitlines():
                line = line.strip()
                if line:
                    try:
                        ipaddress.ip_network(line, strict=False)
                        ips.append(line)
                    except ValueError:
                        pass
        elif provider_name == 'cloudfront':
            # AWS IP ranges JSON, filter hanya CLOUDFRONT service
            data = json.loads(result)
            for entry in data.get('prefixes', []):
                if entry.get('service') == 'CLOUDFRONT':
                    prefix = entry.get('ip_prefix', '')
                    if prefix:
                        ips.append(prefix)
    except Exception as e:
        return None, f"Gagal memproses data {provider_name}: {e}"

    # Simpan ke cache
    try:
        cache_data = {
            'fetched_at': datetime.now().isoformat(),
            'provider': provider_name,
            'ips': ips
        }
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
    except Exception:
        pass  # Gagal simpan cache tidak masalah, hasil tetap dipakai

    return ips, None


def process_ip(ip):
    """Proses satu IP: scan port + deteksi CDN + status HTTP.

    Catatan: Jika ip adalah CIDR (mengandung '/'), hanya network address
    (bagian sebelum '/') yang di-scan dan dicek CDN-nya, bukan semua IP
    dalam rentang tersebut.
    """
    scan_target = ip.split('/')[0] if '/' in ip else ip
    ports = scan_open_ports(scan_target)
    cdn, status = detect_cdn_and_status(scan_target)
    time.sleep(SCAN_DELAY)
    return (ip, ports, cdn, status)


def calc_widths(results):
    """Hitung lebar kolom otomatis"""
    w_ip = max(len(r[0]) for r in results)
    w_ports = max(len(r[1]) for r in results)
    w_cdn = max(len(r[2]) for r in results)
    w_status = max(len(r[3]) for r in results)
    w_ip = max(w_ip, len("IP"))
    w_ports = max(w_ports, len("PORTS"))
    w_cdn = max(w_cdn, len("CDN"))
    w_status = max(w_status, len("STATUS"))
    return w_ip, w_ports, w_cdn, w_status


def save_state(cidr, scanned_count, completed):
    """Simpan progres scan per rentang ke file state."""
    os.makedirs(STATE_DIR, exist_ok=True)
    safe = cidr.replace("/", "_").replace("-", "_").replace(".", "_")
    state_file = f"{STATE_DIR}/cdnscan_{safe}.json"
    state = {
        "cidr": cidr,
        "scanned_count": scanned_count,
        "completed": completed,
        "updated_at": datetime.now().isoformat()
    }
    try:
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[!] Gagal menyimpan state: {e}")


def load_state(cidr):
    """Baca state progres scan per rentang. Return dict atau None."""
    safe = cidr.replace("/", "_").replace("-", "_").replace(".", "_")
    state_file = f"{STATE_DIR}/cdnscan_{safe}.json"
    if not os.path.exists(state_file):
        return None
    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def count_existing_ips(fname):
    """Hitung jumlah IP yang sudah ada di file output (untuk anti-duplikasi)."""
    if not os.path.exists(fname):
        return 0
    try:
        count = 0
        with open(fname, 'r') as f:
            header = f.readline()  # skip header
            for line in f:
                line = line.strip()
                if line:
                    count += 1
        return count
    except Exception:
        return 0


def count_total_batch_ips_cli(targets):
    """Hitung total IP yang akan discan dalam satu batch dari daftar targets CLI.

    targets: list of (label, cidr_str, user_limit, tfname, safe_name, provider)
    user_limit None berarti unlimited (ambil semua sisa IP per target).
    """
    total = 0
    for label, cidr_str, user_limit, tfname, safe_name, provider in targets:
        state = load_state(cidr_str)
        offset = state.get('scanned_count', 0) if state else 0
        all_full = parse_ip_range(cidr_str)
        total_full = len(all_full) if all_full else 0
        sisa = max(0, total_full - offset)
        if sisa > 0:
            ips = min(user_limit, sisa) if user_limit else sisa
            total += ips
    return total


def select_ranges(ranges):
    """Tampilkan daftar rentang IP sebagai nomor dan biarkan pengguna memilih."""
    # Jika mode non-interaktif (-y), pilih semua rentang tanpa prompt
    if AUTO_CONFIRM:
        return list(ranges)

    print(f"\nDaftar rentang IP yang tersedia ({len(ranges)} rentang):")
    for i, r in enumerate(ranges, 1):
        print(f"  {i}. {r}")
    print()
    pilihan = safe_input("Pilih nomor rentang (pisahkan koma, misal 1,3,5): ")
    selected = []
    for p in pilihan.split(','):
        p = p.strip()
        if p.isdigit():
            idx = int(p) - 1
            if 0 <= idx < len(ranges):
                selected.append(ranges[idx])
    # Hilangkan duplikat sambil mempertahankan urutan
    seen = set()
    uniq = []
    for r in selected:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def safe_input(prompt):
    """Wrapper untuk input() dengan penanganan KeyboardInterrupt dan EOFError"""
    if AUTO_CONFIRM:
        return 'y'
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\n    Dibatalkan oleh pengguna.")
        sys.exit(0)


def main():
    # Argumen CLI untuk mode non-interaktif
    parser = argparse.ArgumentParser(description='Scan rentang IP untuk deteksi CDN')
    parser.add_argument('target', nargs='?', help='CIDR, range, IP tunggal, atau nama provider (cloudflare/cloudfront)')
    parser.add_argument('-l', '--limit', type=int, metavar='N', help='Batas IP per scan (maksimal 1000)')
    parser.add_argument('-d', '--delay', type=float, metavar='SEC', help='Jeda antar IP dalam detik (default 0.5)')
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'both'], default='both', help='Format output (default: both)')
    parser.add_argument('-y', '--yes', action='store_true', help='Konfirmasi otomatis semua prompt (non-interaktif)')
    args = parser.parse_args()

    if not args.target:
        print("Usage: python3 cdnscan.py <cidr atau range | nama provider>")
        print("Example: python3 cdnscan.py 104.16.0.0/20")
        print("Example: python3 cdnscan.py cloudflare")
        print("Example: python3 cdnscan.py cloudfront")
        print()
        print("Provider yang tersedia:")
        for name, url in PROVIDER_URLS.items():
            print(f"  - {name} ({url})")
        sys.exit(1)

    # Override konstanta dari argumen CLI
    global SCAN_DELAY, MAX_IPS_PER_SCAN, AUTO_CONFIRM
    if args.delay is not None:
        SCAN_DELAY = args.delay
    if args.limit is not None:
        if args.limit <= 0:
            print("Limit harus lebih dari 0.")
            sys.exit(1)
        MAX_IPS_PER_SCAN = args.limit

    AUTO_CONFIRM = args.yes
    input_str = args.target.strip()
    print(f"Scan target: {input_str}\n")

    # Siapkan direktori output
    try:
        os.makedirs(SCAN_DIR, exist_ok=True)
    except Exception as e:
        print(f"[!] Tidak dapat membuat direktori '{SCAN_DIR}': {e}")
        sys.exit(1)

    safe_name = input_str.replace("/", "_").replace("-", "_").replace(".", "_")

    # Daftar target scan: setiap item = (label, ips_list, fname, safe_name)
    targets = []

    # Cek apakah input adalah nama provider
    if input_str.lower() in PROVIDER_URLS:
        provider_name = input_str.lower()
        # Konfirmasi sebelum fetch IP range
        print(f"[?] Akan mengambil IP range untuk provider '{provider_name}' dari {PROVIDER_URLS[provider_name]}")
        konfirmasi = safe_input("    Lanjutkan fetch IP range? (y/N): ")
        if konfirmasi != 'y':
            print("    Dibatalkan.")
            sys.exit(0)
        ips, err = get_provider_ips(provider_name)
        if err:
            print(f"[!] {err}")
            sys.exit(1)
        if not ips:
            print(f"[!] Tidak ada IP yang ditemukan untuk provider {provider_name}")
            sys.exit(1)
        print(f"[*] Dapat {len(ips)} rentang IP dari provider {provider_name}")

        # Tampilkan daftar dan biarkan pengguna memilih rentang
        selected = select_ranges(ips)
        if not selected:
            print("Tidak ada rentang yang dipilih.")
            sys.exit(0)

        for cidr in selected:
            # Cek state resume untuk rentang ini
            state = load_state(cidr)
            if state and state.get('completed'):
                print(f"[*] Rentang '{cidr}' sudah discan sepenuhnya. Dilewati.")
                continue

            # Tanya berapa IP yang ingin di-scan dalam batch ini (opsional)
            print(f"Rentang: {cidr}")
            if AUTO_CONFIRM:
                user_limit = None
            else:
                limit_input = safe_input("    Mau scan berapa IP dalam batch ini? (Enter untuk semua, maksimal 1000): ")
                user_limit = None
                if limit_input.strip():
                    try:
                        user_limit = int(limit_input.strip())
                        if user_limit <= 0:
                            print("    Limit harus lebih dari 0. Menggunakan semua IP.")
                            user_limit = None
                        elif user_limit > MAX_IPS_PER_SCAN:
                            print(f"    Melebihi batas {MAX_IPS_PER_SCAN} IP per batch. Dibatasi menjadi {MAX_IPS_PER_SCAN}.")
                            user_limit = MAX_IPS_PER_SCAN
                    except ValueError:
                        print("    Input tidak valid. Menggunakan semua IP.")
                        user_limit = None

            range_safe = cidr.replace("/", "_").replace("-", "_").replace(".", "_")
            tsname = f"{provider_name}_{range_safe}"
            tfname = f"{SCAN_DIR}/cdnscan_{tsname}.txt"
            targets.append((cidr, cidr, user_limit, tfname, tsname, provider_name))
            print(f"    Target ditambahkan: {cidr} -> {tfname}")
    else:
        # Manual input (CIDR, range, atau IP tunggal)
        # Cek state resume untuk rentang ini
        state = load_state(input_str)
        if state and state.get('completed'):
            print(f"[*] Rentang '{input_str}' sudah discan sepenuhnya. Dilewati.")
            sys.exit(0)

        print(f"Rentang: {input_str}")
        if AUTO_CONFIRM:
            user_limit = None
        else:
            limit_input = safe_input("    Mau scan berapa IP dalam batch ini? (Enter untuk semua, maksimal 1000): ")
            user_limit = None
            if limit_input.strip():
                try:
                    user_limit = int(limit_input.strip())
                    if user_limit <= 0:
                        print("    Limit harus lebih dari 0. Menggunakan semua IP.")
                        user_limit = None
                    elif user_limit > MAX_IPS_PER_SCAN:
                        print(f"    Melebihi batas {MAX_IPS_PER_SCAN} IP per batch. Dibatasi menjadi {MAX_IPS_PER_SCAN}.")
                        user_limit = MAX_IPS_PER_SCAN
                except ValueError:
                    print("    Input tidak valid. Menggunakan semua IP.")
                    user_limit = None

        tfname = f"{SCAN_DIR}/cdnscan_{safe_name}.txt"
        targets.append((input_str, input_str, user_limit, tfname, safe_name, "manual"))

    # Konfirmasi sebelum memulai scan
    print(f"\n[?] Akan memproses {len(targets)} target.")

    # Verifikasi total IP per batch sebelum scan dimulai
    total = count_total_batch_ips_cli(targets)
    if total > MAX_TOTAL_BATCH:
        print(f"\n[!] Total IP melebihi batas: {total} IP (maksimal {MAX_TOTAL_BATCH} IP per batch)")
        konfirmasi_total = safe_input(f"    Lanjutkan scan dengan membatasi ke {MAX_TOTAL_BATCH} IP? (y/N): ")
        if konfirmasi_total != 'y':
            print("    Dibatalkan.")
            sys.exit(0)

    konfirmasi = safe_input("    Lanjutkan scan? (y/N): ")
    if konfirmasi != 'y':
        print("    Dibatalkan.")
        sys.exit(0)

    print("Memproses dengan threading...\n")

    for label, cidr_str, user_limit, fname, safe_name, provider in targets:
        # Cek state resume + anti-duplikasi dari file output
        state = load_state(cidr_str)
        state_offset = state.get('scanned_count', 0) if state else 0
        file_offset = count_existing_ips(fname)
        offset = max(state_offset, file_offset)  # Terbesar adalah ground truth

        if state and state.get('completed'):
            print(f"[*] Semua IP dari '{label}' sudah discan. Hasil ada di: {fname}")
            continue

        if offset > 0:
            print(f"[*] Melanjutkan dari IP ke-{offset + 1} untuk '{label}' (sudah discan: {offset} IP).")

        # Generate IP batch dari offset
        batch_limit = user_limit if user_limit is not None else MAX_IPS_PER_SCAN
        ips = parse_ip_range(cidr_str, offset=offset, max_ips=batch_limit)
        if not ips:
            print(f"[*] Tidak ada IP baru untuk '{label}'. Rentang mungkin sudah selesai.")
            save_state(cidr_str, offset, True)
            continue

        print(f"\n    Memulai scan target: {label} ({len(ips)} IP, offset={offset})")
        print("    Memproses dengan threading...")

        results = []
        max_workers = min(30, len(ips))
        c = 0
        start_time = time.time()
        spinner_idx = [0]
        SPINNER = ['⠋', '⠙', '⠹', '⠼', '⠴', '⠦', '⠧', '⠏']

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(process_ip, ip): ip for ip in ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    result = None
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append((ip, "-", "-", "-"))
                        result = (ip, "-", "-", "-")

                    c += 1
                    spinner_idx[0] += 1
                    line = build_progress_text(
                        spinner_idx[0], "CDNScan", "", c, len(ips), start_time,
                        filled_char="█", empty_char="░", width=10,
                        label_prefix="", target_suffix="",
                        count_template="[{current}/{total}]", show_target=False,
                    )
                    with print_lock:
                        print(line, end="")
                        sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n\n    [!] Scan dibatalkan oleh pengguna (Ctrl+C).")
            if results:
                print(f"    Hasil parcial ({len(results)} dari {len(ips)} IP) akan disimpan.")
                new_offset = offset + len(results)
                save_state(cidr_str, new_offset, False)
            else:
                print("    Tidak ada hasil yang dihasilkan.")
                continue

        # Urutkan hasil berdasarkan IP (handle CIDR dan single IP)
        def sort_key(item):
            ip_str = item[0].split('/')[0] if '/' in item[0] else item[0]
            return ipaddress.ip_address(ip_str)

        results.sort(key=sort_key)

        # Hitung lebar kolom otomatis
        w_ip, w_ports, w_cdn, w_status = calc_widths(results)
        total_width = w_ip + w_ports + w_cdn + w_status + 16

        # Cetak hasil akhir ke layar (CLI) - format blok key-value
        print()
        for ip, ports, cdn, status in results:
            print(f"{pad_label('IP', 12)}: {ip}")
            print(f"{pad_label('PORTS', 12)}: {format_ports(ports)}")
            print(f"{pad_label('CDN', 12)}: {cdn}")
            print(f"{pad_label('Status', 12)}: {status}")
            print("----------------------------------------------")

        # Simpan ke file output sesuai --format
        save_txt = args.format in ('txt', 'both')
        save_json = args.format in ('json', 'both')

        if save_txt:
            file_exists = os.path.exists(fname) and os.path.getsize(fname) > 0
            try:
                mode = 'a' if file_exists else 'w'
                with open(fname, mode) as f:
                    if not file_exists:
                        f.write(f"═══ CDNSCAN: {input_str} ═══\n\n")
                    for ip, ports, cdn, status in results:
                        f.write(f"IP          : {ip}\n")
                        f.write(f"PORTS       : {format_ports(ports)}\n")
                        f.write(f"CDN         : {cdn}\n")
                        f.write(f"Status      : {status}\n")
                        f.write("----------------------------------------------\n")
            except Exception as e:
                print(f"    [!] Gagal menyimpan file teks: {e}")

        if save_json:
            jname = f"{SCAN_DIR}/cdnscan_{safe_name}.json"
            json_data = []
            # Baca JSON lama jika ada, untuk menumpuk hasil resume
            if os.path.exists(jname):
                try:
                    with open(jname, 'r') as f:
                        json_data = json.load(f)
                except Exception:
                    json_data = []
            for ip, ports, cdn, status in results:
                json_data.append({
                    "ip": ip,
                    "ports": ports,
                    "cdn": cdn,
                    "status": status,
                    "target": cidr_str,
                    "provider": provider
                })
            try:
                with open(jname, 'w') as f:
                    json.dump(json_data, f, indent=2)
            except Exception as e:
                print(f"    [!] Gagal menyimpan file JSON: {e}")

        # Update state
        new_offset = offset + len(results)
        # Cek apakah masih ada IP setelah batch ini untuk menentukan completed
        next_check = parse_ip_range(cidr_str, offset=new_offset, max_ips=1)
        completed = len(next_check) == 0
        save_state(cidr_str, new_offset, completed)
        if completed:
            print(f"\n    [*] Rentang '{label}' sudah discan sepenuhnya ({new_offset} IP).")
        else:
            print(f"\n    [*] Progres: {new_offset} IP telah discan dari '{label}'.")

        if save_txt:
            print(f"\n    Hasil disimpan ke: {fname}")
        if save_json:
            print(f"    JSON disimpan ke: {jname}")

    print("\nScan semua target selesai.")


if __name__ == '__main__':
    main()
