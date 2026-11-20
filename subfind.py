#!/usr/bin/env python3
# subfind.py - Cari subdomain otomatis + IP + CDN + scan port + status HTTP
# Penggunaan: python3 subfind.py <domain>

import sys
import os
import socket
import json
import urllib.request
import urllib.error
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}

# Folder khusus cache daftar subdomain per domain
SUBFIND_CACHE_DIR = "output/subfind_cache"
CACHE_MAX_AGE_SECONDS = 604800  # 7 hari

# Port umum yang akan di-scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 10000, 20865, 20885, 20165, 20185, 20195,
    20971, 20979, 20128
]

# Lock untuk print dan counter thread-safe
print_lock = threading.Lock()
completed_lock = threading.Lock()
completed_count = 0

def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return f"HTTP_ERROR_{e.code}"
    except urllib.error.URLError as e:
        return f"URL_ERROR_{e.reason}"
    except Exception as e:
        return f"ERR_{type(e).__name__}"

def crt_sh(domain):
    """Ambil subdomain dari Certificate Transparency logs (crt.sh)"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    result = fetch(url)
    if result is None:
        return set(), "crt.sh timeout/tidak merespons"
    if result.startswith("HTTP_ERROR_"):
        return set(), f"crt.sh HTTP error: {result.split('_')[-1]}"
    if result.startswith("URL_ERROR_"):
        return set(), f"crt.sh jaringan gagal: {result.split('_')[-1]}"
    if result.startswith("ERR_"):
        return set(), f"crt.sh error: {result.split('_')[-1]}"
    try:
        data = json.loads(result)
        subs = set()
        for entry in data:
            name = entry.get('name_value', '')
            for n in name.split('\n'):
                n = n.strip().lower()
                if n and (n == domain or n.endswith('.' + domain)):
                    subs.add(n)
        return subs, None
    except Exception as e:
        return set(), f"crt.sh parse gagal: {e}"

def hackertarget(domain):
    """Fallback: HackerTarget hostsearch (tanpa API key)"""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = fetch(url)
    if not text or text.startswith("HTTP_ERROR_") or text.startswith("URL_ERROR_") or text.startswith("ERR_"):
        return set(), "hackertarget gagal (timeout/limit)"
    subs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('error'):
            continue
        parts = line.split(',')
        if parts:
            sub = parts[0].strip().lower()
            if sub and (sub == domain or sub.endswith('.' + domain)):
                subs.add(sub)
    return subs, None

def wordlist_fallback(domain):
    """Fallback terakhir: daftar subdomain umum"""
    common = "www mail ftp api dev test staging blog shop cdn vpn ssh ns1 ns2 mx app web portal admin blog dev staging vpn2 test2 beta mobile client dashboard"
    subs = set()
    for sub in common.split():
        host = f"{sub}.{domain}"
        if resolve_ip(host):
            subs.add(host)
    return subs, None

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def get_cache_path(domain):
    """Path file cache daftar subdomain per domain di folder khusus."""
    os.makedirs(SUBFIND_CACHE_DIR, exist_ok=True)
    safe = domain.replace('.', '_').replace('/', '_').replace('\\', '_')
    return f"{SUBFIND_CACHE_DIR}/subfind_{safe}.json"


def load_cache(domain):
    """Baca daftar subdomain dari cache jika masih fresh (< 7 hari)."""
    path = get_cache_path(domain)
    if not os.path.exists(path):
        return None
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        age = (datetime.now() - mtime).total_seconds()
        if age < CACHE_MAX_AGE_SECONDS:
            with open(path, 'r') as f:
                data = json.load(f)
            return set(data.get('subdomains', []))
        else:
            return None  # cache expired
    except Exception:
        return None


def save_cache(domain, subs):
    """Simpan daftar subdomain ke cache folder khusus."""
    path = get_cache_path(domain)
    try:
        with open(path, 'w') as f:
            json.dump({
                'domain': domain,
                'fetched_at': datetime.now().isoformat(),
                'subdomains': sorted(list(subs))
            }, f, indent=2)
    except Exception:
        pass


def scan_ports_summary(ip, ports=COMMON_PORTS, timeout=1.5):
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

def port_name(port):
    names = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt", 10000: "Webmin", 20865: "WS-NatSSH",
        20885: "WS-NatSSH", 20165: "WS-NatSSH", 20185: "WS-NatSSH",
        20195: "WS-NatSSH", 20971: "SSH", 20979: "9Router",
        20128: "Cloudflared"
    }
    return names.get(port, "?")

def get_http_status(host):
    """Cek status HTTP/HTTPS, return kode (200, 301, 403, dst) atau '-'"""
    for scheme in ("http", "https"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers=HEADERS, method="HEAD")
            with urllib.request.urlopen(req, timeout=6) as r:
                return str(r.status)
        except urllib.error.HTTPError as e:
            return str(e.code)
        except Exception:
            continue
    return "-"

def detect_cdn(host, ip):
    # Cek header HTTP dan HTTPS
    for scheme in ("http", "https"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers=HEADERS, method='HEAD')
            with urllib.request.urlopen(req, timeout=5) as r:
                h = str(r.headers).lower()
            if 'cloudflare' in h: return 'Cloudflare'
            if 'cloudfront' in h: return 'CloudFront'
            if 'akamai' in h: return 'Akamai'
            if 'fastly' in h: return 'Fastly'
            if 'sucuri' in h: return 'Sucuri'
        except Exception:
            continue
    # Fallback: IP range Cloudflare
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
    if ip and ip.startswith(cf_prefixes):
        return 'Cloudflare (IP range)'
    return '-'

def process_subdomain(sub):
    """Proses satu subdomain: resolve IP, scan port, status HTTP, CDN"""
    ip = resolve_ip(sub)
    if ip:
        ports_str = scan_ports_summary(ip)
        status = get_http_status(sub)
        cdn = detect_cdn(sub, ip)
    else:
        ports_str = "-"
        status = "-"
        cdn = "-"
    return (sub, str(ip) if ip else '-', ports_str, status, cdn)

def calc_widths(results):
    """Hitung lebar kolom otomatis berdasarkan data terpanjang"""
    w_sub = max(len(r[0]) for r in results)
    w_ip = max(len(r[1]) for r in results)
    w_ports = max(len(r[2]) for r in results)
    w_status = max(len(r[3]) for r in results)
    w_cdn = max(len(r[4]) for r in results)
    # Minimal width agar header masih terbaca
    w_sub = max(w_sub, len("SUBDOMAIN"))
    w_ip = max(w_ip, len("IP"))
    w_ports = max(w_ports, len("PORTS"))
    w_status = max(w_status, len("STATUS"))
    w_cdn = max(w_cdn, len("CDN"))
    return w_sub, w_ip, w_ports, w_status, w_cdn

def main():
    global completed_count
    if len(sys.argv) < 2:
        print("Usage: python3 subfind.py <domain>")
        print("Example: python3 subfind.py contoh.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()
    print(f"Scanning: {domain}\n")

    subs = set()
    errors = []

    # Cek cache terlebih dahulu
    cached = load_cache(domain)
    if cached is not None:
        subs = cached
        print(f"[*] Cache ditemukan: {len(subs)} subdomain (umur < 7 hari)")
    else:
        # 1. crt.sh
        print("[*] Mencoba crt.sh...")
        s, err = crt_sh(domain)
        if s:
            subs |= s
            print(f"    crt.sh: {len(s)} subdomain")
        else:
            errors.append(err or "crt.sh kosong")
            print(f"    {err}  <-- kemungkinan: rate-limit, firewall blokir, atau crt.sh down")

        # 2. hackertarget (fallback jika crt.sh kosong atau error)
        if not subs:
            print("[*] crt.sh kosong/gagal. Coba hackertarget...")
            s, err = hackertarget(domain)
            if s:
                subs |= s
                print(f"    hackertarget: {len(s)} subdomain")
            else:
                errors.append(err or "hackertarget kosong")
                print(f"    {err}")

        # 3. wordlist (fallback terakhir)
        if not subs:
            print("[*] Semua provider online gagal. Coba daftar umum (wordlist)...")
            s, err = wordlist_fallback(domain)
            if s:
                subs |= s
                print(f"    wordlist: {len(s)} subdomain")
            else:
                print("    Tidak ditemukan subdomain apa pun.")

        # Simpan cache jika ada subdomain yang ditemukan
        if subs:
            save_cache(domain, subs)

    if not subs:
        print("\nTidak ada subdomain yang ditemukan.")
        sys.exit(0)

    sorted_subs = sorted(subs)
    total = len(sorted_subs)
    completed_count = 0

    print(f"\nTotal: {total} subdomain unik")
    print("Memproses dengan threading...\n")

    results = []
    max_workers = min(20, total)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_subdomain, sub): sub for sub in sorted_subs}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append((sub, '-', '-', '-', '-'))

            with completed_lock:
                completed_count += 1
                c = completed_count
                # Tampilkan detail hasil yang baru selesai (update baris yang sama)
                sub_disp = result[0]
                ip_disp = result[1]
                ports_disp = result[2]
                status_disp = result[3]
                cdn_disp = result[4]
                line = (f"[{c}/{total}] {sub_disp} | IP: {ip_disp} | Ports: {ports_disp} | "
                        f"Status: {status_disp} | CDN: {cdn_disp}")
                with print_lock:
                    print(f"\r{line}", end="")
                    sys.stdout.flush()

    # Urutkan hasil berdasarkan nama subdomain
    results.sort(key=lambda x: x[0])

    # Hitung lebar kolom otomatis
    w_sub, w_ip, w_ports, w_status, w_cdn = calc_widths(results)
    total_width = w_sub + w_ip + w_ports + w_status + w_cdn + 12  # 12 = spasi antar kolom

    # Cetak tabel akhir
    print("\n" + "=" * total_width)
    print(f"{'SUBDOMAIN':<{w_sub}} {'IP':<{w_ip}} {'PORTS':<{w_ports}} {'STATUS':<{w_status}} {'CDN'}")
    print("-" * total_width)
    for sub, ip, ports, status, cdn in results:
        print(f"{sub:<{w_sub}} {ip:<{w_ip}} {ports:<{w_ports}} {status:<{w_status}} {cdn}")

    # Simpan ke file teks di folder output/
    OUT_DIR = "output"
    os.makedirs(OUT_DIR, exist_ok=True)
    fname = f"{OUT_DIR}/subfind_{domain}.txt"
    with open(fname, 'w') as f:
        f.write("subdomain|ip|ports|status|cdn\n")
        for sub, ip, ports, status, cdn in results:
            f.write(f"{sub}|{ip}|{ports}|{status}|{cdn}\n")

    # Simpan ke file JSON di folder output/
    jname = f"{OUT_DIR}/subfind_{domain}.json"
    json_data = []
    for sub, ip, ports, status, cdn in results:
        json_data.append({
            "subdomain": sub,
            "ip": ip,
            "ports": ports,
            "status": status,
            "cdn": cdn
        })
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    print(f"\nHasil disimpan ke: {fname}")
    print(f"JSON disimpan ke: {jname}")

if __name__ == '__main__':
    main()
