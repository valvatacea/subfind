#!/usr/bin/env python3
# cdnscan.py - Scan rentang IP untuk deteksi CDN
# Penggunaan: python3 cdnscan.py <cidr atau range>
# Contoh: python3 cdnscan.py 104.16.0.0/12
#         python3 cdnscan.py 104.16.0.0-104.16.255.255

import sys
import os
import socket
import json
import ipaddress
import urllib.request
import urllib.error
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}

# Port yang di-scan untuk deteksi CDN (berdasarkan rentang port Cloudflare & CloudFront)
SCAN_PORTS = [
    80, 443, 2052, 2053, 2082, 2083, 2086, 2087,
    2095, 2096, 8080, 8443, 8880
]

# Lock thread-safe
print_lock = threading.Lock()
completed_lock = threading.Lock()
completed_count = 0

def fetch_headers(host, port=80, scheme="http", timeout=5):
    """Ambil header response dari host:port"""
    try:
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, headers=HEADERS, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return str(r.headers).lower(), r.status
    except urllib.error.HTTPError as e:
        return str(e.headers).lower() if e.headers else "", e.code
    except Exception:
        return "", None

def detect_cdn(ip):
    """Deteksi apakah IP milik CDN melalui header dan rentang IP"""
    cdn = "-"
    evidence = []

    # Cek header HTTP dan HTTPS pada port umum
    for port in SCAN_PORTS:
        scheme = "https" if port in (443, 8443) else "http"
        try:
            headers, status = fetch_headers(ip, port, scheme, timeout=5)
            h = headers.lower()
            if 'cloudflare' in h:
                cdn = 'Cloudflare'
                evidence.append(f"header:{port}")
                break
            if 'cloudfront' in h:
                cdn = 'CloudFront'
                evidence.append(f"header:{port}")
                break
            if 'akamai' in h:
                cdn = 'Akamai'
                evidence.append(f"header:{port}")
                break
            if 'fastly' in h:
                cdn = 'Fastly'
                evidence.append(f"header:{port}")
                break
            if 'sucuri' in h:
                cdn = 'Sucuri'
                evidence.append(f"header:{port}")
                break
        except Exception:
            continue

    # Fallback: rentang IP Cloudflare
    if cdn == '-':
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

    return cdn, evidence

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

def parse_ip_range(input_str):
    """Parse input CIDR atau range (start-end) ke daftar IP string"""
    ips = []
    input_str = input_str.strip()

    # Coba CIDR
    try:
        network = ipaddress.ip_network(input_str, strict=False)
        for ip in network.hosts():
            ips.append(str(ip))
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
                while current <= end:
                    ips.append(str(current))
                    current += 1
                return ips
            except ValueError:
                return ips

    # Coba single IP
    try:
        ipaddress.ip_address(input_str)
        return [input_str]
    except ValueError:
        return ips

def process_ip(ip):
    """Proses satu IP: scan port + deteksi CDN"""
    ports = scan_open_ports(ip)
    cdn, evidence = detect_cdn(ip)
    return (ip, ports, cdn, ",".join(evidence) if evidence else "-")

def calc_widths(results):
    """Hitung lebar kolom otomatis"""
    w_ip = max(len(r[0]) for r in results)
    w_ports = max(len(r[1]) for r in results)
    w_cdn = max(len(r[2]) for r in results)
    w_ev = max(len(r[3]) for r in results)
    w_ip = max(w_ip, len("IP"))
    w_ports = max(w_ports, len("PORTS"))
    w_cdn = max(w_cdn, len("CDN"))
    w_ev = max(w_ev, len("EVIDENCE"))
    return w_ip, w_ports, w_cdn, w_ev

def main():
    global completed_count
    if len(sys.argv) < 2:
        print("Usage: python3 cdnscan.py <cidr atau range>")
        print("Example: python3 cdnscan.py 104.16.0.0/20")
        print("Example: python3 cdnscan.py 104.16.0.0-104.16.0.255")
        print("Example: python3 cdnscan.py 104.16.0.1")
        sys.exit(1)

    input_str = sys.argv[1].strip()
    print(f"Scan target: {input_str}\n")

    ips = parse_ip_range(input_str)
    if not ips:
        print("Tidak ada IP valid yang ditemukan dari input.")
        sys.exit(1)

    print(f"Total IP untuk di-scan: {len(ips)}")
    print("Memproses dengan threading...\n")

    results = []
    max_workers = min(30, len(ips))
    completed_count = 0

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

            with completed_lock:
                completed_count += 1
                c = completed_count
                ip_disp = result[0]
                ports_disp = format_ports(result[1])
                cdn_disp = result[2]
                ev_disp = result[3]
                line = (f"[{c}/{len(ips)}] {ip_disp} | Ports: {ports_disp} | "
                        f"CDN: {cdn_disp} | Evidence: {ev_disp}")
                with print_lock:
                    print(f"\r{line}", end="")
                    sys.stdout.flush()

    # Urutkan hasil berdasarkan IP
    results.sort(key=lambda x: ipaddress.ip_address(x[0]))

    # Hitung lebar kolom otomatis
    w_ip, w_ports, w_cdn, w_ev = calc_widths(results)
    total_width = w_ip + w_ports + w_cdn + w_ev + 16

    # Cetak tabel akhir
    print("\n" + "=" * total_width)
    print(f"{'IP':<{w_ip}} {'PORTS':<{w_ports}} {'CDN':<{w_cdn}} {'EVIDENCE'}")
    print("-" * total_width)
    for ip, ports, cdn, ev in results:
        print(f"{ip:<{w_ip}} {format_ports(ports):<{w_ports}} {cdn:<{w_cdn}} {ev}")

    # Simpan ke file teks di output/
    OUT_DIR = "output"
    os.makedirs(OUT_DIR, exist_ok=True)
    safe_name = input_str.replace("/", "_").replace("-", "_").replace(".", "_")
    fname = f"{OUT_DIR}/cdnscan_{safe_name}.txt"
    with open(fname, 'w') as f:
        f.write("ip|ports|cdn|evidence\n")
        for ip, ports, cdn, ev in results:
            f.write(f"{ip}|{format_ports(ports)}|{cdn}|{ev}\n")

    # Simpan ke file JSON di output/
    jname = f"{OUT_DIR}/cdnscan_{safe_name}.json"
    json_data = []
    for ip, ports, cdn, ev in results:
        json_data.append({
            "ip": ip,
            "ports": ports,
            "cdn": cdn,
            "evidence": ev
        })
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    print(f"\nHasil disimpan ke: {fname}")
    print(f"JSON disimpan ke: {jname}")

if __name__ == '__main__':
    main()
