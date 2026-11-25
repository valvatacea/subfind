#!/usr/bin/env python3
# sniscan.py - SNI Host Scanner + TLS Detector + Multi-Port Scan
# Penggunaan:
#   python3 sniscan.py <domain>
# Contoh:
#   python3 sniscan.py instagram.com

from curl_cffi import requests as curl_requests

import sys
import os
import re
import socket
import ssl
import json
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed

from common.validators import validate_domain
from common.nsfw_filter import is_blocked, blocked_message
from common.http_status import get_http_status_multi
from common.progress import build_progress_text
from common.cdn_detect import detect_cdn
from common.port_scan import scan_ports
from common.http_status import HEADERS_WITHOUT_COMPRESSION

socket.setdefaulttimeout(10)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")


def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pad_label(label, width=12):
    return label + " " * max(0, width - len(label))


os.makedirs(OUTPUT_DIR, exist_ok=True)

# Port tambahan yang di-scan selain 443
EXTRA_PORTS = [8443, 2053, 2083, 2087, 2096, 444, 777, 80, 8080, 22, 109, 143, 442]


def fetch(url, timeout=15, retries=3):
    last_err = ""
    for attempt in range(retries):
        try:
            response = curl_requests.get(url, headers=HEADERS_WITHOUT_COMPRESSION, timeout=timeout, impersonate="chrome152")
            if response.status_code >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            if response.status_code >= 400:
                return f"HTTP_ERROR_{response.status_code}"
            return response.text
        except curl_requests.errors.RequestsError as e:
            last_err = f"URL_ERROR_{e}"
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return last_err
        except Exception as e:
            last_err = f"ERR_{type(e).__name__}"
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return last_err
    return last_err


def crt_sh(domain):
    """Ambil subdomain dari Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    result = fetch(url)
    if result == "HTTP_ERROR_404":
        return set(), None
    if result.startswith("HTTP_ERROR_5"):
        return set(), None
    if result.startswith(("HTTP_ERROR_", "URL_ERROR_", "ERR_")):
        return set(), f"crt.sh gagal: {result}"
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


def wordlist_fallback(domain):
    """Fallback: daftar subdomain umum yang resolve ke IP."""
    common = "www mail ftp api dev test staging blog shop cdn vpn ssh ns1 ns2 mx app web portal admin vpn2 test2 beta mobile client dashboard webmail dev2 test3 demo new old backup store m store2 cdn2 img media static files assets help support docs forum news wiki git svn cvn shop2 store3 blog2 news2 app2 mobile2 vpn3 ns3 mx2 remote vpn1 vpn4 vpn5 ns4 ns5 mx3 mx4 mx5 pop imap smtp autodiscover owa exchange sharepoint teams zoom meet chat talk voice fax print printer nas backup1 backup2 db database mysql postgres redis cache search elastic kibana grafana prometheus alerta monitoring nagios zabbix jenkins ci cd pipeline gitlab github bitbucket jira confluence redmine mantis bugzilla phpmyadmin adminer pgadmin robomongo mongo-express kibana logstash filebeat metricbeat packetbeat audit logs log syslog monitor stats status health ping uptime speed speedtest test1 test2 test3 dev dev1 dev3 stage staging1 staging2 prod production live www1 www2 www3 www4 www5 web1 web2 web3 web4 web5 app1 app2 app3 app4 app5 api1 api2 api3 api4 api5 v1 v2 v3 v4 v5 beta1 beta2 alpha gamma delta omega demo1 demo2 demo3 trial trial1 trial2 preview pre preprod uat qa qc quality sandbox sandbox1 sandbox2 devbox devbox1 build build1 ci1 cd1 deploy deploy1 release releases stable unstable nightly weekly monthly yearly annual archive archives old new latest current trunk master main head branch tag version versions update updates patch patches hotfix hotfix1 hotfix2 fix fixes bug bugs issue issues ticket tickets helpdesk support1 support2 care customer clients users user member members account accounts profile profiles login signin signup register registration register2 auth oauth sso saml ldap active directory ad dc dns dns1 dns2 dns3 ns3 ns4 ns5 mx1 mx2 mx3 mx4 mx5 smtp1 smtp2 pop1 pop2 pop3 imap1 imap2 webmail1 webmail2 mail1 mail2 mail3 mail4 mail5 mx imap pop smtp ftp1 ftp2 sftp ssh1 ssh2 git1 git2 svn1 cvs hg bzr docker registry harbor nexus artifactory maven gradle npm yarn pypi cp"
    subs = set()
    for sub in common.split():
        host = f"{sub}.{domain}"
        if resolve_ip(host):
            subs.add(host)
    return subs, None


def resolve_ip(host, timeout=5):
    result = [None]
    def _resolve():
        try:
            result[0] = socket.gethostbyname(host)
        except Exception:
            result[0] = None
    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None
    return result[0]


def tls_handshake(ip, sni_host, port=443, timeout=8):
    """TLS handshake dengan SNI. Koneksi ke IP, SNI nama host dikirim di handshake.
    Return (tls_version, alpn, success, elapsed_ms).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1'])

        start = time.time()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                elapsed_ms = int((time.time() - start) * 1000)
                tls_version = ssock.version()
                alpn = ssock.selected_alpn_protocol() or '-'
                return tls_version, alpn, True, elapsed_ms
    except Exception:
        return '-', '-', False, 0


def scan_port(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def scan_extra_ports(ip):
    return scan_ports(ip, EXTRA_PORTS, timeout=2)


def process_host(sub):
    """Proses satu SNI host: resolve IP, TLS handshake ke IP dengan SNI, scan port lain.
    Return dict: {sni_host, ip, response_time_ms, tls_version, alpn, tls_port, extra_ports, status}.
    """
    ip = resolve_ip(sub)
    if not ip:
        return {
            "sni_host": sub,
            "ip": "-",
            "response_time_ms": 0,
            "tls_version": "-",
            "alpn": "-",
            "tls_port": "-",
            "extra_ports": [],
            "status": "-",
            "cdn": "-",
        }

    status = get_http_status_multi(ip, timeout=5)
    cdn = detect_cdn(ip, host=sub)

    tls, alpn, ok, elapsed_ms = tls_handshake(ip, sub)
    if not ok:
        return {
            "sni_host": sub,
            "ip": ip,
            "response_time_ms": elapsed_ms,
            "tls_version": "-",
            "alpn": "-",
            "tls_port": "-",
            "extra_ports": [],
            "status": status,
            "cdn": cdn,
        }

    extra = scan_extra_ports(ip)

    return {
        "sni_host": sub,
        "ip": ip,
        "response_time_ms": elapsed_ms,
        "tls_version": tls,
        "alpn": alpn,
        "tls_port": "443",
        "extra_ports": extra,
        "status": status,
        "cdn": cdn,
    }


def enumerate_hosts(domain, progress_callback=None, stop_event=None):
    """Enumerasi SNI host untuk domain, return (results, errors).
    progress_callback: fungsi dipanggil dengan (current, total) setelah setiap host selesai diproses.
    stop_event: threading.Event; jika di-set, loop scan akan dihentikan secepatnya.
    """
    if not validate_domain(domain):
        return [], [f"Domain tidak valid: {domain}"]

    errors = []
    subs = set()

    s, err = crt_sh(domain)
    if s:
        subs |= s
    if err:
        errors.append(f"crt.sh: {err}")

    # Fallback ke wordlist hanya jika crt.sh tidak mengembalikan hasil
    if not subs:
        s2, err2 = wordlist_fallback(domain)
        if s2:
            subs |= s2
        if err2:
            errors.append(f"wordlist: {err2}")

    if not subs:
        return [], errors

    # Bersihkan wildcard (*.domain) dari hasil enumerasi
    subs = {n[2:] if n.startswith("*.") else n for n in subs}
    subs = {n for n in subs if n and "*" not in n}

    sorted_subs = sorted(subs)
    results = []

    if progress_callback and sorted_subs:
        progress_callback(0, len(sorted_subs))

    with ThreadPoolExecutor(max_workers=min(20, len(sorted_subs))) as executor:
        futures = {executor.submit(process_host, sub): sub for sub in sorted_subs}
        pending = set(futures.keys())

        while pending:
            done, pending = wait(pending, timeout=2, return_when=FIRST_COMPLETED)
            if not done:
                # Tidak ada host selesai dalam 2s: jangan tandai gagal, lanjut loop.
                # Host yang benar-benar macet akan selesai saat timeout socket (5-8s).
                pass
            for future in done:
                sub = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    results.append({
                        "sni_host": sub, "ip": "-", "response_time_ms": 0,
                        "tls_version": "-", "alpn": "-", "tls_port": "-",
                        "extra_ports": [], "status": "-", "cdn": "-",
                    })
                if progress_callback:
                    progress_callback(len(results), len(sorted_subs))

            # Cek stop_event setelah setiap batch selesai diproses
            if stop_event and stop_event.is_set():
                for f in list(pending):
                    f.cancel()
                try:
                    executor.shutdown(wait=False)
                except Exception:
                    pass
                break

    results.sort(key=lambda x: x["sni_host"])
    return results, errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sniscan.py <domain>")
        print("Example: python3 sniscan.py instagram.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()
    if not validate_domain(domain):
        print(f"Domain tidak valid: {domain}")
        sys.exit(1)
    blocked, kata = is_blocked(domain)
    if blocked:
        print(blocked_message(domain, kata))
        sys.exit(1)

    print(f"═══ SNISCAN (TLS HANDSHAKE & MULTI-PORT): {domain} ═══")
    print()

    start_time = time.time()
    spinner_idx = [0]

    def progress_callback(current, total):
        spinner_idx[0] += 1
        line = build_progress_text(
            spinner_idx[0], "SNIScan", domain, current, total, start_time,
            filled_char="█", empty_char="░", width=10, label_prefix="Scanning"
        )
        print(f"\r{line}", end="")

    results, errors = enumerate_hosts(domain, progress_callback=progress_callback)
    print()  # baris baru setelah progres selesai
    print()  # baris kosong pemisah

    if errors:
        print(f"[!] Provider gagal: {'; '.join(errors)}")

    if not results:
        print("\nTidak ada SNI host yang ditemukan.")
        sys.exit(0)

    # Output teks format opsi B: blok key-value per SNI host
    for r in results:
        extra_str = ",".join(str(p) for p in r["extra_ports"]) if r["extra_ports"] else "-"
        print(f"{pad_label('SNI Host', 12)}: {esc(r['sni_host'])}")
        print(f"{pad_label('Direct IP', 12)}: {esc(r['ip'])} ({r['response_time_ms']}ms)")
        print(f"{pad_label('TLS/ALPN', 12)}: {esc(r['tls_version'])} | ALPN: {esc(r['alpn'])}")
        print(f"{pad_label('Port TLS', 12)}: {esc(r['tls_port'])}({esc(r['tls_version'])})")
        print(f"{pad_label('Port Lain', 12)}: {esc(extra_str)}")
        print(f"{pad_label('CDN', 12)}: {esc(r['cdn'])}")
        print("----------------------------------------------")

    # Simpan teks
    fname = f"{OUTPUT_DIR}/sniscan_{domain}.txt"
    with open(fname, 'w') as f:
        f.write(f"═══ SNISCAN (TLS HANDSHAKE & MULTI-PORT): {domain} ═══\n\n")
        for r in results:
            extra_str = ",".join(str(p) for p in r["extra_ports"]) if r["extra_ports"] else "-"
            f.write(f"{pad_label('SNI Host', 12)}: {esc(r['sni_host'])}\n")
            f.write(f"{pad_label('Direct IP', 12)}: {esc(r['ip'])} ({r['response_time_ms']}ms)\n")
            f.write(f"{pad_label('TLS/ALPN', 12)}: {esc(r['tls_version'])} | ALPN: {esc(r['alpn'])}\n")
            f.write(f"{pad_label('Port TLS', 12)}: {esc(r['tls_port'])}({esc(r['tls_version'])})\n")
            f.write(f"{pad_label('Port Lain', 12)}: {esc(extra_str)}\n")
            f.write(f"{pad_label('CDN', 12)}: {esc(r['cdn'])}\n")
            f.write("----------------------------------------------\n")

    # Simpan JSON dengan metadata
    jname = f"{OUTPUT_DIR}/sniscan_{domain}.json"
    json_data = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "total": len(results),
        "results": [
            {
                "sni_host": r["sni_host"],
                "ip": r["ip"],
                "response_time_ms": r["response_time_ms"],
                "tls_version": r["tls_version"],
                "alpn": r["alpn"],
                "tls_port": r["tls_port"],
                "extra_ports": r["extra_ports"],
                "status": r.get("status", "-"),
                "cdn": r["cdn"],
            }
            for r in results
        ],
    }
    try:
        with open(jname, 'w') as f:
            json.dump(json_data, f, indent=2)
    except Exception as e:
        print(f"[!] Gagal menyimpan JSON: {e}")

    print()
    print("Selesai.")


if __name__ == '__main__':
    main()
