#!/usr/bin/env python3
# subfind.py - Cari subdomain otomatis + IP + CDN + scan port + status HTTP
# Penggunaan: python3 subfind.py <domain>

from curl_cffi import requests as curl_requests

import sys
import os
import re
import socket
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime

from common.validators import validate_domain
from common.nsfw_filter import is_blocked, blocked_message
from common.http_status import get_http_status_multi
from common.progress import build_progress_text
from common.cdn_detect import detect_cdn as detect_cdn_common
from common.port_scan import scan_ports, COMMON_PORTS
from common.http_status import HEADERS_WITHOUT_COMPRESSION


# Timeout default untuk semua operasi socket (DNS, connect, vb.)
socket.setdefaulttimeout(10)

# Folder dasar berdasarkan lokasi file ini (seperti worktree repo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pad_label(label, width=12):
    return label + " " * max(0, width - len(label))

# Folder khusus cache daftar subdomain per domain
SUBFIND_CACHE_DIR = os.path.join(BASE_DIR, "output", "subfind_cache")
# Validasi domain menggunakan common.validators.validate_domain
CACHE_MAX_AGE_SECONDS = 2592000  # 30 hari

# Port diimpor dari common.port_scan (COMMON_PORTS = [80, 443])

# Lock untuk print dan counter thread-safe
print_lock = threading.Lock()
completed_lock = threading.Lock()
completed_count = 0

def fetch(url, timeout=15, retries=2) -> str:
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
        except curl_requests.errors.ConnectTimeout as e:
            return f"URL_ERROR_{e}"
        except curl_requests.errors.ReadTimeout as e:
            return f"URL_ERROR_{e}"
        except curl_requests.errors.ConnectionError as e:
            return f"URL_ERROR_{e}"
        except Exception as e:
            last_err = f"ERR_{type(e).__name__}"
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return last_err
    return last_err

def crt_sh(domain):
    """Ambil subdomain dari Certificate Transparency logs (crt.sh)"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    result = fetch(url)
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
    common = "www mail ftp api dev test staging blog shop cdn vpn ssh ns1 ns2 mx app web portal admin vpn2 test2 beta mobile client dashboard webmail dev2 test3 demo new old backup store m store2 cdn2 img media static files assets help support docs forum news wiki git svn cvn shop2 store3 blog2 news2 app2 mobile2 vpn3 ns3 mx2 remote vpn1 vpn4 vpn5 ns4 ns5 mx3 mx4 mx5 pop imap smtp autodiscover owa exchange sharepoint teams zoom meet chat talk voice fax print printer nas backup1 backup2 db database mysql postgres redis cache search elastic kibana grafana prometheus alerta monitoring nagios zabbix jenkins ci cd pipeline gitlab github bitbucket jira confluence redmine mantis bugzilla phpmyadmin adminer pgadmin robomongo mongo-express kibana logstash filebeat metricbeat packetbeat audit logs log syslog rsyslog monitor stats status health ping uptime speed speedtest test1 test2 test3 dev dev1 dev3 stage staging1 staging2 prod production live www1 www2 www3 www4 www5 web1 web2 web3 web4 web5 app1 app2 app3 app4 app5 api1 api2 api3 api4 api5 v1 v2 v3 v4 v5 beta1 beta2 alpha gamma delta omega demo1 demo2 demo3 trial trial1 trial2 preview pre preprod uat qa qc quality sandbox sandbox1 sandbox2 devbox devbox1 build build1 ci1 cd1 deploy deploy1 release releases stable unstable nightly weekly monthly yearly annual archive archives old new latest current trunk master main head branch tag version versions update updates patch patches hotfix hotfix1 hotfix2 fix fixes bug bugs issue issues ticket tickets helpdesk support1 support2 care customer clients users user member members account accounts profile profiles login signin signup register registration register2 auth oauth sso saml ldap active directory ad dc dns dns1 dns2 dns3 ns3 ns4 ns5 mx1 mx2 mx3 mx4 mx5 smtp1 smtp2 pop1 pop2 pop3 imap1 imap2 webmail1 webmail2 mail1 mail2 mail3 mail4 mail5 mx imap pop smtp ftp1 ftp2 sftp ssh1 ssh2 git1 git2 svn1 cvs hg bzr docker registry harbor nexus artifactory maven gradle npm yarn pypi cpan rubygems nuget chocolatey brew apt yum dnf repo repos repository mirror mirrors download downloads upload uploads files file docs doc documentation wiki1 wiki2 knowledge kb kb1 kb2 faq faqs blog1 blog2 blog3 news1 news2 press release releases media press pr media1 media2 images image img1 img2 img3 img4 img5 video videos stream streaming live live1 live2 stream1 stream2 radio tv video1 video2 audio music mp3 mp4 podcast podcasts shop store store1 store2 store3 cart checkout pay payment payments billing invoice invoices price pricing prices buy sell order orders basket basket1 basket2 shop1 shop2 shop3 market marketplace deal deals coupon coupons discount sale sales promo promos campaign campaigns affiliate affiliates partner partners reseller resellers wholesale retail b2b b2c enterprise corp corporate business company about contact contactus contact-us contact1 contact2 aboutus about-us about1 about2 team teams staff careers jobs job hr human resources legal privacy terms tos eula cookie cookies gdpr compliance audit security secure ssl tls cert certs certificate certificates ca pkcs key keys vpn vpn1 vpn2 vpn3 vpn4 vpn5 remote remote1 remote2 rdp citrix terminal terminal1 terminal2 citrix1 citrix2 wan lan wan1 wan2 lan1 lan2 gateway gw gw1 gw2 router switch switch1 switch2 firewall fw fw1 fw2 ips ids proxy proxies proxy1 proxy2 squid cache caches cdn1 cdn2 cdn3 cdn4 cdn5 edge edges edge1 edge2 origin origins shield shield1 shield2 balance lb lb1 lb2 haproxy nginx apache httpd iis tomcat jetty jboss wildfly glassfish weblogic websphere node node1 node2 node3 python ruby perl php java dotnet csharp go rust swift kotlin scala clojure haskell erlang elixir lisp scheme prolog forth assembly asm c cpp cplus cplusplus objc objective matlab mathematica maple octave scilab r rstudio shiny tableau powerbi bi businessintelligence analytics analytic stats statistics metrics metric monitor monitoring observability observ trace tracing span spans log logs logging event events alert alerts alarm alarms notification notifications message messages queue queues topic topics exchange exchanges binding bindings channel channels stream streams pubsub pub sub consumer consumers producer producers worker workers job jobs cron crontab schedule scheduler task tasks workflow workflows pipeline pipelines ci cd devops devsecops secops sec security sec1 sec2 sec3 soc soc1 soc2 noca noca1 noca2 helpdesk it it1 it2 it3 ops ops1 ops2 sysadmin admin1 admin2 root superuser sudo su user1 user2 user3 user4 user5 guest guests anonymous anon nobody nobody1 nobody2 test testing tests qa qc qc1 qc2 qa1 qa2 uat uat1 uat2 preprod preprod1 preprod2 staging staging1 staging2 staging3 prod prod1 prod2 prod3 production live live1 live2 canary canary1 canary2 blue green blue1 blue2 green1 green2 primary secondary tertiary master slave node1 node2 node3 node4 node5 master1 master2 replica replicas replica1 replica2 replica3 standby standby1 standby2 failover failover1 failover2 dr dr1 dr2 backup backup1 backup2 backup3 archive archives archived vault safe safe1 safe2 secure secure1 secure2 encrypted encrypt decrypt key keys cert certs ssl tls ca pki pki1 pki2 smime pgp gpg dkim spf dmarc dnssec dns1 dns2 dns3 dns4 dns5 resolver resolvers resolver1 resolver2 nslookup dig host whois ip ip1 ip2 ip3 ipv4 ipv6 subnet subnets vlan vlans vlan1 vlan2 vlan3 vlan4 vlan5 mac mac1 mac2 arp arp1 arp2 dhcp dhcp1 dhcp2 pxe pxe1 pxe2 boot boot1 boot2 network networks net net1 net2 net3 intranet extranet internet web web1 web2 web3 web4 web5 site sites page pages homepage index default welcome start home home1 home2 index1 index2 default1 default2 welcome1 welcome2 landing landing1 landing2 splash splash1 splash2 portal portal1 portal2 dashboard1 dashboard2 dashboard3 control control1 control2 panel panel1 panel2 cp cpanel plesk directadmin webmin usermin virtualmin cockpit ansible puppet chef salt terraform packer vagrant docker1 docker2 k8s kube kubectl minikube openshift rancher swarm mesos marathon consul etcd zookeeper kafka rabbitmq activemq zeromq zmq nats nats1 nats2 pulsar pulsar1 pulsar2 redis1 redis2 redis3 redis4 redis5 memcached memcache memcache1 memcache2 mongodb mongo mongo1 mongo2 mongo3 mysql1 mysql2 mysql3 mysql4 mysql5 mariadb mariadb1 mariadb2 postgres1 postgres2 postgres3 postgres4 postgres5 postgresql oracle oracle1 oracle2 mssql mssql1 mssql2 sql sql1 sql2 sqlserver db1 db2 db3 db4 db5 database1 database2 database3 data datas dataset datasets warehouse warehouses lake lakes mart marts bi1 bi2 bi3 olap olap1 olap2 oltp oltp1 oltp2 etl etl1 etl2 elt elt1 elt2 pipeline1 pipeline2 stream1 stream2 stream3 kafka1 kafka2 kafka3 kafka4 kafka5 rabbit1 rabbit2 activemq1 activemq2 zero1 zero2 nats1 nats2 pulsar1 pulsar2"
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


def get_cache_path(domain, provider):
    """Path file cache subdomain per provider per domain di folder khusus."""
    os.makedirs(SUBFIND_CACHE_DIR, exist_ok=True)
    safe = domain.replace('.', '_').replace('/', '_').replace('\\', '_')
    return f"{SUBFIND_CACHE_DIR}/subfind_{safe}_{provider}.json"


def load_cache(domain, provider):
    """Baca cache subdomain per provider dari file tersendiri jika masih fresh (< 7 hari)."""
    path = get_cache_path(domain, provider)
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


def save_cache(domain, provider, subs):
    """Simpan cache subdomain per provider ke file tersendiri."""
    path = get_cache_path(domain, provider)
    try:
        with open(path, 'w') as f:
            json.dump({
                'domain': domain,
                'provider': provider,
                'fetched_at': datetime.now().isoformat(),
                'subdomains': sorted(list(subs))
            }, f, indent=2)
    except Exception:
        pass


def scan_ports_summary(ip, ports=COMMON_PORTS, timeout=1.5):
    """Scan port terbuka pada IP, return daftar angka port saja"""
    open_ports = scan_ports(ip, ports, timeout=timeout)
    return ",".join(str(p) for p in open_ports) if open_ports else "-"

def detect_cdn(ip, host=None):
    """Deteksi CDN dari IP range cache atau header response HTTP.

    Tier 1: Cek IP range cache (cloudflare.json, cloudfront.json) — CIDR exact match
    Tier 2: Jika tidak cocok, cek header response HTTP
    Tier 3: Return '-' jika tidak ditemukan

    Args:
        ip: IP address string
        host: Nama host untuk header detection (opsional, default = ip)
    """
    return detect_cdn_common(ip, host=host)

def process_subdomain(sub):
    """Proses satu subdomain: resolve IP, scan port, status HTTP, CDN (sekali request per scheme)"""
    ip = resolve_ip(sub)
    if not ip:
        return (sub, '-', '-', '-', '-')

    ports_str = scan_ports_summary(ip)

    http_status = get_http_status_multi(sub, timeout=6)
    cdn = detect_cdn(ip, host=sub)

    return (sub, str(ip), ports_str, http_status, cdn)

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


def enumerate_domain(domain, progress_callback=None, stop_event=None):
    """Enumerasi subdomain untuk domain, return (results, errors).
    Digunakan baik oleh CLI main() maupun bot. Tidak mencetak ke stdout.
    Memakai cache per provider (30 hari) seperti CLI asli.
    progress_callback: fungsi dipanggil dengan (current, total) setelah setiap subdomain selesai diproses.
    stop_event: threading.Event; jika di-set, loop scan akan dihentikan secepatnya.
    """
    if not validate_domain(domain):
        return [], [f"Domain tidak valid: {domain}"]

    errors = []
    provider_subs = {
        "crt.sh": set(),
        "hackertarget": set(),
        "wordlist": set(),
    }
    provider_cached = {
        "crt.sh": set(),
        "hackertarget": set(),
        "wordlist": set(),
    }

    # Cek cache per provider
    for provider in provider_subs:
        cached_p = load_cache(domain, provider)
        if cached_p is not None:
            provider_cached[provider] = cached_p

    # 1. crt.sh (selalu fetch)
    s, err = crt_sh(domain)
    provider_subs["crt.sh"] = s if s else set()
    if err:
        errors.append(f"crt.sh: {err}")

    # 2. hackertarget (selalu fetch)
    s, err = hackertarget(domain)
    provider_subs["hackertarget"] = s if s else set()
    if err:
        errors.append(f"hackertarget: {err}")

    # 3. wordlist (selalu fetch)
    s, err = wordlist_fallback(domain)
    provider_subs["wordlist"] = s if s else set()

    # Bandingkan & simpan cache per provider (logika sama dengan CLI asli)
    provider_final = {}
    for provider, fetched in provider_subs.items():
        cached_p = provider_cached[provider]
        if not fetched:
            # Provider gagal fetch, gunakan cache lama jika ada
            provider_final[provider] = cached_p if cached_p is not None else set()
            continue
        if cached_p is not None:
            if fetched == cached_p:
                provider_final[provider] = cached_p
            elif len(fetched) >= len(cached_p):
                save_cache(domain, provider, fetched)
                provider_final[provider] = fetched
            else:
                # Fetch lebih sedikit dari cache, pegang cache lama
                provider_final[provider] = cached_p
        else:
            save_cache(domain, provider, fetched)
            provider_final[provider] = fetched

    # Gabungkan semua provider_final untuk scan
    subs = set()
    for psubs in provider_final.values():
        subs |= psubs

    if not subs:
        return [], errors

    sorted_subs = sorted(subs)
    results = []
    max_workers = min(20, len(sorted_subs))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_subdomain, sub): sub for sub in sorted_subs}
        pending = set(futures.keys())

        while pending:
            done, pending = wait(pending, timeout=5, return_when=FIRST_COMPLETED)
            if not done:
                for future in list(pending):
                    sub = futures[future]
                    results.append((sub, '-', '-', '-', '-'))
                pending.clear()
                break
            for future in done:
                sub = futures[future]
                try:
                    result = future.result()
                except Exception:
                    result = (sub, '-', '-', '-', '-')
                results.append(result)
                if progress_callback:
                    progress_callback(len(results), len(sorted_subs))

            # Cek stop_event setelah setiap batch selesai diproses
            if stop_event and stop_event.is_set():
                break

    results.sort(key=lambda x: x[0])
    return results, errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 subfind.py <domain>")
        print("Example: python3 subfind.py contoh.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()
    if not validate_domain(domain):
        print(f"Domain tidak valid: {domain}")
        sys.exit(1)
    blocked, kata = is_blocked(domain)
    if blocked:
        print(blocked_message(domain, kata))
        sys.exit(1)
    print(f"Scanning: {domain}\n")

    start_time = time.time()
    spinner_idx = [0]

    def progress_callback(current, total):
        spinner_idx[0] += 1
        line = build_progress_text(
            spinner_idx[0], "SubFind", domain, current, total, start_time,
            filled_char="█", empty_char="░", width=10, label_prefix="Scanning"
        )
        print(f"\r{line}", end="")

    results, errors = enumerate_domain(domain, progress_callback=progress_callback)
    print()  # baris baru setelah progres selesai

    if errors:
        print(f"[!] Provider gagal: {'; '.join(errors)}")

    if not results:
        print("\nTidak ada subdomain yang ditemukan.")
        sys.exit(0)

    total = len(results)

    w_sub, w_ip, w_ports, w_status, w_cdn = calc_widths(results)
    total_width = w_sub + w_ip + w_ports + w_status + w_cdn + 12

    print("\n" + "=" * total_width)
    # Output teks ke layar (CLI) - format blok key-value
    for sub, ip, ports, status, cdn in results:
        print(f"{pad_label('Subdomain', 12)}: {sub}")
        print(f"{pad_label('IP', 12)}: {ip}")
        print(f"{pad_label('PORTS', 12)}: {ports}")
        print(f"{pad_label('Status', 12)}: {status}")
        print(f"{pad_label('CDN', 12)}: {cdn}")
        print("----------------------------------------------")

    OUT_DIR = os.path.join(BASE_DIR, "output")
    os.makedirs(OUT_DIR, exist_ok=True)
    fname = f"{OUT_DIR}/subfind_{domain}.txt"
    with open(fname, 'w') as f:
        f.write(f"═══ SUBFIND: {domain} ═══\n\n")
        for sub, ip, ports, status, cdn in results:
            f.write(f"Subdomain   : {sub}\n")
            f.write(f"IP          : {ip}\n")
            f.write(f"PORTS       : {ports}\n")
            f.write(f"Status      : {status}\n")
            f.write(f"CDN         : {cdn}\n")
            f.write("----------------------------------------------\n")

    jname = f"{OUT_DIR}/subfind_{domain}.json"
    json_data = []
    for sub, ip, ports, status, cdn in results:
        json_data.append({
            "subdomain": sub,
            "ip": ip,
            "ports": ports,
            "status": status,
            "cdn": cdn,
            "target": domain
        })
    with open(jname, 'w') as f:
        json.dump(json_data, f, indent=2)

    print(f"\n    Hasil disimpan ke: {fname}")
    print(f"    JSON disimpan ke: {jname}")

if __name__ == '__main__':
    main()
