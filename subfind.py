#!/usr/bin/env python3
# subfind.py - Cari subdomain otomatis + IP + CDN + scan port + status HTTP
# Penggunaan: python3 subfind.py <domain>

import sys
import os
import re
import socket
import json
import time
import urllib.request
import urllib.error
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime

HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}

# Timeout default untuk semua operasi socket (DNS, connect, vb.)
socket.setdefaulttimeout(10)

# Folder dasar berdasarkan lokasi file ini (seperti worktree repo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Folder khusus cache daftar subdomain per domain
SUBFIND_CACHE_DIR = os.path.join(BASE_DIR, "output", "subfind_cache")
# Regex validasi domain sederhana
DOMAIN_RE = re.compile(r'^(?!\-)[A-Za-z0-9\-]{1,63}(?<!\-)(\.[A-Za-z0-9\-]{1,63}(?<!\-))*\.[A-Za-z]{2,}$')
CACHE_MAX_AGE_SECONDS = 2592000  # 30 hari

# Port umum yang akan di-scan (hanya HTTP dan HTTPS)
COMMON_PORTS = [
    80, 443
]

# Lock untuk print dan counter thread-safe
print_lock = threading.Lock()
completed_lock = threading.Lock()
completed_count = 0

def fetch(url, timeout=15, retries=2) -> str:
    last_err = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            last_err = f"HTTP_ERROR_{e.code}"
            # 5xx bisa dicoba ulang, 4xx langsung gagal
            if 500 <= e.code < 600 and attempt < retries - 1:
                time.sleep(1)
                continue
            return last_err
        except urllib.error.URLError as e:
            # DNS gagal / connection refused ngga akan berubah pada retry
            return f"URL_ERROR_{e.reason}"
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
    open_ports = []
    for port in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
        except Exception:
            pass
        finally:
            if s:
                s.close()
    return ",".join(open_ports) if open_ports else "-"

CF_PREFIXES = (
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

def detect_cdn(ip):
    """Deteksi CDN dari IP range Cloudflare (tanpa HTTP request)"""
    if ip and ip.startswith(CF_PREFIXES):
        return 'Cloudflare (IP range)'
    return '-'

def process_subdomain(sub):
    """Proses satu subdomain: resolve IP, scan port, status HTTP, CDN (sekali request per scheme)"""
    ip = resolve_ip(sub)
    if not ip:
        return (sub, '-', '-', '-', '-')

    ports_str = scan_ports_summary(ip)

    http_status = '-'
    cdn = '-'

    for scheme in ("http", "https"):
        try:
            req = urllib.request.Request(f"{scheme}://{sub}", headers=HEADERS, method="GET")
            with urllib.request.urlopen(req, timeout=6) as r:
                http_status = str(r.status)
                h = str(r.headers).lower()
                if 'cloudflare' in h:
                    cdn = 'Cloudflare'
                elif 'cloudfront' in h:
                    cdn = 'CloudFront'
                elif 'akamai' in h:
                    cdn = 'Akamai'
                elif 'fastly' in h:
                    cdn = 'Fastly'
                elif 'sucuri' in h:
                    cdn = 'Sucuri'
                break
        except urllib.error.HTTPError as e:
            http_status = str(e.code)
            break
        except Exception:
            continue

    # Fallback CDN via IP range
    if cdn == '-':
        cdn = detect_cdn(ip)

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


def enumerate_domain(domain, progress_callback=None):
    """Enumerasi subdomain untuk domain, return (results, errors).
    Digunakan baik oleh CLI main() maupun bot. Tidak mencetak ke stdout.
    Memakai cache per provider (30 hari) seperti CLI asli.
    progress_callback: fungsi dipanggil dengan (current, total) setelah setiap subdomain selesai diproses.
    """
    if not DOMAIN_RE.match(domain):
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
            done, pending = wait(pending, timeout=60, return_when=FIRST_COMPLETED)
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

    results.sort(key=lambda x: x[0])
    return results, errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 subfind.py <domain>")
        print("Example: python3 subfind.py contoh.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()
    if not DOMAIN_RE.match(domain):
        print(f"Domain tidak valid: {domain}")
        sys.exit(1)
    print(f"Scanning: {domain}\n")

    results, errors = enumerate_domain(domain)

    if errors:
        print(f"[!] Provider gagal: {'; '.join(errors)}")

    if not results:
        print("\nTidak ada subdomain yang ditemukan.")
        sys.exit(0)

    total = len(results)

    w_sub, w_ip, w_ports, w_status, w_cdn = calc_widths(results)
    total_width = w_sub + w_ip + w_ports + w_status + w_cdn + 12

    print("\n" + "=" * total_width)
    print(f"{'SUBDOMAIN':<{w_sub}} {'IP':<{w_ip}} {'PORTS':<{w_ports}} {'STATUS':<{w_status}} {'CDN'}")
    print("-" * total_width)
    for sub, ip, ports, status, cdn in results:
        print(f"{sub:<{w_sub}} {ip:<{w_ip}} {ports:<{w_ports}} {status:<{w_status}} {cdn}")

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
