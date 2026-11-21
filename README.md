# Subfind — Subdomain & CDN Scanner Toolkit

Kumpulan skrip CLI untuk mencari subdomain, mengubah domain menjadi IP, dan memindai rentang IP untuk deteksi layanan CDN (Content Delivery Network). Cocok untuk analisis jaringan, deteksi infrastruktur CDN, dan audit keamanan pada aset milik sendiri.

## Fitur Utama

| Fitur | Detail |
|-------|--------|
| **Subdomain Finder** | Cari subdomain via crt.sh dengan fallback HackerTarget + wordlist |
| **Port Scan** | Deteksi port terbuka pada setiap subdomain/IP |
| **CDN Detection** | Deteksi otomatis Cloudflare, CloudFront, Akamai, Fastly, Sucuri via header + rentang IP |
| **HTTP Status** | Ambil kode status HTTP (200, 301, 404, 500, dst.) |
| **Resume per Rentang** | Lanjutkan scan dari mana berhenti (state file per rentang) |
| **Anti-Duplikasi** | Tidak akan memindai IP yang sudah ada di file output |
| **Rate Limiting** | Jeda antar IP agar tidak dianggap serangan (default 0,5 detik) |
| **Batas IP per Scan** | Maksimal 3000 IP per batch (dapat diubah) |
| **Output** | Teks (`.txt`) dan JSON (`.json`) di folder `output/` |
| **CLI Args** | Opsi non-interaktif (`-l`, `-d`, `-f`, `-y`) |
| **Validasi Domain** | Validasi domain terpusat di `common/validators.py` |

## Struktur Repo

```
/root/subfind/
├── bot/                    # Telegram bot (D2IP / SubFind / CDNScan / SNIScan)
│   ├── main.py             # Bot Telegram dengan menu inline dan pagination
│   ├── __init__.py
│   ├── .env                # BOT_TOKEN (jangan di-commit)
│   ├── .env.example        # Contoh .env
│   ├── requirements.txt
│   ├── setup_profile.py
│   ├── setup_profile_photo.py
│   └── setup_profile_photo_ptb.py
├── cdnscan.py              # Scanner rentang IP + deteksi CDN + status HTTP
├── common/                 # Modul bersama (validasi domain, dll.)
│   ├── __init__.py
│   └── validators.py       # Fungsi validate_domain()
├── d2ip.sh                 # Resolver domain ke IP
├── .gitignore              # output/, __pycache__, .env, .venv diabaikan Git
├── output/                 # Hasil scan (disimpan di sini, tidak di-commit)
│   └── cdnscan_*.txt / .json
├── sniscan.py              # SNI Host Scanner + TLS Detector + Multi-Port Scan
├── subfind.py              # Subdomain finder + IP + CDN
└── README.md               # Dokumentasi ini
```

## Persyaratan

- Python 3 (bawaan sistem)
- Akses internet (untuk crt.sh, HackerTarget, dan fetch IP range provider)
- Tidak ada `pip install` — semua modul bawaan Python

## Instalasi

```bash
git clone https://github.com/valvatacea/subfind.git
cd subfind
chmod +x d2ip.sh
```

## Penggunaan

### 1. cdnscan.py — Scan Rentang IP & Deteksi CDN

```bash
python3 cdnscan.py <cidr atau range | nama provider>
```

**Contoh manual (CIDR):**
```bash
python3 cdnscan.py 104.16.0.0/24
python3 cdnscan.py 104.16.0.0-104.16.0.255
python3 cdnscan.py 1.1.1.1
```

**Contoh provider:**
```bash
python3 cdnscan.py cloudflare
python3 cdnscan.py cloudfront
```

**Argumen CLI (non-interaktif):**
```bash
python3 cdnscan.py 104.16.0.0/24 -l 500 -d 0.3 -f both -y
```

| Argumen | Pendek | Keterangan |
|---------|--------|------------|
| `target` | (positional) | CIDR, range, IP tunggal, atau nama provider (`cloudflare`/`cloudfront`) |
| `--limit` | `-l N` | Batas IP per scan (maksimal 1000, default 1000) |
| `--delay` | `-d SEC` | Jeda antar IP dalam detik (default 0.5) |
| `--format` | `-f` | Format output: `txt`, `json`, atau `both` (default: `both`) |
| `--yes` | `-y` | Konfirmasi otomatis semua prompt (non-interaktif) |

**Output:**
- `output/cdnscan_<cidr>.txt` — Blok key-value: `IP / PORTS / CDN / STATUS`
- `output/cdnscan_<cidr>.json` — JSON array dengan kunci `ip`, `ports`, `cdn`, `status`, `target`, `provider`

**Contoh output teks:**
```
═══ CDNSCAN: 104.16.0.0/24 ═══

IP          : 104.16.0.1
PORTS       : 80,443
CDN         : Cloudflare
Status      : 200
----------------------------------------------
IP          : 104.16.0.2
PORTS       : 80,443
CDN         : Cloudflare
Status      : 200
```

### 2. subfind.py — Subdomain Finder + IP + CDN

```bash
python3 subfind.py <domain>
```

**Contoh:**
```bash
python3 subfind.py example.com
```

Fitur:
- Cari subdomain dari crt.sh (fallback HackerTarget jika crt.sh gagal/limit)
- Wordlist tambahan untuk subdomain umum
- Threading untuk pemrosesan paralel
- Port scan dan deteksi CDN pada setiap subdomain
- Tampilan progres in-place (update baris yang sama)
- Export ke format JSON
- Validasi domain melalui `common/validators.py`

**Output:**
- `output/subfind_<domain>.txt` — Blok key-value: `Subdomain / IP / PORTS / STATUS / CDN`
- `output/subfind_<domain>.json` — JSON array dengan kunci `subdomain`, `ip`, `ports`, `status`, `cdn`, `target`

### 3. sniscan.py — SNI Host Scanner + TLS Detector + Multi-Port Scan

```bash
python3 sniscan.py <domain>
```

**Contoh:**
```bash
python3 sniscan.py instagram.com
```

Fitur:
- Cari subdomain/SNI host via crt.sh dengan fallback HackerTarget + wordlist
- Resolve IP untuk setiap subdomain
- TLS handshake dengan SNI (deteksi versi TLS dan ALPN)
- Scan port tambahan (8443, 2053, 2083, 2087, 2096, 444, 777, 80, 8080, 22, 109, 143, 442)
- Threading untuk pemrosesan paralel
- Validasi domain melalui `common/validators.py`

**Output:**
- `output/sniscan_<domain>.txt` — Blok key-value: `SNI Host / Direct IP / TLS/ALPN / Port TLS / Port Lain`
- `output/sniscan_<domain>.json` — JSON array dengan kunci `sni_host`, `ip`, `response_time_ms`, `tls_version`, `alpn`, `tls_port`, `extra_ports`, `target`

**Contoh output teks:**
```
═══ SNISCAN (TLS HANDSHAKE & MULTI-PORT): instagram.com ═══

SNI Host    : admin.instagram.com
Direct IP   : 57.144.100.134 (64ms)
TLS/ALPN    : TLSv1.3 | ALPN: h2
Port TLS    : 443(TLSv1.3)
Port Lain   : 80
----------------------------------------------
```

### 4. d2ip.sh — Resolver Domain ke IP

```bash
./d2ip.sh <domain>
```

**Contoh:**
```bash
./d2ip.sh example.com
```

Mengubah nama domain menjadi alamat IP.

## Fitur Resume (Lanjutkan Scan)

Setiap rentang yang discan disimpan state-nya di `output/states/<cidr>.json`. Jika scan dibatalkan (Ctrl+C) atau dihentikan, jalankan lagi perintah yang sama — skrip akan:
1. Membaca berapa IP sudah tersimpan di file output
2. Melewati IP yang sudah dipindai
3. Hanya memindai IP yang belum

**Contoh alur resume:**
```
Run 1: cdnscan.py 104.16.0.0/24 -l 500   → scan 500 IP pertama, simpan state
Run 2: cdnscan.py 104.16.0.0/24           → lanjut dari IP ke-501
Run 3: cdnscan.py 104.16.0.0/24           → skip semua jika sudah selesai
```

## Rate Limiting & Keamanan

- Default jeda `0,5 detik` antar IP (dapat diubah via `-d`)
- Maksimal 1000 IP per batch (dapat diubah via `-l`)
- Untuk rentang besar, gunakan batch kecil dan jalankan berkali-kali agar tidak dianggap port scan serangan oleh firewall target

**Peringatan:** Hanya scan jaringan yang Anda miliki atau yang telah Anda peroleh izin tertulis. Scanning port tanpa izin dapat melanggar Kebijakan Layanan (ToS) dan hukum setempat.

## Output & Folder

Semua hasil disimpan di folder `output/` (tidak di-commit ke Git karena sudah ada di `.gitignore`):

```
output/
├── cdnscan_104_16_0_0_24.txt
├── cdnscan_104_16_0_0_24.json
├── subfind_*.txt
├── subfind_*.json
├── sniscan_*.txt
├── sniscan_*.json
├── states/
│   └── cdnscan_104_16_0_0_24.json
└── ipranges/
    ├── cloudflare.json
    └── cloudfront.json
```

- `output/cdnscan_*.txt` — Hasil scan dalam format teks (blok key-value)
- `output/cdnscan_*.json` — Hasil scan dalam format JSON
- `output/subfind_*.txt` — Hasil scan subdomain dalam format teks (blok key-value)
- `output/subfind_*.json` — Hasil scan subdomain dalam format JSON
- `output/sniscan_*.txt` — Hasil scan SNI dalam format teks (blok key-value)
- `output/sniscan_*.json` — Hasil scan SNI dalam format JSON
- `output/states/*.json` — State progres resume per rentang
- `output/ipranges/*.json` — Cache IP range provider (7 hari)

## Contoh Kerja Lengkap

```bash
# Masuk ke direktori repo
cd /root/subfind

# Scan rentang Cloudflare kecil dengan batas 100 IP
python3 cdnscan.py 173.245.48.0/20 -l 100 -d 0.3 -y

# Lihat hasil
cat output/cdnscan_cloudflare_173_245_48_0_20.txt

# Lanjutkan scan rentang yang sama (resume otomatis)
python3 cdnscan.py cloudflare
# Pilih rentang 173.245.48.0/20, akan lanjut dari mana berhenti
```

## Peringatan Etis

Skrip ini adalah **port scanner dan CDN detector**. Penggunaan terhadap jaringan yang bukan milik Anda tanpa izin dapat:
- Terdeteksi sebagai ancaman oleh IDS/IPS
- Memblokir IP Anda secara permanen
- Melanggar Kebijakan Layanan (ToS) beberapa penyedia cloud

Gunakan hanya pada aset yang Anda miliki atau dengan izin tertulis dari pemilik jaringan.

## Lisensi

Proprietari / Internal — untuk penggunaan pribadi dan bisnis terkait jasa VPN/SSH/OTP.

---

Dibuat untuk kebutuhan deteksi infrastruktur CDN dan pemetaan subdomain.  
Repo: [valvatacea/subfind](https://github.com/valvatacea/subfind) (private)