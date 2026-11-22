# Subfind — Subdomain & CDN Scanner Toolkit

Toolkit CLI dan Telegram Bot untuk pemetaan subdomain, deteksi layanan CDN, pemindaian rentang IP, dan resolusi domain ke SNI. Dibangun untuk analisis jaringan, deteksi infrastruktur, dan audit keamanan pada aset milik sendiri.

## Fitur Utama

| Fitur | Deskripsi |
|-------|-----------|
| **SubFind** | Enumerasi subdomain via crt.sh dengan fallback HackerTarget + wordlist, deteksi IP, port, status HTTP, dan CDN |
| **CDNScan** | Pemindaian rentang IP/CIDR dengan deteksi CDN (Cloudflare, CloudFront, dst.) dan status HTTP, dukungan resume per rentang |
| **SNIScan** | Pencarian host SNI via TLS handshake, deteksi versi TLS/ALPN, dan pemindaian port tambahan |
| **D2IP** | Resolve domain ke IP melalui socket dan multiple resolver |
| **Telegram Bot** | Antarmuka inline untuk semua fitur di atas dengan pagination dan filter hasil |
| **Filter NSFW** | Pemblokir domain yang mengandung kata kunci tidak pantas sebelum scan dimulai (CLI dan Bot) |

## Struktur Repositori

```
/root/subfind/
├── bot/                    # Telegram Bot (D2IP / SubFind / CDNScan / SNIScan)
│   ├── main.py             # Bot Telegram dengan menu inline dan pagination
│   ├── __init__.py
│   ├── .env.example        # Contoh variabel lingkungan
│   ├── requirements.txt
│   └── setup_profile*.py
├── cdnscan.py              # Scanner rentang IP + deteksi CDN + status HTTP
├── common/                 # Modul bersama
│   ├── __init__.py
│   ├── validators.py       # Validasi domain terpusat
│   ├── nsfw_filter.py      # Filter domain tidak pantas (NSFW)
│   ├── nsfw_blocklist.txt  # Daftar kata kunci blokir manual
│   ├── nsfw_blocklist_shallalist.txt  # Daftar blokir dari Shallalist (835 ribu domain)
│   ├── http_status.py      # Utilitas pemeriksaan status HTTP
│   └── progress.py         # Utilitas progres spinner dan ETA
├── d2ip.sh                 # Resolver domain ke IP
├── sniscan.py              # SNI Host Scanner + TLS Detector + Multi-Port Scan
├── subfind.py              # Subdomain Finder + IP + CDN
├── update_nsfw_blocklist.py# Skrip update daftar blokir dari Shallalist mirror
├── .gitignore
├── requirements.txt
└── README.md
```

## Persyaratan

- Python 3 (bawaan sistem)
- Akses internet (untuk crt.sh, HackerTarget, dan fetch IP range provider)
- Tidak diperlukan `pip install` — semua modul menggunakan standar library Python

## Instalasi

```bash
git clone https://github.com/valvatacea/subfind.git
cd subfind
chmod +x d2ip.sh
```

## Penggunaan CLI

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
| `--limit` | `-l N` | Batas IP per scan (maksimal 1000) |
| `--delay` | `-d SEC` | Jeda antar IP dalam detik (default 0.5) |
| `--format` | `-f` | Format output: `txt`, `json`, atau `both` (default: `both`) |
| `--yes` | `-y` | Konfirmasi otomatis semua prompt |

**Output:** `output/cdnscan_<cidr>.txt` dan `.json`

### 2. subfind.py — Subdomain Finder + IP + CDN

```bash
python3 subfind.py <domain>
```

**Contoh:**
```bash
python3 subfind.py example.com
```

Fitur:
- Enumerasi subdomain dari crt.sh dengan fallback HackerTarget + wordlist
- Deteksi IP, port, status HTTP, dan CDN per subdomain
- Threading untuk pemrosesan paralel
- Export ke format JSON
- Validasi domain melalui `common/validators.py`

**Output:** `output/subfind_<domain>.txt` dan `.json`

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
- Simpan hasil ke JSON dengan metadata target

**Output:** `output/sniscan_<domain>.txt` dan `.json`

### 4. d2ip.sh — Resolver Domain ke IP

```bash
./d2ip.sh <domain>
```

**Contoh:**
```bash
./d2ip.sh example.com
```

Mengubah nama domain menjadi alamat IP melalui socket dan multiple resolver.

## Filter NSFW (Domain Tidak Pantas)

Sebelum scan dimulai, domain dicek terhadap daftar blokir kata kunci tidak pantas. Jika terdeteksi, scan dibatalkan dan pesan peringatan ditampilkan.

**File blokir:**
- `common/nsfw_blocklist.txt` — daftar kata kunci manual (dapat diedit)
- `common/nsfw_blocklist_shallalist.txt` — daftar domain dari Shallalist (835 ribu entri)

**Mengupdate daftar Shallalist:**
```bash
python3 common/update_nsfw_blocklist.py
```

Filter aktif pada semua mode input domain: `subfind`, `sniscan`, `d2ip` (CLI dan Telegram Bot).

## Telegram Bot

Bot Telegram tersedia di folder `bot/`. Jalankan dari root repositori:

```bash
python3 -m bot.main
```

**Persyaratan bot:**
- Buat `.env` di folder `bot/` dengan isi:
  ```
  BOT_TOKEN=token_bot_anda
  ```
- Install dependensi:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r bot/requirements.txt
  ```

**Fitur bot:**
- Menu inline untuk D2IP, SubFind, CDNScan, SNIScan
- Pagination hasil scan (Prev / Next)
- Filter hasil berdasarkan field tertentu (status, port, IP, CDN, dsb.)
- Filter NSFW otomatis sebelum scan
- Riwayat scan per domain

## Fitur Resume (Lanjutkan Scan)

Setiap rentang yang discan disimpan state-nya di `output/states/<cidr>.json`. Jika scan dibatalkan (Ctrl+C) atau dihentikan, jalankan lagi perintah yang sama — skrip akan melanjutkan dari IP yang belum dipindai.

**Contoh alur resume:**
```
Run 1: cdnscan.py 104.16.0.0/24 -l 500   → scan 500 IP pertama, simpan state
Run 2: cdnscan.py 104.16.0.0/24           → lanjut dari IP ke-501
Run 3: cdnscan.py 104.16.0.0/24           → skip semua jika sudah selesai
```

## Rate Limiting & Keamanan

- Default jeda 0,5 detik antar IP (dapat diubah via `-d`)
- Maksimal 1000 IP per batch (dapat diubah via `-l`)
- Untuk rentang besar, gunakan batch kecil dan jalankan berkali-kali agar tidak dianggap port scan serangan oleh firewall target

**Peringatan Etis:** Hanya scan jaringan yang Anda miliki atau yang telah Anda peroleh izin tertulis. Scanning port tanpa izin dapat melanggar Kebijakan Layanan (ToS) dan hukum setempat. Gunakan hanya pada aset yang Anda miliki.

## Output & Folder

Semua hasil disimpan di folder `output/` (tidak di-commit ke Git karena sudah ada di `.gitignore`):

```
output/
├── cdnscan_<cidr>.txt / .json
├── subfind_<domain>.txt / .json
├── sniscan_<domain>.txt / .json
├── states/
│   └── cdnscan_<cidr>.json          # State progres resume per rentang
└── ipranges/
    ├── cloudflare.json
    └── cloudfront.json              # Cache IP range provider (7 hari)
```

## Lisensi

Proprietari / Internal — untuk penggunaan pribadi dan bisnis terkait jasa VPN/SSH/OTP.

Repo: [valvatacea/subfind](https://github.com/valvatacea/subfind) (private)
