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

## Struktur Repo

```
/root/subfind/
├── cdnscan.py        # Scanner rentang IP + deteksi CDN + status HTTP
├── subfind.py        # Subdomain finder + IP + CDN
├── d2ip.sh           # Resolver domain ke IP
├── .gitignore        # output/ dan __pycache__ diabaikan Git
├── output/           # Hasil scan (disimpan di sini, tidak di-commit)
│   └── cdnscan_*.txt / .json
└── README.md         # Dokumentasi ini
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
- `output/cdnscan_<cidr>.txt` — Tabel pipe-delimited: `ip|ports|cdn|status`
- `output/cdnscan_<cidr>.json` — JSON array dengan kunci `ip`, `ports`, `cdn`, `status`

**Contoh output teks:**
```
IP          PORTS  CDN        STATUS
-------------------------------------------
1.1.1.1     80,443 Cloudflare 200
1.1.1.2     80,443 Cloudflare 200
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

### 3. d2ip.sh — Resolver Domain ke IP

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
├── states/
│   └── cdnscan_104_16_0_0_24.json
└── ipranges/
    ├── cloudflare.json
    └── cloudfront.json
```

- `output/cdnscan_*.txt` — Hasil scan dalam format teks
- `output/cdnscan_*.json` — Hasil scan dalam format JSON
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
