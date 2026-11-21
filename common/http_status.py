# common/http_status.py - Utilitas pemeriksaan status HTTP bersama
# Berisi fungsi untuk mengambil kode status HTTP dari host:port via GET request.
# Tidak berubah tampilan output — hanya mengekstrak duplikasi kode dari
# subfind.py, cdnscan.py, dan sniscan.py.

import urllib.request
import urllib.error


HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}


def get_http_status(host, port=80, scheme="http", timeout=5):
    """Ambil kode status HTTP dari host:port via GET request.

    Args:
        host: Nama domain atau alamat IP (tanpa scheme dan port).
        port: Port tujuan (default 80).
        scheme: Skema URL (default "http", gunakan "https" untuk port 443).
        timeout: Batas waktu dalam detik (default 5).

    Returns:
        String kode status HTTP (misal "200", "404", "500") atau
        "-" jika gagal (koneksi ditolak, timeout, TLS error, dll.).
    """
    url = f"{scheme}://{host}:{port}"
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return str(r.status)
    except urllib.error.HTTPError as e:
        return str(e.code)
    except (urllib.error.URLError, Exception):
        return "-"


def get_http_status_multi(host, timeout=5):
    """Coba HTTP dan HTTPS untuk mendapatkan status HTTP.

    Mencoba HTTP (port 80) terlebih dahulu, lalu HTTPS (port 443) jika
    HTTP gagal. Mengembalikan status code pertama yang sukses.

    Args:
        host: Nama domain atau alamat IP (tanpa scheme dan port).
        timeout: Batas waktu dalam detik per percobaan (default 5).

    Returns:
        String kode status HTTP atau "-" jika keduanya gagal.
    """
    # Coba HTTP terlebih dahulu
    status = get_http_status(host, port=80, scheme="http", timeout=timeout)
    if status != "-":
        return status
    # Coba HTTPS sebagai fallback
    return get_http_status(host, port=443, scheme="https", timeout=timeout)