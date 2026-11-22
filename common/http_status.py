# common/http_status.py - Utilitas pemeriksaan status HTTP bersama
# Berisi fungsi untuk mengambil kode status HTTP dari host:port via GET request.
# Tidak berubah tampilan output — hanya mengekstrak duplikasi kode dari
# subfind.py, cdnscan.py, dan sniscan.py.
from curl_cffi import requests as curl_requests

HEADERS_WITH_COMPRESSION = {
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
}

HEADERS_WITHOUT_COMPRESSION = {
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

# Backward compatibility alias
HEADERS = HEADERS_WITHOUT_COMPRESSION


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
        response = curl_requests.get(url, headers=HEADERS_WITH_COMPRESSION, timeout=timeout, impersonate="chrome120")
        return str(response.status_code)
    except Exception:
        return "-"


def fetch_headers(host, port=80, scheme="http", timeout=5):
    """Ambil header response HTTP dari host:port via GET request.

    Args:
        host: Nama domain atau alamat IP.
        port: Port tujuan (default 80).
        scheme: Skema URL (default "http", gunakan "https" untuk port 443).
        timeout: Batas waktu dalam detik (default 5).

    Returns:
        Tuple (headers_string, status_code) atau ("", None) jika gagal.
    """
    url = f"{scheme}://{host}:{port}/"
    try:
        response = curl_requests.get(url, headers=HEADERS_WITH_COMPRESSION, timeout=timeout, impersonate="chrome120")
        return str(response.headers).lower(), response.status_code
    except Exception:
        return "", None


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
