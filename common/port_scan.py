# common/port_scan.py - Deteksi port terbuka bersama
# Digunakan oleh cdnscan.py, subfind.py, dan sniscan.py
import socket

# Daftar port terpadu untuk semua scan (subfind, cdnscan, sniscan)
COMMON_PORTS = [80, 443]


def scan_ports(ip, ports, timeout=1.5):
    """Scan daftar port pada IP, return daftar angka port terbuka.

    Args:
        ip: Alamat IP string.
        ports: List port integer, misal [80, 443].
        timeout: Batas waktu koneksi per port dalam detik.

    Returns:
        List port integer yang terbuka, contoh [80, 443].
    """
    open_ports = []
    for port in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            if s:
                s.close()
    return open_ports
