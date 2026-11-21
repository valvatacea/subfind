#!/usr/bin/env python3
# common/validators.py - Validator yang dapat digunakan oleh semua skrip
# Penggunaan:
#   from common.validators import validate_domain
#   if not validate_domain(domain):
#       print("Domain tidak valid")
import re


def validate_domain(domain):
    """Validasi nama domain.

    Args:
        domain: String nama domain (misal: contoh.com, sub.domain.co.id)

    Returns:
        bool: True jika domain valid, False jika tidak valid
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.lower().strip()
    if not domain:
        return False

    # Panjang maksimal nama domain: 253 karakter
    if len(domain) > 253:
        return False

    # Regex untuk validasi domain:
    # - Tidak boleh dimulai dengan -
    # - Tidak boleh ada strip berturut-turut (--)
    # - Setiap label: 1-63 karakter, huruf, angka, atau -
    # - Setiap label tidak boleh diakhiri dengan -
    # - Minimal satu titik pemisah
    # - TLD minimal 2 karakter
    pattern = r'^(?!-)(?!.*--)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$'
    return bool(re.match(pattern, domain))
