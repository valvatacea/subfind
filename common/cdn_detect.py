#!/usr/bin/env python3
# common/cdn_detect.py - Deteksi CDN via IP range cache dan header response
# Digunakan oleh cdnscan.py, subfind.py, dan sniscan.py
import os
import json
import ipaddress
import datetime
from curl_cffi import requests as curl_requests

from common.http_status import fetch_headers, HEADERS_WITHOUT_COMPRESSION

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPRANGE_DIR = os.path.join(BASE_DIR, "output", "ipranges")
CACHE_MAX_AGE_SECONDS = 604800  # 7 hari

PROVIDER_URLS = {
    'cloudflare': 'https://www.cloudflare.com/ips-v4',
    'cloudfront': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
}

# Header yang mencurigakan sebagai CDN + nilai yang mengindikasikannya
CDN_HEADER_SIGNATURES = [
    (('cf-ray',), 'Cloudflare'),
    (('server',), 'cloudflare'),
    (('via',), 'cloudfront'),
    (('x-cache',), 'cloudfront'),
    (('server',), 'AkamaiGHost'),
    (('server',), 'fastly'),
]


def get_provider_ips(provider_name, progress_callback=None):
    """Unduh IP range dari provider, simpan cache, return daftar CIDR string."""
    provider_name = provider_name.lower()
    if provider_name not in PROVIDER_URLS:
        return None, f"Provider '{provider_name}' tidak didukung. Tersedia: {', '.join(PROVIDER_URLS.keys())}"

    os.makedirs(IPRANGE_DIR, exist_ok=True)
    cache_file = f"{IPRANGE_DIR}/{provider_name}.json"

    # Cek cache masih valid
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache = json.load(f)
            fetched_at = datetime.datetime.fromisoformat(cache.get('fetched_at', '2000-01-01'))
            age = (datetime.datetime.now() - fetched_at).total_seconds()
            if age < CACHE_MAX_AGE_SECONDS:
                return cache.get('ips', []), None
        except Exception:
            pass  # Cache rusak, fetch ulang

    # Fetch dari provider
    url = PROVIDER_URLS[provider_name]
    try:
        response = curl_requests.get(url, headers=HEADERS_WITHOUT_COMPRESSION, timeout=30, impersonate="chrome152")
        result = response.text
    except Exception as e:
        return None, f"Gagal mengunduh {provider_name}: {e}"

    ips = []
    try:
        if provider_name == 'cloudflare':
            for line in result.splitlines():
                line = line.strip()
                if line:
                    try:
                        ipaddress.ip_network(line, strict=False)
                        ips.append(line)
                    except ValueError:
                        pass
        elif provider_name == 'cloudfront':
            data = json.loads(result)
            for entry in data.get('prefixes', []):
                if entry.get('service') == 'CLOUDFRONT':
                    prefix = entry.get('ip_prefix', '')
                    if prefix:
                        ips.append(prefix)
    except Exception as e:
        return None, f"Gagal memproses data {provider_name}: {e}"

    # Simpan cache
    try:
        cache_data = {
            'fetched_at': datetime.datetime.now().isoformat(),
            'provider': provider_name,
            'ips': ips,
        }
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
    except Exception:
        pass

    return ips, None


def load_cached_ranges(provider_name):
    """Baca daftar CIDR dari cache provider jika masih fresh."""
    provider_name = provider_name.lower()
    cache_file = f"{IPRANGE_DIR}/{provider_name}.json"
    if not os.path.exists(cache_file):
        return []
    try:
        with open(cache_file, 'r') as f:
            cache = json.load(f)
        fetched_at = datetime.datetime.fromisoformat(cache.get('fetched_at', '2000-01-01'))
        age = (datetime.datetime.now() - fetched_at).total_seconds()
        if age < CACHE_MAX_AGE_SECONDS:
            return cache.get('ips', [])
    except Exception:
        pass
    return []


def ip_in_ranges(ip, ranges):
    """Cek apakah IP masuk dalam salah satu CIDR range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def detect_cdn_from_headers(host, port=443, timeout=5):
    """Deteksi CDN dari header response HTTP/HTTPS."""
    for scheme in ('https', 'http'):
        try:
            headers_str, status = fetch_headers(host, port=port, scheme=scheme, timeout=timeout)
            if not headers_str:
                continue
            headers_lower = headers_str.lower()
            for header_keys, cdn_name in CDN_HEADER_SIGNATURES:
                header_key = header_keys[0]
                if header_key in headers_lower:
                    # Cek apakah nilai header mengandung indikator CDN
                    # Ambil baris header yang relevan
                    for line in headers_lower.splitlines():
                        if line.strip().startswith(f"{header_key}:"):
                            header_value = line.split(':', 1)[1].strip()
                            if cdn_name.lower() in header_value:
                                return cdn_name.capitalize()
                            # Untuk cf-ray, via, x-cache: cukup header ada
                            if header_key in ('cf-ray', 'via', 'x-cache'):
                                return cdn_name.capitalize()
        except Exception:
            continue
    return None


def detect_cdn(ip, host=None):
    """Deteksi CDN untuk IP.
    
    Tier 1: Cek IP range cache (cloudflare.json, cloudfront.json) — CIDR exact match
    Tier 2: Jika tidak cocok, cek header response HTTP (Server, cf-ray, via, x-cache)
    Tier 3: Return '-' jika tidak ditemukan
    
    Args:
        ip: IP address string
        host: Nama host untuk header detection (opsional, default = ip)
    """
    if not ip or ip == '-':
        return '-'

    # Tier 1: Cek semua provider yang punya cache
    for provider_name in PROVIDER_URLS:
        ranges = load_cached_ranges(provider_name)
        if ranges and ip_in_ranges(ip, ranges):
            display = 'Cloudflare' if provider_name == 'cloudflare' else 'CloudFront'
            return f'{display} (IP range)'

    # Tier 2: Deteksi via header response
    target_host = host or ip
    result = detect_cdn_from_headers(target_host)
    if result:
        return f'{result} (header)'

    # Tier 3: Tidak ditemukan
    return '-'
