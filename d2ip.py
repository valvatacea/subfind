#!/usr/bin/env python3
# d2ip.py - Resolve domain ke IP address
# Output dicetak ke layar (stdout), mirip d2ip.py

import sys
import os
import re
import shutil
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.validators import validate_domain
from common.nsfw_filter import is_blocked

if len(sys.argv) < 2:
    print("Usage: d2ip.py <domain>")
    print("Example: d2ip.py google.com")
    sys.exit(1)

DOMAIN = sys.argv[1]

# Validasi domain + filter NSFW (opsional, via Python)
if not validate_domain(DOMAIN):
    print("Domain tidak valid.")
    sys.exit(1)

blocked, kata = is_blocked(DOMAIN)
if blocked:
    print(f"Domain diblokir: {kata}")
    sys.exit(1)

print(f"Domain: {DOMAIN}")
print("")

# Coba dengan dig
if shutil.which("dig"):
    print("=== dig ===")
    subprocess.run(["dig", "+short", DOMAIN])

# Coba dengan host
if shutil.which("host"):
    print("=== host ===")
    out = subprocess.run(["host", DOMAIN], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if re.search(r'has (IPv6 )?address', line):
            parts = line.split()
            if parts:
                print(parts[-1])

# Coba dengan getent (bawaan glibc)
if shutil.which("getent"):
    print("=== getent ===")
    out = subprocess.run(["getent", "hosts", DOMAIN], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        parts = line.split()
        if parts:
            print(parts[0])

# Coba dengan nslookup
if shutil.which("nslookup"):
    print("=== nslookup ===")
    out = subprocess.run(["nslookup", DOMAIN], capture_output=True, text=True)
    first = True
    for line in out.stdout.splitlines():
        if line.startswith("Address:"):
            parts = line.split()
            if len(parts) >= 2:
                if first:
                    first = False
                    continue  # skip baris pertama (DNS server)
                print(parts[1])

print("")
print("Selesai.")
