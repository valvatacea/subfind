#!/usr/bin/env python3
"""Reverse DNS (IP -> domain) helper untuk bot."""
import socket
import sys
import os
import json


def validate_ip(ip):
    """Validasi IPv4/IPv6. Return True jika valid."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def reverse_lookup(ip, timeout=5):
    """Lakukan PTR lookup untuk IP. Return (hostnames_list, error_str).

    hostnames_list: list of hostname (bisa kosong).
    error_str: None jika sukses, pesan error jika gagal.
    """
    if not validate_ip(ip):
        return [], "IP tidak valid"

    # Set timeout untuk socket (gethostbyaddr pakai socket internal)
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, socket.timeout, OSError) as e:
            return [], f"Gagal resolve PTR: {e}"
        names = [hostname] + [a for a in (aliaslist or []) if a and a != hostname]
        # dedup
        uniq = []
        seen = set()
        for n in names:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        if not uniq:
            return [], "Tidak ada PTR record"
        return uniq, None
    finally:
        socket.setdefaulttimeout(old_timeout)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 rdns.py <ip>")
        sys.exit(1)
    ip = sys.argv[1].strip()
    names, err = reverse_lookup(ip)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "output")
    os.makedirs(out_dir, exist_ok=True)
    safe = ip.replace(":", "_")
    jname = os.path.join(out_dir, f"rdns_{safe}.json")
    tname = os.path.join(out_dir, f"rdns_{safe}.txt")
    if err:
        print(f"Error: {err}")
        print()
        print("Selesai.")
        data = {"ip": ip, "hostnames": [], "error": err}
    else:
        for n in names:
            print(n)
        print()
        print("Selesai.")
        data = {"ip": ip, "hostnames": names, "error": None}
    try:
        with open(jname, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass
    try:
        with open(tname, "w") as f:
            if err:
                f.write(f"Error: {err}\n")
            else:
                f.write(f"IP: {ip}\n")
                for n in names:
                    f.write(f"{n}\n")
    except Exception:
        pass


if __name__ == "__main__":
    main()
