"""Nonblocking, cached country lookup for VPN server flags."""
import ipaddress
import json
import re
import socket
import threading
import time
import urllib.request
from pathlib import Path

FILE = Path('/etc/mihomo/rules/vpn-country-cache.json')
LOCK = threading.Lock()
PENDING = set()
CACHE = None
MAX_AGE = 7 * 24 * 3600


def _cache():
    global CACHE
    if CACHE is None:
        try: CACHE = json.loads(FILE.read_text())
        except (OSError, ValueError): CACHE = {}
        if not isinstance(CACHE, dict): CACHE = {}
    return CACHE


def _resolve(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        address = next((ipaddress.ip_address(item[4][0]) for item in addresses
                        if ipaddress.ip_address(item[4][0]).is_global), None)
    return str(address) if address and address.is_global else ''


def _fetch(host):
    code = ''
    try:
        address = _resolve(host)
        if address:
            request = urllib.request.Request('https://ipwho.is/' + address,
                                             headers={'User-Agent': 'UniversalVPNCore/1.0'})
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read(8192))
            found = result.get('country_code', '') if result.get('success') else ''
            if re.fullmatch('[A-Z]{2}', found): code = found
    except (OSError, ValueError, KeyError): pass
    with LOCK:
        cache = _cache()
        cache[host] = {'code': code, 'time': time.time()}
        PENDING.discard(host)
        try:
            from durable_io import write
            write(FILE, json.dumps(cache, separators=(',', ':')).encode())
        except OSError: pass


def countries(hosts):
    now = time.time()
    result = {}
    with LOCK:
        cache = _cache()
        for host in set(hosts):
            if not isinstance(host, str) or not 1 <= len(host) <= 253 or not re.fullmatch(r'[A-Za-z0-9.:-]+', host):
                continue
            item = cache.get(host, {})
            if not isinstance(item, dict): item = {}
            age = MAX_AGE if item.get('code') else 300
            if now - item.get('time', 0) < age:
                result[host] = item.get('code', '')
            elif host not in PENDING and len(PENDING) < 8:
                PENDING.add(host)
                threading.Thread(target=_fetch, args=(host,), daemon=True).start()
    return result
