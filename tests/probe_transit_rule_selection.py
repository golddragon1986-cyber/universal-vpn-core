"""Probe 30k-rule selection with a second Mihomo instance, without LAN routing."""
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import types
from unittest.mock import patch

sys.path.insert(0, '/etc/mihomo/rules')
import network_priority
import router_routes
import transit_mode


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def replace_one(text, pattern, replacement):
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1: raise AssertionError(pattern)
    return updated


base = Path('/etc/mihomo/default_config_candidate.yaml').read_text()
base = base.replace('  - MATCH,SELECTOR # TRANSIT-FALLBACK\n', '  - MATCH,DIRECT\n')
prefixes = [f'11.{(i * 2) >> 8}.{(i * 2) & 255}.0/24' for i in range(29999)]
prefixes.append('198.51.100.0/24')
service = {'name': 'TRANSIT-probe', 'target': 'TRANSIT', 'enabled': True, 'networks': prefixes}
stubs = {
    'service_routes_panel': types.SimpleNamespace(read_services=lambda: [service]),
    'routes_table_ui': types.SimpleNamespace(service_networks=lambda item: item['networks']),
    'routing_panel': types.SimpleNamespace(read_settings=lambda: {
        'main_proxy': 'LOADBALANCE', 'services_enabled': True}),
}

with tempfile.TemporaryDirectory(prefix='.transit-probe-', dir='/etc/mihomo/rules') as folder:
    folder = Path(folder)
    with patch.object(network_priority, 'ROOT', folder), \
         patch.object(router_routes, 'read_targets', return_value={}), \
         patch.dict(sys.modules, stubs):
        config = network_priority.apply(transit_mode.with_fallback(base))
        config = router_routes.with_service_tun_routes(config, base)
    mixed, dns, controller = (free_port() for _ in range(3))
    config = replace_one(config, r'^mixed-port: \d+$', f'mixed-port: {mixed}')
    config = replace_one(config, r'^external-controller: .+$',
                         f'external-controller: 127.0.0.1:{controller}')
    config = replace_one(config, r'^bind-address: .+$', 'bind-address: 127.0.0.1')
    config = replace_one(config, r'^allow-lan: .+$', 'allow-lan: false')
    config = replace_one(config, r'^log-level: .+$', 'log-level: debug')
    config = replace_one(config, r'^  listen: 0\.0\.0\.0:53$', f'  listen: 127.0.0.1:{dns}')
    tun_match = re.search(r'(?ms)^tun:\n.*?(?=^[a-z][\w-]*:|\Z)', config)
    if not tun_match:
        raise AssertionError('tun block missing')
    tun = tun_match.group()
    tun = replace_one(tun, r'^  enable: (?:true|false)$', '  enable: false')
    tun = replace_one(tun, r'^  auto-route: true$', '  auto-route: false')
    tun = replace_one(tun, r'^  auto-redirect: true$', '  auto-redirect: false')
    config = config[:tun_match.start()] + tun + config[tun_match.end():]
    config = replace_one(config, r'^  store-selected: true$', '  store-selected: false')
    config = replace_one(config, r'^  store-fake-ip: true$', '  store-fake-ip: false')
    config = replace_one(config, r'^      - DIRECT\n      - LOADBALANCE$',
                         '      - LOADBALANCE\n      - DIRECT')
    config = re.sub(r'(?ms)^listeners:\n.*?(?=^[a-z][\w-]*:|\Z)',
                    'listeners: []\n', config)
    path = folder / 'probe.yaml'
    path.write_text(config)
    validated = subprocess.run(['mihomo', '-t', '-d', '/etc/mihomo', '-f', str(path)],
                               capture_output=True, text=True, timeout=30)
    if validated.returncode:
        raise RuntimeError((validated.stdout + validated.stderr)[-1200:])
    log_path = folder / 'mihomo.log'
    with log_path.open('w+') as log:
        process = subprocess.Popen(['mihomo', '-d', '/etc/mihomo', '-f', str(path)],
                                   stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(('127.0.0.1', mixed), timeout=.3):
                        break
                except OSError:
                    if process.poll() is not None: raise RuntimeError('Mihomo exited before listener')
                    time.sleep(.2)
            else: raise RuntimeError('Mihomo listener did not start')
            time.sleep(2)
            responses = {}
            probes = []
            for address in ('198.51.100.1', '203.0.113.1'):
                sock = socket.create_connection(('127.0.0.1', mixed), timeout=2)
                probes.append(sock)
                sock.settimeout(3)
                sock.sendall((f'CONNECT {address}:80 HTTP/1.1\r\nHost: {address}:80\r\n'
                              'Proxy-Connection: keep-alive\r\n\r\n').encode())
                try: responses[address] = sock.recv(1024).decode(errors='replace')[:100]
                except socket.timeout: responses[address] = 'timeout'
            time.sleep(10)
            for sock in probes:
                sock.close()
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
        log.flush()
        lines = log_path.read_text().splitlines()
    matches = {address: [line for line in lines if address in line]
               for address in ('198.51.100.1', '203.0.113.1')}
    if not any('dial TRANSIT (match RuleSet/' in line
               for line in matches['198.51.100.1']):
        raise AssertionError('in-set address did not select TRANSIT')
    if not any('match Match using SELECTOR[' in line
               for line in matches['203.0.113.1']):
        raise AssertionError('out-of-set address did not select VPN fallback')
    print(json.dumps({'prefixes': len(prefixes), 'mixed_port': mixed,
                      'match_lines': {key: value[-3:] for key, value in matches.items()},
                      'responses': responses,
                      'log_count': len(lines)},
                     ensure_ascii=False))
