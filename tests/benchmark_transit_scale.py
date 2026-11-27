"""Offline 30k TRANSIT prefix benchmark; never applies RouterOS or live config.

Run from the panel container, where Mihomo and the mounted configuration exist.
"""
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
import types
from unittest.mock import patch

sys.path.insert(0, '/etc/mihomo/rules')
import router_routes
import network_priority
import client_policy
import transit_mode

candidate = Path('/etc/mihomo/default_config_candidate.yaml').read_text()
candidate = candidate.replace('  - MATCH,SELECTOR # TRANSIT-FALLBACK\n',
                              '  - MATCH,DIRECT\n')
assert candidate.count('  - MATCH,DIRECT\n') == 1, 'Unexpected fallback in live candidate'
original_root = network_priority.ROOT
results = []

with tempfile.TemporaryDirectory(prefix='.transit-scale-', dir='/etc/mihomo/rules') as folder:
    network_priority.ROOT = Path(folder)
    with patch.object(router_routes, 'read_targets', return_value={}):
        for count in (1000, 10000, 30000):
            prefixes = [f'11.{(i * 2) >> 8}.{(i * 2) & 255}.0/24' for i in range(count)]
            service = {'name': 'TRANSIT-scale', 'target': 'TRANSIT',
                       'enabled': True, 'networks': prefixes}
            stubs = {
                'service_routes_panel': types.SimpleNamespace(read_services=lambda: [service]),
                'routes_table_ui': types.SimpleNamespace(service_networks=lambda item: item['networks']),
                'routing_panel': types.SimpleNamespace(read_settings=lambda: {
                    'main_proxy': 'LOADBALANCE', 'services_enabled': True}),
            }
            with patch.dict(sys.modules, stubs):
                start = time.perf_counter()
                config = network_priority.apply(transit_mode.with_fallback(candidate))
                compiled = time.perf_counter() - start
                start = time.perf_counter()
                routed = router_routes.with_service_tun_routes(config, candidate)
                routed_time = time.perf_counter() - start
            provider = json.loads((Path(folder) / 'index.json').read_text())
            assert ',TRANSIT,no-resolve' in provider['rules']
            assert routed.rfind('  - MATCH,SELECTOR # TRANSIT-FALLBACK\n') > routed.find(',TRANSIT,no-resolve')
            if count == 30000:
                class FakeRouter:
                    def __init__(self):
                        self.writes = 0
                        self.rows = {}
                        self.cfg = {'bypass_table': 'uvpn-main-direct'}
                    def routes(self): return []
                    def rules(self): return []
                    def call(self, path, method='GET', data=None):
                        if method == 'GET': return self.rows.get(path, [])
                        if method == 'PUT':
                            self.writes += 1
                            row = {'.id': str(self.writes), **data}
                            self.rows.setdefault(path, []).append(row)
                            return row
                        raise AssertionError((path, method))
                fake = FakeRouter()
                with patch.dict(sys.modules, stubs), \
                     patch.object(router_routes, 'Router', return_value=fake), \
                     patch.object(router_routes, 'configured', return_value=True), \
                     patch.object(router_routes, 'auto_rest', return_value=False), \
                     patch.object(router_routes, 'SERVICE_STATE', Path(folder) / 'service.state'):
                    router_routes.sync_service_routes(set(prefixes))
                assert fake.writes == 0, 'TRANSIT must not create per-prefix RouterOS entries'
                policy = FakeRouter()
                with patch.dict(sys.modules, stubs), \
                     patch.object(router_routes, 'ensure_wan_route'):
                    client_policy.apply(policy, [], {'lists': {'LAN': {'interfaces': ['LAN']}}})
                assert policy.writes < 32, 'Full LAN capture must use constant RouterOS state'
            config_file = Path(folder) / f'candidate-{count}.yaml'
            config_file.write_text(routed)
            start = time.perf_counter()
            checked = subprocess.run(['mihomo', '-t', '-d', '/etc/mihomo', '-f', str(config_file)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, timeout=60)
            parsed = time.perf_counter() - start
            results.append({
                'prefixes': count,
                'provider_format': provider['files'][0].rsplit('.', 1)[-1],
                'compiled_sec': round(compiled, 3),
                'tun_routes_sec': round(routed_time, 3),
                'mihomo_parse_sec': round(parsed, 3),
                'mihomo_parse_rc': checked.returncode,
                'config_bytes': len(routed),
                'tun_prefixes': routed.count('    - 11.'),
                'routeros_writes': fake.writes if count == 30000 else None,
                'routeros_policy_writes': policy.writes if count == 30000 else None,
                'provider_bytes': sum((Path(folder) / name).stat().st_size for name in provider['files']),
                'mihomo_child_peak_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            })
            print(json.dumps(results[-1]), flush=True)
            if checked.returncode:
                print(checked.stdout[-1000:], file=sys.stderr)
                break

network_priority.ROOT = original_root
