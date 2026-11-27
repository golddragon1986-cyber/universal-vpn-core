"""Focused checks for the TRANSIT template and bounded DNS answer cache."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


PANEL = Path(__file__).resolve().parents[1] / 'vendor' / 'panel'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, PANEL / 'panel' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_name(packet, offset):
    while packet[offset]:
        if packet[offset] & 0xc0 == 0xc0:
            return '', offset + 2
        offset += packet[offset] + 1
    return '', offset + 1


sys.modules['dns_panel'] = types.SimpleNamespace(read_name=read_name)
cache = load('dns_response_cache', 'dns_response_cache.py')
transit = load('transit_mode', 'transit_mode.py')


def packet(ident, ttl=30, flags=0x8180):
    question = b'\x01a\x04test\x00\x00\x01\x00\x01'
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4) + b'\x01\x02\x03\x04'
    return struct.pack('!6H', ident, flags, 1, 1, 0, 0) + question + answer


def query(ident):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + b'\x01a\x04test\x00\x00\x01\x00\x01'


class CacheTests(unittest.TestCase):
    def setUp(self):
        cache.clear()

    def test_transaction_and_ttl(self):
        original = packet(1)
        query = packet(2)
        with patch.object(cache.time, 'monotonic', return_value=100):
            cache.put(('TRANSIT', b'a'), original)
        with patch.object(cache.time, 'monotonic', return_value=102.2):
            reply = cache.get(('TRANSIT', b'a'), query)
        self.assertEqual(struct.unpack_from('!H', reply)[0], 2)
        self.assertEqual(struct.unpack_from('!I', reply, len(reply) - 10)[0], 28)
        self.assertIsNone(cache.get(('DIRECT', b'a'), query))

    def test_expiry_and_invalid_response(self):
        query = packet(2)
        with patch.object(cache.time, 'monotonic', return_value=100):
            cache.put('short', packet(1, ttl=1))
            cache.put('negative', packet(1, flags=0x8183))
        with patch.object(cache.time, 'monotonic', return_value=102):
            self.assertIsNone(cache.get('short', query))
        self.assertIsNone(cache.get('negative', query))

    def test_forwarder_reuses_answer_only_for_same_route(self):
        calls = []
        dns = types.SimpleNamespace(
            read_name=read_name,
            read_settings=lambda: {'servers': [{'enabled': True, 'name': 'test',
                                                 'address': '1.1.1.1', 'route': 'DIRECT'}]},
            bootstrap_servers=lambda _values: [],
            exchange=lambda _server, _name, _qtype, **kwargs: (
                calls.append(kwargs.get('routed')) or packet(struct.unpack_from('!H', kwargs['request'])[0])),
            receive=lambda *_args: b'')
        zones = types.SimpleNamespace(match=lambda _name: None)
        with patch.dict(sys.modules, dns_panel=dns, dns_response_cache=cache,
                        local_dns_zones=zones):
            forwarder = load('dns_forwarder', 'dns_forwarder.py')
            self.assertEqual(forwarder.resolve(query(1), 'TRANSIT')[:2], b'\x00\x01')
            self.assertEqual(forwarder.resolve(query(2), 'TRANSIT')[:2], b'\x00\x02')
            self.assertEqual(forwarder.resolve(query(3), 'DIRECT')[:2], b'\x00\x03')
        self.assertEqual(calls, ['TRANSIT', 'DIRECT'])


class TransitTests(unittest.TestCase):
    def test_unmatched_capture_uses_main_route_and_restores_direct(self):
        source = (PANEL / 'default-config.yaml').read_text(encoding='utf-8')
        with patch.object(transit, 'active', return_value=True):
            captured = transit.with_fallback(source)
            self.assertIn('  - MATCH,SELECTOR # TRANSIT-FALLBACK\n', captured)
            self.assertEqual(transit.with_fallback(captured), captured)
        with patch.object(transit, 'active', return_value=False):
            self.assertEqual(transit.with_fallback(captured), source)

    def test_main_and_standalone_rule_enable_capture(self):
        routing = types.SimpleNamespace(read_settings=lambda: {
            'main_proxy': 'DIRECT', 'services_enabled': True})
        services = types.SimpleNamespace(read_services=lambda: [
            {'enabled': True, 'target': 'TRANSIT'}])
        with patch.dict(sys.modules, routing_panel=routing, service_routes_panel=services):
            self.assertTrue(transit.active())
            routing.read_settings = lambda: {'main_proxy': 'TRANSIT', 'services_enabled': False}
            self.assertTrue(transit.active())
            routing.read_settings = lambda: {'main_proxy': 'DIRECT', 'services_enabled': False}
            self.assertFalse(transit.active())

    def test_template_upgrade_is_idempotent(self):
        source = (PANEL / 'default-config.yaml').read_text(encoding='utf-8')
        legacy = source.replace('      - TRANSIT\n', '', 1).replace(
            '  - name: TRANSIT\n    type: select\n    proxies:\n      - DIRECT\n', '', 1)
        upgraded = transit.with_group(legacy)
        self.assertEqual(upgraded.count('  - name: TRANSIT\n'), 1)
        self.assertEqual(transit.with_group(upgraded), upgraded)

    def test_sniffer_only_when_transit_active(self):
        source = (PANEL / 'default-config.yaml').read_text(encoding='utf-8')
        with patch.object(transit, 'sniffer_active', return_value=True):
            enabled = transit.with_sniffer(source)
            self.assertIn('force-dns-mapping: true', enabled)
            self.assertEqual(transit.with_sniffer(enabled), enabled)
        with patch.object(transit, 'sniffer_active', return_value=False):
            self.assertEqual(transit.with_sniffer(enabled), source)

    def test_client_transit_enables_sniffer_without_global_capture(self):
        clients = types.SimpleNamespace(read=lambda: [
            {'enabled': True, 'route': 'TRANSIT'}])
        with patch.object(transit, 'active', return_value=False), \
             patch.dict(sys.modules, client_policy=clients):
            self.assertTrue(transit.sniffer_active())

    def test_mihomo_accepts_transit_config(self):
        candidate = Path('/etc/mihomo/default_config_candidate.yaml')
        if not candidate.exists(): self.skipTest('No live Mihomo candidate')
        with patch.object(transit, 'sniffer_active', return_value=True):
            config = transit.with_sniffer(transit.with_group(candidate.read_text()))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'transit.yaml'
            path.write_text(config)
            result = subprocess.run(['mihomo', '-t', '-d', '/etc/mihomo', '-f', str(path)],
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-1600:])


if __name__ == '__main__':
    unittest.main()
