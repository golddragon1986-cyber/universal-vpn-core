"""Xray JSON subscriptions retain the Mihomo REALITY compatibility setting."""

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

here = Path(__file__).resolve().parent
source = here.parent / 'vendor' / 'panel' / 'panel'
sys.path.insert(0, str(source if source.is_dir() else here))
sys.path.insert(1, str(here.parent))

import vpn_subscriptions


OUTBOUND = {
    'tag': 'server-1', 'protocol': 'vless',
    'settings': {'vnext': [{'address': 'vpn.example', 'port': 443,
                            'users': [{'id': '12345678-1234-1234-1234-123456789abc',
                                       'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
    'streamSettings': {'network': 'raw', 'security': 'reality',
                       'realitySettings': {'serverName': 'example.com',
                                           'fingerprint': 'firefox',
                                           'publicKey': 'test-public-key',
                                           'shortId': 'abcd'}},
}


class RealityCompatTests(unittest.TestCase):
    def test_xray_json_enables_mihomo_hybrid_in_compatible_image(self):
        with patch.dict('os.environ', {'MIHOMO_REALITY_COMPAT': '1'}):
            node = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        self.assertTrue(node['reality-opts']['support-x25519mlkem768'])
        self.assertEqual(node['client-fingerprint'], 'firefox')

    def test_import_update_preserves_existing_node_identity(self):
        with patch.dict('os.environ', {'MIHOMO_REALITY_COMPAT': '1'}):
            new = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        old = copy.deepcopy(new)
        del old['reality-opts']['support-x25519mlkem768']
        self.assertEqual(vpn_subscriptions.identity(old), vpn_subscriptions.identity(new))

    def test_noncompatible_image_keeps_original_profile(self):
        with patch.dict('os.environ', {}, clear=True):
            node = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        self.assertNotIn('support-x25519mlkem768', node['reality-opts'])


if __name__ == '__main__':
    unittest.main()
