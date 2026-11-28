"""Xray JSON subscriptions retain the Mihomo REALITY compatibility setting."""

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

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
    def test_unchanged_subscription_only_writes_metadata(self):
        v = vpn_subscriptions
        source = {'name': 'Server-466.02GB-64D', 'type': 'vless', 'server': 'vpn.example', 'port': 443}
        stored = {**source, 'name': 'Subscription-Server'}
        node = {'proxy': stored, 'connection': stored, 'subscription': 'sid', 'balance': True,
                'source_label': 'Server', 'source_key': v.identity(source), 'client': 'mihomo'}
        db = {'nodes': [node], 'subscriptions': {'sid': {
            'name': 'Subscription', 'engine': 'mihomo', 'profile': 'standard', 'url': 'https://example.com'}}}
        before_apply = Mock()
        with patch.object(v.manager, 'read', return_value=db), \
                patch.object(v.manager, 'put') as put, patch.object(v.manager, 'save') as save, \
                patch.object(v.manager, 'sync') as sync, patch.object(v.clients, 'binary', return_value=True), \
                patch.object(v.clients, 'validate') as validate, patch.object(v, 'pinned_channels', return_value=set()):
            message = v.refresh('sid', before_apply=before_apply, _fetched=([source], {'total': 100}))
        self.assertIn('Список серверов не изменился', message)
        put.assert_called_once()
        self.assertEqual(put.call_args.args[1]['nodes'], [node])
        save.assert_not_called()
        sync.assert_not_called()
        validate.assert_not_called()
        before_apply.assert_not_called()

    def test_xray_json_enables_mihomo_hybrid_in_compatible_image(self):
        with patch.dict('os.environ', {'MIHOMO_REALITY_COMPAT': '1'}), \
                patch.object(vpn_subscriptions.manager, 'reality_client_version', return_value='26.11.9'):
            node = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        self.assertTrue(node['reality-opts']['support-x25519mlkem768'])
        self.assertEqual(node['reality-opts']['client-version'], '26.11.9')
        self.assertEqual(node['client-fingerprint'], 'firefox')

    def test_import_update_preserves_existing_node_identity(self):
        with patch.dict('os.environ', {'MIHOMO_REALITY_COMPAT': '1'}), \
                patch.object(vpn_subscriptions.manager, 'reality_client_version', return_value='26.11.9'):
            new = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        old = copy.deepcopy(new)
        del old['reality-opts']['support-x25519mlkem768']
        del old['reality-opts']['client-version']
        self.assertEqual(vpn_subscriptions.identity(old), vpn_subscriptions.identity(new))

    def test_noncompatible_image_keeps_original_profile(self):
        with patch.dict('os.environ', {}, clear=True), \
                patch.object(vpn_subscriptions.manager, 'reality_client_version', return_value=None):
            node = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'mihomo')
        self.assertNotIn('support-x25519mlkem768', node['reality-opts'])
        self.assertNotIn('client-version', node['reality-opts'])

    def test_xray_engine_does_not_receive_mihomo_client_version(self):
        with patch.object(vpn_subscriptions.manager, 'reality_client_version', return_value='26.11.9'):
            node = vpn_subscriptions.xray_vless(copy.deepcopy(OUTBOUND), 'server-1', 'xray')
        self.assertNotIn('reality-opts', node)


if __name__ == '__main__':
    unittest.main()
