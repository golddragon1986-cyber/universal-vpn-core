import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/panel/panel'))
import vpn_import as vpn
import vpn_components as components

KEY=base64.b64encode(bytes(range(32))).decode()
WG='[Interface]\nPrivateKey = '+KEY+'\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = '+KEY+'\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0\n'

class VPNTests(unittest.TestCase):
    def test_wireguard_ipv6_endpoint(self):
        node=vpn.parse(WG,'wireguard','Test')[0]
        self.assertEqual((node['server'],node['port'],node['ip']),('2001:db8::1',51820,'10.9.0.2'))

    def test_awg3_parameters_are_preserved(self):
        text=WG.replace('[Peer]','HeaderProtectionKey = '+KEY+'\nRandomTrailers = true\nS4 = 20\n[Peer]')
        awg=vpn.parse(text,'awg')[0]['amnezia-wg-option']
        self.assertEqual(awg,{'header-protection-key':KEY,'random-trailers':True,'s4':20,'version':3})

    def test_no_shell_hooks_or_silent_unknown_fields(self):
        for field in ('PostUp = reboot','Unknown = 1'):
            with self.assertRaises(ValueError):vpn.parse(WG.replace('[Peer]',field+'\n[Peer]'))

    def test_generic_json_preserves_nested_options(self):
        node={'name':'X','type':'openvpn','ca':'certificate','peer-info':{'IV_PROTO':'2'}}
        self.assertEqual(vpn.parse(json.dumps({'proxies':[node]})),[node])

    def test_openvpn_inline_and_script_rejection(self):
        text='client\nremote vpn.example 1194\nproto udp\n<ca>\nCERTIFICATE\n</ca>\n'
        self.assertEqual(vpn.parse(text,'openvpn')[0]['ca'],'CERTIFICATE\n')
        with self.assertRaises(ValueError):vpn.parse(text+'up /bin/sh','openvpn')

    def test_selected_json_type_is_enforced(self):
        with self.assertRaises(ValueError):vpn.parse('{"type":"socks5"}','json:wireguard')

    def test_distinct_names_and_unknown_type(self):
        used={'X'}
        self.assertEqual(vpn.unique({'name':'X','type':'ssh'},used)['name'],'X-2')
        with self.assertRaises(ValueError):vpn.unique({'type':'exec'},set())

    def test_uri_credentials_are_decoded(self):
        node=vpn.parse('socks5://user:p%40ss@vpn.example:1080#Test')[0]
        self.assertEqual(node['password'],'p@ss')
        self.assertEqual(node['type'],'socks5')

    def test_unknown_uri_options_are_not_discarded(self):
        with self.assertRaises(ValueError):vpn.parse('trojan://pass@vpn.example:443?obfs=test')

    def test_arbitrary_package_and_core_removal_are_rejected(self):
        with patch.object(components,'run') as run:
            with self.assertRaises(ValueError):components.change('x;reboot','install')
            with self.assertRaises(ValueError):components.change('mihomo','remove')
            run.assert_not_called()

    def test_disk_budget_prevents_install(self):
        with patch.object(components,'disk_limit',return_value=150_000_000),patch.object(components,'installed',return_value=False),patch.object(components,'used_bytes',return_value=145_000_000),patch.object(components,'run') as run:
            with self.assertRaises(ValueError):components.change('openvpn','install')
            run.assert_not_called()

    def test_disk_limit_can_be_temporarily_disabled(self):
        from types import SimpleNamespace
        with patch.object(components,'disk_limit',return_value=0),patch.object(components,'installed',return_value=False),patch.object(components,'used_bytes',return_value=250_000_000),patch.object(components.shutil,'disk_usage',return_value=SimpleNamespace(free=1_000_000_000)),patch.object(components,'run') as run:
            components.change('openvpn','install')
            run.assert_called_once_with(['apk','add','--no-cache','openvpn'])

if __name__=='__main__':unittest.main()
