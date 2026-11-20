import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vendor/panel/panel'))
import log_panel as logs


class LogsTests(unittest.TestCase):
    def test_only_explicit_routes_are_attributed(self):
        proxies={'SELECTOR':{'type':'Selector'},'VPN-A':{'type':'Vless'},'DIRECT':{'type':'Direct'}}
        self.assertEqual(logs.classify('[TCP] x --> example.com:443 using SELECTOR[VPN-A]',proxies),
                         (['SELECTOR','VPN-A'],['Selector','Vless']))
        self.assertEqual(logs.classify('DNS query for VPN-A',proxies),([],[]))
        self.assertEqual(logs.classify('connection failed using UNKNOWN',proxies),([],[]))
        self.assertEqual(logs.classify('[TCP] dial VPN-A (match Match/) x --> example.com:443 error: timeout',proxies),
                         (['VPN-A'],['Vless']))

    def test_bounded_messages_and_ring(self):
        with logs.LOCK:
            logs.ROWS.clear()
        with patch.object(logs,'RECORD_LEVEL','info'):
            for _ in range(600):logs.append({'type':'info','payload':'a'*10000})
        self.assertEqual(len(logs.ROWS),512)
        self.assertEqual(len(logs.ROWS[-1]['message']),2048)

    def test_recording_threshold_and_silent(self):
        logs.ROWS.clear()
        with patch.object(logs,'RECORD_LEVEL','warning'):
            logs.append({'type':'debug','payload':'ignored'})
            logs.append({'type':'error','payload':'kept'})
        with patch.object(logs,'RECORD_LEVEL','silent'):
            logs.append({'type':'error','payload':'ignored'})
        self.assertEqual([row['message'] for row in logs.ROWS],['kept'])

    def test_invalid_level_cannot_reach_core(self):
        with patch.object(logs,'api') as api:
            with self.assertRaises(ValueError):logs.set_level('trace\nlog-level: debug')
            api.assert_not_called()

    def test_failed_persistence_rolls_back_core(self):
        with patch.object(logs,'api',return_value={'log-level':'warning'}) as api, patch.object(logs,'write',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):logs.set_level('debug')
            self.assertEqual(api.call_args.args,('/configs',{'log-level':'warning'},'PATCH'))

    def test_setting_survives_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(logs,'SETTINGS',Path(directory)/'settings.json'),patch.object(logs,'api',return_value={'log-level':'warning'}) as api:
                logs.set_level('info')
                self.assertEqual(logs.saved_level(),'info')
                logs.restore_level()
                self.assertEqual(api.call_args.args,('/configs',{'log-level':'info'},'PATCH'))


if __name__=='__main__':unittest.main()
