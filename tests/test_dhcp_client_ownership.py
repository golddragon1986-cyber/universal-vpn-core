"""A static DHCP lease must not own a manual client merely because the IP matches."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

here = Path(__file__).resolve().parent
source = here.parent / 'vendor' / 'panel' / 'panel'
sys.path.insert(0, str(source if source.is_dir() else here))
sys.path.insert(1, str(here.parent))
import client_batch
import client_panel
import client_policy
import dhcp_leases


ADDRESS = '192.168.88.254'
LEASE = {'.id': '*2', 'address': ADDRESS, 'active-address': ADDRESS,
         'mac-address': '86:CC:AC:C3:A2:F2', 'active-mac-address': '86:CC:AC:C3:A2:F2',
         'server': 'defconf', 'active-server': 'defconf', 'client-id': 'client-1',
         'status': 'bound', 'dynamic': False, 'disabled': False}
OWNER = dhcp_leases.owner_key(dhcp_leases.model(LEASE))


class Router:
    def call(self, path, *args):
        if path == 'ip/firewall/address-list':
            return [{'.id': '*1', 'list': 'uvpn-main-lan', 'address': ADDRESS,
                     'comment': '', 'disabled': False}]
        if path == dhcp_leases.PATH:
            return [LEASE]
        return []


def row(owner=''):
    return {'id': '*1', 'list': 'uvpn-main-lan', 'address': ADDRESS,
            'label': '', 'name': 'Manual client', 'route': 'RULES',
            'enabled': True, 'dhcp_owner': owner}


def state(owner=''):
    return {'rows': [row(owner)], 'raw': Router().call('ip/firewall/address-list'),
            'lists': {'uvpn-main-lan': {'active': True}}, 'protected': [],
            'bindings': [], 'management_bindings': []}


def unpin():
    return {'id': '*2', 'ip': ADDRESS, 'mac': LEASE['mac-address'],
            'server': 'defconf', 'client_id': 'client-1', 'action': 'unpin'}


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        choices = patch.object(client_policy, 'choices', return_value=['RULES'])
        choices.start()
        self.addCleanup(choices.stop)

    def test_disabling_lease_removes_only_its_owned_route(self):
        action = dict(unpin(), action='disable')
        for owner in ('', OWNER):
            with self.subTest(owner=owner):
                before = state(owner)
                with patch.object(client_panel, 'read_state', return_value=before):
                    change = client_batch.plan(
                        [row(owner)], client_panel.fingerprint(before), Router(),
                        lease_actions=[action])
                self.assertEqual(change['desired'], [] if owner else [row()])

    def planned(self, before, desired):
        with patch.object(client_panel, 'read_state', return_value=before):
            return client_batch.plan(desired, client_panel.fingerprint(before), Router(),
                                     lease_actions=[unpin()])

    def test_stale_dhcp_row_does_not_block_manual_change(self):
        manual = dict(row(), address='192.168.0.0/16')
        stale = dict(row(OWNER), id='new-stale')
        before = state()
        before['rows'] = [manual]
        with patch.object(client_panel, 'read_state', return_value=before), \
                patch.dict(LEASE, disabled=True):
            change = client_batch.plan(
                [manual, stale], client_panel.fingerprint(before), Router())
        self.assertEqual(change['desired'], [manual])

    def test_manual_client_with_same_ip_survives_unpin(self):
        change = self.planned(state(), [row()])
        self.assertEqual(change['desired'][0]['id'], '*1')
        self.assertEqual(change['dhcp_actions'][0]['action'], 'unpin')

    def test_owned_client_must_be_removed_before_unpin(self):
        with self.assertRaisesRegex(ValueError, 'удалите маршрут DHCP-клиента'):
            self.planned(state(OWNER), [row(OWNER)])
        change = self.planned(state(OWNER), [])
        self.assertEqual(change['desired'], [])

    def test_manual_client_cannot_claim_lease_ownership(self):
        with self.assertRaisesRegex(ValueError, 'Связь клиента с DHCP-арендой'):
            self.planned(state(), [row(OWNER)])

    def test_owner_persists_only_when_explicitly_saved(self):
        with patch.object(client_policy, 'read', return_value=[row(OWNER)]):
            enriched = client_policy.enrich([{'id': '*1', 'list': 'uvpn-main-lan',
                                              'address': ADDRESS, 'label': '', 'enabled': True}])
        self.assertEqual(enriched[0]['dhcp_owner'], OWNER)
        with patch.object(client_policy, 'read', return_value=[row()]):
            manual = client_policy.enrich([{'id': '*1', 'list': 'uvpn-main-lan',
                                            'address': ADDRESS, 'label': '', 'enabled': True}])
        self.assertEqual(manual[0]['dhcp_owner'], '')

    def test_disabled_manual_host_can_coexist_with_dhcp(self):
        before = state()
        manual = dict(row(), enabled=False)
        owned = dict(row(OWNER), id='new-dhcp')
        with patch.object(client_panel, 'read_state', return_value=before):
            plan = client_batch.plan([manual, owned], client_panel.fingerprint(before), Router())
            self.assertEqual(plan['desired'], [manual, owned])
            with self.assertRaisesRegex(ValueError, 'Конфликт маршрутов'):
                client_batch.plan([row(), owned], client_panel.fingerprint(before), Router())

    def test_same_address_keeps_distinct_metadata_by_router_id(self):
        manual = dict(row(), enabled=False, name='Manual')
        owned = dict(row(OWNER), id='*3', name='DHCP')
        live = [{k: item[k] for k in ('id', 'list', 'address', 'label', 'enabled')}
                for item in (manual, owned)]
        with patch.object(client_policy, 'read', return_value=[manual, owned]):
            self.assertEqual(client_policy.enrich(live), [manual, owned])


if __name__ == '__main__':
    unittest.main()
