"""Render UI fixtures with isolated data; check markup, placeholders and both languages."""
import ast
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / 'vendor/panel/panel'
sys.path.insert(0, str(PANEL))
import ui_i18n as ui
import manage_ru_blocked as app
import routing_panel as routing
import router_routes as rr
import proxy_manager as proxies
import service_routes_panel as services
import client_panel as clients
import client_policy
import dns_panel as dns
import local_dns_zones
import vpn_components
import vpn_clients
import vpn_subscriptions
import configuration_draft
import geodata_panel


def main():
    for path in PANEL.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    missing = set()
    for path in PANEL.iterdir():
        if path.suffix not in {'.py', '.js', '.html'} or path.name.startswith('ui_'):
            continue
        for match in ui.SEGMENT.finditer(path.read_text(encoding='utf-8')):
            key = match.group().strip()
            if key not in ui.CATALOG:
                missing.add(key)
    assert not missing, sorted(missing)
    sample = '<label>{name}</label><input name="main_proxy" value="{value}" placeholder="Сеть">'
    assert ui.text(sample) == '<label>{name}</label><input name="main_proxy" value="{value}" placeholder="Network">'
    assert ui.text('ЗАПОЛНИТЕ- ВСТАВЬТЕ') == 'ЗАПОЛНИТЕ- ВСТАВЬТЕ'
    state = {'rows': [{'id': '*A', 'list': 'LAN', 'address': '10.0.0.0/24', 'name': 'Пользовательский клиент', 'label': '', 'route': 'RULES', 'enabled': True}], 'readonly': [], 'lists': {'LAN': {'interfaces': ['LAN'], 'active': True}}, 'bindings': [], 'management_bindings': [], 'protected': [], 'live': True, 'observed': ''}
    database = {'nodes': [{'proxy': {'name': 'Пользовательский сервер', 'type': 'vless', 'server': 'example.com', 'port': 443}, 'balance': True}], 'subscriptions': {}, 'balance_overrides': {}}
    rules = [{'id': 'test-rule', 'name': 'Пользовательское правило', 'domains': ['example.com'], 'target': 'SELECTOR', 'enabled': True}]
    class Response(io.BytesIO):
        status = 200
    def urlopen(*args, **kwargs):
        return Response(b'{"proxies": [], "version": "test"}')
    patches = [patch.object(app, 'BASE', str(PANEL)),
               patch.object(app, 'urlopen', side_effect=urlopen),
               patch.object(app, 'cached_domain_counts', return_value=(0, 0), create=True),
               patch.object(app, 'get_active_proxy_nodes', return_value=[]),
               patch.object(app, 'read_services', return_value=rules),
               patch.object(app, 'route_targets', return_value=['SELECTOR', 'DIRECT', 'LOADBALANCE']),
               patch.object(app, 'read_source', return_value=set()),
               patch.object(app, 'read_local', return_value=set()),
               patch.object(app, 'read_service_domain_states', return_value={}),
               patch.object(app, 'get_domain_counts', return_value=(0, 0)),
               patch.object(services, 'read_services', return_value=rules),
               patch.object(services, 'route_targets', return_value=['SELECTOR', 'DIRECT', 'LOADBALANCE']),
               patch.object(routing, 'global_info', return_value={'all': ['DIRECT', 'LOADBALANCE'], 'now': 'DIRECT'}),
               patch.object(routing, 'read_settings', return_value={'main_proxy': 'DIRECT', 'services_enabled': True}),
               patch.object(proxies, 'read', return_value=database),
               patch.object(proxies, 'client_endpoints', return_value={}),
               patch.object(proxies.urllib.request, 'urlopen', side_effect=urlopen),
               patch.object(clients, 'snapshot', return_value=(state, '')),
               patch.object(client_policy, 'choices', return_value=['RULES', 'BYPASS', 'SELECTOR', 'DIRECT', 'LOADBALANCE']),
               patch.object(rr, 'route_count', return_value=0),
               patch.object(rr, 'snapshot', return_value={'routes': [], 'live': True, 'observed': ''}),
               patch.object(rr, 'target_choices', return_value=['SELECTOR', 'DIRECT', 'LOADBALANCE']),
               patch.object(rr, 'read_targets', return_value={}),
               patch.object(rr, 'default_target', return_value='SELECTOR'),
               patch.object(rr, 'configured', return_value=False),
               patch.object(dns, 'read_settings', return_value={'fake_ip': True, 'servers': [{'id': 'test', 'name': 'Пользовательский DNS', 'address': '8.8.8.8', 'route': 'DIRECT', 'enabled': True}]}),
               patch.object(dns, 'route_choices', return_value=['SELECTOR', 'DIRECT', 'LOADBALANCE']),
               patch.object(local_dns_zones, 'read', return_value=[]),
               patch.object(vpn_components, 'status', return_value={'used': 0, 'items': [{'id': 'mihomo', 'title': 'Mihomo', 'installed': True, 'version': 'test'}]}),
               patch.object(vpn_components.os, 'uname', create=True, return_value=type('U', (), {'release': 'test'})()),
               patch.object(vpn_clients, 'binary', return_value='/test'),
               patch.object(configuration_draft, 'preview', side_effect=contextlib.nullcontext),
               patch.object(configuration_draft, 'load', return_value={}),
               patch.object(configuration_draft, 'status', return_value={'dirty': False}),
               patch.object(geodata_panel, 'entries', return_value={})]
    output = ROOT / 'build/ui-fixtures'
    pages = {'domains': '/', 'domains-loaded': '/?load=1', 'services': '/?tab=services',
             'vpn': '/?tab=vpn', 'subscriptions': '/?tab=vpn&view=subscriptions',
             'clients': '/?tab=clients', 'routes': '/?tab=routes', 'dns': '/?tab=dns',
             'geodata': '/?tab=geodata', 'components': '/?tab=components',
             'logs': '/?tab=logs', 'backup': '/?tab=backup'}
    with contextlib.ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        for language in ('en', 'ru'):
            directory = output / language
            directory.mkdir(parents=True, exist_ok=True)
            for name, url in pages.items():
                handler = object.__new__(app.Handler)
                handler.path = url
                handler.headers = {'Cookie': 'ui_language=' + language}
                handler.wfile = io.BytesIO()
                status = []
                handler.send_response = status.append
                handler.send_header = lambda *args: None
                handler.end_headers = lambda: None
                handler.do_GET()
                page = handler.wfile.getvalue().decode('utf-8')
                assert status == [200], (name, status, page[-1000:])
                assert 'id="ui-language-toggle"' in page, name
                assert page.index('form="core-restart-form"') < page.index('id="ui-language-toggle"'), name
                assert 'lang="' + language + '"' in page, name
                (directory / (name + '.html')).write_text(page, encoding='utf-8')
    print(json.dumps({'catalog_fragments': len(ui.CATALOG), 'pages': len(pages), 'locales': 2, 'fixtures': str(output)}))


if __name__ == '__main__':
    main()
