"""Create empty state on the first managed start; never reset existing state."""
import json
import os
from pathlib import Path

ROOT = Path('/etc/mihomo')
PACKAGE = Path(__file__).resolve().parent


def create(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError('Refusing state symlink: ' + str(path))
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, 'wb') as out:
        out.write(data if isinstance(data, bytes) else data.encode())
        out.flush()
        os.fsync(out.fileno())

def update_branding(path):
    source = path.read_bytes()
    updated = source.replace(
        b'<div class="unified-logo">V</div>',
        b'<div class="unified-logo" aria-hidden="true">UvpnC</div>',
    ).replace(
        b'<div class="unified-brand-title">VPN Control Panel</div>',
        b'<div class="unified-brand-title">Universal VPN Core</div>',
    ).replace(
        b'.unified-logo{width:40px;height:40px;',
        b'.unified-logo{height:40px;padding:0 9px;',
    ).replace(
        b'background:#315ee8;color:white;font-weight:800;font-size:20px}',
        b'background:#315ee8;color:white;font-weight:800;font-size:13px}',
    ).replace(
        b"// Apply shared branding to pages served by an already running panel process.\n"
        b"document.querySelector('.unified-logo').textContent='V';\n"
        b"document.querySelector('.unified-brand-title').textContent='VPN Control Panel';\n",
        b"",
    )
    if updated != source:
        import sys
        sys.path.insert(0, str(PACKAGE / 'panel'))
        from durable_io import write
        write(path, updated)


def main():
    rules = ROOT / 'rules'
    rules.mkdir(parents=True, exist_ok=True)
    (ROOT / 'template').mkdir(parents=True, exist_ok=True)
    (ROOT / 'user_sh').mkdir(parents=True, exist_ok=True)
    # Keep code in the mounted state directory to preserve it on RouterOS updates.
    for source in (PACKAGE / 'panel').iterdir():
        if source.is_file():
            target = rules / source.name
            create(target, source.read_bytes())
            if source.suffix == '.sh':
                target.chmod(0o755)
    update_branding(rules / 'manage_ru_blocked.py')
    update_branding(rules / 'action_queue_ui.html')
    template = (PACKAGE / 'default-config.yaml').read_text()
    if os.environ.get('MIHOMO_PANEL_TUN') == '1':
        template = template.replace('tun:\n  enable: false', 'tun:\n  enable: true')
    if os.environ.get('MIHOMO_PANEL_TUN_AUTO_REDIRECT') == '0':
        template = template.replace('  auto-redirect: true', '  auto-redirect: false')
    for name in ('default_config.yaml', 'default_config_candidate.yaml',
                 'template/default_config.yaml', 'rules/panel-managed-template.yaml'):
        create(ROOT / name, template)
    primary_dns = os.environ.get('UVPNC_PRIMARY_DNS')
    main_dns = os.environ.get('UVPNC_MAIN_DNS')
    if primary_dns or main_dns:
        import sys
        sys.path.insert(0, str(PACKAGE / 'panel'))
        from dns_panel import parse_settings
        primary_dns = (primary_dns or '').replace(',', '\n')
        main_dns = main_dns or ''
        if not main_dns.startswith('https://'):
            main_dns = main_dns.replace(',', '\n')
        values = parse_settings({'default-nameserver': [primary_dns],
                                 'nameserver': [main_dns]})
        create(rules / 'dns-settings.json', json.dumps(values, ensure_ascii=False) + '\n')
    seed_state = PACKAGE / 'default-state'
    for source in seed_state.rglob('*'):
        if source.is_file():
            create(rules / source.relative_to(seed_state), source.read_bytes())
    empty = {
        'resource-limits.json': {'disk_limit_bytes': 0},
        'service-routes.json': json.loads((PACKAGE / 'default-services.json').read_text(encoding='utf-8')),
        'managed-proxies.json': {'nodes': [], 'balance_overrides': {}},
        'routing-settings.json': {'main_proxy': 'DIRECT', 'services_enabled': True,
                                 'dns_enhanced_mode_before_direct': 'fake-ip'},
    }
    for name, value in empty.items():
        create(rules / name, json.dumps(value, ensure_ascii=False) + '\n')
    for name in ('ru-blocked-source.txt', 'ru-blocked-local-add.txt',
                 'ru-blocked-local-remove.txt', 'ru-blocked-local-delete.txt',
                 'ru-blocked-filters.txt', 'ru-blocked-domain.txt'):
        seed = PACKAGE / 'default-domains' / name
        create(rules / name, seed.read_bytes() if seed.is_file() else '')
    for name in ('telegram-ip.yaml', 'ru-blocked-mihomo.yaml'):
        create(rules / name, 'payload: []\n')
    create(rules / 'user-proxies.yaml', '{"proxies": []}\n')
    create(ROOT / 'srv.yaml', 'proxies: []\n')
    create(ROOT / '.mihomo-panel-managed', '1\n')


if __name__ == '__main__':
    main()
