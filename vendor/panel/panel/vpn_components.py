from ui_i18n import text as _ui
"""Fixed component catalog; package commands never accept user-supplied names or URLs."""
import html
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
from storage_space import require_many
from pathlib import Path
from urllib.request import Request, urlopen

CATALOG = {
    'openvpn': ('OpenVPN CLI', 'openvpn', 12_000_000),
    'wireguard-tools': ('WireGuard tools', 'wireguard-tools-wg', 3_000_000),
    'sing-box': ('sing-box', 'sing-box', 80_000_000),
    'xray': ('Xray', 'xray', 80_000_000),
}
LIMIT = 150_000_000
SYSTEM_PACKAGES = {
    'python3': ('Python 3', 'python3', 20_000_000),
    'busybox': ('BusyBox', 'busybox', 3_000_000),
    'apk-tools': ('Alpine APK', 'apk-tools', 5_000_000),
    'ca-certificates': ('Сертификаты CA', 'ca-certificates', 2_000_000),
    'iptables-legacy': ('iptables legacy', 'iptables-legacy', 4_000_000),
    'nftables': ('nftables', 'nftables', 5_000_000),
    'musl': ('musl libc', 'musl', 4_000_000),
    'libssl3': ('OpenSSL TLS', 'libssl3', 4_000_000),
    'libcrypto3': ('OpenSSL Crypto', 'libcrypto3', 8_000_000),
}
CATALOG.update(SYSTEM_PACKAGES)
RESOURCE_SETTINGS=Path('/etc/mihomo/rules/resource-limits.json')
LOCAL_SING_BOX=Path('/usr/local/bin/sing-box')
BUNDLED_APK_VERSIONS=Path(__file__).with_name('bundled-apk-versions.json')


def disk_limit():
    if not RESOURCE_SETTINGS.exists():return LIMIT
    value=json.loads(RESOURCE_SETTINGS.read_text()).get('disk_limit_bytes',LIMIT)
    if not isinstance(value,int) or isinstance(value,bool) or value<0:raise ValueError('Некорректный лимит диска')
    return value


def reload_local_sing_box():
    configuration=Path('/etc/mihomo/clients/sing-box.json')
    if not configuration.is_file() or not LOCAL_SING_BOX.is_file():return
    import vpn_clients
    with vpn_clients.LOCK:
        if not vpn_clients.users('sing-box'):vpn_clients.pause_unused('sing-box');return
        run([str(LOCAL_SING_BOX),'check','-c',str(configuration)],timeout=20)
        vpn_clients.reload_sb()


def run(args, timeout=180):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-1500:])
    return result.stdout.strip()


def used_bytes():
    result=run(['du','-sk','/bin','/sbin','/lib','/usr','/mihomo','/etc','/var','/root'])
    return sum(int(line.split()[0]) for line in result.splitlines())*1024


def installed(package):
    result=subprocess.run(['apk','info','-e',package],capture_output=True,text=True)
    return result.returncode==0

def installed_version(package):
    for line in run(['apk','list','--installed','--all-matches',package]).splitlines():
        match = re.match(re.escape(package) + r'-([0-9][^\s]*)\s', line)
        if match:
            return match[1]
    return ''


def status():
    core=run(['/mihomo','-v']).splitlines()[0]
    bundled=json.loads(BUNDLED_APK_VERSIONS.read_text()) if BUNDLED_APK_VERSIONS.is_file() else {}
    items=[{'id':'mihomo','title':'Mihomo','installed':True,'version':core.split()[2],'detail':core,'reserve':80_000_000,'local':False,'core':True}]
    for key,(title,package,reserve) in CATALOG.items():
        local=(key=='sing-box' and LOCAL_SING_BOX.is_file()) or (key=='xray' and Path('/usr/local/bin/xray').is_file())
        present=local or installed(package)
        if key in SYSTEM_PACKAGES and not present:
            if package in bundled:
                items.append({'id':key,'title':title,'installed':True,'version':bundled[package],'reserve':reserve,'local':False,'bundled':True})
            continue
        version=(run([str(LOCAL_SING_BOX),'version']).splitlines()[0].removeprefix('sing-box version ') if key=='sing-box' else run(['/usr/local/bin/xray','version']).splitlines()[0].split()[1]) if local else installed_version(package) if present else ''
        items.append({'id':key,'title':title,'installed':present,'version':version,'reserve':reserve,'local':local})
    return {'used':used_bytes(),'limit':disk_limit(),'items':items}


def ensure_ca_bundle():
    from durable_io import write

    config = Path('/etc/ca-certificates.conf')
    certificates = Path('/usr/share/ca-certificates')
    if not config.exists():
        entries = sorted(certificates.glob('mozilla/*.crt'))
        if entries:
            write(config, ''.join(f'{entry.relative_to(certificates)}\n' for entry in entries).encode(), mode=0o644)
    Path('/etc/ca-certificates/update.d').mkdir(parents=True, exist_ok=True)
    bundle = Path('/etc/ssl/certs/ca-certificates.crt')
    if not bundle.is_file() or not bundle.stat().st_size:
        run(['update-ca-certificates'])
        if not bundle.is_file() or not bundle.stat().st_size:
            raise RuntimeError('Не удалось восстановить системный список доверенных CA')


def change(component, operation, version_id=None):
    if operation == 'restart':
        from component_binary import restart
        return restart(component)
    if operation not in ('install','remove','update','set_version'):
        raise ValueError('Неизвестное действие')
    if component in SYSTEM_PACKAGES and operation != 'update':
        raise ValueError('Для системного пакета доступно только обновление')
    if operation=='set_version':
        from component_versions import install
        return install(component,version_id)
    if operation=='update' and component in ('mihomo','xray'):
        from component_versions import catalog,install
        if not next((x['installed'] for x in status()['items'] if x['id']==component),False):raise ValueError('Компонент ещё не установлен')
        choices=[x for x in catalog(True)['items'][component] if x['id'].startswith('github:') and x['installable']]
        if not choices:raise ValueError('Нет доступных официальных сборок для архитектуры контейнера')
        current=next((x['version'] for x in status()['items'] if x['id']==component),'')
        if current.removeprefix('v')==choices[0]['version'].removeprefix('v'):return 'Установлена актуальная версия '+component+': '+current
        return install(component,choices[0]['id'])
    limit=disk_limit()
    if component=='mihomo':
        raise ValueError('Mihomo обслуживает DNS и маршрутизацию; удалить работающее ядро нельзя')
    if component not in CATALOG:
        raise ValueError('Неизвестный компонент')
    title,package,reserve=CATALOG[component]
    if operation=='remove' and component in ('sing-box','xray'):
        import vpn_clients
        with vpn_clients.LOCK:vpn_clients.pause_unused(component)
    if component=='xray' and Path('/usr/local/bin/xray').is_file() and operation=='remove':
        if subprocess.run(['pidof','xray'],capture_output=True).returncode==0:raise ValueError('Сначала остановите Xray')
        Path('/usr/local/bin/xray').unlink();return 'Xray удалён; конфигурация сохранена'
    if component=='sing-box' and LOCAL_SING_BOX.is_file():
        if operation=='install':return 'Локальная сборка sing-box уже установлена'
        if operation=='update':
            from sing_box_update import update
            return update()
        if subprocess.run(['pidof','sing-box'],capture_output=True).returncode==0:
            raise ValueError('Сначала остановите sing-box: он используется сохранёнными соединениями')
        LOCAL_SING_BOX.unlink()
        return 'Локальный sing-box удалён; конфигурация сохранена'
    present=installed(package)
    if operation=='remove':
        if not present:return title+' уже удалён'
        # Refuse removal while a separately launched client is alive.
        for executable in ({'wireguard-tools':'wg'}.get(component,component),):
            if subprocess.run(['pidof',executable],capture_output=True).returncode==0:
                raise ValueError('Сначала остановите клиент '+title)
        run(['apk','del',package])
        return title+' удалён. Сохранённые соединения не удалены.'
    if operation=='update' and not present:
        raise ValueError('Компонент ещё не установлен')
    if limit and used_bytes()+reserve>limit:
        raise ValueError('Компонент не помещается в лимит диска. Доступно '+str(max(0,limit-used_bytes())//1_000_000)+' МБ')
    require_many([('/',reserve),(tempfile.gettempdir(),reserve)],'Установка '+title)
    command=['apk','add','--no-cache']
    if operation=='update':command.append('--upgrade')
    if component in SYSTEM_PACKAGES:
        ensure_ca_bundle()
        try:
            run(command+[package])
        finally:
            ensure_ca_bundle()
    else:
        run(command+[package])
    if limit and used_bytes()>limit:
        if not present:run(['apk','del',package])
        raise RuntimeError('Превышен лимит 150 МБ; новая установка отменена')
    return title+(' обновлён' if present else ' установлен')


def render():
    state=status();esc=lambda value:html.escape(str(value),quote=True)
    rows=[]
    for item in state['items']:
        key=esc(item['id']);present=item['installed']
        if item.get('bundled'):
            rows.append(''.join(('<tr><td><strong>', f"{esc(_ui(item['title']))}", _ui('</strong><span class="component-state">Системный пакет Alpine</span></td><td>'), f"{esc(item['version'])}", _ui('</td><td colspan="2">Обновляется вместе с образом</td></tr>'))))
            continue
        actions=''
        if present:
            if item['id'] in SYSTEM_PACKAGES:
                actions+='<form method="post" class="component-update" hidden><input type="hidden" name="action" value="component_change"><input type="hidden" name="component" value="'+key+_ui('"><button name="operation" value="update">Обновить</button></form>')
            if item['id']!='mihomo' and item['id'] not in SYSTEM_PACKAGES:actions+='<form method="post" data-component-title="'+esc(_ui(item['title']))+_ui('" onsubmit="return confirm(\'Удалить компонент «\'+this.dataset.componentTitle+\'»?\')"><input type="hidden" name="action" value="component_change"><input type="hidden" name="component" value="')+key+_ui('"><button class="component-remove" name="operation" value="remove">Удалить</button></form>')
        if item['id'] in SYSTEM_PACKAGES:
            rows.append(''.join(('<tr data-system-component="', f'{key}', '"><td><strong>', f"{esc(_ui(item['title']))}", _ui('</strong><span class="component-state">Системный пакет Alpine</span></td><td>'), f"{esc(item['version'])}", _ui('</td><td><span class="component-version-note">Проверьте доступные версии</span>'), f'{actions}', '</td></tr>')))
            continue
        rows.append('<tr data-component="'+key+'" data-installed="'+('1' if present else '0')+'"><td><strong>'+esc(_ui(item['title']))+'</strong><span class="component-state '+('installed' if present else '')+'">'+(_ui('Установлен') if present else _ui('Не установлен'))+'</span></td><td title="'+esc(item.get('detail',item['version']))+'">'+esc(item['version'] or '—')+'</td><td><div class="component-controls"><form method="post" class="component-version-form"><input type="hidden" name="action" value="component_change"><input type="hidden" name="component" value="'+key+_ui('"><select name="version_id" required disabled aria-label="Версия ')+esc(_ui(item['title']))+_ui('"><option value="">Сначала проверьте версии</option></select><button name="operation" value="set_version" class="install-selected" disabled>')+(_ui('Переустановить') if present else _ui('Установить'))+'</button>'+(_ui('<button name="operation" value="restart" formnovalidate>Перезапустить</button>') if present and item['id'] in ('mihomo','sing-box','xray') else '')+_ui('<button name="operation" value="set_version" class="update-selected" hidden disabled>Обновить</button></form>')+actions+'</div><small class="component-version-note"></small></td></tr>')
    body=_ui(Path(__file__).with_name('components_ui.html').read_text(encoding='utf-8'))
    body=body.replace('DISK_USED',str(round(state['used']/1_000_000,1)))
    body=body.replace('DISK_FREE',str(round(shutil.disk_usage('/').free/1_000_000,1)))
    body=body.replace('KERNEL_RELEASE',esc(os.uname().release)).replace('COMPONENT_ROWS',''.join(rows))
    return _ui('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Компоненты</title></head><body>')+body+'</body></html>'

