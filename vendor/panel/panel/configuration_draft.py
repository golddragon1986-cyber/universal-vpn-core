"""Persistent configuration draft, isolated from runtime/background readers."""
import contextvars
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager, closing
from pathlib import Path

ROOT = Path('/etc/mihomo')
LOCK = threading.RLock()
VIEW = contextvars.ContextVar('configuration_draft', default=None)
FILES = {'routing-settings.json', 'dns-settings.json', 'service-routes.json',
         'local-domain-dns.json', 'ru-blocked-local-add.txt', 'ru-blocked-local-remove.txt',
         'ru-blocked-local-delete.txt', 'ru-blocked-source.txt', 'ru-blocked-filters.txt'}
ACTION_NAMES = {'routing_save', 'dns_save', 'domain_dns', 'filter_save', 'clear_auto_domains',
                'add', 'enable', 'disable', 'delete', 'route_apply', 'client_apply'}


def staged_action(action):
    if action in {'service_refresh_geodata', 'service_update_source'}:
        return False
    return action in ACTION_NAMES or action.startswith(('service_', 'route_'))


def staging():
    return bool(VIEW.get() and VIEW.get().get('writing'))


def directory():
    return ROOT / 'rules/.configuration-draft'


def load():
    path = directory() / 'manifest.json'
    manifest = json.loads(path.read_bytes()) if path.exists() else {'files': {}, 'revision': 0}
    if manifest.get('applying_job'):
        database = ROOT/'rules/configuration-jobs.sqlite3'
        with closing(sqlite3.connect(database)) as db:
            row = db.execute('SELECT status FROM jobs WHERE id=?',(manifest['applying_job'],)).fetchone()
        if row and row[0] == 'done':
            clean_providers(set(manifest.get('obsolete_providers',[])) | set(manifest.get('created_providers',[])))
            manifest = {'files':{}, 'revision':manifest['revision']}
            save(manifest)
        elif row and row[0] == 'failed':
            manifest.pop('applying_job',None)
            from durable_io import write
            write(path,json.dumps(manifest,ensure_ascii=False).encode())
    return manifest


def active_bytes(name):
    path = ROOT / 'rules' / name
    return path.read_bytes() if path.exists() else None


def digest(raw):
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def equivalent(name, a, b):
    if a == b: return True
    try:
        if name.endswith('.json'):
            a, b = json.loads(a or b'{}'), json.loads(b or b'{}')
            if name == 'dns-settings.json':
                for value in (a, b):
                    for row in value.get('servers', []): row.pop('id', None)
            return a == b
        return set((a or b'').splitlines()) == set((b or b'').splitlines())
    except (ValueError, TypeError): return False


def state_path(path):
    path = Path(path); view = VIEW.get()
    if view and path.parent == ROOT / 'rules' and path.name in view['files']:
        return directory() / view['files'][path.name].get('file', path.name)
    return path


def capture_write(path, raw):
    path = Path(path); view = VIEW.get()
    if not staging() or path.parent != ROOT / 'rules' or path.name not in FILES: return False
    from durable_io import write
    name = path.name
    original = active_bytes(name)
    if equivalent(name, original, raw):
        view['files'].pop(name, None)
        return True
    entry = dict(view['files'].get(name, {'baseline': digest(original)}))
    entry['file'] = 'data-' + uuid.uuid4().hex
    token = VIEW.set(None)
    try:
        directory().mkdir(mode=0o700, exist_ok=True)
        write(directory() / entry['file'], raw)
        view['files'][name] = entry
    finally: VIEW.reset(token)
    return True


@contextmanager
def preview():
    with LOCK:
        token = VIEW.set(load())
        try: yield
        finally: VIEW.reset(token)


def save(manifest):
    from durable_io import write
    manifest.pop('writing', None)
    manifest['revision'] += 1
    directory().mkdir(mode=0o700, exist_ok=True)
    write(directory() / 'manifest.json', json.dumps(manifest, ensure_ascii=False).encode())
    clean_shadows(manifest)


def clean_shadows(manifest):
    keep = {entry.get('file', name) for name, entry in manifest['files'].items()}
    for path in directory().iterdir():
        if path.name not in keep and (path.name.startswith('data-') or path.name in FILES):
            path.unlink(missing_ok=True)


def provider_refs(path):
    if not path.exists(): return set()
    return {name for item in json.loads(path.read_bytes()) for name in item.get('geo_sets', [])}


def defer_provider_removal(names):
    if not staging(): return False
    view = VIEW.get()
    view['obsolete_providers'] = sorted(set(view.get('obsolete_providers', [])) | set(names))
    return True


def clean_providers(names, protected=()):
    from geodata_service_files import remove_providers
    remove_providers(set(names) - set(protected) - provider_refs(ROOT/'rules/service-routes.json'))


def status():
    with LOCK:
        manifest = load()
        return {'pending': bool(manifest['files'] or manifest.get('routes') or manifest.get('clients')), 'revision': manifest['revision'],
                'sections': list(manifest['files']) + (['routes'] if manifest.get('routes') else []) + (['clients'] if manifest.get('clients') else [])}


def stage(raw, execute):
    from urllib.parse import parse_qs
    data = parse_qs(raw); action = data.get('action', [''])[0]
    if not staged_action(action): raise ValueError('Это действие применяется отдельно')
    with LOCK:
        manifest = load()
        if manifest.get('applying_job'):raise ValueError('Дождитесь завершения применения конфигурации')
        if action == 'client_apply':
            import client_panel,router_routes,re
            router_routes.check_token(data.get('client_token',[''])[0])
            rows=json.loads(data.get('clients',['[]'])[0]);baseline=data.get('baseline',[''])[0];original=data.get('rows_baseline',[''])[0]
            lease_requests=json.loads(data.get('lease_requests',['[]'])[0])
            lease_actions=json.loads(data.get('lease_actions',['[]'])[0])
            if not isinstance(rows,list) or len(rows)>512 or not re.fullmatch('[0-9a-f]{64}',baseline) or not re.fullmatch('[0-9a-f]{64}',original):raise ValueError('Некорректный черновик клиентов')
            if not isinstance(lease_requests,list) or len(lease_requests)>64:raise ValueError('Некорректный список DHCP-аренд')
            if not isinstance(lease_actions,list) or len(lease_actions)>64:raise ValueError('Некорректный список действий DHCP')
            if client_panel.rows_fingerprint(rows)==original and not lease_requests and not lease_actions:manifest.pop('clients',None)
            else:manifest['clients']={'rows':rows,'baseline':baseline,'lease_requests':lease_requests,'lease_actions':lease_actions}
            message='Клиенты сохранены в общий черновик'
        elif action == 'route_apply':
            from route_batch import fingerprint
            import router_routes
            router_routes.check_token(data.get("route_token",[""])[0])
            rows = json.loads(data.get('draft', ['[]'])[0])
            baseline = data.get('baseline', [''])[0]
            import re
            if not re.fullmatch('[0-9a-f]{64}',baseline) or not isinstance(rows,list) or len(rows)>512:raise ValueError('Некорректный черновик маршрутов')
            if fingerprint(rows) == baseline: manifest.pop('routes', None)
            else: manifest['routes'] = {'rows': rows, 'baseline': baseline}
            message = 'Маршруты сохранены в черновик'
        elif action == 'dns_save':
            # Keep unfinished table rows too; full validation belongs to Apply.
            rows = json.loads(data.get('servers', ['[]'])[0])
            if not isinstance(rows, list) or len(rows) > 32: raise ValueError('Допустимо до 32 DNS-серверов')
            for row in rows:
                if (not isinstance(row,dict) or not all(isinstance(row.get(key),str) for key in ('id','name','address','route'))
                        or type(row.get('enabled')) is not bool or any(len(row[key])>2048 for key in ('id','name','address','route'))):
                    raise ValueError('Некорректная строка DNS')
            manifest['writing'] = True
            token = VIEW.set(manifest)
            try:
                capture_write(ROOT/'rules/dns-settings.json', json.dumps({'version':2, 'fake_ip':data.get('fake_ip',['0'])[-1]=='1', 'servers':rows},ensure_ascii=False).encode())
            finally: VIEW.reset(token)
            message = 'DNS сохранены в черновик'
        elif action.startswith('route_'):
            raise ValueError('Сохраните полный черновик маршрутов перед применением')
        else:
            previous = load()
            manifest['writing'] = True
            token = VIEW.set(manifest)
            protected = provider_refs(state_path(ROOT/'rules/service-routes.json'))
            try: message = execute({'path': '/action', 'body': raw})
            except Exception:
                VIEW.reset(token)
                clean_providers(manifest.get('obsolete_providers',[]),protected)
                clean_shadows(previous)
                raise
            else:
                names = provider_refs(state_path(ROOT/'rules/service-routes.json'))
                VIEW.reset(token)
                created = set(manifest.get('created_providers',[])) | (names-provider_refs(ROOT/'rules/service-routes.json'))
                clean_providers(created,names)
                manifest['created_providers'] = sorted(created & names)
        save(manifest)
        return {'ok': True, 'message': message, **status()}


def discard():
    with LOCK:
        manifest = load()
        if manifest.get('applying_job'):raise ValueError('Дождитесь завершения применения конфигурации')
        clean_providers(manifest.get('created_providers',[]))
        save({'files': {}, 'revision': manifest['revision']})
        return {'ok': True, **status()}


def apply(report=lambda _: None, after_commit=None, job_id=None, revision=None):
    from durable_io import write
    import route_batch
    import router_routes as rr
    with LOCK, rr.LOCK:
        manifest = load()
        if revision is not None and int(revision) != manifest['revision']: raise ValueError('Черновик изменился. Повторите применение.')
        if not status()['pending']: return 'Изменений конфигурации нет'
        for name, entry in manifest['files'].items():
            if digest(active_bytes(name)) != entry['baseline']: raise ValueError('Действующая конфигурация изменилась: '+name+'. Отмените черновик и повторите изменения.')
        routes = manifest.get('routes')
        current = route_batch.snapshot()
        if routes and routes['baseline'] != route_batch.fingerprint(current): raise ValueError('Действующие маршруты изменились. Отмените черновик.')
        client_plan=None
        if manifest.get('clients'):
            import client_batch
            client_plan=client_batch.plan(manifest['clients']['rows'],manifest['clients']['baseline'],
                                          lease_requests=manifest['clients'].get('lease_requests',[]),
                                          lease_actions=manifest['clients'].get('lease_actions',[]))
        normalized_dns = None
        if 'dns-settings.json' in manifest['files']:
            from dns_panel import parse_settings
            dns = json.loads((directory()/manifest['files']['dns-settings.json'].get('file','dns-settings.json')).read_bytes())
            normalized_dns = parse_settings({'servers':[json.dumps(dns['servers'])], 'fake_ip':['1' if dns['fake_ip'] else '0']})
        if job_id is not None:
            manifest['applying_job'] = job_id
            write(directory()/'manifest.json',json.dumps(manifest,ensure_ascii=False).encode())
        report('Установка настроек из общего черновика')
        for name,entry in manifest['files'].items(): write(ROOT/'rules'/name, (directory()/entry.get('file',name)).read_bytes())
        if normalized_dns is not None:write(ROOT/'rules/dns-settings.json',json.dumps(normalized_dns,ensure_ascii=False).encode())
        def prepare():
            import boot_config
            if client_plan:
                import client_policy
                client_policy.save(client_plan['desired'])
            report('Сборка правил и списков доменов')
            boot_config.run(['python3', str(ROOT/'rules/build-service-routes.py')])
            from domain_provider import update_split
            update_split(root=ROOT, source='ru-blocked-source.txt' in manifest['files'], offline=True)
        data = {'route_token': [rr.TOKEN],
                'baseline': [route_batch.fingerprint(current)],
                'draft': [json.dumps(routes['rows'] if routes else current)]}
        def committed(callback):
            def finish():
                callback()
                clean_providers(set(manifest.get('obsolete_providers',[])) | set(manifest.get('created_providers',[])))
                # New edits made after the job completed must survive cleanup.
                with LOCK:
                    if load()['revision'] == manifest['revision']: discard()
            if after_commit: after_commit(finish)
            else: finish()
        route_batch.apply(data, report, committed, job_id, prepare=prepare, force=True, client_plan=client_plan)
        return 'Конфигурация применена: DNS, основной маршрут, домены, правила, IP-маршруты и клиенты.'
