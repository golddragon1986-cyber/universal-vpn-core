"""RouterOS route management with fixed gateway and server-side LAN guards."""
import base64,html,ipaddress,json,os,re,secrets,socket,ssl,threading,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.parse import urlencode,quote
from durable_io import write

ROOT=Path('/etc/mihomo')
CONFIG=ROOT/'clients/routeros.json'
CACHE=ROOT/'rules/router-routes-observed.json'
JOURNAL=ROOT/'clients/router-route-operation.json'
TOKEN=secrets.token_urlsafe(32)
LOCK=threading.RLock()
PREFIX='universal-vpn: '
SERVICE_ROUTE=PREFIX+'service'
SERVICE_RETURN=PREFIX+'service return path'
SERVICE_STATE=ROOT/'rules/service-routes-routeros.state'
TARGETS=ROOT/'rules/route-targets.json'
AUTO_TABLE='uvpn-main-direct'
WAN_ROUTE='uvpn-main: WAN bypass'
FAKE=ipaddress.ip_network('198.18.0.0/16')
PRIVATE=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4')]

def settings():
    if auto_rest():
        return {'url':'https://172.31.41.1:8443/rest','gateway':'172.31.41.2',
                'user':'uvpn-main-panel','password':os.environ['MIHOMO_ROUTEROS_REST_PASSWORD'],
                'bypass_table':AUTO_TABLE}
    if not CONFIG.is_file():raise ValueError('Доступ из контейнера к RouterOS ещё не настроен')
    data=json.loads(CONFIG.read_text(encoding='utf-8-sig'))
    if data.get('url')!='https://172.31.41.1:8443/rest' or data.get('gateway')!='172.31.41.2':
        raise ValueError('Недопустимый адрес подключения RouterOS')
    return data

def auto_rest():
    return bool(os.environ.get('MIHOMO_ROUTEROS_REST_PASSWORD') and os.environ.get('MIHOMO_ROUTEROS_REST_CA'))

def configured():
    return auto_rest() or CONFIG.is_file()

class Router:
    def __init__(self):
        self.cfg=settings()
        self.context=ssl.create_default_context(cadata=os.environ['MIHOMO_ROUTEROS_REST_CA']) if auto_rest() else ssl.create_default_context(cafile=self.cfg['ca'])
    def call(self,path,method='GET',data=None):
        auth=base64.b64encode((self.cfg['user']+':'+self.cfg['password']).encode()).decode()
        req=Request(self.cfg['url']+'/'+path,data=None if data is None else json.dumps(data).encode(),method=method,
                    headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        try:
            with urlopen(req,context=self.context,timeout=8) as r:
                body=r.read();return json.loads(body) if body else None
        except Exception as e:raise RuntimeError('RouterOS не выполнил запрос '+method+' '+path.split('?')[0]) from e
    def routes(self):return self.call('ip/route')
    def addresses(self):return self.call('ip/address')
    def rules(self):return self.call('routing/rule')

def via_container(route):
    return route.get('gateway','').split('%')[0]=='172.31.41.2' and route.get('routing-table','main')=='main'
def yes(value):return value is True or value=='true' or value=='yes'
def mutable(route):
    return via_container(route) and not yes(route.get('dynamic',False)) and route.get('dst-address')!=str(FAKE) and route.get('comment')!=SERVICE_ROUTE
def rid(value):
    if not re.fullmatch(r'\*[0-9A-Fa-f]+',str(value)):raise ValueError('Недопустимый идентификатор маршрута')
    return quote(value,safe='*')

def validate_destination(value,addresses=(),server_ips=()):
    try:net=ipaddress.ip_network(value.strip(),strict=True)
    except ValueError:raise ValueError('Укажите IPv4-сеть с правильной маской, например 203.0.113.0/24')
    if net.version!=4:raise ValueError('Поддерживаются только IPv4-маршруты')
    protected=PRIVATE+[FAKE]
    for x in addresses:
        try:protected.append(ipaddress.ip_interface(x['address']).network)
        except (ValueError,KeyError):raise ValueError('Не удалось проверить адреса роутера')
    for x in ('8.8.8.8','1.1.1.1',*server_ips):
        try:protected.append(ipaddress.ip_network(str(x)+'/32'))
        except ValueError:raise ValueError('Не удалось проверить адрес VPN-сервера')
    if net.prefixlen==0 or any(net.overlaps(x) for x in protected):
        raise ValueError('Маршрут затрагивает локальную или служебную сеть, адрес роутера, VPN-сервера либо DNS. Доступ к панели должен сохраняться.')
    if not net.network_address.is_global or not net.broadcast_address.is_global:
        raise ValueError('Через контейнер можно направлять только публичные IPv4-сети')
    return str(net)

def server_ips():
    result=[]
    path=ROOT/'clients/sing-box.json'
    if path.exists():
        for out in json.loads(path.read_text()).get('outbounds',[]):
            if out.get('server'):
                result.extend(x[4][0] for x in socket.getaddrinfo(out['server'],None,socket.AF_INET))
    path=ROOT/'rules/user-proxies.yaml'
    if path.exists():
        # The managed provider is JSON (also valid YAML).
        for p in json.loads(path.read_text()).get('proxies',[]):
            if p.get('server'):result.extend(x[4][0] for x in socket.getaddrinfo(p['server'],None,socket.AF_INET))
    return list(set(result))

def snapshot():
    live=configured()
    if live:
        r=Router();data={'routes':r.routes(),'addresses':r.addresses(),'observed':time.strftime('%Y-%m-%d %H:%M:%S')}
        write(CACHE,json.dumps(data).encode())
    elif CACHE.exists():data=json.loads(CACHE.read_text(encoding='utf-8-sig'))
    else:data={'routes':[],'addresses':[],'observed':''}
    return {'routes':[x for x in data['routes'] if via_container(x)],'live':live,'observed':data['observed']}


_COUNT_CACHE = (0, None)
_COUNT_LOCK = threading.Lock()

def route_count():
    """Actual RouterOS routes through the container, without domain rules."""
    global _COUNT_CACHE
    with _COUNT_LOCK:
        now=time.monotonic()
        if now-_COUNT_CACHE[0]<5:return _COUNT_CACHE[1]
        try:
            if not configured():raise RuntimeError('RouterOS недоступен')
            count=sum(via_container(row) for row in Router().routes())
        except Exception:
            count=_COUNT_CACHE[1]
            if count is None and CACHE.exists():
                try:count=sum(via_container(row) for row in json.loads(CACHE.read_bytes())['routes'])
                except (ValueError,KeyError):pass
        _COUNT_CACHE=(now,count)
        return count

def check_token(value):
    if not secrets.compare_digest(str(value),TOKEN):raise ValueError('Обновите вкладку маршрутов перед изменением')

def container_files():
    return [ROOT/'rules/panel-managed-template.yaml',ROOT/'default_config.yaml',ROOT/'default_config_candidate.yaml',ROOT/'template/default_config.yaml',ROOT/'rules/router-ip.yaml',ROOT/'rules/client-settings.json',TARGETS]

def service_networks(text):
    block = text.partition('# BEGIN SERVICE-ROUTES')[2].partition('# END SERVICE-ROUTES')[0]
    nets=set(re.findall(r'^  - IP-CIDR,([^,\n]+),[^,\n]+,no-resolve$', block, re.M))
    nets.update(net for net,value in read_targets().items() if value.get('override') and value.get('enabled',True))
    return nets

def with_service_tun_routes(text, template):
    pattern = r'(?m)^  route-address:\n((?:^    - .*\n)*)'
    baseline = re.search(pattern, template)
    entries = baseline[1].splitlines(keepends=True) if baseline else []
    fake_entry = f'    - {FAKE}\n'
    if fake_entry not in entries:
        entries.insert(0, fake_entry)
    for net in sorted(service_networks(text)):
        line = f'    - {net}\n'
        if line not in entries:
            entries.append(line)
    route_addresses = '  route-address:\n'+''.join(entries)
    updated, count = re.subn(pattern, lambda _: route_addresses, text, count=1)
    if count:
        return updated
    return re.sub(r'(?m)^tun:\n', lambda _: 'tun:\n'+route_addresses, text, count=1)

def sync_service_routes(networks):
    if not configured():
        return
    with LOCK:
        router = Router()
        routes = router.routes()
        retired=read_targets()
        for row in routes:
            value=retired.get(row.get('dst-address'),{})
            if mutable(row) and value.get('unavailable') and not value.get('enabled',True) and not yes(row.get('disabled')):
                router.call('ip/route/'+rid(row['.id']),'PATCH',{'disabled':True})
                row['disabled']=True
        if auto_rest() and not any(via_container(r) and r.get('dst-address') == str(FAKE) and yes(r.get('active')) for r in routes):
            networks = set()
        rules = router.rules()
        managed_routes = {r['dst-address']:r for r in routes if via_container(r) and r.get('comment') == SERVICE_ROUTE}
        managed_rules = {r['dst-address']:r for r in rules if r.get('src-address') == '172.31.41.2/32' and r.get('comment') == SERVICE_RETURN}
        if not (networks or managed_routes or managed_rules):
            SERVICE_STATE.unlink(missing_ok=True)
            return
        table = router.cfg['bypass_table']
        if networks:
            ensure_wan_route(router, routes)
            routes = router.routes() if auto_rest() else routes
            if not any(r.get('routing-table') == table and r.get('dst-address') == '0.0.0.0/0' and yes(r.get('active')) for r in routes):
                raise ValueError('Настройте активный маршрут по умолчанию в таблице обхода RouterOS')
            addresses, servers = router.addresses(), server_ips()
            for net in networks:
                validate_destination(net, addresses, servers)
                if any(r.get('dst-address') == net and r.get('routing-table','main') == 'main' and r.get('comment') != SERVICE_ROUTE for r in routes):
                    raise ValueError('В RouterOS уже существует отдельный маршрут '+net)
                if any(r.get('dst-address') == net and r.get('src-address') == '172.31.41.2/32' and r.get('comment') != SERVICE_RETURN for r in rules):
                    raise ValueError('В RouterOS уже существует отдельное правило для '+net)
        changes = []

        def add(path, data):
            result = router.call(path,'PUT',data)
            changes.append((path+'/'+rid(result['.id']), 'DELETE', None))

        def remove(path, row, fields):
            router.call(path+'/'+rid(row['.id']),'DELETE')
            changes.append((path, 'PUT', {key:row[key] for key in fields if key in row}))

        route_fields = ('dst-address','gateway','routing-table','distance','comment')
        rule_fields = ('dst-address','src-address','table','action','comment')
        if not SERVICE_STATE.exists():
            write(SERVICE_STATE,b'pending\n')
        try:
            for net in sorted(managed_routes.keys() - networks):
                remove('ip/route', managed_routes[net], route_fields)
            for net in sorted(managed_rules.keys() - networks):
                remove('routing/rule', managed_rules[net], rule_fields)
            for net in sorted(networks - managed_rules.keys()):
                add('routing/rule', {'src-address':'172.31.41.2/32','dst-address':net,'action':'lookup-only-in-table','table':table,'comment':SERVICE_RETURN})
            for net in sorted(networks - managed_routes.keys()):
                add('ip/route', {'dst-address':net,'gateway':'172.31.41.2','routing-table':'main','distance':'100','comment':SERVICE_ROUTE})
        except Exception:
            for path, method, data in reversed(changes):
                router.call(path, method, data)
            raise
        if not networks:
            SERVICE_STATE.unlink(missing_ok=True)

def ensure_wan_route(router, routes):
    if not auto_rest():
        return
    default = next((r for r in routes if r.get('routing-table','main') == 'main' and r.get('dst-address') == '0.0.0.0/0' and yes(r.get('active')) and r.get('immediate-gw')), None)
    if default is None:
        raise ValueError('Не найден активный маршрут WAN по умолчанию')
    gateway = default['immediate-gw']
    current = next((r for r in routes if r.get('routing-table') == AUTO_TABLE and r.get('comment') == WAN_ROUTE), None)
    if current is None:
        router.call('ip/route','PUT',{'dst-address':'0.0.0.0/0','gateway':gateway,'routing-table':AUTO_TABLE,'comment':WAN_ROUTE})
    elif current.get('gateway') != gateway:
        router.call('ip/route/'+rid(current['.id']),'PATCH',{'gateway':gateway})

def watch_service_routes():
    import fcntl
    last_error = None
    while True:
        try:
            candidate = ROOT/'default_config_candidate.yaml'
            with open(str(candidate)+'.apply.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with LOCK:
                    networks = service_networks(candidate.read_text()) if candidate.exists() else set()
                    if networks or SERVICE_STATE.exists():
                        sync_service_routes(networks)
            last_error = None
        except Exception as error:
            message = str(error)
            if message != last_error:
                print('RouterOS service routes pending: '+message,flush=True)
            last_error = message
        time.sleep(20)

def read_targets():
    data=json.loads(TARGETS.read_text()) if TARGETS.exists() else {}
    return {net:({'target':value or 'SELECTOR','metric':100,'enabled':True,'override':False} if isinstance(value,str) else {**value,'target':value.get('target') or 'SELECTOR'}) for net,value in data.items()}


def checked_metric(value):
    if isinstance(value,(bool,float)):raise ValueError('Укажите целую метрику от 1 до 254')
    try: value=int(value)
    except (ValueError,TypeError): raise ValueError('Укажите метрику от 1 до 254')
    if not 1<=value<=254: raise ValueError('Укажите метрику от 1 до 254')
    return value


def target_choices():
    from dns_panel import route_choices
    return route_choices()


def default_target():
    return 'SELECTOR'


def checked_target(value):
    value=value or default_target()
    if value not in target_choices(): raise ValueError('Выберите доступный маршрут')
    return value


def sync_container(routes,reload=True):
    import boot_config,os
    nets=sorted({r['dst-address'] for r in routes if via_container(r) and r.get('comment')!=SERVICE_ROUTE and not yes(r.get('disabled'))})
    if str(FAKE) not in nets:raise ValueError('Отсутствует защищённый маршрут Fake IP')
    template=ROOT/'rules/panel-managed-template.yaml';text=template.read_text()
    route_addresses='  route-address:\n'+''.join('    - '+n+'\n' for n in nets)
    text,count=re.subn(r'(?m)^  route-address:\n(?:^    - .*\n)*', route_addresses,text,count=1)
    if count==0:
        text,count=re.subn(r'(?m)^tun:\n','tun:\n'+route_addresses,text,count=1)
        if count==0:raise ValueError('Не найден раздел TUN')
    if '  CONTAINER-ROUTES:\n' not in text:
        text=text.replace('rule-providers:\n','rule-providers:\n  CONTAINER-ROUTES:\n    type: file\n    behavior: classical\n    format: yaml\n    path: /etc/mihomo/rules/router-ip.yaml\n',1)
        text=text.replace('rules:\n','rules:\n  - RULE-SET,CONTAINER-ROUTES,SELECTOR\n',1)
    text=text.replace('  - RULE-SET,TELEGRAM-IP,SELECTOR\n','')
    targets=read_targets()
    manual={r['dst-address']:r for r in routes if mutable(r)}
    targets={net:value for net,value in targets.items() if value.get('override') or net in manual}
    for net,row in manual.items():
        value=targets.setdefault(net,{'target':default_target(),'metric':100,'override':False})
        value.update(enabled=not yes(row.get('disabled')),label=row.get('comment','').removeprefix(PREFIX))
    text=re.sub(r'(?ms)^  # BEGIN MANUAL-NETWORK-ROUTES\n.*?^  # END MANUAL-NETWORK-ROUTES\n','',text)
    text=text.replace('  - RULE-SET,CONTAINER-ROUTES,SELECTOR\n','')
    write(TARGETS,json.dumps(targets,ensure_ascii=False).encode())
    write(ROOT/'rules/router-ip.yaml',('payload:\n'+''.join('  - IP-CIDR,'+n+',no-resolve\n' for n in nets if n!=str(FAKE))).encode())
    write(template,text.encode())
    settings=json.loads((ROOT/'rules/routing-settings.json').read_text())
    runtime,_=boot_config.compose(text,settings)
    if not reload:
        import subprocess,tempfile
        with tempfile.NamedTemporaryFile(mode='w',dir=ROOT,suffix='.yaml') as f:
            f.write(runtime);f.flush()
            result=subprocess.run(['mihomo','-t','-d',str(ROOT),'-f',f.name],capture_output=True,timeout=30)
            if result.returncode:raise RuntimeError('Ядро отклонило конфигурацию маршрутов')
    for n in ('default_config.yaml','default_config_candidate.yaml'):write(ROOT/n,runtime.encode())
    write(ROOT/'template/default_config.yaml',text.encode())
    if reload:
        apply = boot_config.apply_module()
        apply.put_config()
        from routing_panel import set_global_proxy
        set_global_proxy(settings['main_proxy'])
        apply.save_last_good()

def intent(action,route,rules):
    write(JOURNAL,json.dumps({'action':action,'route':route,'rules':rules,'committed':False}).encode())
def committed():
    data=json.loads(JOURNAL.read_text());data['committed']=True;write(JOURNAL,json.dumps(data).encode())
def clear_intent():
    if JOURNAL.exists():JOURNAL.unlink()

def recover_pending():
    if not JOURNAL.exists():return
    data=json.loads(JOURNAL.read_text())
    if data['action']=='route_apply':
        from route_batch import recover
        recover(data);return
    router=Router();route=data['route'];net=route['dst-address']
    if not data.get('committed'):
        if data['action'] in {'route_toggle','route_metric'}:
            router.call('ip/route/'+rid(route['.id']),'PATCH',{'distance':str(route.get('distance',100)),'disabled':yes(route.get('disabled'))})
        elif data['action']=='route_add':
            for x in router.routes():
                if via_container(x) and x.get('dst-address')==net and x.get('comment')==route.get('comment'):
                    router.call('ip/route/'+rid(x['.id']),'DELETE')
            previous={x['.id'] for x in data['rules']}
            for x in router.rules():
                if x.get('.id') not in previous and x.get('dst-address')==net and x.get('src-address')=='172.31.41.2/32' and x.get('comment')==PREFIX+'return path':router.call('routing/rule/'+rid(x['.id']),'DELETE')
        else:
            existing=router.rules()
            for rule in data['rules']:
                if not any(x.get('dst-address')==net and x.get('src-address')==rule.get('src-address') and x.get('table')==rule.get('table') for x in existing):router.call('routing/rule','PUT',{k:rule[k] for k in ('src-address','dst-address','action','table','comment') if k in rule})
            if not any(via_container(x) and x.get('dst-address')==net for x in router.routes()):router.call('ip/route','PUT',{k:route[k] for k in ('dst-address','gateway','routing-table','distance','comment') if k in route})
    sync_container(router.routes(),reload=False);clear_intent()

def saved_files():return {p:p.read_bytes() if p.exists() else None for p in container_files()}
def rollback_files(before):
    import boot_config
    for p,raw in before.items():
        if raw is not None:write(p,raw)
        elif p.exists():p.unlink()
    boot_config.apply_module().put_config()
    from routing_panel import read_settings,set_global_proxy
    set_global_proxy(read_settings()['main_proxy'])

def change(action,data):
    check_token(data.get('route_token',[''])[0])
    with LOCK:
        router=Router();routes=router.routes();before=saved_files()
        bypass_comment=PREFIX+'return path'
        if action in {'route_target','route_toggle','route_metric','route_delete'} and data.get('route_id',[''])[0].startswith('local:'):
            net=data['route_id'][0][6:];targets=read_targets();value=targets.get(net)
            if not value or not value.get('override'): raise ValueError('Ручная запись не найдена')
            if action=='route_target':value['target']=checked_target(data.get('target',[''])[0])
            elif action=='route_metric':value['metric']=checked_metric(data.get('metric',[''])[0])
            elif action=='route_toggle':value['enabled']=not value.get('enabled',True)
            else:del targets[net]
            try:
                write(TARGETS,json.dumps(targets,ensure_ascii=False).encode());sync_container(routes)
                sync_service_routes(service_networks((ROOT/'default_config_candidate.yaml').read_text()))
            except Exception:
                rollback_files(before);raise
            return 'Ручная запись '+net+' обновлена'
        if action in {'route_target','route_toggle','route_metric'}:
            key=data.get('route_id',[''])[0];rid(key)
            route=next((r for r in routes if r.get('.id')==key),None)
            if not route or not mutable(route): raise ValueError('Маршрут управляется правилом или защищён')
            targets=read_targets();value=targets.setdefault(route['dst-address'],{'target':default_target(),'metric':100,'enabled':not yes(route.get('disabled')),'override':False})
            patch={}
            if action=='route_target':value['target']=checked_target(data.get('target',[''])[0])
            elif action=='route_toggle':
                value['enabled']=yes(route.get('disabled'));patch['disabled']=not value['enabled']
            else:
                value['metric']=checked_metric(data.get('metric',[''])[0]);patch['distance']=str(value['metric'])
            if patch:intent(action,route,[])
            try:
                if patch:router.call('ip/route/'+rid(key),'PATCH',patch)
                write(TARGETS,json.dumps(targets,ensure_ascii=False).encode())
                sync_container(router.routes() if patch else routes)
            except Exception:
                if patch:router.call('ip/route/'+rid(key),'PATCH',{'distance':str(route.get('distance',100)),'disabled':yes(route.get('disabled'))})
                rollback_files(before);clear_intent();raise
            if patch:committed()
            return 'Маршрут '+route['dst-address']+' обновлён'
        if action=='route_add':
            net=validate_destination(data.get('destination',[''])[0],router.addresses(),server_ips())
            existing=next((x for x in routes if x.get('dst-address')==net and x.get('routing-table','main')=='main'),None)
            label=data.get('label',['Маршрут'])[0].strip()[:80] or 'Маршрут'
            if any(ord(x)<32 for x in label):raise ValueError('Недопустимый комментарий')
            target=checked_target(data.get('target',[default_target()])[0])
            metric=checked_metric(data.get('metric',['100'])[0])
            from service_routes_panel import read_services
            from routes_table_ui import service_networks as declared_networks
            is_service=(existing and existing.get('comment')==SERVICE_ROUTE) or any(net==str(ipaddress.ip_network(n)) for item in read_services() for n in declared_networks(item))
            if net in read_targets() or (existing and not is_service):raise ValueError('Такая ручная запись уже существует')
            if is_service:
                targets=read_targets();targets[net]={'target':target,'metric':metric,'enabled':True,'override':True,'label':label}
                try:
                    write(TARGETS,json.dumps(targets,ensure_ascii=False).encode());sync_container(routes)
                    sync_service_routes(service_networks((ROOT/'default_config_candidate.yaml').read_text()))
                except Exception:
                    rollback_files(before);raise
                return 'Добавлена ручная запись '+net+' с метрикой '+str(metric)
            route={'dst-address':net,'gateway':'172.31.41.2','routing-table':'main','distance':str(metric),'comment':PREFIX+label}
            rule={'src-address':'172.31.41.2/32','dst-address':net,'action':'lookup-only-in-table','table':router.cfg['bypass_table'],'comment':bypass_comment}
            made_rule=None;made_route=None
            ensure_wan_route(router, routes)
            intent(action,route,router.rules())
            try:
                targets=read_targets();targets[net]={'target':target,'metric':metric,'enabled':True,'override':False,'label':label};write(TARGETS,json.dumps(targets,ensure_ascii=False).encode())
                sync_container(routes+[route])
                made_rule=router.call('routing/rule','PUT',rule)
                made_route=router.call('ip/route','PUT',route)
                if not any(x.get('dst-address')==net and via_container(x) for x in router.routes()):raise RuntimeError('Маршрут не подтверждён RouterOS')
            except Exception:
                if made_route:router.call('ip/route/'+rid(made_route['.id']),'DELETE')
                if made_rule:router.call('routing/rule/'+rid(made_rule['.id']),'DELETE')
                rollback_files(before);clear_intent();raise
            committed()
            return 'Добавлен маршрут '+net+' через контейнер'
        if action=='route_delete':
            key=data.get('route_id',[''])[0];rid(key)
            route=next((x for x in routes if x.get('.id')==key),None)
            if not route or not mutable(route):raise ValueError('Этот маршрут нельзя удалить из панели')
            net=route['dst-address'];rules=[x for x in router.rules() if x.get('src-address')=='172.31.41.2/32' and x.get('dst-address')==net and x.get('table')==router.cfg['bypass_table'] and (x.get('comment','').startswith(PREFIX) or x.get('comment')=='4011 Telegram DIRECT return path')]
            intent(action,route,rules)
            router.call('ip/route/'+rid(key),'DELETE')
            removed=[]
            try:
                sync_container([x for x in routes if x.get('.id')!=key])
                for rule in rules:
                    router.call('routing/rule/'+rid(rule['.id']),'DELETE');removed.append(rule)
            except Exception:
                rollback_files(before)
                for rule in removed:router.call('routing/rule','PUT',{k:rule[k] for k in ('src-address','dst-address','action','table','comment') if k in rule})
                router.call('ip/route','PUT',{k:route[k] for k in ('dst-address','gateway','routing-table','distance','comment') if k in route})
                clear_intent()
                raise
            committed()
            return 'Удалён маршрут '+net
        raise ValueError('Неизвестное действие')

def migrate_route_metrics():
    if not configured(): return
    with LOCK:
        router=Router();routes=router.routes();targets=read_targets()
        for route in routes:
            if not via_container(route) or route.get('dst-address')==str(FAKE):continue
            if route.get('comment')==SERVICE_ROUTE:
                metric=100
            elif mutable(route):
                value=targets.setdefault(route['dst-address'],{'target':default_target(),'metric':100,'override':False})
                value.update(enabled=not yes(route.get('disabled')),label=route.get('comment','').removeprefix(PREFIX))
                metric=value.get('metric',100)
            else:continue
            if str(route.get('distance'))!=str(metric):router.call('ip/route/'+rid(route['.id']),'PATCH',{'distance':str(metric)})
        write(TARGETS,json.dumps(targets,ensure_ascii=False).encode())


def migrate_telegram():
    with LOCK:
        router=Router();routes=router.routes()
        for route in routes:
            if via_container(route) and route.get('comment')=='4011 Telegram static via Mihomo':
                router.call('ip/route/'+rid(route['.id']),'PATCH',{'comment':PREFIX+'Telegram'})
        sync_container(router.routes())

def render(params=None):
    from routes_table_ui import render_table
    return render_table(params or {})
