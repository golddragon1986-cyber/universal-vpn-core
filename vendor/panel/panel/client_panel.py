from ui_i18n import text as _ui, message as _ui_message
"""Source networks selected by RouterOS container routing, separate from destinations."""
import hashlib
import html
import ipaddress
import json
import time
from pathlib import Path
from urllib.parse import urlencode
import router_routes as rr

CACHE = rr.ROOT/'rules/container-clients-observed.json'
MARKER = 'uvpn-main: clients list marker'
MANAGEMENT_LIST = 'uvpn-main-management'


def address(value):
    value = str(value).strip()
    if '-' in value:
        first, last = map(ipaddress.IPv4Address, value.split('-',1))
        if int(first)>int(last):raise ValueError('Начало диапазона должно быть меньше конца')
        if first.is_unspecified or last.is_multicast or int(last)>=0xe0000000:raise ValueError('Укажите адреса клиентов IPv4')
        return str(first)+'-'+str(last)
    net = ipaddress.ip_network(value,strict=True)
    if net.version!=4 or net.prefixlen==0 or net.network_address.is_unspecified or net.overlaps(ipaddress.ip_network('224.0.0.0/3')):
        raise ValueError('Укажите IPv4-адрес или сеть клиентов')
    return str(net.network_address) if net.prefixlen==32 else str(net)


def contains(value, query):
    try:
        if '-' in value:
            first,last=map(ipaddress.IPv4Address,value.split('-',1))
            search=ipaddress.ip_network(query,strict=False)
            return search.version==4 and int(first)<=int(search.broadcast_address) and int(search.network_address)<=int(last)
        return ipaddress.ip_network(value,strict=False).overlaps(ipaddress.ip_network(query,strict=False))
    except ValueError:return False


def editable(row):
    if rr.yes(row.get('dynamic')) or row.get('comment')==MARKER:return False
    try:address(row['address']);return True
    except (ValueError,KeyError):return False


def model(row):
    return {'id':row['.id'],'list':row['list'],'address':row['address'],
            'label':row.get('comment',''),'enabled':not rr.yes(row.get('disabled'))}


def rows_fingerprint(rows):
    fields=('id','list','address','label','enabled','name','route','dhcp_owner')
    clean=[{key:row.get(key, 'RULES' if key=='route' else '') for key in fields} for row in rows]
    return hashlib.sha256(json.dumps(sorted(clean,key=lambda x:x['id']),sort_keys=True).encode()).hexdigest()


def fingerprint(state):
    return hashlib.sha256(json.dumps({'rows':rows_fingerprint(state['rows']),
        'bindings':state['bindings'],'management':state['management_bindings'],'lists':state['lists'],'protected':state['protected']},sort_keys=True).encode()).hexdigest()


def read_state(router=None, *, cache=True):
    router=router or rr.Router()
    entries=router.call('ip/firewall/address-list')
    nat=router.call('ip/firewall/nat')
    filters=router.call('ip/firewall/filter')
    bindings=[];management=[];lists={};protected=set()
    for rule in nat:
        if rule.get('action')!='dst-nat' or rule.get('to-addresses')!='172.31.41.2':continue
        name=rule.get('src-address-list','')
        if not name or name.startswith('!'):continue
        if rule.get('to-ports') in {'9091','9090'}:
            protected.add(name);management.append({'path':'ip/firewall/nat','id':rule['.id'],'list':name})
        if rule.get('chain')!='dstnat' or rule.get('to-ports','53')!='53' or rule.get('dst-port')!='53':continue
        interfaces=rule.get('in-interface-list') or rule.get('in-interface') or 'Все'
        lists.setdefault(name,{'interfaces':[],'active':False})
        if interfaces not in lists[name]['interfaces']:lists[name]['interfaces'].append(interfaces)
        lists[name]['active'] |= not rr.yes(rule.get('disabled')) and not rr.yes(rule.get('invalid'))
        bindings.append({'path':'ip/firewall/nat','id':rule['.id'],'list':name})
    for rule in filters:
        name=rule.get('src-address-list','')
        if name and rule.get('action')=='accept' and rule.get('comment','').startswith('uvpn-main: base'):
            protected.add(name);management.append({'path':'ip/firewall/filter','id':rule['.id'],'list':name})
        if name in lists and rule.get('chain')=='forward' and rule.get('action')=='accept' and rule.get('out-interface')=='uvpn-main-br':
            bindings.append({'path':'ip/firewall/filter','id':rule['.id'],'list':name})
    if not lists:
        name='uvpn-main-lan'
        lists[name]={'interfaces':['LAN'],'active':False}
    raw=[row for row in entries if row.get('list') in lists]
    from client_policy import enrich
    state={'rows':enrich([model(row) for row in raw if editable(row)]),
           'readonly':[model(row) for row in raw if not editable(row) and row.get('comment')!=MARKER],
           'raw':raw,'lists':lists,'bindings':sorted(bindings,key=lambda x:(x['path'],x['id'])),
           'management_bindings':sorted([item for item in management if item['list'] in lists],key=lambda x:(x['path'],x['id'])),
           'protected':sorted(protected & lists.keys()),'live':True,'observed':time.strftime('%Y-%m-%d %H:%M:%S')}
    if cache:
        from durable_io import write
        write(CACHE,json.dumps(state,ensure_ascii=False).encode())
    return state


def snapshot():
    try:return read_state(),''
    except Exception as error:
        if CACHE.exists():
            data=json.loads(CACHE.read_bytes());data['live']=False;return data,str(error)
        return {'rows':[],'readonly':[],'raw':[],'lists':{},'bindings':[],'management_bindings':[],'protected':[],'live':False,'observed':''},str(error)


def render(params):
    from configuration_draft import load
    state,error=snapshot()
    from client_policy import choices
    seed={'state':state,'baseline':fingerprint(state),'rows_baseline':rows_fingerprint(state['rows']),
          'pending':load().get('clients'),'token':rr.TOKEN,'routes':choices(),
          'view':{key:params.get(key,[''])[0] for key in ('q','source','status')}}
    data=json.dumps(seed,ensure_ascii=False).replace('<','\\u003c')
    e=lambda x:html.escape(str(x),quote=True)
    options=''.join('<option value="'+e(name)+'">'+e(name)+'</option>' for name in state['lists'])
    dhcp_markup = _ui('''<section class="routing-panel dhcp-panel" id="dhcp-clients">
<h2>Клиенты DHCP-сервера RouterOS</h2>
<p>Аренды читаются из RouterOS. Чтобы задать маршрут устройству с динамическим адресом, закрепите аренду в общем черновике.</p>
<div class="dhcp-toolbar"><p id="dhcp-status" role="status">Загрузка DHCP-аренд…</p><button type="button" id="dhcp-refresh">Обновить</button></div>
<form id="dhcp-search" class="clients-search"><input name="q" placeholder="Имя, IP или MAC" aria-label="Поиск DHCP-клиента">
<select name="server" aria-label="DHCP-сервер"><option value="">Все DHCP-серверы</option></select>
<select name="status" aria-label="Состояние DHCP-клиента"><option value="">Все состояния</option><option value="active">Активные</option><option value="off">Неактивные</option></select>
<select name="type" aria-label="Тип DHCP-аренды"><option value="">Все аренды</option><option value="static">Закреплённые</option><option value="dynamic">Динамические</option></select>
<button>Найти</button><button type="button" id="dhcp-search-reset">Сбросить поиск</button></form>
<div class="dhcp-table-wrap"><table class="dhcp-table"><thead><tr>
<th>Устройство</th><th>IP-адрес</th><th>MAC</th><th>Состояние</th><th>Маршрут</th><th>Действия</th>
</tr></thead><tbody id="dhcp-table-body"></tbody></table></div>
</section>''')
    page = _ui('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Клиенты</title></head><body>\n<section class="routing-panel clients-panel"><h2>Клиенты контейнера</h2>\n<p>Сети и адреса источников, для которых RouterOS направляет DNS-запросы и трафик правил через контейнер.</p>\n<p class="clients-error" role="alert">')+e(_ui_message(error))+_ui('</p>\n<h3>Список клиентов</h3><form id="clients-search" class="clients-search"><input name="q" placeholder="IP, сеть или название" aria-label="Поиск клиента">\n<select name="source" aria-label="Источник клиентов"><option value="">Все источники</option>')+options+_ui('</select>\n<select name="status" aria-label="Статус клиента"><option value="">Все статусы</option><option value="enabled">Включённые</option><option value="disabled">Отключённые</option></select>\n<button>Найти</button><button type="button" id="clients-search-reset">Сбросить поиск</button></form>\n<p id="clients-inline-status" role="status"></p><p id="clients-count"></p><div class="clients-scroll"><table class="clients-table"><thead><tr><th>Сеть / адрес</th><th>Внутреннее имя</th><th>Маршрут</th><th>Действия</th></tr></thead><tbody id="clients-table-body"></tbody></table></div>\n<button type="button" id="client-add-row">Добавить клиента</button><div id="clients-pages"></div><p class="hint">Изменения ожидают общей кнопки «Применить конфигурацию». Более узкая включённая сеть имеет приоритет. «По общим правилам» сохраняет обычную обработку; отдельный канал направляет весь внешний трафик клиента в него; «Через RouterOS» исключает перехват DNS и контейнер. Локальные сети сохраняют прямую доступность. Маршрут для динамической DHCP-аренды можно настроить после её закрепления.</p>\n</section><script type="application/json" id="clients-data">')+data+'''</script><style>
.clients-search,#client-add-form{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:16px 0}
.clients-search input,#client-add-form input{flex:1;min-width:160px}.clients-search :is(input,select,button),#client-add-form :is(input,select,button){height:40px;margin:0;box-sizing:border-box}
.clients-scroll{overflow:auto}.clients-table{width:100%;border-collapse:collapse}.clients-table :is(th,td){padding:10px;border-bottom:1px solid var(--ui-border);text-align:left;vertical-align:middle}.clients-table input{width:160px;max-width:100%;height:40px;margin:0;box-sizing:border-box}.clients-table td:first-child input{width:185px}.clients-table button{display:inline-block;margin:0 6px 0 0;white-space:nowrap}.clients-table .client-pending{background:rgba(72,106,170,.12)}.clients-table .client-removed{opacity:.6}#clients-pages{display:flex;gap:10px;align-items:center;margin-top:16px}.clients-error{color:#ee8d8d}.clients-table small{display:block;color:var(--ui-muted);font-size:12px}.clients-panel .hint{margin-top:16px}
.clients-table{min-width:940px}.clients-table input{width:130px}.clients-table td:first-child input{width:155px}.clients-table td:nth-child(3){min-width:120px;font-size:12px}.clients-table select{width:175px;height:40px;margin:0}.clients-table td:nth-child(4){white-space:nowrap}.clients-table td:last-child{min-width:160px}.clients-table td:last-child button{padding:10px 9px;margin-right:4px}.clients-table :is(th,td){padding:9px 6px}
</style><script>'''+_ui(Path(__file__).with_suffix('.js').read_text(encoding='utf-8'))+'''</script></body></html>'''
    return page.replace('<script type="application/json" id="clients-data">',
                        dhcp_markup + '<script type="application/json" id="clients-data">', 1)
