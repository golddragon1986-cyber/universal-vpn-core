from ui_i18n import text as _ui, message as _ui_message
"""RouterOS local DNS authority, queried directly even for pinned VPN clients."""
import ipaddress
import json
import re
import threading
import logging
import html
from datetime import datetime, timezone
from pathlib import Path
from durable_io import write
import router_routes as rr

FILE=rr.ROOT/'rules/routeros-local-dns.json'
ROUTER='172.31.41.1'

def read():
    return json.loads(FILE.read_bytes()) if FILE.exists() else []

def refresh():
    router=rr.Router();static=router.call('ip/dns/static')
    try:forwarders=router.call('ip/dns/forwarders')
    except RuntimeError:forwarders=[]
    groups={row.get('name'):row for row in forwarders};zones=[]
    for row in static:
        name=row.get('name','').strip().rstrip('.').lower()
        supported=bool(re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)*',name)) and not row.get('regexp')
        upstreams=[]
        if row.get('type')=='FWD':
            target=row.get('forward-to','')
            candidates=groups.get(target,{}).get('dns-servers',target)
            candidates=candidates if isinstance(candidates,list) else candidates.split(',')
            addresses=[]
            for value in candidates:
                try:
                    addr=ipaddress.ip_address(value.strip())
                    if addr.version==4 and str(addr) not in {'127.0.0.1','172.31.41.2'}:addresses.append(str(addr))
                except ValueError:pass
            upstreams=addresses
        # RouterOS owns the FWD policy and has the necessary AD return path.
        # Preserve the container's identity only for ordinary routed DNS; local
        # zones go to the router resolver, never to a public fallback here.
        value=row.get('forward-to','') if row.get('type')=='FWD' else next((str(row[key]) for key in ('address','cname','text','mx-exchange','srv-target','ns','ptr') if row.get(key)), '—')
        zones.append({'name':name or row.get('regexp',''),'subdomains':rr.yes(row.get('match-subdomain')),'servers':[ROUTER],
                      'upstreams':upstreams,'type':row.get('type','A'),'value':value,
                      'enabled':not rr.yes(row.get('disabled')),'supported':supported})
    write(FILE,json.dumps(zones,ensure_ascii=False).encode())
    return zones

def match(name):
    name=name.rstrip('.').lower()
    matches=[row for row in read() if row.get('enabled',True) and row.get('supported',True)
             and (name==row['name'] or row['subdomains'] and name.endswith('.'+row['name']))]
    return max(matches,key=lambda row:len(row['name'])) if matches else None

def start():
    def watch():
        while True:
            try:refresh()
            except Exception as error:logging.warning('Local RouterOS DNS zones: %s',error)
            threading.Event().wait(60)
    threading.Thread(target=watch,name='local-dns-zones',daemon=True).start()

def configure(text):
    """Local names precede domain rule FakeIP/reject policies in Mihomo."""
    from dns_panel import dns_section
    zones=[row for row in read() if row.get('enabled',True) and row.get('supported',True)]
    if not zones:return text
    section=dns_section(text);block=section[0]
    block=re.sub(r'(?ms)^    # BEGIN LOCAL-DNS-ZONES\n.*?^    # END LOCAL-DNS-ZONES\n','',block)
    filters=''.join('    - '+('DOMAIN-SUFFIX' if row['subdomains'] else 'DOMAIN')+','+row['name']+',real-ip\n' for row in zones)
    block=block.replace('  fake-ip-filter:\n','  fake-ip-filter:\n    # BEGIN LOCAL-DNS-ZONES\n'+filters+'    # END LOCAL-DNS-ZONES\n',1)
    policies=''
    for row in zones:
        key=('+.' if row['subdomains'] else '')+row['name']
        if re.search(r'^    [\'\"]?'+re.escape(key)+r'[\'\"]?:',block,re.M):continue
        policies+='    '+json.dumps(key)+':\n      - "tcp://127.0.0.1:1054"\n'
    if policies:
        if '  nameserver-policy:\n' not in block:block=block.replace('dns:\n','dns:\n  nameserver-policy:\n',1)
        block=block.replace('  nameserver-policy:\n','  nameserver-policy:\n'+policies,1)
    return text[:section.start()]+block+text[section.end():]


def render():
    e=lambda value:html.escape(str(value),quote=True)
    try:rows=read();error=''
    except (OSError,ValueError):rows=[];error=_ui('Не удалось прочитать список локальных DNS-записей.')
    sections=[]
    for forwarded,title in ((True,_ui('Перенаправленные зоны')),(False,_ui('Статические записи'))):
        entries=[]
        for row in sorted(rows,key=lambda item:item['name']):
            if (row.get('type')=='FWD')!=forwarded:continue
            value=e(row.get('value','—'))
            if forwarded and row.get('upstreams'):value+='<br><small>'+e(', '.join(row['upstreams']))+'</small>'
            entries.append('<tr><td>'+e(row['name'])+'</td><td>'+e(row.get('type','—'))+'</td><td>'+value+'</td><td>'+(_ui('Да') if row['subdomains'] else _ui('Нет'))+'</td><td>'+(_ui('Включено') if row.get('enabled',True) else _ui('Отключено'))+'</td></tr>')
        sections.append('<h3>'+title+_ui('</h3><div style="overflow:auto"><table class="routeros-dns-table"><thead><tr><th>Имя / зона</th><th>Тип</th><th>')+(_ui('DNS / перенаправление') if forwarded else _ui('Значение'))+_ui('</th><th>Поддомены</th><th>Состояние</th></tr></thead><tbody>')+(''.join(entries) or _ui('<tr><td colspan="5">Записей нет</td></tr>'))+'</tbody></table></div>')
    updated=datetime.fromtimestamp(FILE.stat().st_mtime,timezone.utc).strftime('%d.%m.%Y %H:%M UTC') if FILE.exists() else _ui('ожидается чтение RouterOS')
    return _ui('<div class="panel"><details class="panel-spoiler"><summary>Локальные DNS-записи RouterOS (')+str(len(rows))+')</summary><p role="status">'+e(_ui_message(error) if error else _ui('Последнее чтение: ')+updated)+'</p>'+''.join(sections)+'</details></div><style>body .unified-main .routeros-dns-table{width:100%;min-width:600px}body .unified-main .routeros-dns-table td{overflow-wrap:anywhere}body .unified-main .routeros-dns-table small{color:var(--ui-muted)}</style>'
