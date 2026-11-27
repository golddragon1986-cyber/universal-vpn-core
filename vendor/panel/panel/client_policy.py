"""Client aliases and source policies; no RouterOS comments are repurposed."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path
import router_routes as rr
from durable_io import write

FILE=rr.ROOT/'rules/client-settings.json'
TAG='uvpn-main: client policy'
CHAIN='uvpn-main-clients'
DNS_CHAIN='uvpn-main-client-dns'
TABLE='uvpn-main-clients'

def read():
    return json.loads(FILE.read_bytes()) if FILE.exists() else []

def key(row):return (row['list'],row['address'])

def enrich(rows):
    saved={key(row):row for row in read()}
    return [{**row,'name':saved.get(key(row),{}).get('name',''),
             'route':saved.get(key(row),{}).get('route','RULES'),
             'dhcp_owner':saved.get(key(row),{}).get('dhcp_owner','')} for row in rows]

def choices():
    return ['RULES','BYPASS']+[value for value in rr.target_choices() if value!='DIRECT']

def networks(value):
    if '-' in value:
        first,last=map(ipaddress.IPv4Address,value.split('-'))
        return list(ipaddress.summarize_address_range(first,last))
    return [ipaddress.ip_network(value+'/32' if '/' not in value else value)]

def effective(rows):
    """Specific clients win; tie order is stable. Return disjoint IPv4 networks."""
    entries=[]
    for row in rows:
        if row['enabled']:
            for net in networks(row['address']):entries.append((net,row))
    entries.sort(key=lambda pair:(-pair[0].prefixlen,str(pair[1].get('id','')),pair[1]['list']))
    claimed=[];result=[]
    for net,row in entries:
        remaining=[net]
        for used in claimed:
            remaining=[part for item in remaining for part in
                       (list(item.address_exclude(used)) if used.subnet_of(item) else [] if item.subnet_of(used) else [item])]
        for part in remaining:result.append((part,row))
        claimed.extend(remaining)
        if len(result)>4096:raise ValueError('Слишком много пересечений сетей клиентов')
    return result

def save(rows):
    write(FILE,json.dumps(rows,ensure_ascii=False).encode())

def compose(text):
    rows=effective(read())
    lines=[]
    for net,row in rows:
        target=row.get('route','RULES')
        if target in {'RULES','BYPASS'}:continue
        lines.append('  - '+json.dumps('SRC-IP-CIDR,'+str(net)+','+target)+'\n')
    text=re.sub(r'(?ms)^  # BEGIN CLIENT-POLICY\n.*?^  # END CLIENT-POLICY\n','',text)
    if lines:text=text.replace('rules:\n','rules:\n  # BEGIN CLIENT-POLICY\n'+''.join(lines)+'  # END CLIENT-POLICY\n',1)
    return text

def runtime():
    """Only forwarded client packets enter TUN; container upstreams keep main."""
    from transit_mode import active as transit_active
    capture = transit_active()
    rows=[(net,row) for net,row in effective(read()) if row.get('route','RULES') not in {'RULES','BYPASS'}]
    def run(args,check=True):
        p=subprocess.run(['ip',*args],capture_output=True,text=True,timeout=10)
        if check and p.returncode:raise RuntimeError('Не удалось применить маршруты клиентов в контейнере: '+p.stderr[-300:])
        return p.stdout
    # Reserved priorities belong exclusively to this module.
    for line in run(['-4','rule','show']).splitlines():
        match=re.match(r'(\d+):',line)
        if match and (4000<=int(match[1])<8100 or 10900<=int(match[1])<15000) and re.search(r'lookup 206\b',line):run(['-4','rule','del','pref',match[1]])
    if not rows and not capture:
        run(['-4','route','flush','table','206'],False);return
    links=list(Path('/sys/class/net').iterdir())
    tunnels=[p.name for p in links if (p/'tun_flags').exists()]
    if len(tunnels)!=1:raise RuntimeError('Не найден единственный TUN-интерфейс ядра')
    ingress_links=[p.name for p in links if (p/'type').exists() and (p/'type').read_text().strip()=='1']
    if len(ingress_links)!=1:raise RuntimeError('Не найден единственный входной Ethernet-интерфейс контейнера')
    ingress=ingress_links[0]
    run(['-4','route','replace','table','206','default','dev',tunnels[0]])
    for index,(net,row) in enumerate(rows):
        run(['-4','rule','add','pref',str(4000+index),'iif',ingress,'from',str(net),'lookup','206'])
    if capture:
        run(['-4','rule','add','pref','8099','iif',ingress,'lookup','206'])

def owned_snapshot(router):
    return {path:[row for row in router.call(path) if row.get('comment')==TAG]
            for path in ('ip/firewall/mangle','ip/firewall/nat','ip/firewall/filter','ip/route','routing/table')}

def clear(router):
    for path in ('ip/firewall/mangle','ip/firewall/nat','ip/firewall/filter','ip/route','routing/table'):
        for row in router.call(path):
            if row.get('comment')==TAG:router.call(path+'/'+rr.rid(row['.id']),'DELETE')

def prepend(router,path,data):
    data=dict(data)
    first=next((row['.id'] for row in router.call(path) if not rr.yes(row.get('dynamic'))),None)
    data.pop('place-before',None)
    if first:data['place-before']=first
    router.call(path,'PUT',data)

def restore(router,saved):
    clear(router)
    allowed={'routing/table':{'name','fib','comment'},'ip/route':{'dst-address','gateway','routing-table','distance','comment','disabled'}}
    firewall={'chain','action','src-address','dst-address','dst-address-type','in-interface-list','out-interface-list','connection-state','new-routing-mark','passthrough','jump-target','protocol','dst-port','to-addresses','to-ports','comment','disabled'}
    for path in ('routing/table','ip/route','ip/firewall/filter','ip/firewall/nat','ip/firewall/mangle'):
        for row in reversed(saved.get(path,[])):
            data={k:v for k,v in row.items() if k in allowed.get(path,firewall)}
            if path.startswith('ip/firewall/'):prepend(router,path,data)
            else:router.call(path,'PUT',data)

def sync_transit(router=None):
    """Rebuild RouterOS ingress only when full LAN capture changed."""
    from transit_mode import active as transit_active
    router=router or rr.Router()
    mangle=router.call('ip/firewall/mangle')
    nat=router.call('ip/firewall/nat')
    installed=any(row.get('comment')==TAG and row.get('chain')==CHAIN
                  and row.get('action')=='mark-routing'
                  and row.get('src-address','') in {'','0.0.0.0/0'}
                  for row in mangle)
    dns_ready=all(any(row.get('comment')==TAG and row.get('chain')==DNS_CHAIN
                      and row.get('protocol')==protocol and not row.get('src-address')
                      and row.get('action')=='dst-nat' and row.get('to-ports')=='53'
                      for row in nat) for protocol in ('udp','tcp'))
    if installed==transit_active() and (not installed or dns_ready):return None
    from client_panel import read_state
    previous=owned_snapshot(router)
    try:apply(router,read(),read_state(router,cache=False))
    except Exception:
        restore(router,previous)
        raise
    return previous


def apply(router,rows,state):
    from transit_mode import active as transit_active
    capture=transit_active()
    clear(router)
    entries=effective(rows)
    if not capture and not any(row.get('route','RULES')!='RULES' for _,row in entries):return
    def add(path,data):
        data={**data,'comment':TAG}
        if 'place-before' in data:prepend(router,path,data)
        else:router.call(path,'PUT',data)
    forced=capture or any(row.get('route','RULES') not in {'RULES','BYPASS'} for _,row in entries)
    if forced:
        add('routing/table',{'name':TABLE,'fib':True})
        add('ip/route',{'dst-address':'0.0.0.0/0','gateway':'172.31.41.2@main','routing-table':TABLE})
    rr.ensure_wan_route(router,router.routes())
    interfaces=sorted({interface for value in state['lists'].values() for interface in value['interfaces']})
    if any(value not in {'LAN'} for value in interfaces):raise ValueError('Индивидуальные маршруты поддерживают входной список интерфейсов LAN')
    # Keep local networks/router services on their original path.
    for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','224.0.0.0/3'):
        add('ip/firewall/mangle',{'chain':CHAIN,'dst-address':net,'action':'return'})
    add('ip/firewall/mangle',{'chain':CHAIN,'dst-address-type':'local','action':'return'})
    for net,row in entries:
        route=row.get('route','RULES')
        if route=='RULES':continue
        add('ip/firewall/mangle',{'chain':CHAIN,'src-address':str(net),'action':'mark-routing','new-routing-mark':router.cfg['bypass_table'] if route=='BYPASS' else TABLE,'passthrough':False})
        for protocol in ('udp','tcp'):
            dns={'chain':DNS_CHAIN,'src-address':str(net),'protocol':protocol,'dst-port':'53','action':'accept'}
            if route!='BYPASS':dns.update(action='dst-nat',**{'to-addresses':'172.31.41.2','to-ports':'1055'})
            add('ip/firewall/nat',dns)
        # Established traffic must not be fasttracked into the main table.
        for field in ('src-address','dst-address'):
            add('ip/firewall/filter',{'chain':'forward',field:str(net),'connection-state':'established,related','action':'accept','place-before':'0'})
    if capture:
        # Specific BYPASS clients above keep their WAN route. Unmatched LAN
        # sources enter the TUN, where the final DIRECT exits via RouterOS NAT.
        add('ip/firewall/mangle',{'chain':CHAIN,'action':'mark-routing','new-routing-mark':TABLE,'passthrough':False})
        for protocol in ('udp','tcp'):
            add('ip/firewall/nat',{'chain':DNS_CHAIN,'protocol':protocol,'dst-port':'53',
                                  'action':'dst-nat','to-addresses':'172.31.41.2','to-ports':'53'})
        for field in ('in-interface-list','out-interface-list'):
            add('ip/firewall/filter',{'chain':'forward',field:'LAN',
                                      'connection-state':'established,related','action':'accept','place-before':'0'})
    add('ip/firewall/mangle',{'chain':'prerouting','in-interface-list':'LAN','action':'jump','jump-target':CHAIN,'place-before':'0'})
    if entries or capture:
        add('ip/firewall/nat',{'chain':'dstnat','in-interface-list':'LAN','protocol':'udp','dst-port':'53','action':'jump','jump-target':DNS_CHAIN,'place-before':'0'})
        add('ip/firewall/nat',{'chain':'dstnat','in-interface-list':'LAN','protocol':'tcp','dst-port':'53','action':'jump','jump-target':DNS_CHAIN,'place-before':'0'})
