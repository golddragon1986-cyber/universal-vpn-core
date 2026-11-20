import concurrent.futures,json,sys,time
from pathlib import Path
from urllib.request import ProxyHandler,build_opener,urlopen
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as m,vpn_clients as v
nodes=[n for n in m.read()['nodes'] if n['proxy']['name'] in ('FL','SV-inbound')]
assert len(nodes)==2
def check(n):
    assert v.current(n)=='sing-box'
    assert n.get('balance') is True
    port=n['proxy']['port']
    opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:'+str(port)}))
    statuses=[];latencies=[]
    for _ in range(8):
        try:
            with opener.open('https://www.gstatic.com/generate_204',timeout=10) as r:r.read(1024);statuses.append(r.status)
        except Exception as e:statuses.append(type(e).__name__)
    for _ in range(3):
        try:latencies.append(m.delay(n['proxy']['name']))
        except Exception as e:latencies.append(type(e).__name__)
    return {'name':n['proxy']['name'],'client':v.current(n),'balance':n['balance'],'https_statuses':statuses,'mihomo_bridge_delay_ms':latencies}
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(check,nodes))
with urlopen('http://127.0.0.1:9090/proxies/LOADBALANCE',timeout=10) as r:group=json.load(r)
with urlopen('http://127.0.0.1:9090/proxies/SELECTOR',timeout=10) as r:selector=json.load(r)
state=json.loads(Path('/tmp/sing-box-supervisor.json').read_text())
report={'nodes':results,'balance_members':group['all'],'selected_route':selector['now'],'supervisor':{k:state.get(k) for k in ('ready','healthy','total','version')},'memory_events':Path('/sys/fs/cgroup/memory.events').read_text()}
Path('/etc/mihomo/singbox-live-verified.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report),flush=True)
assert all(x['https_statuses']==[204]*8 and all(isinstance(y,int) and y>0 for y in x['mihomo_bridge_delay_ms']) for x in results)
assert set(group['all'])=={'CHANNEL-FL','CHANNEL-SV-inbound'}
assert selector['now']=='LOADBALANCE'
assert state['ready'] and state['healthy']==state['total']==2
