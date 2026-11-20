import concurrent.futures,http.client,json,socket,ssl,sys
from pathlib import Path
from urllib.request import urlopen
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as m,vpn_clients as v
nodes=[n for n in m.read()['nodes'] if n['proxy']['name'] in ('SV-inbound','FL')]
assert len(nodes)==2 and all(v.current(n)=='xray' and n.get('balance') is True for n in nodes)
def recv(s,n):
    result=b''
    while len(result)<n:
        b=s.recv(n-len(result))
        if not b:raise OSError('SOCKS closed')
        result+=b
    return result
def probe(n):
    port=n['proxy']['port']
    def connect(addr,timeout=None,source_address=None):
        s=socket.create_connection(('127.0.0.1',port),timeout=8);s.sendall(b'\x05\x01\x00')
        if recv(s,2)!=b'\x05\x00':raise OSError('SOCKS auth')
        h=addr[0].encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(h)])+h+addr[1].to_bytes(2,'big'))
        r=recv(s,4)
        if r[1]:raise OSError('SOCKS rejected')
        recv(s,(4 if r[3]==1 else 16 if r[3]==4 else recv(s,1)[0])+2);return s
    conn=http.client.HTTPSConnection('www.gstatic.com',timeout=12,context=ssl.create_default_context());conn._create_connection=connect
    try:conn.request('GET','/generate_204');r=conn.getresponse();r.read(1024);return r.status
    except Exception as error:return type(error).__name__
    finally:conn.close()
reports=[]
for node in nodes:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:statuses=list(pool.map(lambda _:probe(node),range(12)))
    delays=[]
    for _ in range(3):
        try:delays.append(m.delay(node['proxy']['name']))
        except Exception as e:delays.append(type(e).__name__)
    reports.append({'name':node['proxy']['name'],'client':v.current(node),'balance':node['balance'],'https_statuses':statuses,'provider_delays_ms':delays})
with urlopen('http://127.0.0.1:9090/proxies/LOADBALANCE',timeout=8) as r:balance=json.load(r)['all']
with urlopen('http://127.0.0.1:9090/proxies/SELECTOR',timeout=8) as r:selected=json.load(r)['now']
report={'nodes':reports,'balance_members':balance,'selected':selected,'memory_events':Path('/sys/fs/cgroup/memory.events').read_text()}
(Path('/etc/mihomo')/'xray-live-verified.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
assert all(x['https_statuses']==[204]*12 and all(isinstance(y,int) and y>0 for y in x['provider_delays_ms']) for x in reports)
assert set(balance)=={'CHANNEL-SV-inbound','CHANNEL-FL'} and selected=='LOADBALANCE'
