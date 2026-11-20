import concurrent.futures,http.client,json,os,re,sys,threading,time
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo');WORK=ROOT/'tcp-proxy-speed-20261106';WORK.mkdir(mode=0o700,exist_ok=True)
def api(path,data=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data is not None else 'GET')
    with urlopen(req,timeout=30) as r:
        b=r.read();return json.loads(b) if b else None
action=sys.argv[1]
if action=='setup':
    text=(ROOT/'default_config.yaml').read_text()
    (WORK/'baseline.yaml').write_text(text);(WORK/'baseline.yaml').chmod(0o600)
    text,n=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,speedtest.selectel.ru,CHANNEL-SV-inbound\n',text)
    if n!=1:raise RuntimeError('Unexpected rules block')
    path=WORK/'temporary.yaml';path.write_text(text);path.chmod(0o600)
    api('/configs?force=true',{'path':str(path)})
    print('Only test domain forced through SV; persistent configuration unchanged',flush=True)
elif action=='restore':
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    print('Persistent configuration restored',flush=True)
elif action=='container':
    source=(ROOT/'benchmark-hap-vpn.py').read_text().split('baseline=snapshot();results=[]')[0]
    source=source.replace("('mihomo','python3')","('mihomo','python3','sing-box','xray')")
    ns={};exec(compile(source,'benchmark-helpers','exec'),ns)
    stop=threading.Event();samples=[ns['snapshot']()];paths=set()
    def monitor():
        while not stop.wait(.5):
            samples.append(ns['snapshot']())
            try:
                for c in api('/connections').get('connections',[]):
                    m=c.get('metadata',{})
                    if m.get('host')=='speedtest.selectel.ru':paths.add(str(m.get('type'))+': '+' > '.join(c.get('chains',[])))
            except Exception:pass
    workers=int(sys.argv[2]) if len(sys.argv)>2 else 1
    if workers not in (1,4):raise ValueError('Expected 1 or 4 streams')
    def download(_):
        connection=http.client.HTTPConnection('127.0.0.1',1080,timeout=20);count=0
        try:
            connection.request('GET','http://speedtest.selectel.ru/100MB',headers={'Range':'bytes=0-33554431','Cache-Control':'no-cache'})
            response=connection.getresponse();status=response.status
            if status!=206:raise RuntimeError('Expected HTTP 206, got '+str(status))
            while True:
                block=response.read(65536)
                if not block:break
                count+=len(block)
            return {'status':status,'bytes':count}
        finally:connection.close()
    t=threading.Thread(target=monitor,daemon=True);t.start();start=time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:streams=list(pool.map(download,range(workers)))
    finally:
        elapsed=time.monotonic()-start;stop.set();t.join(timeout=3);samples.append(ns['snapshot']())
    count=sum(s['bytes'] for s in streams)
    database=json.loads((ROOT/'rules/managed-proxies.json').read_text())
    engine=next(n.get('client','mihomo') for n in database['nodes'] if n['proxy']['name']=='SV-inbound')
    result={'origin':'container','proxy':'127.0.0.1:1080 HTTP mixed','channel':'SV-inbound/'+engine,'streams':streams,'bytes':count,'seconds':elapsed,'mbps':count*8/elapsed/1e6,'paths':sorted(paths),'stats':ns['summarize'](samples)}
    (WORK/('container-'+str(workers)+'-result.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
    assert all(s['bytes']==33554432 for s in streams) and any('SV-inbound' in p for p in paths)
