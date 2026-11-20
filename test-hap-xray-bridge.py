import concurrent.futures,http.client,importlib.util,json,os,socket,ssl,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.parse import quote
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients as v
ROOT=Path('/etc/mihomo')
nodes=[(v.canonical(n),18751+i) for i,n in enumerate(proxy_manager.read()['nodes']) if n['proxy']['name'] in ('SV-inbound','FL')]
cfg={'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
for p,port in nodes:
    tag='qa-'+str(port);out=v.convert(p,'xray');out['tag']=tag;cfg['outbounds'].append(out)
    cfg['inbounds'].append({'tag':tag,'protocol':'socks','listen':'127.0.0.1','port':port,'settings':{'udp':True}})
    cfg['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':tag})
def api(path,data=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data is not None else 'GET')
    with urlopen(req,timeout=25) as r:
        b=r.read();return json.loads(b) if b else None
def check(item):
    p,port=item;values=[]
    for timeout in (5000,15000,15000):
        start=time.monotonic()
        try:r=api('/proxies/QA-XRAY-'+str(port)+'/delay?url='+quote('https://www.gstatic.com/generate_204',safe='')+'&timeout='+str(timeout));result=r
        except Exception as e:result={'error':type(e).__name__,'status':getattr(e,'code',None)}
        values.append({'timeout_ms':timeout,'seconds':round(time.monotonic()-start,2),'result':result})
    return {'name':p['name'],'checks':values}
fd,xpath=tempfile.mkstemp(prefix='.xray-bridge-',suffix='.json',dir=ROOT/'clients')
with os.fdopen(fd,'w') as f:json.dump(cfg,f)
original=(ROOT/'default_config.yaml').read_text()
if '\nproxies:' in original:raise RuntimeError('Existing inline proxies; inspect before diagnostic')
extra='\nproxies:\n'+''.join('  - name: QA-XRAY-'+str(port)+'\n    type: socks5\n    server: 127.0.0.1\n    port: '+str(port)+'\n    udp: true\n' for _,port in nodes)
fd,mpath=tempfile.mkstemp(prefix='.mihomo-bridge-',suffix='.yaml',dir=ROOT)
with os.fdopen(fd,'w') as f:f.write(original+extra)
proc=None;loaded=False
try:
    log=(ROOT/'clients/.xray-bridge.log').open('w')
    proc=subprocess.Popen([v.binary('xray'),'run','-config',xpath],stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'GOMEMLIMIT':'40MiB','GOGC':'50'})
    time.sleep(2)
    api('/configs?force=true',{'path':mpath});loaded=True
    time.sleep(2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(check,nodes))
    print(json.dumps(results),flush=True)
    (ROOT/'xray-mihomo-bridge-result.json').write_text(json.dumps(results,indent=2))
finally:
    if loaded:api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    if proc:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    Path(xpath).unlink(missing_ok=True);Path(mpath).unlink(missing_ok=True)
