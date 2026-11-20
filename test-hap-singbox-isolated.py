import concurrent.futures,json,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.request import ProxyHandler,build_opener
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as m,vpn_clients as v
ROOT=Path('/etc/mihomo/clients')
nodes=[(v.canonical(n),18651+i) for i,n in enumerate(m.read()['nodes']) if n['proxy']['name'] in ('FL','SV-inbound')]
cfg={'log':{'level':'warn','timestamp':True},'inbounds':[],'outbounds':[],'route':{'rules':[]}}
for p,port in nodes:
    tag='isolated-'+str(port)
    out=v.convert(p,'sing-box');out['tag']=tag;cfg['outbounds'].append(out)
    cfg['inbounds'].append({'type':'mixed','tag':tag,'listen':'127.0.0.1','listen_port':port})
    cfg['route']['rules'].append({'inbound':[tag],'action':'route','outbound':tag})
def probe(item):
    p,port=item;opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:'+str(port)}))
    statuses=[]
    for _ in range(3):
        try:
            with opener.open('https://www.gstatic.com/generate_204',timeout=8) as r:
                r.read(1024);statuses.append(r.status)
        except Exception as e:statuses.append(type(e).__name__)
    return {'name':p['name'],'statuses':statuses}
fd,path=tempfile.mkstemp(prefix='.isolated-',dir=ROOT)
with os.fdopen(fd,'w') as f:json.dump(cfg,f)
all_results=[]
try:
    subprocess.run([v.binary('sing-box'),'check','-c',path],check=True,timeout=30,capture_output=True)
    for attempt in range(1,5):
        log=Path('/tmp/isolated-sing-box.log')
        with log.open('w') as stream:
            proc=subprocess.Popen([v.binary('sing-box'),'run','-c',path],stdout=stream,stderr=subprocess.STDOUT,env={**os.environ,'GOMEMLIMIT':'60MiB','GOGC':'50'})
        try:
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                try:
                    for _,port in nodes:
                        with socket.create_connection(('127.0.0.1',port),timeout=.3):pass
                    break
                except OSError:
                    if proc.poll() is not None:break
                    time.sleep(.2)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(probe,nodes))
            text=log.read_text()
            result={'attempt':attempt,'results':results,'reality_errors':text.count('reality verification failed'),'unsupported_curve':text.count('unsupported curve'),'process_exit':proc.poll()}
            all_results.append(result);print(json.dumps(result),flush=True)
            if all(x['statuses']==[204,204,204] for x in results):break
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    Path('/etc/mihomo/isolated-singbox-results.json').write_text(json.dumps(all_results,indent=2))
finally:Path(path).unlink(missing_ok=True)
