import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
from urllib.request import Request,urlopen

ROOT=Path('/etc/mihomo')
CG=Path('/sys/fs/cgroup')
PLAIN=os.environ.get('BENCH_HTTP')=='1'
RESULT=ROOT/('vpn-benchmark-http-result.json' if PLAIN else 'vpn-benchmark-result.json')

def api(path,data=None,method=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
    with urlopen(req,timeout=45) as response:
        raw=response.read()
        return json.loads(raw) if raw else None

def pairs(path):
    return {a.rstrip(':'):int(b) for a,b in (line.split()[:2] for line in Path(path).read_text().splitlines())}

def snapshot():
    cpus={}
    for line in Path('/proc/stat').read_text().splitlines():
        if line.startswith('cpu'):
            parts=line.split();cpus[parts[0]]=list(map(int,parts[1:9]))
    processes={}
    for p in Path('/proc').glob('[0-9]*/stat'):
        try:
            content=p.read_text(); name=content.split('(',1)[1].rsplit(')',1)[0]
            tail=content.rsplit(')',1)[1].split()
            if name in ('mihomo','python3'):
                processes[str(p.parent.name)]={'name':name,'ticks':int(tail[11])+int(tail[12])}
        except (OSError,ValueError,IndexError):pass
    mem=pairs('/proc/meminfo')
    return {'time':time.monotonic(),'cpu':cpus,'processes':processes,
            'memory':int((CG/'memory.current').read_text()),'swap':int((CG/'memory.swap.current').read_text()),
            'events':pairs(CG/'memory.events'),'cgcpu':pairs(CG/'cpu.stat'),
            'vm':{k:v for k,v in pairs('/proc/vmstat').items() if k in ('pswpin','pswpout','pgmajfault')},
            'mem_available_kib':mem.get('MemAvailable',0)}

def summarize(samples):
    first,last=samples[0],samples[-1];seconds=last['time']-first['time']
    cpu={};iowait={}
    for key,values in first['cpu'].items():
        delta=[b-a for a,b in zip(values,last['cpu'][key])];total=sum(delta) or 1
        cpu[key]=round(100*(total-delta[3]-delta[4])/total,1)
        iowait[key]=round(100*delta[4]/total,1)
    hz=os.sysconf('SC_CLK_TCK');process={}
    for pid,end in last['processes'].items():
        if pid in first['processes']:
            name=end['name']+(' (benchmark)' if int(pid)==os.getpid() else '')
            process[name]=round(process.get(name,0)+(end['ticks']-first['processes'][pid]['ticks'])/hz/seconds*100,1)
    return {'cpu_busy_pct':cpu,'cpu_iowait_pct':iowait,'process_cpu_pct_one_core':process,
            'memory_peak_mib':round(max(x['memory'] for x in samples)/1048576,1),
            'swap_start_mib':round(first['swap']/1048576,2),'swap_end_mib':round(last['swap']/1048576,2),
            'mem_available_min_mib':round(min(x['mem_available_kib'] for x in samples)/1024,1),
            'memory_event_delta':{k:last['events'][k]-v for k,v in first['events'].items()},
            'vm_delta':{k:last['vm'][k]-v for k,v in first['vm'].items()},
            'cgroup_cpu_cores':round((last['cgcpu']['usage_usec']-first['cgcpu']['usage_usec'])/1e6/seconds,2)}

def run_phase(name,port,workers,seconds=18):
    stop=threading.Event();samples=[snapshot()];counter=[0];lock=threading.Lock();errors=[];chains=set()
    start=time.monotonic();deadline=start+seconds
    def sample():
        while not stop.wait(1):
            samples.append(snapshot())
            try:
                for conn in api('/connections').get('connections',[]):
                    if conn.get('metadata',{}).get('inboundName','').startswith('benchmark-'):
                        chains.add(' > '.join(conn.get('chains',[])))
            except Exception:pass
    def download():
        conn=None
        try:
            if PLAIN:
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
                conn.request('GET','http://speedtest.selectel.ru/100MB',headers={'Cache-Control':'no-cache','User-Agent':'Mozilla/5.0'})
            else:
                conn=http.client.HTTPSConnection('127.0.0.1',port,timeout=8,context=ssl.create_default_context())
                conn.set_tunnel('speedtest.selectel.ru',443)
                conn.request('GET','/100MB',headers={'Cache-Control':'no-cache','User-Agent':'Mozilla/5.0'})
            response=conn.getresponse()
            if response.status!=200:raise RuntimeError('HTTP '+str(response.status))
            while time.monotonic()<deadline:
                block=response.read(65536)
                if not block:break
                with lock:
                    counter[0]+=len(block)
                    if counter[0]>=192*1024*1024:break
        except Exception as error:
            errors.append(type(error).__name__+': '+str(error)[:140])
        finally:
            if conn:conn.close()
    monitor=threading.Thread(target=sample,daemon=True);monitor.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda _:download(),range(workers)))
    elapsed=time.monotonic()-start;stop.set();monitor.join(timeout=3);samples.append(snapshot())
    result={'channel':name,'streams':workers,'finished_unix':time.time(),'seconds':round(elapsed,2),'bytes':counter[0],
            'mbps':round(counter[0]*8/elapsed/1e6,2),'errors':errors,'chains':sorted(chains),**summarize(samples)}
    print(json.dumps(result),flush=True)
    return result

baseline=snapshot();results=[]
config=ROOT/'benchmark-local-listeners.yaml'
original=(ROOT/'default_config.yaml').read_text()
if '\nlisteners:' in original:raise RuntimeError('Existing custom listeners; inspect before test')
proxies=api('/proxies')['proxies']
channels=[('DIRECT',18180)]+[(name,18181+i) for i,name in enumerate(proxies) if name.startswith('CHANNEL-')]
listeners='\nlisteners:\n'+''.join('  - name: benchmark-'+str(port)+'\n    type: mixed\n    listen: 127.0.0.1\n    port: '+str(port)+'\n    proxy: '+json.dumps(name)+'\n' for name,port in channels)
fd=os.open(config,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as out:out.write(original+listeners)
try:
    check=subprocess.run(['mihomo','-t','-d',str(ROOT),'-f',str(config)],capture_output=True,timeout=45)
    if check.returncode:raise RuntimeError('Temporary listener configuration rejected')
    api('/configs?force=true',{'path':str(config)},'PUT')
    time.sleep(2)
    for name,port in channels:
        for streams in (1,4):
            results.append(run_phase(name,port,streams))
            RESULT.write_text(json.dumps({'results':results},indent=2))
            time.sleep(2)
finally:
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')},'PUT')
    config.unlink(missing_ok=True)
    print('Original configuration restored',flush=True)
RESULT.write_text(json.dumps({'source':('http' if PLAIN else 'https')+'://speedtest.selectel.ru/100MB','results':results,'restored':True},indent=2))
