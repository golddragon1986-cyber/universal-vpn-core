"""Read private live config locally; report only endpoint labels and outcomes."""
import concurrent.futures,json,os,subprocess,tempfile,time,urllib.request
from pathlib import Path

def probe(port):
    try:
        o=urllib.request.build_opener(urllib.request.ProxyHandler({'https':f'http://127.0.0.1:{port}'}))
        start=time.monotonic()
        with o.open('https://www.gstatic.com/generate_204',timeout=5) as r:
            r.read(); return {'ok':r.status==204,'ms':round((time.monotonic()-start)*1000)}
    except Exception as e:return {'ok':False,'error':type(e).__name__}

cfg=json.loads(Path('/etc/mihomo/clients/sing-box.json').read_text())
for inbound in cfg['inbounds']:inbound['listen_port']+=1000
for outbound in cfg['outbounds']:
    if 'tls' in outbound:outbound['tls']['utls']['fingerprint']='randomized'
with tempfile.TemporaryDirectory(prefix='fingerprint-') as d:
    path=Path(d)/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
    with (Path(d)/'log').open('w+') as log:
        p=subprocess.Popen(['/usr/local/bin/sing-box','run','-c',str(path)],stdout=log,stderr=log,env={**os.environ,'GOMEMLIMIT':'40MiB','GOGC':'50'})
        try:
            time.sleep(1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                for i in range(12):
                    results=list(pool.map(probe,[18181,18182,19181,19182]))
                    print(json.dumps({'round':i+1,'chrome':results[:2],'randomized':results[2:]}),flush=True)
                    if i==0 and not any(r['ok'] for r in results[2:]):break
                    time.sleep(.5)
            log.flush();text=(Path(d)/'log').read_text()
            print(json.dumps({'errors':{k:text.count(k) for k in ['unsupported curve','timeout','authentication']}}),flush=True)
            for outbound in cfg['outbounds']:
                for value in [outbound.get('server'),outbound.get('uuid'),outbound.get('tls',{}).get('server_name'),*outbound.get('tls',{}).get('reality',{}).values()]:
                    if isinstance(value,str) and value:text=text.replace(value,'[redacted]')
            print(json.dumps({'diagnostic':text.splitlines()[-2:]}),flush=True)
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
