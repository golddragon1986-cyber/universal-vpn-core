"""Isolated native Mihomo health-check/failover test; live routes untouched."""
import http.client,json,subprocess,tempfile,time,urllib.request
from pathlib import Path

API='http://127.0.0.1:19490'
def api(path,data=None):
    request=urllib.request.Request(API+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='GET' if data is None else 'PUT')
    with urllib.request.urlopen(request,timeout=4) as r:
        b=r.read();return json.loads(b) if b else None
def wait_alive(expected):
    end=time.monotonic()+18
    while time.monotonic()<end:
        try:
            a=api('/proxies/TEST-A')['alive'];b=api('/proxies/TEST-B')['alive']
            if a==expected and b:return
        except Exception:pass
        time.sleep(.5)
    raise RuntimeError('Automatic health status did not converge')
def connections():
    held=[]
    try:
        for _ in range(6):
            c=http.client.HTTPSConnection('127.0.0.1',19480,timeout=8)
            held.append(c);c.set_tunnel('www.gstatic.com',443)
            c.request('HEAD','/generate_204');r=c.getresponse();r.read();assert r.status==204
        return [x['chains'] for x in api('/connections')['connections']]
    finally:
        for c in held:c.close()

cfg={'mixed-port':19480,'bind-address':'127.0.0.1','external-controller':'127.0.0.1:19490','mode':'rule','log-level':'warning','unified-delay':True,
 'proxies':[{'name':'LEAF-A','type':'socks5','server':'127.0.0.1','port':18181},{'name':'LEAF-B','type':'socks5','server':'127.0.0.1','port':18182}],
 'proxy-groups':[{'name':'TEST-A','type':'select','proxies':['LEAF-A','REJECT']},{'name':'TEST-B','type':'select','proxies':['LEAF-B']},
 {'name':'TEST-BALANCE','type':'load-balance','strategy':'round-robin','proxies':['TEST-A','TEST-B'],'url':'https://www.gstatic.com/generate_204','interval':2,'timeout':3000,'lazy':False,'expected-status':204}],
 'rules':['MATCH,TEST-BALANCE']}
with tempfile.TemporaryDirectory(prefix='health-check-') as d:
    f=Path(d)/'config.json';f.write_text(json.dumps(cfg))
    with (Path(d)/'log').open('w') as log:
        p=subprocess.Popen(['mihomo','-d',d,'-f',str(f)],stdout=log,stderr=log)
        try:
            wait_alive(True)
            api('/proxies/TEST-A',{'name':'REJECT'})
            wait_alive(False)
            failed=connections();assert len(failed)>=6 and all('LEAF-B' in chain for chain in failed)
            print(json.dumps({'failed_channel_excluded':True,'new_connections':len(failed)}),flush=True)
            api('/proxies/TEST-A',{'name':'LEAF-A'})
            wait_alive(True)
            recovered=connections();assert any('LEAF-A' in c for c in recovered) and any('LEAF-B' in c for c in recovered)
            print(json.dumps({'channel_automatically_recovered':True,'new_connections':len(recovered)}),flush=True)
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
