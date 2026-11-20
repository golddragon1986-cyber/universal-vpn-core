import copy,json,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.request import ProxyHandler,build_opener
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients
original=vpn_clients.canonical(next(n for n in proxy_manager.read()['nodes'] if n['proxy']['name']=='SV-inbound'))
reports=[]
for fingerprint in ('randomized','chrome','firefox'):
    profile=copy.deepcopy(original);profile['client-fingerprint']=fingerprint
    cfg={'mixed-port':18881,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'warning','proxies':[profile],'rules':['MATCH,SV-inbound']}
    with tempfile.TemporaryDirectory(prefix='.reality-probe-',dir='/etc/mihomo') as directory:
        root=Path(directory);path=root/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
        with (root/'log').open('w+') as log:
            process=subprocess.Popen(['mihomo','-d',directory,'-f',str(path)],stdout=log,stderr=log,env={**os.environ,'GOMEMLIMIT':'30MiB','GOGC':'50'})
            try:
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:
                    try:
                        with socket.create_connection(('127.0.0.1',18881),timeout=.5):break
                    except OSError:time.sleep(.3)
                results=[]
                opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:18881'}))
                for url in ('https://www.gstatic.com/generate_204','https://telegram.org'):
                    start=time.monotonic()
                    try:
                        with opener.open(url,timeout=6) as response:response.read(1024);result={'status':response.status}
                    except Exception as error:result={'error':type(error).__name__,'reason':str(error)}
                    result['seconds']=round(time.monotonic()-start,2);results.append(result)
                log.flush();text=(root/'log').read_text()
                def redact(value):
                    if isinstance(value,dict):
                        for key,item in value.items():
                            if key in ('uuid','server','servername','public-key','short-id') and isinstance(item,str) and item:
                                nonlocal_text[0]=nonlocal_text[0].replace(item,'[redacted]')
                            else:redact(item)
                    elif isinstance(value,list):
                        for item in value:redact(item)
                nonlocal_text=[text];redact(profile)
                report={'fingerprint':fingerprint,'results':results,'process_exit':process.poll(),'errors':{key:text.count(key) for key in ('REALITY authentication failed','unsupported curve','CurvePreferences','timeout','EOF')},'safe_log_tail':nonlocal_text[0][-1600:]}
                reports.append(report);print(json.dumps(report),flush=True)
            finally:
                process.terminate()
                try:process.wait(timeout=4)
                except subprocess.TimeoutExpired:process.kill();process.wait()
Path('/etc/mihomo/reality-isolated-results-20261107.json').write_text(json.dumps(reports,indent=2))
