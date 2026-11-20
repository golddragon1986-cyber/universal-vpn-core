"""Two private VLESS profiles, two loopback HTTP inbounds; no route or panel changes."""
import concurrent.futures
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ENGINE=sys.argv[1]
BINARY=sys.argv[2]
PROFILES=Path(sys.argv[3])
REPORT=Path(sys.argv[4])
FINGERPRINT=sys.argv[5] if len(sys.argv)>5 else None
NODES=json.loads(PROFILES.read_text())
if len(NODES)!=2 or any(p.get('type')!='vless' or not p.get('reality-opts') for p in NODES):
    raise ValueError('Expected exactly two VLESS/REALITY profiles')


def configuration():
    if ENGINE=='mihomo':
        return {'listeners':[{'name':'vpn'+str(i+1),'type':'http','listen':'127.0.0.1','port':18181+i,'proxy':p['name']} for i,p in enumerate(NODES)],
                'proxies':NODES,'rules':['MATCH,DIRECT'],'log-level':'warning'}
    inbounds=[];outbounds=[];rules=[]
    for i,p in enumerate(NODES):
        reality=p['reality-opts'];tag='vpn'+str(i+1);port=18181+i
        fingerprint=FINGERPRINT or p.get('client-fingerprint','chrome')
        if ENGINE=='sing-box':
            inbound={'type':'http','tag':tag,'listen':'127.0.0.1','listen_port':port}
            outbound={'type':'vless','tag':tag,'server':p['server'],'server_port':p['port'],'uuid':p['uuid'],
                      'tls':{'enabled':True,'server_name':p['servername'],
                             'utls':{'enabled':True,'fingerprint':fingerprint},
                             'reality':{'enabled':True,'public_key':reality['public-key'],'short_id':reality.get('short-id','')}}}
            if p.get('flow'):outbound['flow']=p['flow']
            if os.environ.get('VPN_REALITY_MLKEM')=='1':outbound['tls']['reality']['enable_mlkem']=True
            if os.environ.get('VPN_TEST_BAD_KEY')=='1':outbound['tls']['reality']['public_key']=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            rules.append({'inbound':[tag],'action':'route','outbound':tag})
        elif ENGINE=='xray':
            inbound={'protocol':'http','tag':tag,'listen':'127.0.0.1','port':port,'settings':{}}
            user={'id':p['uuid'],'encryption':'none'}
            if p.get('flow'):user['flow']=p['flow']
            outbound={'protocol':'vless','tag':tag,'settings':{'vnext':[{'address':p['server'],'port':p['port'],'users':[user]}]},
                      'streamSettings':{'network':'tcp','security':'reality','realitySettings':{
                          'serverName':p['servername'],'fingerprint':fingerprint,'password':reality['public-key'],'shortId':reality.get('short-id','')}}}
            rules.append({'type':'field','inboundTag':[tag],'outboundTag':tag})
        else:raise ValueError('Unknown engine')
        inbounds.append(inbound);outbounds.append(outbound)
    if ENGINE=='sing-box':return {'log':{'level':'warn','timestamp':True},'inbounds':inbounds,'outbounds':outbounds,'route':{'rules':rules}}
    return {'log':{'loglevel':'warning'},'inbounds':inbounds,'outbounds':outbounds,'routing':{'rules':rules}}


def memory():
    path=Path('/sys/fs/cgroup/memory.current')
    return int(path.read_text()) if path.exists() else None


def probe(index,url,expected):
    start=time.monotonic()
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({'https':'http://127.0.0.1:'+str(18181+index)}))
        with opener.open(url,timeout=10) as response:
            body=response.read(2*1024*1024)
            ok=response.status==expected
            if 'bytes=' in url:ok=ok and len(body)>=1_000_000
            return {'node':index+1,'ok':ok,'status':response.status,'bytes':len(body),'ms':round((time.monotonic()-start)*1000)}
    except Exception as error:
        reason=str(getattr(error,'reason',type(error).__name__))[:300]
        for p in NODES:
            for value in [p.get('uuid'),p.get('server'),p.get('servername'),*p.get('reality-opts',{}).values()]:
                if isinstance(value,str) and value:reason=reason.replace(value,'[redacted]')
        return {'node':index+1,'ok':False,'error':type(error).__name__,'status':getattr(error,'code',None),'reason':reason,'ms':round((time.monotonic()-start)*1000)}


report={'engine':ENGINE,'fingerprint':FINGERPRINT or 'original','started':time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'local_mlkem_option':os.environ.get('VPN_REALITY_MLKEM')=='1',
        'intentional_wrong_key':os.environ.get('VPN_TEST_BAD_KEY')=='1',
        'version':subprocess.run([BINARY,'-v' if ENGINE=='mihomo' else 'version'],capture_output=True,text=True).stdout.splitlines()[:3],
        'rounds':[],'memory_bytes':[],'target_urls':[]}
with tempfile.TemporaryDirectory(prefix='vpn-engine-',dir='/tmp') as directory:
    config=Path(directory)/'config.json';config.write_text(json.dumps(configuration()));config.chmod(0o600)
    log=Path(directory)/'private.log'
    check=[BINARY,'check','-c',str(config)] if ENGINE=='sing-box' else [BINARY,'run','-test','-config',str(config)]
    if ENGINE=='mihomo':check=[BINARY,'-t','-d',directory,'-f',str(config)]
    result=subprocess.run(check,capture_output=True,text=True,timeout=20)
    report['config_valid']=result.returncode==0
    if result.returncode:
        # Validation diagnostics sanitized against all top-level private values.
        error=(result.stderr or result.stdout)[-2000:]
        for p in NODES:
            for value in [p.get('uuid'),p.get('server'),p.get('servername'),*p.get('reality-opts',{}).values()]:
                if isinstance(value,str) and value:error=error.replace(value,'[redacted]')
        report['validation_error']=error
    else:
        command=[BINARY,'run','-c',str(config)] if ENGINE=='sing-box' else [BINARY,'run','-config',str(config)]
        if ENGINE=='mihomo':command=[BINARY,'-d',directory,'-f',str(config)]
        with log.open('w') as output:
            process=subprocess.Popen(command,stdout=output,stderr=output,env={**os.environ,'GOMEMLIMIT':'70MiB','GOGC':'50'})
            try:
                time.sleep(1)
                report['process_started']=process.poll() is None
                if report['process_started']:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                        for round_id in range(int(os.environ.get('VPN_TEST_ROUNDS','10'))):
                            targets=[('https://www.gstatic.com/generate_204',204)]
                            if os.environ.get('VPN_TEST_TARGETS')=='mixed':targets=[('https://example.com/',200),('https://www.cloudflare.com/cdn-cgi/trace',200),('https://www.gstatic.com/generate_204',204)]
                            url,status=targets[round_id%len(targets)]
                            report['target_urls'].append(url)
                            results=list(pool.map(lambda index:probe(index,url,status),range(2)))
                            report['rounds'].append(results);report['memory_bytes'].append(memory())
                            REPORT.write_text(json.dumps(report,indent=2))
                            print(json.dumps({'engine':ENGINE,'round':round_id+1,'results':results}),flush=True)
                            time.sleep(float(os.environ.get('VPN_TEST_INTERVAL','.5')))
                        download_url=os.environ.get('VPN_TEST_DOWNLOAD_URL','https://speed.cloudflare.com/__down?bytes=1048576')
                        report['download']=list(pool.map(lambda index:probe(index,download_url,200),range(2)))
                else:report['exit_code']=process.returncode
                # Counts only; private engine logs are destroyed with the temporary directory.
                text=log.read_text(errors='replace')
                report['log_counts']={name:text.lower().count(name) for name in ['error','timeout','unsupported curve','authentication']}
                diagnostic='\n'.join(text.splitlines()[-8:])
                for p in NODES:
                    for value in [p.get('uuid'),p.get('server'),p.get('servername'),*p.get('reality-opts',{}).values()]:
                        if isinstance(value,str) and value:diagnostic=diagnostic.replace(value,'[redacted]')
                report['diagnostic']=diagnostic
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
REPORT.write_text(json.dumps(report,indent=2))
print(json.dumps({'engine':ENGINE,'config_valid':report['config_valid'],
                  'successes':[sum(r[i]['ok'] for r in report['rounds']) for i in range(2)],
                  'total_per_node':len(report['rounds']),'download':report.get('download'),
                  'peak_container_memory':max((n for n in report['memory_bytes'] if n),default=None)}),flush=True)
