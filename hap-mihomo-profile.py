import json,re,sys,os,signal
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo')
WORK=ROOT/'cpu-profile-20261107'
def api(path,data=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data else 'GET')
    with urlopen(req,timeout=30) as response:
        body=response.read();return json.loads(body) if body else None
action=sys.argv[1]
if action=='setup':
    WORK.mkdir(mode=0o700,exist_ok=True)
    text=(ROOT/'default_config.yaml').read_text()
    backup=WORK/'baseline.yaml'
    if not backup.exists():backup.write_text(text);backup.chmod(0o600)
    text,count=re.subn(r'(?m)^log-level:.*$','log-level: debug',text);assert count==1
    text,count=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,server-32926.prod.hosts.ooklaserver.net,CHANNEL-SV-inbound\n  - DOMAIN,speedtest.selectel.ru,CHANNEL-SV-inbound\n',text);assert count==1
    path=WORK/'temporary.yaml';path.write_text(text);path.chmod(0o600)
    api('/configs?force=true',{'path':str(path)})
    print(json.dumps({'setup':True,'log_level':api('/configs').get('log-level')}))
elif action=='restore':
    baseline=WORK/'baseline.yaml'
    if (WORK/'activated').exists():
        (ROOT/'default_config.yaml').write_bytes(baseline.read_bytes())
        state=json.loads(Path('/tmp/mihomo-supervisor.json').read_text())
        os.kill(state['pid'],signal.SIGHUP)
        (WORK/'activated').unlink()
        print(json.dumps({'restored':True,'core_restarting':True}));sys.exit(0)
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    print(json.dumps({'restored':True,'log_level':api('/configs').get('log-level')}))
elif action=='activate':
    baseline=WORK/'baseline.yaml'
    assert (ROOT/'default_config.yaml').read_bytes()==baseline.read_bytes(),'Configuration changed since snapshot'
    (WORK/'activated').write_text('1')
    (ROOT/'default_config.yaml').write_bytes((WORK/'temporary.yaml').read_bytes())
    state=json.loads(Path('/tmp/mihomo-supervisor.json').read_text())
    os.kill(state['pid'],signal.SIGHUP)
    print(json.dumps({'activated':True,'core_restarting':True}))
