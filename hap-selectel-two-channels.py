import json,re,sys
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo')
def api(path,data=None):
    request=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data else 'GET')
    with urlopen(request,timeout=20) as response:
        body=response.read();return json.loads(body) if body else None
action=sys.argv[1]
if action=='setup':
    text=(ROOT/'default_config.yaml').read_text()
    text,count=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,speedtest.selectel.ru,LOADBALANCE\n',text)
    assert count==1
    path=ROOT/'tcp-proxy-speed-20261106/cloudflare-two-channels.yaml'
    path.write_text(text);path.chmod(0o600)
    api('/configs?force=true',{'path':str(path)})
    print('Cloudflare test domain routed through LOADBALANCE')
elif action=='status':
    rows=[{'type':c['metadata'].get('type'),'chains':c.get('chains')} for c in api('/connections')['connections'] if c['metadata'].get('host')=='speedtest.selectel.ru']
    print(json.dumps(rows))
    assert rows and all('LOADBALANCE' in c['chains'] for c in rows) and any('SV-inbound' in c['chains'] for c in rows) and any('FL' in c['chains'] for c in rows)
elif action=='restore':
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    print('Persistent configuration restored')


