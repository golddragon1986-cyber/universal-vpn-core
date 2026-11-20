import json,re,sys
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo')
def api(path,data=None):
    request=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data else 'GET')
    with urlopen(request,timeout=20) as response:
        body=response.read();return json.loads(body) if body else None
action=sys.argv[1]
if action=='io':
    counters={}
    for line in Path('/proc/vmstat').read_text().splitlines():
        key,value=line.split()
        if key in ('pswpin','pswpout'):counters[key]=int(value)
    disks=[]
    for line in Path('/proc/diskstats').read_text().splitlines():
        fields=line.split()
        if fields[2].startswith(('sd','usb','mmc')):disks.append({'device':fields[2],'sectors_read':int(fields[5]),'sectors_written':int(fields[9]),'io_ms':int(fields[12])})
    path=Path('/sys/fs/cgroup/memory.swap.current')
    print(json.dumps({'swap':counters,'swap_bytes':int(path.read_text()) if path.exists() else None,'disks':disks}));sys.exit(0)
if action=='setup':
    text=(ROOT/'default_config.yaml').read_text()
    text,count=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,server-32926.prod.hosts.ooklaserver.net,CHANNEL-SV-inbound\n',text)
    assert count==1
    path=ROOT/'tcp-proxy-speed-20261106/stockholm-retn-temporary.yaml'
    path.write_text(text);path.chmod(0o600)
    api('/configs?force=true',{'path':str(path)})
    print('Cloudflare test domain routed through SV-inbound')
elif action=='status':
    rows=[{'type':c['metadata'].get('type'),'chains':c.get('chains')} for c in api('/connections')['connections'] if c['metadata'].get('host')=='server-32926.prod.hosts.ooklaserver.net']
    print(json.dumps(rows))
    assert rows and all('SV-inbound' in c['chains'] for c in rows)
elif action=='restore':
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    print('Persistent configuration restored')



