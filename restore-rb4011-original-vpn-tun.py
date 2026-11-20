"""Restore only pre-ac3 VPN profiles and the existing TUN path, on the RB4011."""
import copy,json,re,sys,tarfile
from pathlib import Path
from urllib.request import urlopen
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as manager
import transparent_tcp
from durable_io import write

root=Path('/etc/mihomo');rules=root/'rules'
with urlopen('http://127.0.0.1:9091/api/actions/status',timeout=10) as response:queue=json.load(response)
assert queue['running']==queue['queued']==0,'Panel queue must be idle'
with tarfile.open(root/'before-ac3-transfer-20261106.tgz','r:gz') as archive:
    original=json.load(archive.extractfile('state/rules/managed-proxies.json'))
assert [n['proxy']['name'] for n in original['nodes']]==['SB-SV','FL-testARM']
assert all(n.get('client','mihomo')=='mihomo' and n['proxy']['type']=='vless' and n['proxy']['server'] not in ('127.0.0.1','localhost') for n in original['nodes'])
assert (Path('/sys/class/net')/'mihomo').exists(),'Existing TUN interface missing'
block=re.search(r'(?m)^tun:\n(?:[ \t].*\n|\n)*',(root/'default_config.yaml').read_text()).group()
assert re.search(r'(?m)^\s+enable:\s*true\b',block),'TUN disabled'
before=manager.read();service_path=rules/'service-routes.json';services_raw=service_path.read_bytes();tcp_raw=transparent_tcp.CONFIG.read_bytes()
services=json.loads(services_raw)
mapping={'SV-inbound':'SB-SV','FL':'FL-testARM','CHANNEL-SV-inbound':'CHANNEL-SB-SV','CHANNEL-FL':'CHANNEL-FL-testARM'}
for service in services:
    if service.get('target') in mapping:service['target']=mapping[service['target']]
settings=json.loads(tcp_raw);settings['enabled']=False
try:
    manager.save(original)
    write(service_path,json.dumps(services,ensure_ascii=False,indent=2).encode())
    write(transparent_tcp.CONFIG,json.dumps(settings,indent=2).encode())
    manager.sync()
    transparent_tcp.apply()
    print(json.dumps({'restored_profiles':[n['proxy']['name'] for n in manager.read()['nodes']],'tcp':'TUN','udp':'TUN','additional_clients_installed':False}),flush=True)
except BaseException:
    manager.save(before);write(service_path,services_raw);write(transparent_tcp.CONFIG,tcp_raw)
    manager.sync();transparent_tcp.apply()
    raise
