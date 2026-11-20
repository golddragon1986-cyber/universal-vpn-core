import copy,hashlib,json,sys,re
from pathlib import Path
from urllib.request import urlopen
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients
def api(path):
    with urlopen('http://127.0.0.1:9090'+path,timeout=10) as response:return json.load(response)
state=proxy_manager.read();node=next(n for n in state['nodes'] if n['proxy']['name']=='SV-inbound');canonical=vpn_clients.canonical(node)
def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()
baseline=json.loads((Path('/etc/mihomo/rules/user-proxies.yaml')).read_text())
configured=next(p for p in baseline['proxies'] if p['name']=='SV-inbound')
checks={}
for name in ('SELECTOR','CHANNEL-SV-inbound','LOADBALANCE'):
    try:
        group=api('/proxies/'+name);checks[name]={k:group.get(k) for k in ('type','now','all')}
    except Exception as error:checks[name]={'error':type(error).__name__}
try:latency=proxy_manager.delay('SV-inbound')
except Exception as error:latency=type(error).__name__+': '+str(error)
paths={}
for name in ('default_config.yaml','default_config_candidate.yaml','cpu-profile-20261107/baseline.yaml'):
    text=(Path('/etc/mihomo')/name).read_text()
    match=re.search(r'(?ms)^  USER-MANAGED:\n(.*?)(?=^  [^ ]|^[^ ]|\Z)',text)
    paths[name]=re.findall(r'(?m)^\s+path:\s*(.*)$',match.group(1)) if match else []
print(json.dumps({'canonical_matches_provider_file':canonical==configured,'canonical_sha256':digest(canonical),'groups':checks,'health':latency,'config_log_level':api('/configs').get('log-level'),'provider_paths':paths}))
