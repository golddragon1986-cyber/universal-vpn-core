import json,sys
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import quote,urlencode
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as manager
def api(path):
    with urlopen('http://127.0.0.1:9090'+path,timeout=15) as response:return json.load(response)
nodes=manager.read()['nodes']
checks=[]
for n in nodes:
    attempts=[]
    for url in ('https://www.gstatic.com/generate_204','https://telegram.org','https://cp.cloudflare.com/generate_204'):
        try:
            delay=api('/providers/proxies/USER-MANAGED/'+quote(n['proxy']['name'],safe='')+'/healthcheck?'+urlencode({'url':url,'timeout':10000}))['delay']
            attempts.append({'url':url,'delay':delay})
            if delay>0:break
        except Exception as error:attempts.append({'url':url,'error':str(error)})
    checks.append({'name':n['proxy']['name'],'client':n.get('client'),'balance':n.get('balance'),'delay_ms':next((a['delay'] for a in attempts if a.get('delay',0)>0),-1),'attempts':attempts})
result={'nodes':checks,'balance_members':api('/proxies/LOADBALANCE')['all'],'selected_route':api('/proxies/SELECTOR')['now']}
print(json.dumps(result),flush=True)
assert all(n['client']=='mihomo' and n['balance'] and n['delay_ms']>0 for n in result['nodes'])
assert result['selected_route']=='LOADBALANCE'
assert set(result['balance_members'])=={'CHANNEL-FL','CHANNEL-SV-inbound'}
Path('/etc/mihomo/rb4011-transfer-verified.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
