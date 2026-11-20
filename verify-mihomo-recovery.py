import json,sys
from urllib.request import ProxyHandler,build_opener
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager
health=[]
for _ in range(5):
    try:health.append(proxy_manager.delay('SV-inbound'))
    except Exception as error:health.append(type(error).__name__)
opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:1080'}));web=[]
for _ in range(3):
    try:
        with opener.open('https://telegram.org',timeout=8) as response:response.read(1024);web.append(response.status)
    except Exception as error:web.append(type(error).__name__)
report={'sv_delay_ms':health,'telegram_https':web}
Path('/etc/mihomo/recovery-verification-20261107.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report),flush=True)
assert all(isinstance(value,int) and value>0 for value in health)
assert web==[200]*3
