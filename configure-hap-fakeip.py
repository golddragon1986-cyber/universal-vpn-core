"""Enable persistent TUN/Fake IP on the clean hAP instance."""
import json
from pathlib import Path
import subprocess
import sys
import re
from urllib.request import Request, urlopen
root=Path('/etc/mihomo')
sys.path.insert(0,str(root/'rules'))
from durable_io import write
template=root/'rules/panel-managed-template.yaml'
text=template.read_text()
new='tun:\n  enable: true\n  stack: mixed\n  auto-route: true\n  auto-redirect: false\n  auto-detect-interface: true\n  inet4-address:\n    - 198.19.0.1/30\n  route-address:\n    - 198.18.0.0/16\n'
changed,count=re.subn(r'^tun:\n(?:[ \t].*\n|\n)*',new,text,flags=re.M)
if count != 1:
    raise RuntimeError('Unexpected TUN template; no changes applied')
if not Path(str(template)+'.before-fakeip').exists():
    write(str(template)+'.before-fakeip',text.encode())
settings=root/'rules/routing-settings.json'
original=settings.read_bytes()
if not Path(str(settings)+'.before-fakeip').exists():
    write(str(settings)+'.before-fakeip',original)
data=json.loads(original)
data.update(main_proxy='LOADBALANCE',dns_enhanced_mode_before_direct='fake-ip')
import boot_config
runtime,mode=boot_config.compose(changed,data)
candidate=root/'fakeip-validated.yaml'
write(candidate,runtime.encode())
subprocess.run(['mihomo','-t','-d',str(root),'-f',str(candidate)],check=True,timeout=60)
write(template,changed.encode())
write(settings,(json.dumps(data)+'\n').encode())
for path in [root/'template/default_config.yaml',root/'default_config_candidate.yaml',root/'default_config.yaml']:
    write(path,(changed if path.parent.name=='template' else runtime).encode())
request=Request('http://127.0.0.1:9090/configs?force=true',data=json.dumps({'path':str(root/'default_config.yaml')}).encode(),headers={'Content-Type':'application/json'},method='PUT')
with urlopen(request,timeout=60) as response:
    print('Reload HTTP',response.status)
print('Persistent TUN/Fake IP configuration validated')
