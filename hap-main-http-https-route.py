import json,re,sys
from pathlib import Path
from urllib.request import Request,urlopen
root=Path('/etc/mihomo');directory=root/'http-https-main-20261107';directory.mkdir(mode=0o700,exist_ok=True)
def reload(path):
    request=Request('http://127.0.0.1:9090/configs?force=true',data=json.dumps({'path':str(path)}).encode(),headers={'Content-Type':'application/json'},method='PUT')
    with urlopen(request,timeout=25):pass
if sys.argv[1]=='setup':
    text=(root/'default_config.yaml').read_text()
    original=directory/'baseline.yaml';original.write_text(text);original.chmod(0o600)
    candidate,count=re.subn(r'(?m)^rules:\n','rules:\n  - IP-CIDR,139.45.201.129/32,CHANNEL-SV-inbound,no-resolve\n',text);assert count==1
    path=directory/'temporary.yaml';path.write_text(candidate);path.chmod(0o600);reload(path)
    print(json.dumps({'setup':True}))
else:
    reload(root/'default_config.yaml');print(json.dumps({'restored':True}))
