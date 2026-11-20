import json,tarfile,time
from pathlib import Path
from urllib.request import urlopen
ROOT=Path('/etc/mihomo');OUT=ROOT/'before-ac3-transfer-20261106.tgz'
with urlopen('http://127.0.0.1:9091/api/actions/status',timeout=10) as r:state=json.load(r)
assert state['running']==0 and state['queued']==0,'Panel queue must be idle'
def filter_member(info):
    if '__pycache__' in info.name or info.name.endswith(('.pyc','.tgz','.tar','.tar.gz')):return None
    return info
with tarfile.open(OUT,'w:gz') as tar:
    tar.add(ROOT,arcname='state',filter=filter_member)
    tar.add('/usr/local/lib/mihomo-panel',arcname='package',filter=filter_member)
OUT.chmod(0o600);print(json.dumps({'backup':OUT.name,'bytes':OUT.stat().st_size}),flush=True)
