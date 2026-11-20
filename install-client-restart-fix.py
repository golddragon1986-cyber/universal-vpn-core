import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
from durable_io import write
root=Path('/etc/mihomo');source=(root/'fix-check/vpn_clients.py').read_bytes()
compile(source,'vpn_clients.py','exec')
backup=root/'before-client-restart-fix-20261106';backup.mkdir(mode=0o700,exist_ok=True)
for name in ('rules/managed-proxies.json','clients/panel-xray.json','default_config.yaml'):
    path=root/name;target=backup/path.name
    if path.exists() and not target.exists():write(target,path.read_bytes(),0o600)
for index,path in enumerate((root/'rules/vpn_clients.py',Path('/usr/local/lib/mihomo-panel/panel/vpn_clients.py'))):
    old=backup/('vpn_clients-'+str(index)+'.py')
    if not old.exists():write(old,path.read_bytes(),0o600)
    write(path,source,0o600)
print(json.dumps({'installed':True,'sha256':hashlib.sha256(source).hexdigest(),'backup':str(backup)}))
