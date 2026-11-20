import copy,hashlib,io,json,sys,tarfile
from pathlib import Path
ROOT=Path('/etc/mihomo');sys.path.insert(0,str(ROOT/'rules'))
import proxy_manager,vpn_clients
state=['rules/service-routes.json','rules/routing-settings.json','rules/log-settings.json','rules/resource-limits.json','rules/ru-blocked-source.txt','rules/ru-blocked-local-add.txt','rules/ru-blocked-local-remove.txt','rules/ru-blocked-local-delete.txt','rules/ru-blocked-filters.txt','rules/ru-blocked-domain.txt','rules/ru-blocked-mihomo.mrs','rules/ru-blocked-mihomo.yaml','rules/telegram-ip.yaml','rules/router-ip.yaml','rules/panel-managed-template.yaml']
db=copy.deepcopy(proxy_manager.read())
for node in db['nodes']:
    original=vpn_clients.canonical(node)
    node['proxy']=original;node['connection']=copy.deepcopy(original);node['client']='mihomo'
    node.pop('client_proxies',None);node.pop('client_ports',None)
archive=ROOT/'ac3-settings-for-rb4011.tgz';count=0
with tarfile.open(archive,'w:gz') as tar:
    for path in sorted((ROOT/'rules').iterdir()):
        if path.is_file() and path.suffix in ('.py','.sh','.html','.css','.js'):
            tar.add(path,arcname='rules/'+path.name,recursive=False);count+=1
    for name in state:
        path=ROOT/name
        if path.is_file():tar.add(path,arcname=name,recursive=False);count+=1
    data=json.dumps(db,ensure_ascii=False,indent=2).encode();info=tarfile.TarInfo('rules/managed-proxies.json');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
    for name in ('entrypoint.sh','initialize.py','default-config.yaml','management-acl-mode','official-container','VERSION'):
        p=Path('/usr/local/lib/mihomo-panel')/name
        if p.is_file():tar.add(p,arcname='package/'+name,recursive=False);count+=1
archive.chmod(0o600)
print(json.dumps({'archive':archive.name,'files':count+1,'bytes':archive.stat().st_size,'sha256':hashlib.file_digest(archive.open('rb'),'sha256').hexdigest(),'nodes':[{'name':n['proxy']['name'],'client':n['client'],'balance':n.get('balance')} for n in db['nodes']],'vpn_binaries_included':False,'routeros_credentials_included':False}),flush=True)
