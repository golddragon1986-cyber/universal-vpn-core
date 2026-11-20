import copy,io,json,re,subprocess,sys,tarfile
from pathlib import Path,PurePosixPath
from urllib.request import urlopen
ROOT=Path('/etc/mihomo');PKG=Path('/usr/local/lib/mihomo-panel')
sys.path.insert(0,str(ROOT/'rules'));from durable_io import write
with urlopen('http://127.0.0.1:9091/api/actions/status',timeout=10) as response:status=json.load(response)
assert status['running']==status['queued']==0,'Wait for idle panel queue'
old=(ROOT/'default_config.yaml').read_text()
old_tun=re.search(r'(?m)^tun:\n(?:[ \t].*\n|\n)*',old).group(0)
keep={k:re.search(r'(?m)^  '+k+r': (.+)$',old_tun).group(1) for k in ('device','mtu') if re.search(r'(?m)^  '+k+r': (.+)$',old_tun)}
allowed_state={'service-routes.json','routing-settings.json','log-settings.json','resource-limits.json','managed-proxies.json','ru-blocked-source.txt','ru-blocked-local-add.txt','ru-blocked-local-remove.txt','ru-blocked-local-delete.txt','ru-blocked-filters.txt','ru-blocked-domain.txt','ru-blocked-mihomo.mrs','ru-blocked-mihomo.yaml','telegram-ip.yaml','router-ip.yaml','panel-managed-template.yaml'}
code=[];files=0
with tarfile.open(ROOT/'ac3-settings-for-rb4011.tgz','r:gz') as archive:
    for member in archive:
        parts=PurePosixPath(member.name).parts
        if not member.isfile() or len(parts)!=2 or any(x in ('..','.') for x in parts):raise RuntimeError('Unexpected transfer entry')
        data=archive.extractfile(member).read()
        if parts[0]=='rules':
            name=parts[1];is_code=Path(name).suffix in ('.py','.sh','.html','.css','.js')
            if not is_code and name not in allowed_state:raise RuntimeError('Unexpected state file')
            if name=='panel-managed-template.yaml':
                text=data.decode()
                for key,value in keep.items():
                    if not re.search(r'(?m)^  '+key+r':',text):text=text.replace('tun:\n','tun:\n  '+key+': '+value+'\n',1)
                data=text.encode()
            write(ROOT/member.name,data,0o755 if name.endswith('.sh') else 0o600)
            if is_code:
                target=PKG/'panel'/name;target.parent.mkdir(parents=True,exist_ok=True)
                write(target,data,0o755 if name.endswith('.sh') else 0o644);code.append(name)
        elif parts[0]=='package' and parts[1] in ('entrypoint.sh','initialize.py','default-config.yaml','management-acl-mode','official-container','VERSION'):
            write(PKG/parts[1],data,0o755 if parts[1].endswith('.sh') else 0o644)
        else:raise RuntimeError('Unexpected transfer path')
        files+=1
db=json.loads((ROOT/'rules/managed-proxies.json').read_text())
assert all(n.get('client')=='mihomo' and n['proxy'].get('server') not in ('127.0.0.1','localhost') for n in db['nodes'])
write(ROOT/'rules/user-proxies.yaml',json.dumps({'proxies':[n['proxy'] for n in db['nodes']]}).encode())
settings={'enabled':True,'interface':'veth-universal','container_address':'172.31.41.2','clients':['10.0.0.0/24','192.168.0.0/16'],'port':7893}
write(ROOT/'rules/transparent-tcp.json',(json.dumps(settings,indent=2)+'\n').encode())
print(json.dumps({'files_imported':files,'code_files':len(code),'vpn_clients':[{'name':n['proxy']['name'],'engine':n['client']} for n in db['nodes']],'preserved_tun':keep,'clients':settings['clients'],'additional_vpn_binaries_installed':False}),flush=True)
