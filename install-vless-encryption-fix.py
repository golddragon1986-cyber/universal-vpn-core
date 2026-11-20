import hashlib,json,py_compile,sys
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
anchor="    typ=p['type']\n"
patch="""    # VLESS encryption=none is implicit in sing-box; preserve the source profile.
    if typ=='vless' and 'encryption' in p:
        if p['encryption']!='none':
            raise ValueError('Перенос VLESS encryption поддерживается только для значения none')
        p=copy.deepcopy(p)
        p.pop('encryption')
"""
from durable_io import write
for path in (Path('/etc/mihomo/rules/vpn_clients.py'),Path('/usr/local/lib/mihomo-panel/panel/vpn_clients.py')):
    if not path.exists():continue
    text=path.read_text()
    if "if typ=='vless' and 'encryption' in p:" in text:
        print(str(path)+': already fixed');continue
    if text.count(anchor)!=1:raise RuntimeError('Unexpected converter layout; no replacement for '+str(path))
    candidate=text.replace(anchor,anchor+patch,1)
    compile(candidate,str(path),'exec')
    backup=Path(str(path)+'.before-encryption-fix')
    if not backup.exists():write(backup,text.encode())
    write(path,candidate.encode())
    print(str(path)+': fixed')
import vpn_clients,proxy_manager
for node in proxy_manager.read()['nodes']:
    p=vpn_clients.canonical(node)
    if p.get('type')!='vless':continue
    path,cfg,port=vpn_clients.build_external(node,'sing-box')
    vpn_clients.validate('sing-box',cfg)
    print(json.dumps({'name':p['name'],'sing_box_config_check':'passed','source_profile_preserved':True}))
