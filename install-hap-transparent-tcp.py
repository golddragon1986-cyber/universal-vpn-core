import json,re,subprocess,sys
from pathlib import Path
ROOT=Path('/etc/mihomo');WORK=ROOT/'tcp-redirect-20261106'
sys.path.insert(0,str(ROOT/'rules'));from durable_io import write
source=(ROOT/'fix-check/transparent_tcp.py').read_bytes();compile(source,'transparent_tcp.py','exec')
files=[ROOT/n for n in ('default_config.yaml','default_config_candidate.yaml','template/default_config.yaml','rules/panel-managed-template.yaml')]
package=Path('/usr/local/lib/mihomo-panel');entry=package/'entrypoint.sh'
extras=[entry,ROOT/'rules/config_backup.py',package/'panel/config_backup.py',ROOT/'rules/transparent-tcp.json']
backups={path:(path.read_bytes() if path.exists() else None) for path in files+extras}
backup_dir=WORK/'before-install';backup_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
for i,(path,data) in enumerate(backups.items()):
    if data is not None and not (backup_dir/str(i)).exists():write(backup_dir/str(i),data)
write(backup_dir/'manifest.json',json.dumps([{'path':str(p),'file':str(i) if data is not None else None} for i,(p,data) in enumerate(backups.items())]).encode())
try:
    for p in (ROOT/'rules/transparent_tcp.py',package/'panel/transparent_tcp.py'):write(p,source)
    for path in files:
        text=path.read_text()
        if re.search(r'(?m)^redir-port:',text):
            if not re.search(r'(?m)^redir-port: 7893\s*$',text):raise RuntimeError('Existing redirect port differs')
        else:text='redir-port: 7893\n'+text
        write(path,text.encode())
    text=entry.read_text();anchor='python3 /etc/mihomo/rules/boot_config.py\n'
    if 'transparent_tcp.py' not in text:
        if text.count(anchor)!=1:raise RuntimeError('Unexpected entrypoint layout')
        hook="if [ -f /etc/mihomo/rules/transparent-tcp.json ]; then\n    python3 /etc/mihomo/rules/transparent_tcp.py || echo 'Transparent TCP setup failed; retaining TUN fallback'\nfi\n"
        write(entry,text.replace(anchor,anchor+hook,1).encode(),0o755)
    for path in extras[1:3]:
        if not path.exists():continue
        text=path.read_text()
        if "EXTRA.add('rules/transparent-tcp.json')" not in text:text=text.replace('def allowed(name):',"EXTRA.add('rules/transparent-tcp.json')\n\ndef allowed(name):",1)
        if '    transparent_tcp.apply()' not in text:
            text=text.replace('    restore_level()\n','    restore_level()\n    import transparent_tcp\n    transparent_tcp.apply()\n',1)
        compile(text,str(path),'exec');write(path,text.encode())
    settings={'enabled':True,'interface':'veth-universal','container_address':'172.31.41.2','clients':['192.168.99.0/24','192.168.8.0/23'],'port':7893}
    write(ROOT/'rules/transparent-tcp.json',(json.dumps(settings,indent=2)+'\n').encode())
    check=subprocess.run(['mihomo','-t','-d',str(ROOT),'-f',str(ROOT/'default_config.yaml')],capture_output=True,timeout=45)
    if check.returncode:raise RuntimeError('Persistent redirect configuration rejected')
    from urllib.request import Request,urlopen
    request=Request('http://127.0.0.1:9090/configs?force=true',data=json.dumps({'path':str(ROOT/'default_config.yaml')}).encode(),headers={'Content-Type':'application/json'},method='PUT')
    with urlopen(request,timeout=40) as response:assert response.status==204
    import transparent_tcp
    print(json.dumps(transparent_tcp.apply()),flush=True)
except Exception:
    try:
        import transparent_tcp;transparent_tcp.remove()
    except Exception:pass
    for path,data in backups.items():
        if data is None:path.unlink(missing_ok=True)
        else:write(path,data,0o755 if path==entry else 0o600)
    raise
