import ipaddress,json,os,re,socket,subprocess,sys,time
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo');WORK=ROOT/'tcp-redirect-20261106';WORK.mkdir(mode=0o700,exist_ok=True)
IPT='iptables-legacy';CHAIN='UVPN_TCP_STAGE';PORT=7893
def command(args,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if check and p.returncode:raise RuntimeError((p.stderr+p.stdout)[-1000:])
    return p
def api(path,data=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data is not None else 'GET')
    with urlopen(req,timeout=40) as r:
        raw=r.read();return json.loads(raw) if raw else None
def cleanup():
    jump=['-i','veth-universal','-s','192.168.99.0/24','-p','tcp','-j',CHAIN]
    while command([IPT,'-t','nat','-C','PREROUTING',*jump],False).returncode==0:
        command([IPT,'-t','nat','-D','PREROUTING',*jump])
    if command([IPT,'-t','nat','-S',CHAIN],False).returncode==0:
        command([IPT,'-t','nat','-F',CHAIN]);command([IPT,'-t','nat','-X',CHAIN])
action=sys.argv[1]
if action=='setup':
    target=str(ipaddress.IPv4Address(sys.argv[2]));assert ipaddress.ip_address(target) in ipaddress.ip_network('198.18.0.0/16')
    baseline=WORK/'baseline.yaml'
    if not baseline.exists():baseline.write_bytes((ROOT/'default_config.yaml').read_bytes());baseline.chmod(0o600)
    text=baseline.read_text()
    if re.search(r'(?m)^redir-port:',text):raise RuntimeError('Existing redirect port; inspect before changes')
    text='redir-port: '+str(PORT)+'\n'+text
    text,count=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,speedtest.selectel.ru,CHANNEL-SV-inbound\n',text)
    if count!=1:raise RuntimeError('Unexpected rules block')
    path=WORK/'temporary.yaml';path.write_text(text);path.chmod(0o600)
    checked=command(['mihomo','-t','-d',str(ROOT),'-f',str(path)],False)
    if checked.returncode:raise RuntimeError('Redirect config rejected')
    cleanup()
    try:
        api('/configs?force=true',{'path':str(path)})
        deadline=time.monotonic()+10
        while True:
            try:
                with socket.create_connection(('127.0.0.1',PORT),timeout=.3):break
            except OSError:
                if time.monotonic()>deadline:raise RuntimeError('Redirect listener did not open')
                time.sleep(.2)
        command([IPT,'-t','nat','-N',CHAIN])
        command([IPT,'-t','nat','-A',CHAIN,'-p','tcp','-d',target+'/32','-j','REDIRECT','--to-ports',str(PORT)])
        command([IPT,'-t','nat','-I','PREROUTING','1','-i','veth-universal','-s','192.168.99.0/24','-p','tcp','-j',CHAIN])
        print(json.dumps({'redirect_test_ip':target,'port':PORT,'udp':'unchanged through mixed TUN'}),flush=True)
    except Exception:
        cleanup();api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')});raise
elif action=='observe':
    active=[]
    for conn in api('/connections').get('connections',[]):
        m=conn.get('metadata',{})
        if m.get('host')=='speedtest.selectel.ru':
            active.append({k:m.get(k) for k in ('type','sourceIP','destinationIP','destinationPort','host')})
    print(json.dumps(active),flush=True)
    print(command([IPT,'-t','nat','-L',CHAIN,'-n','-v','-x']).stdout,flush=True)
elif action=='rollback':
    cleanup();api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')});print('Staged redirect removed; mixed TUN restored',flush=True)
