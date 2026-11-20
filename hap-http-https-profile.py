import hashlib,json,re,sys,time,os,signal
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo');WORK=ROOT/'http-https-profile-20261107'
def api(path,payload=None):
    request=Request('http://127.0.0.1:9090'+path,data=None if payload is None else json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='PUT' if payload is not None else 'GET')
    with urlopen(request,timeout=25) as response:
        body=response.read();return json.loads(body) if body else None
action=sys.argv[1]
if action=='setup':
    assert not (WORK/'active').exists(),'Diagnostic setup already active'
    WORK.mkdir(mode=0o700,exist_ok=True)
    original=(ROOT/'default_config.yaml').read_text()
    (WORK/'baseline.yaml').write_text(original);(WORK/'baseline.yaml').chmod(0o600)
    text,count=re.subn(r'(?m)^log-level:.*$','log-level: debug',original);assert count==1
    match=re.search(r'(?m)^external-controller:\s*(.*?)\s*$',text);assert match
    old=match.group(1).strip('\"\'');assert old in ('0.0.0.0:9090',':9090','*:9090')
    new=':9090' if old!=':9090' else '0.0.0.0:9090'
    text=text[:match.start()]+f'external-controller: "{new}"'+text[match.end():]
    address=sys.argv[2]
    import ipaddress
    address=str(ipaddress.IPv4Address(address))
    text,count=re.subn(r'(?m)^rules:\n',f'rules:\n  - IP-CIDR,{address}/32,CHANNEL-SV-inbound,no-resolve\n  - DOMAIN,server-32926.prod.hosts.ooklaserver.net,CHANNEL-SV-inbound\n',text);assert count==1
    provider=json.loads((ROOT/'rules/user-proxies.yaml').read_text())
    for proxy in provider['proxies']:
        if proxy.get('name')=='SV-inbound':proxy['client-fingerprint']='chrome'
    provider_path=WORK/'provider.json';provider_path.write_text(json.dumps(provider));provider_path.chmod(0o600)
    assert 'rules/user-proxies.yaml' in text
    text=text.replace('rules/user-proxies.yaml','http-https-profile-20261107/provider.json')
    path=WORK/'temporary.yaml';path.write_text(text);path.chmod(0o600)
    (WORK/'active').write_text('1')
    try:api('/configs?force=true',{'path':str(path)})
    except Exception as error:print(json.dumps({'api_rebind':type(error).__name__}))
    print(json.dumps({'setup':True,'persistent_config_unchanged':(ROOT/'default_config.yaml').read_text()==original}))
elif action=='restore':
    baseline=(WORK/'baseline.yaml').read_bytes()
    if (WORK/'core-active').exists():
        (ROOT/'default_config.yaml').write_bytes(baseline)
        state=json.loads(Path('/tmp/mihomo-supervisor.json').read_text());os.kill(state['pid'],signal.SIGHUP)
        (WORK/'core-active').unlink();(WORK/'active').unlink(missing_ok=True)
        print(json.dumps({'restored':True,'core_restarting':True}));sys.exit(0)
    assert (ROOT/'default_config.yaml').read_bytes()==baseline,'Persistent config changed; restore must not overwrite it'
    try:api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    except Exception as error:print(json.dumps({'api_rebind':type(error).__name__}))
    (WORK/'active').unlink(missing_ok=True)
    print(json.dumps({'restored':True,'persistent_sha256':hashlib.sha256(baseline).hexdigest()}))
elif action=='activate':
    baseline=(WORK/'baseline.yaml').read_bytes()
    assert (ROOT/'default_config.yaml').read_bytes()==baseline
    (WORK/'core-active').write_text('1')
    (ROOT/'default_config.yaml').write_bytes((WORK/'temporary.yaml').read_bytes())
    state=json.loads(Path('/tmp/mihomo-supervisor.json').read_text());os.kill(state['pid'],signal.SIGHUP)
    print(json.dumps({'core_restarting':True}))
