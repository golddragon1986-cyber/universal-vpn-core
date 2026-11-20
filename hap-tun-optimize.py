import ast,json,os,re,subprocess,sys,time
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/etc/mihomo');WORK=ROOT/'tun-optimization-20261106'
WORK.mkdir(mode=0o700,exist_ok=True)
def api(path,data=None):
    req=Request('http://127.0.0.1:9090'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='PUT' if data is not None else 'GET')
    with urlopen(req,timeout=40) as r:
        raw=r.read();return json.loads(raw) if raw else None
def stack(text,value):
    changed,n=re.subn(r'(?m)^  stack: (?:gvisor|system|mixed)\s*$', '  stack: '+value,text)
    if n!=1:raise RuntimeError('Unexpected TUN stack layout')
    return changed
action=sys.argv[1];phase=sys.argv[2] if len(sys.argv)>2 else ''
if action=='prepare':
    if phase not in ('gvisor','system','mixed'):raise ValueError('Unknown stack')
    for name in ('default_config.yaml','default_config_candidate.yaml','template/default_config.yaml','rules/panel-managed-template.yaml'):
        backup=WORK/name
        if not backup.exists():backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes((ROOT/name).read_bytes());backup.chmod(0o600)
    text=stack((WORK/'default_config.yaml').read_text(),phase)
    text,n=re.subn(r'(?m)^rules:\n','rules:\n  - DOMAIN,speedtest.selectel.ru,CHANNEL-SV-inbound\n',text)
    if n!=1:raise RuntimeError('Unexpected rules block')
    path=WORK/'temporary.yaml';path.write_text(text);path.chmod(0o600)
    check=subprocess.run(['mihomo','-t','-d',str(ROOT),'-f',str(path)],capture_output=True,timeout=45)
    if check.returncode:raise RuntimeError('TUN configuration rejected')
    api('/configs?force=true',{'path':str(path)})
    print(json.dumps({'stack':phase,'benchmark_domain_route':'CHANNEL-SV-inbound'}),flush=True)
elif action=='monitor':
    if not re.fullmatch('[a-z0-9-]+',phase):raise ValueError('Invalid phase')
    source=(ROOT/'benchmark-hap-vpn.py').read_text().split('baseline=snapshot();results=[]')[0]
    source=source.replace("('mihomo','python3')","('mihomo','python3','sing-box','xray')")
    ns={};exec(compile(source,'benchmark-helpers','exec'),ns)
    flag=WORK/(phase+'.stop');flag.unlink(missing_ok=True)
    samples=[ns['snapshot']()];print('READY',flush=True)
    while time.monotonic()-samples[0]['time']<90 and not flag.exists():
        time.sleep(.5);samples.append(ns['snapshot']())
    samples.append(ns['snapshot']());result=ns['summarize'](samples)
    a,b=samples[0]['cpu']['cpu'],samples[-1]['cpu']['cpu'];delta=[y-x for x,y in zip(a,b)]
    result['host_busy_cpu_seconds']=(sum(delta)-delta[3]-delta[4])/os.sysconf('SC_CLK_TCK')
    result['seconds']=samples[-1]['time']-samples[0]['time']
    (WORK/(phase+'.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
elif action=='stop':
    if not re.fullmatch('[a-z0-9-]+',phase):raise ValueError('Invalid phase')
    (WORK/(phase+'.stop')).touch()
elif action in ('restore','persist'):
    from importlib import import_module
    sys.path.insert(0,str(ROOT/'rules'));from durable_io import write
    for name in ('default_config.yaml','default_config_candidate.yaml','template/default_config.yaml','rules/panel-managed-template.yaml'):
        original=(WORK/name).read_text()
        if action=='persist':original=stack(original,phase)
        write(ROOT/name,original.encode())
    api('/configs?force=true',{'path':str(ROOT/'default_config.yaml')})
    print('Persistent stack applied' if action=='persist' else 'Original configuration restored',flush=True)
elif action=='verify':
    sys.path.insert(0,str(ROOT/'rules'));import proxy_manager,vpn_clients
    config=api('/configs');active=str(config.get('tun',{}).get('stack','')).lower()
    group=api('/proxies/LOADBALANCE')['all'];selected=api('/proxies/SELECTOR')['now']
    nodes=[]
    for node in proxy_manager.read()['nodes']:
        if node['proxy']['name'] in ('SV-inbound','FL'):
            nodes.append({'name':node['proxy']['name'],'client':vpn_clients.current(node),'balance':node['balance'],'delay_ms':proxy_manager.delay(node['proxy']['name'])})
    report={'active_stack':active,'selected':selected,'balance_members':group,'nodes':nodes,'persistent_stack_mixed':all('  stack: mixed' in (ROOT/name).read_text() for name in ('default_config.yaml','default_config_candidate.yaml','template/default_config.yaml','rules/panel-managed-template.yaml')),'temporary_test_rule_removed':'DOMAIN,speedtest.selectel.ru,CHANNEL-SV-inbound' not in (ROOT/'default_config.yaml').read_text()}
    print(json.dumps(report),flush=True);(WORK/'final-verification.json').write_text(json.dumps(report,indent=2))
    assert active=='mixed' and selected=='LOADBALANCE' and set(group)=={'CHANNEL-SV-inbound','CHANNEL-FL'}
    assert all(n['client']=='sing-box' and n['balance'] and n['delay_ms']>0 for n in nodes)
    assert report['persistent_stack_mixed'] and report['temporary_test_rule_removed']
