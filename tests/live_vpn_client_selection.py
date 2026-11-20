"""On-device integration check using an isolated, disabled copy of an existing node."""
import json,sys
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager as m
import vpn_clients as v

name='CLIENT-QA-SELECT'
old=m.read()
assert not any(n['proxy']['name']==name for n in old['nodes'])
config=v.SB.read_bytes()
try:
    node=v.canonical(old['nodes'][0]);node['name']=name
    m.import_connections(json.dumps(node))
    print('TEST import disabled copy: OK',flush=True)
    print(v.select(name,'sing-box'),flush=True)
    saved=next(n for n in m.read()['nodes'] if n['proxy']['name']==name)
    assert saved['client']=='sing-box' and saved['connection']['server']==node['server']
    assert saved['balance'] is False
    assert m.delay(name)>0
    print('TEST selected client persisted, endpoint preserved, traffic probe: OK',flush=True)
finally:
    if any(n['proxy']['name']==name for n in m.read()['nodes']):m.delete_many([name])
    if v.SB.read_bytes()!=config:
        v.write(v.SB,config,0o600);v.reload_sb()
    assert m.read()==old
    print('TEST cleanup, original database and sing-box config restored: OK',flush=True)
