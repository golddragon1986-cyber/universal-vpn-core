import json,sys,shutil
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients
for node in proxy_manager.read()['nodes']:
    p=vpn_clients.canonical(node)
    value=p.get('encryption')
    print(json.dumps({'name':p['name'],'type':p['type'],'client':vpn_clients.current(node),'encryption':value if value in (None,'','none') else 'non-default value (hidden)','fingerprint':p.get('client-fingerprint'),'mlkem':bool(p.get('reality-opts',{}).get('support-x25519mlkem768')),'keys':sorted(p)}))
print('sing-box installed:',bool(shutil.which('sing-box')))
