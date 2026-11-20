import collections,json,os,subprocess
from pathlib import Path
root=Path('/usr/local/x-ui/bin');config=json.loads((root/'config.json').read_text())
print(json.dumps({'xray_version':subprocess.check_output([str(root/'xray-linux-amd64'),'version'],text=True).splitlines()[:2],'log':{key:config.get('log',{}).get(key) for key in ('loglevel','access','error','dnsLog')},'inbounds':[
    {'tag':i.get('tag'),'port':i.get('port'),'protocol':i.get('protocol'),'client_flows':dict(collections.Counter(c.get('flow','') for c in i.get('settings',{}).get('clients',[]))),'decryption':i.get('settings',{}).get('decryption'),'network':i.get('streamSettings',{}).get('network'),'security':i.get('streamSettings',{}).get('security'),'reality':{key:i.get('streamSettings',{}).get('realitySettings',{}).get(key) for key in ('show','xver','maxTimeDiff','minClientVer','maxClientVer')},'server_name_count':len(i.get('streamSettings',{}).get('realitySettings',{}).get('serverNames',[])),'short_id_count':len(i.get('streamSettings',{}).get('realitySettings',{}).get('shortIds',[])),'sniffing':i.get('sniffing'),'sockopt':{key:i.get('streamSettings',{}).get('sockopt',{}).get(key) for key in ('tcpFastOpen','tcpMptcp','tcpNoDelay','tcpCongestion')}}
    for i in config.get('inbounds',[])], 'outbound_protocols':[o.get('protocol') for o in config.get('outbounds',[])],'routing_rule_count':len(config.get('routing',{}).get('rules',[]))}))
for process in Path('/proc').iterdir():
    if not process.name.isdigit():continue
    try:
        executable=os.readlink(process/'exe')
        if executable.endswith('xray-linux-amd64'):
            print(json.dumps({'pid':int(process.name),'executable':executable,'cwd':os.readlink(process/'cwd'),'started_config_paths':[s for s in (process/'cmdline').read_bytes().decode().split('\0') if s.endswith('.json')]}))
    except (OSError,PermissionError):pass
