"""Compile IPv4 policy by metric then prefix length into compact file providers."""
import hashlib
import json
import re
import ipaddress
import subprocess
import tempfile
from pathlib import Path
from durable_io import write

ROOT=Path('/etc/mihomo/rules/network-policy')
RULE_START='  # BEGIN NETWORK-PRIORITY\n'
RULE_END='  # END NETWORK-PRIORITY\n'
PROVIDER_START='  # BEGIN NETWORK-PRIORITY-PROVIDERS\n'
PROVIDER_END='  # END NETWORK-PRIORITY-PROVIDERS\n'


def apply(text):
    from service_routes_panel import read_services
    from geodata_service_files import provider_file, mrs_command
    from routes_table_ui import service_networks
    import router_routes
    from routing_panel import read_settings
    items=read_services() if read_settings().get('services_enabled',True) else []
    manual=router_routes.read_targets()
    signature=[manual]
    for item in items:
        files=[]
        for name in item.get('geo_sets',[]):
            path,behavior,_=provider_file(name)
            if behavior=='ipcidr':files.append((name,path.stat().st_mtime_ns,path.stat().st_size))
        signature.append((item.get('enabled',True),item.get('target'),item.get('networks',[]),files))
    key=hashlib.sha256(json.dumps(signature,sort_keys=True).encode()).hexdigest()
    ROOT.mkdir(parents=True,exist_ok=True)
    index=ROOT/'index.json'
    cached=json.loads(index.read_text()) if index.exists() else {}
    if cached.get('key')!=key or any(not (ROOT/name).exists() for name in cached.get('files',[])):
        entries={}
        def add(net,target,metric,order):
            net=ipaddress.ip_network(net,strict=False)
            if net.version!=4:return
            candidate=(metric,order,target)
            if net not in entries or candidate[:2]<entries[net][:2]:entries[net]=candidate
        for position,item in enumerate(items):
            if not item.get('enabled',True) or item.get('target')=='PASS':continue
            target=item.get('target') or 'SELECTOR'
            if target not in {'SELECTOR','DIRECT','REJECT','LOADBALANCE'} and not target.startswith('CHANNEL-'):target='CHANNEL-'+target
            for net in service_networks(item):add(net,target,100,position)
        for position,(net,item) in enumerate(manual.items()):
            if item.get('enabled',True):add(net,item['target'],item.get('metric',100),len(items)+position)
        groups={}
        for net,(metric,order,target) in entries.items():groups.setdefault((metric,-net.prefixlen,target),[]).append(net)
        rules='';providers='';files=[]
        for (metric,prefix,target),nets in sorted(groups.items()):
            payload=''.join(str(net)+'\n' for net in sorted(nets,key=lambda n:int(n.network_address))).encode()
            digest=hashlib.sha256(target.encode()+str(metric).encode()+payload).hexdigest()[:32]
            name='NET-'+digest
            fmt='mrs' if len(nets)>20000 else 'text'
            path=ROOT/(name+'.'+fmt)
            if not path.exists():
                if fmt=='mrs':
                    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                        source=Path(tmp)/'networks.txt';dest=Path(tmp)/'networks.mrs';source.write_bytes(payload)
                        subprocess.run(mrs_command(131072,'ipcidr','text',str(source),str(dest)),capture_output=True,check=True,timeout=30)
                        write(path,dest.read_bytes())
                else:write(path,payload)
            files.append(path.name)
            providers+='  '+name+':\n    type: file\n    behavior: ipcidr\n    format: '+fmt+'\n    path: '+str(path)+'\n'
            rules+='  - '+json.dumps('RULE-SET,'+name+','+target+',no-resolve')+'\n'
        cached={'key':key,'files':files,'rules':rules,'providers':providers}
        write(index,json.dumps(cached).encode())
    for start,end in [(RULE_START,RULE_END),(PROVIDER_START,PROVIDER_END)]:
        text=re.sub(re.escape(start)+'.*?'+re.escape(end),'',text,flags=re.S)
    # Replace the previous direct/manual block with the unified priority policy.
    text=re.sub(r'(?ms)^  # BEGIN MANUAL-NETWORK-ROUTES\n.*?^  # END MANUAL-NETWORK-ROUTES\n','',text)
    if cached['rules']:
        text=text.replace('rules:\n','rules:\n'+RULE_START+cached['rules']+RULE_END,1)
        text=text.replace('rule-providers:\n','rule-providers:\n'+PROVIDER_START+cached['providers']+PROVIDER_END,1)
    return text
