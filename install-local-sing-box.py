"""Install the locally built ML-KEM client and private config in this test instance."""
import hashlib
import json
import os
import shutil
from pathlib import Path

ROOT=Path('/etc/mihomo')
source=ROOT/'sing-box-1.14.4-mlkem-armv7'
expected=(ROOT/'sing-box-local.sha256').read_text().strip()
if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise RuntimeError('Binary SHA256 mismatch')
destination=Path('/usr/local/bin/sing-box')
temporary=destination.with_suffix('.new')
shutil.copyfile(source,temporary)
temporary.chmod(0o755)
os.replace(temporary,destination)
profiles=json.loads((ROOT/'test-vpn-profiles.private.json').read_text())
if len(profiles)!=2:raise ValueError('Expected two profiles')
config={'log':{'level':'warn','timestamp':True},'inbounds':[],'outbounds':[],'route':{'rules':[]}}
for i,p in enumerate(profiles):
    tag='vpn'+str(i+1);r=p['reality-opts']
    config['inbounds'].append({'type':'mixed','tag':tag,'listen':'127.0.0.1','listen_port':18181+i})
    outbound={'type':'vless','tag':tag,'server':p['server'],'server_port':p['port'],'uuid':p['uuid'],
              'tls':{'enabled':True,'server_name':p['servername'],'utls':{'enabled':True,'fingerprint':p.get('client-fingerprint','randomized')},
                     'reality':{'enabled':True,'enable_mlkem':True,'public_key':r['public-key'],'short_id':r.get('short-id','')}}}
    if p.get('flow'):outbound['flow']=p['flow']
    config['outbounds'].append(outbound)
    config['route']['rules'].append({'inbound':[tag],'action':'route','outbound':tag})
directory=ROOT/'clients';directory.mkdir(exist_ok=True);directory.chmod(0o700)
path=directory/'sing-box.json';path.write_text(json.dumps(config,indent=2)+'\n');path.chmod(0o600)
limits=ROOT/'rules/resource-limits.json'
data=json.loads(limits.read_text()) if limits.exists() else {}
data['disk_limit_bytes']=0
limits.write_text(json.dumps(data)+'\n');limits.chmod(0o600)
entrypoint=Path('/usr/local/lib/mihomo-panel/entrypoint.sh')
temporary=entrypoint.with_suffix('.new');temporary.write_bytes((ROOT/'entrypoint-update.sh').read_bytes());temporary.chmod(0o755);os.replace(temporary,entrypoint)
for path in [source,ROOT/'sing-box-test-armv7',ROOT/'entrypoint-update.sh']:
    path.unlink(missing_ok=True)
print('Installed local sing-box; two private profiles; disk cap temporarily disabled')
