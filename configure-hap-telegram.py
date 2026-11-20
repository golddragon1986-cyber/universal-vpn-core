import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
root=Path('/etc/mihomo')
sys.path.insert(0,str(root/'rules'))
from durable_io import write
from service_routes_panel import read_services,write_services
import router_routes
import boot_config
public=json.loads((root/'telegram-public-data.json').read_text())
items=read_services()
existing=next((x for x in items if str(x.get('name','')).casefold()=='telegram'),None)
if existing is None:
    existing={'id':str(uuid.uuid4()),'name':'Telegram'}
    items.append(existing)
existing.update(enabled=True,target='LOADBALANCE',domains=public['domains'])
write_services(items)
subprocess.run(['python3',str(root/'rules/build-service-routes.py')],check=True)
settings_path=root/'rules/routing-settings.json'
settings=json.loads(settings_path.read_text())
settings.update(services_enabled=True,main_proxy='LOADBALANCE',dns_enhanced_mode_before_direct='fake-ip')
write(settings_path,(json.dumps(settings)+'\n').encode())
routes=[{'dst-address':n,'gateway':'172.31.41.2','routing-table':'main','active':True,'dynamic':False,'comment':'universal-vpn: Telegram'} for n in public['nets']]
routes.insert(0,{'dst-address':'198.18.0.0/16','gateway':'172.31.41.2','routing-table':'main','active':True,'dynamic':False,'comment':'Universal VPN Fake IP'})
router_routes.sync_container(routes,reload=False)
write(root/'rules/router-routes-observed.json',json.dumps({'routes':routes,'addresses':[{'address':'192.168.99.1/24'},{'address':'172.31.41.1/24'},{'address':'5.23.108.48/21'}],'observed':time.strftime('%Y-%m-%d %H:%M:%S')}).encode())
boot_config.apply_module().put_config()
print('Telegram service and IP route provider applied:',len(public['nets']),'networks,',len(public['domains']),'domains')
