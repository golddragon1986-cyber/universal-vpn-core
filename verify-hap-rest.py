import json
import os
import sys
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
from durable_io import write
path=Path('/etc/mihomo/clients/routeros.json')
write(path,path.read_bytes())
path.chmod(0o600)
import router_routes
data=router_routes.snapshot()
assert data['live'], 'RouterOS REST is not live'
routes=data['routes']
assert any(x.get('dst-address')=='198.18.0.0/16' for x in routes)
assert sum(x.get('comment')=='universal-vpn: Telegram' for x in routes)==9
router_routes.sync_container(router_routes.Router().routes(),reload=True)
print(json.dumps({'live':data['live'],'routes_via_container':len(routes),'credentials_mode':oct(path.stat().st_mode & 0o777)}))
