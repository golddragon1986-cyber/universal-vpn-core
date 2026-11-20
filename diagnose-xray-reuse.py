import hashlib,json,socket,sys
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients
for node in proxy_manager.read()['nodes']:
    if node['proxy']['name']!='SV-inbound':continue
    port=node.get('client_ports',{}).get('xray')
    listening=False
    if port:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=2):listening=True
        except OSError:pass
    print(json.dumps({'name':node['proxy']['name'],'client':node.get('client'),'cached_xray':'xray' in node.get('client_proxies',{}),'port':port,'listening':listening,'xray_binary':bool(vpn_clients.binary('xray')),'xray_config_exists':vpn_clients.XR.exists(),'source_sha256':hashlib.sha256(Path(vpn_clients.__file__).read_bytes()).hexdigest()}))
