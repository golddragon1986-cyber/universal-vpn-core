from ui_i18n import text as _ui
"""Active configuration values used to distinguish live state from draft edits."""
import json
from pathlib import Path

def render(base):
    def read(name,default):
        path=Path(base)/name
        return json.loads(path.read_bytes()) if path.exists() else default
    services=read('service-routes.json',[])
    dns=read('dns-settings.json',{}).get('servers',[])
    routing=read('routing-settings.json',{})
    targets=read('route-targets.json',{})
    active={'services':{row.get('id'):row.get('enabled',True) for row in services},
            'serviceRoutes':{row.get('id'):row.get('target','SELECTOR') for row in services},
            'dns':{row['id']:row['enabled'] for row in dns},
            'dnsRoutes':{row['id']:row.get('route','SELECTOR') for row in dns},
            'manualRoutes':{net:item.get('target','SELECTOR') for net,item in targets.items() if isinstance(item,dict)},
            'mainRoute':routing.get('main_proxy','DIRECT'),
            'routing':routing.get('services_enabled',True)}
    encoded = json.dumps(active).replace('<', '\\u003c')
    return '<script>window.activeToggleStates='+encoded+';window.activeRouteStates=window.activeToggleStates;</script><script>'+_ui(Path(__file__).with_suffix('.js').read_text(encoding='utf-8'))+'</script>'
