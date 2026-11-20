from ui_i18n import text as _ui
"""Shared Apply/Cancel controls for a manual-route draft."""
import json
from pathlib import Path
from route_batch import snapshot, fingerprint
import router_routes


def render(routes, choices, params):
    rows=snapshot(routes)
    from configuration_draft import load
    pending=load().get('routes')
    seed={'pending':pending,'rows':rows,'baseline':fingerprint(rows),'routes':choices,'view':{key:params.get(key,[''])[0] for key in ('q','source','status')}}
    data=json.dumps(seed,ensure_ascii=False).replace('<','\\u003c')
    toolbar=_ui('<div class="route-draft-toolbar"><h3>Список маршрутов</h3><form method="post" id="route-apply-form">\n<input type="hidden" name="action" value="route_apply"><input type="hidden" name="route_token" value="')+router_routes.TOKEN+_ui('"><input type="hidden" name="baseline"><input type="hidden" name="draft">\n<button type="submit" hidden disabled>Применить</button><button type="button" hidden id="route-draft-cancel" disabled>Отмена</button></form><span id="route-draft-message" role="status"></span></div>')
    script='<script type="application/json" id="route-draft-data">'+data+'</script><style>.route-draft-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.route-draft-toolbar h3{margin-right:auto}.route-draft-toolbar form{display:flex;gap:8px;margin:0}.route-draft-toolbar #route-draft-message{font-size:12px;color:var(--ui-muted);flex-basis:100%}.routes-table .route-pending{background:rgba(72,106,170,.12)}.routes-table .route-removed{opacity:.6}.routes-table input[data-route-field=label]{width:140px;min-width:90px;height:40px;box-sizing:border-box}.routes-table input[data-route-field=metric]{width:70px;height:40px;box-sizing:border-box}.route-add-form input[name=metric]{flex:0 0 90px;min-width:90px;width:90px}</style><script>'+_ui(Path(__file__).with_suffix('.js').read_text(encoding='utf-8'))+'</script>'
    return toolbar,script
