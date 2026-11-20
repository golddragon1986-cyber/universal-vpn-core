from ui_i18n import text as _ui, message as _ui_message
"""Paginated IPv4 route listing with rule ownership and explicit manual targets."""
import html
import ipaddress
import json
import os
import subprocess
import tempfile
from urllib.parse import urlencode


def service_networks(item):
    yield from item.get('networks', [])
    from geodata_service_files import provider_file, mrs_command
    from service_routes_panel import MRS_DOMAIN_CACHE_LOCK
    for provider in item.get('geo_sets', []):
        path, behavior, fmt = provider_file(provider)
        if behavior != 'ipcidr': continue
        cache = path.with_suffix('.networks')
        with MRS_DOMAIN_CACHE_LOCK:
            if not cache.exists() or cache.stat().st_mtime_ns < path.stat().st_mtime_ns:
                with tempfile.TemporaryDirectory(prefix='.net-cache-', dir=path.parent) as tmp:
                    dest = os.path.join(tmp, 'networks.txt')
                    subprocess.run(mrs_command(131072,'ipcidr',fmt,str(path),dest),capture_output=True,check=True,timeout=15,
                                   env={**os.environ,'GOGC':'35','GOMEMLIMIT':'80MiB'})
                    os.replace(dest, cache)
        with cache.open(encoding='utf-8') as source:
            for line in source:
                line=line.strip()
                if line and not line.startswith('#'): yield line


def render_table(params):
    import router_routes as rr
    from service_routes_panel import read_services, service_edit_url
    e=lambda x:html.escape(str(x),quote=True)
    query=params.get('q',[''])[0].strip().lower()
    source_filter=params.get('source',['all'])[0]
    status_filter=params.get('status',['all'])[0]
    try: page=max(1,int(params.get('page',['1'])[0]))
    except ValueError: page=1
    try: data=rr.snapshot();error=''
    except Exception as ex: data={'routes':[],'live':False,'observed':''};error=str(ex)
    try: choices=rr.target_choices()
    except Exception: choices=['DIRECT','LOADBALANCE']
    targets=rr.read_targets();fallback=rr.default_target()
    labels=lambda route: _ui('Основной маршрут') if route=='SELECTOR' else _ui('Напрямую (DIRECT)') if route=='DIRECT' else _ui('Балансировка (LOADBALANCE)') if route=='LOADBALANCE' else route.removeprefix('CHANNEL-')
    def options(selected):
        return ''.join('<option value="'+e(route)+'"'+(' selected' if route==selected else '')+'>'+e(labels(route))+'</option>' for route in dict.fromkeys(choices+[selected]))
    disabled='' if data['live'] else ' disabled'
    records={r['dst-address']:{'net':r['dst-address'],'router':r,'source':'local','name':r.get('comment','').replace(rr.PREFIX,''),'owner':None} for r in data['routes']}
    owner_index={}
    try:
        for index,item in enumerate(read_services()):
            for raw in service_networks(item):
                net=ipaddress.ip_network(raw,strict=False)
                if net.version!=4:continue
                key=str(net)
                record=records.setdefault(key,{'net':key,'router':None,'source':'service','name':item['name'],'owner':item})
                if record['router'] is None or record['router'].get('comment')==rr.SERVICE_ROUTE:
                    record.update(source='service',name=item['name'],owner=record['owner'] or item)
                if item.get('enabled',True) and item.get('target')!='PASS':
                    owner_index.setdefault((net.prefixlen,int(net.network_address)),(index,item))
    except Exception as ex:error=(error+' '+str(ex)).strip()
    try: search_net=ipaddress.ip_network(query,strict=False) if query else None
    except ValueError:search_net=None
    found=[]
    display_records=list(records.values())
    for net,value in targets.items():
        if value.get('override'):
            display_records.append({'net':net,'router':None,'source':'local','owner':None,'name':value.get('label',_ui('Ручной маршрут')),'manual':value})
    for record in display_records:
        net=ipaddress.ip_network(record['net'])
        route=record['router']
        if net==rr.FAKE:record.update(source='protected',name=_ui('Fake IP · защищён'),owner=None)
        elif record['source']=='service':
            candidates=[owner_index[(prefix,int(net.network_address) & ((0xffffffff << (32-prefix)) & 0xffffffff))]
                        for prefix in range(net.prefixlen+1)
                        if (prefix,int(net.network_address) & ((0xffffffff << (32-prefix)) & 0xffffffff)) in owner_index]
            if candidates:
                record['owner']=min(candidates,key=lambda x:x[0])[1];record['name']=record['owner']['name']
        owner=record['owner']
        manual=record.get('manual') or (targets.get(record['net']) if record['source']=='local' else None)
        record['manual']=manual
        enabled=manual.get('enabled',True) if manual else owner.get('enabled',True) if owner else not rr.yes(route.get('disabled',False)) if route else False
        record['enabled']=enabled
        if source_filter!='all' and record['source']!=source_filter:continue
        if status_filter!='all' and (status_filter=='enabled')!=enabled:continue
        matches = (search_net.version==4 and net.overlaps(search_net)) if search_net is not None else (query in record['net'].lower() or query in record['name'].lower())
        if query and not matches:continue
        found.append(record)
    found.sort(key=lambda r:((r.get('manual') or {}).get('metric',100),-ipaddress.ip_network(r['net']).prefixlen,int(ipaddress.ip_network(r['net']).network_address)))
    count=len(found);pages=max(1,(count+24)//25);page=min(page,pages)
    rows=[]
    for record in found[(page-1)*25:page*25]:
        net=record['net'];route=record['router'];owner=record['owner'];name=e(record['name'])
        action='';control='—'
        if owner:
            url=e(service_edit_url(owner));name='<a href="'+url+'">'+e(owner['name'])+'</a>'
            control='<a href="'+url+'">'+e(labels(owner['target']))+'</a>'
            action=_ui('Управляется правилом')
        elif record.get('manual') or (route and rr.mutable(route)):
            value=record.get('manual') or {'target':fallback,'metric':100}
            key=('local:'+net) if value.get('override') else route['.id']
            def fields(action):
                return '<input type="hidden" name="action" value="'+action+'"><input type="hidden" name="route_token" value="'+e(rr.TOKEN)+'"><input type="hidden" name="route_id" value="'+e(key)+'">'
            control='<form method="post">'+fields('route_target')+_ui('<select name="target" aria-label="Маршрут сети ')+e(net)+'" onchange="this.form.requestSubmit()"'+disabled+'>'+options(value['target'])+'</select></form>'
            action='<div class="route-row-actions"><form method="post">'+fields('route_toggle')+'<button'+disabled+'>'+(_ui('Отключить') if record['enabled'] else _ui('Включить'))+'</button></form><form method="post">'+fields('route_delete')+'<button class="danger"'+disabled+_ui('>Удалить</button></form></div>')
        elif record['source']=='protected': action=_ui('Защищён')
        status=_ui('Активен') if record['enabled'] and route and rr.yes(route.get('active')) else _ui('Ожидает применения') if record['enabled'] and not route else _ui('Неактивен') if record['enabled'] else _ui('Отключён')
        metric='100' if owner else '—'
        if record.get('manual') or (route and rr.mutable(route)):
            value=record.get('manual') or {'metric':100}
            metric='<form method="post">'+fields('route_metric')+'<input type="number" name="metric" min="1" max="254" value="'+str(value.get('metric',100))+_ui('" aria-label="Метрика сети ')+e(net)+'" onchange="this.form.requestSubmit()"'+disabled+'></form>'
        if record.get('manual') and record['manual'].get('override'):
            status=_ui('Активен') if record['enabled'] else _ui('Отключён')
        row_attr=(' data-manual-net="'+e(net)+'"') if record.get('manual') or (route and rr.mutable(route)) else ''
        rows.append('<tr'+row_attr+'><td>'+e(net)+'</td><td>'+name+'</td><td>'+control+'</td><td>'+metric+'</td><td>'+status+'</td><td>'+action+'</td></tr>')
    def pick(name,values,current):
        return '<select name="'+name+'">'+''.join('<option value="'+value+'"'+(' selected' if value==current else '')+'>'+label+'</option>' for value,label in values)+'</select>'
    filters=pick('source',[('all',_ui('Все источники')),('local',_ui('Локальные')),('service',_ui('Правила')),('protected',_ui('Защищённые'))],source_filter)+pick('status',[('all',_ui('Все статусы')),('enabled',_ui('Включённые')),('disabled',_ui('Отключённые'))],status_filter)
    navigation=''
    for offset,title in [(-1,_ui('Назад')),(1,_ui('Вперёд'))]:
        if 1<=page+offset<=pages:navigation+='<a href="/?'+e(urlencode({'tab':'routes','q':query,'source':source_filter,'status':status_filter,'page':page+offset}))+'">'+title+'</a> '
    state=_ui('Данные RouterOS · шлюз 172.31.41.2') if data['live'] else _ui('Снимок маршрутов. Нет подключения к RouterOS.')
    from route_draft_ui import render as render_draft
    draft_toolbar,draft_script=render_draft(data['routes'],choices,params)
    refresh_script = _ui("<script>document.getElementById('routes-reset-search').addEventListener('click',()=>{location.href='/?tab=routes';});window.refreshRouteRows=async function(context,job){\nconst status=document.getElementById('route-inline-status');\nif(job.status==='done'||context.action==='route_apply'){\n const response=await fetch(location.href,{cache:'no-store'});if(!response.ok)throw Error('Не удалось обновить таблицу маршрутов');\n const doc=new DOMParser().parseFromString(await response.text(),'text/html'),fresh=doc.getElementById('route-results');\n if(!fresh)throw Error('Таблица маршрутов не найдена');\n document.getElementById('route-results').replaceWith(document.importNode(fresh,true));\n if(context.action==='route_apply'){window.routeDraftRefresh(JSON.parse(doc.getElementById('route-draft-data').textContent),job.status==='done');if(job.status!=='done')window.routeDraftError('Ошибка: '+job.message);}\n if(context.action==='route_add'&&context.form.isConnected&&new URLSearchParams(new FormData(context.form)).toString()===context.baseline){context.form.elements.destination.value='';context.form.elements.label.value='';delete context.form.dataset.queueDirty;}\n status.textContent=job.status!=='done'?'Ошибка: '+job.message:context.action==='route_apply'?'Изменения применены.':context.action==='route_add'?'Маршрут добавлен.':context.action==='route_delete'?'Маршрут удалён.':'Маршрут изменён.';\n}else status.textContent='Ошибка: '+(job.message||'Маршрут не применён');\n};</script>")
    return _ui('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Маршруты</title></head><body><section class="routing-panel"><h2>Маршруты через контейнер</h2><p>')+e(state)+'</p><p role="alert">'+e(_ui_message(error))+_ui('</p><details><summary>Добавить маршрут</summary><form method="post" class="route-add-form"><input type="hidden" name="action" value="route_add"><input type="hidden" name="route_token" value="')+e(rr.TOKEN)+_ui('"><input name="destination" required placeholder="IPv4-сеть/маска" aria-label="IPv4-сеть"><input name="label" maxlength="80" placeholder="Название" aria-label="Название маршрута"><input type="number" name="metric" value="100" min="1" max="254" aria-label="Метрика нового маршрута"><select name="target" aria-label="Маршрут новой сети">')+options(fallback)+'</select><button'+disabled+_ui('>Добавить</button></form><p id="route-inline-status" role="status"></p></details>')+draft_toolbar+'<form method="get" class="routes-search"><input type="hidden" name="tab" value="routes"><input name="q" value="'+e(query)+_ui('" placeholder="IP, сеть или название" aria-label="Поиск маршрута">')+filters+_ui('<button>Найти</button><button type="button" id="routes-reset-search">Сбросить поиск</button></form><div id="route-results"><p>Найдено: ')+str(count)+_ui('</p><div class="routes-scroll"><table class="routes-table"><thead><tr><th>Сеть</th><th>Источник / название</th><th>Маршрут</th><th>Метрика</th><th>Состояние</th><th>Действия</th></tr></thead><tbody>')+(''.join(rows) or _ui('<tr><td colspan="6">Нет маршрутов по заданному запросу</td></tr>'))+_ui('</tbody></table></div><p>Страница ')+str(page)+_ui(' из ')+str(pages)+' · '+navigation+_ui('</p></div><p class="hint">Метрика правил — 100. Меньшая метрика имеет приоритет, при равенстве — более узкая сеть. Сети правил редактируются в соответствующем правиле. Локальные и служебные сети, VPN-серверы и DNS защищены. Маршрут Fake IP удалить нельзя.</p></section><style>.routes-table{width:100%;border-collapse:collapse}.routes-table th,.routes-table td{text-align:left;padding:10px;border-bottom:1px solid #526078;vertical-align:middle}.routes-table form{margin:0}.routes-table select{max-width:240px;min-width:160px;margin:0}.route-row-actions{display:flex;gap:6px}.routes-table input[name=metric]{width:70px;height:40px;box-sizing:border-box;margin:0}.routes-scroll{overflow:auto}.routes-search,.route-add-form{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:16px 0}.routes-search input{flex:1;min-width:180px}.route-add-form input{flex:1;min-width:170px}.routes-search input,.routes-search select,.routes-search button,.route-add-form input,.route-add-form select,.route-add-form button{height:40px;box-sizing:border-box;margin:0}.routing-panel a,.routing-panel a:visited{color:#b8d5ff}.routing-panel button:disabled{opacity:.45;cursor:not-allowed}</style>')+refresh_script+draft_script+'</body></html>'
