"""Edit a managed VPN connection and its client in one transaction."""
import copy
import hashlib
import html
import json
import re
import uuid

from ui_i18n import text as _ui


def dialog_id(name):
    return 'vpn-editor-' + hashlib.sha256(name.encode()).hexdigest()[:16]


def assets():
    return _ui('''<style>
body .proxy-manager .proxy-manager-table{table-layout:fixed;width:100%}
body .proxy-manager .proxy-manager-table :is(th,td){padding:6px 5px;overflow:hidden}
body .proxy-manager .proxy-manager-table .vpn-country{text-align:center!important;width:5%;white-space:nowrap}
body .proxy-manager .proxy-manager-table .vpn-country img{display:block;width:24px;height:18px;object-fit:cover;margin:auto;border:1px solid #526078;border-radius:2px}
body .proxy-manager .proxy-manager-table .vpn-name-cell{overflow:hidden}
body .proxy-manager .proxy-manager-table .vpn-type{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .proxy-manager .vpn-open-editor{display:block;width:100%;padding:0;border:0;background:transparent;color:inherit;text-align:left;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}
body .proxy-manager .vpn-open-editor:hover{text-decoration:underline;color:var(--ui-primary)}
body .proxy-manager .vpn-name-cell small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .proxy-manager .vpn-endpoint{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .proxy-manager .proxy-manager-table .vpn-status-button,body .proxy-manager .proxy-manager-table .proxy-health-btn{width:100%!important;min-width:0!important;margin:0;padding:7px 5px;min-height:38px;box-sizing:border-box;white-space:nowrap!important;line-height:20px}
body .proxy-manager .proxy-manager-table .vpn-traffic{font-size:14px;white-space:nowrap}
body .proxy-manager .proxy-select-cell input[type=checkbox]{display:block;margin:0 auto}
body .proxy-manager .proxy-manager-table tr:not(.vpn-group-heading)>:is(td,th){white-space:nowrap}
body .vpn-editor{width:min(760px,calc(100vw - 36px));max-height:calc(100vh - 40px);overflow:auto;box-sizing:border-box;padding:22px;background:var(--ui-surface,#171e2b);color:var(--ui-text,#f4f7ff);border:1px solid var(--ui-border,#344056);border-radius:12px}
body .vpn-editor::backdrop{background:rgba(0,0,0,.7)}
body .vpn-editor h2{margin:0 0 8px}
body .vpn-editor-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .vpn-editor-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
body .vpn-editor-fields label,body .vpn-editor-json{display:grid;gap:4px;min-width:0}
body .vpn-editor :is(input,select,textarea){width:100%;min-width:0;box-sizing:border-box;margin:0}
body .vpn-editor-json textarea{min-height:280px;font-family:monospace}
body .vpn-editor-buttons{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
body .vpn-editor-section{grid-column:1/-1;margin:10px 0 0;padding-top:10px;border-top:1px solid var(--ui-border);font-weight:700}
</style><script>
document.addEventListener('click',event=>{
 const open=event.target.closest('[data-vpn-editor]');
 if(open){document.getElementById(open.dataset.vpnEditor)?.showModal();return;}
 const close=event.target.closest('[data-close-editor]');
 if(close)document.getElementById(close.dataset.closeEditor)?.close();
});
document.addEventListener('DOMContentLoaded',()=>{
 document.querySelectorAll('.vpn-editor').forEach(dialog=>{
  const form=dialog.querySelector('form'),client=form?.elements.client,network=form?.elements.network;
  if(!client||!network)return;
  function refresh(){
   const engine=client.value;
   for(const option of network.options)option.disabled=!!option.dataset.engines&&!option.dataset.engines.split(',').includes(engine);
   if(network.selectedOptions[0]?.disabled)network.value='tcp';
   for(const block of form.querySelectorAll('[data-network-fields],[data-engine-fields]'))block.hidden=(!!block.dataset.networkFields&&!block.dataset.networkFields.split(',').includes(network.value))||(!!block.dataset.engineFields&&!block.dataset.engineFields.split(',').includes(engine))||(block.dataset.networkFields==='tcp,http'&&network.value==='tcp'&&engine!=='xray');
   const transportHeading=form.querySelector('[data-transport-heading]');
   if(transportHeading)transportHeading.hidden=![...form.querySelectorAll('[data-network-fields]')].some(block=>!block.hidden);
   for(const block of form.querySelectorAll('[data-tls-fields]'))block.hidden=form.elements.tls_mode.value!==block.dataset.tlsFields;
  }
  form.addEventListener('change',refresh);refresh();
 });
 const cells=[...document.querySelectorAll('.vpn-country[data-vpn-host]')];
 const localFlags={
  FI:'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="18" viewBox="0 0 24 18"><path fill="#fff" d="M0 0h24v18H0z"/><path fill="#003580" d="M7 0h4v18H7zM0 7h24v4H0z"/></svg>',
  SE:'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="18" viewBox="0 0 24 18"><path fill="#006aa7" d="M0 0h24v18H0z"/><path fill="#fecc00" d="M7 0h3v18H7zM0 7h24v3H0z"/></svg>'
 };
 let tries=0;
 async function countries(){
  try{const response=await fetch('/api/vpn-countries',{cache:'no-store'});if(!response.ok)return;
   const data=await response.json();let missing=0;
   for(const cell of cells){const code=data.countries?.[cell.dataset.vpnHost];
    if(/^[A-Z]{2}$/.test(code||'')){
     if(cell.dataset.vpnCode!==code){const icon=document.createElement('img');icon.src=localFlags[code]?'data:image/svg+xml,'+encodeURIComponent(localFlags[code]):'https://flagcdn.com/24x18/'+code.toLowerCase()+'.png';icon.alt=code;icon.width=24;icon.height=18;icon.onerror=()=>cell.replaceChildren(code);cell.replaceChildren(icon);cell.dataset.vpnCode=code;}
     cell.title=code;
    }
    else missing++;}
   if(missing&&++tries<8)setTimeout(countries,3000);
  }catch(error){}
 }
 if(cells.length)countries();
});
</script>''')


def render(node):
    import vpn_clients
    profile = vpn_clients.canonical(node)
    name = node['proxy']['name']
    e = lambda value: html.escape(str(value or ''), quote=True)
    ident = dialog_id(name)
    engine = vpn_clients.current(node)
    client_options = ''.join('<option value="' + key + '"' + (' selected' if key == engine else '') + (' disabled' if not vpn_clients.binary(key) else '') + '>' + e(label) + (_ui(' · не установлен') if not vpn_clients.binary(key) else '') + '</option>' for key, label in vpn_clients.NAMES.items())
    client_field = '<label><span>' + _ui('Клиент VPN') + '</span><select name="client">' + client_options + '</select></label>'
    fields = []
    if profile.get('type') == 'vless' and 'xray_outbound' not in profile:
        reality = profile.get('reality-opts') or {}
        mode = 'reality' if reality else 'tls' if profile.get('tls') else 'none'
        def field(label, key, value, kind='text', extra=''):
            return '<label' + extra + '><span>' + _ui(label) + '</span><input type="' + kind + '" name="' + key + '" value="' + e(value) + '"></label>'
        def choice(label, key, current, values):
            options = ''.join('<option value="' + e(value) + '"' + (' selected' if value == current else '') + (' data-engines="' + engines + '"' if engines else '') + '>' + _ui(text) + '</option>' for value, text, engines in values)
            return '<label><span>' + _ui(label) + '</span><select name="' + key + '">' + options + '</select></label>'
        net = profile.get('network', 'tcp')
        ws = profile.get('ws-opts') or {}
        grpc = profile.get('grpc-opts') or {}
        raw = profile.get('xray-raw') or {}
        http_opts = profile.get('http-opts') or {}
        xhttp = profile.get('xhttp-opts') or {}
        fingerprint = node.get('tls_fingerprint') or profile.get('client-fingerprint', 'chrome')
        fields.extend((
            client_field,
            field('Адрес', 'server', profile.get('server', '')),
            field('Порт', 'port', profile.get('port', ''), 'number'),
            field('UUID (id)', 'uuid', profile.get('uuid', '')),
            choice('Управление потоком (Flow)', 'flow', profile.get('flow', ''), [('', 'Нет', ''), ('xtls-rprx-vision', 'xtls-rprx-vision', ''), ('xtls-rprx-vision-udp443', 'xtls-rprx-vision-udp443', 'xray')]),
            choice('Транспорт', 'network', net, [('tcp', 'raw / TCP', ''), ('ws', 'WebSocket', ''), ('grpc', 'gRPC', ''), ('http', 'HTTP', 'mihomo,sing-box'), ('h2', 'HTTP/2', 'mihomo'), ('xhttp', 'XHTTP', 'mihomo,xray'), ('mkcp', 'mKCP', 'xray'), ('httpupgrade', 'HTTP Upgrade', 'sing-box,xray'), ('quic', 'QUIC', 'sing-box')]),
            '<div class="vpn-editor-section" data-transport-heading>' + _ui('Транспорт и камуфляж') + '</div>',
            choice('Тип raw-камуфляжа', 'raw_type', raw.get('type', 'none'), [('none', 'none', ''), ('http', 'HTTP', '')]).replace('<label>', '<label data-network-fields="tcp" data-engine-fields="xray">', 1),
            field('HTTP Host', 'raw_host', raw.get('host', '') if net == 'tcp' else ((http_opts.get('headers') or {}).get('Host') or [''])[0], extra=' data-network-fields="tcp,http"'),
            field('HTTP Path', 'raw_path', raw.get('path', '') if net == 'tcp' else (http_opts.get('path') or [''])[0], extra=' data-network-fields="tcp,http"'),
            field('WebSocket Path', 'ws_path', ws.get('path', ''), extra=' data-network-fields="ws"'),
            field('WebSocket Host', 'ws_host', (ws.get('headers') or {}).get('Host', ''), extra=' data-network-fields="ws"'),
            field('gRPC Service Name', 'grpc_service', grpc.get('grpc-service-name', ''), extra=' data-network-fields="grpc"'),
            field('XHTTP Path', 'xhttp_path', xhttp.get('path', ''), extra=' data-network-fields="xhttp"'),
            field('XHTTP Host', 'xhttp_host', xhttp.get('host', ''), extra=' data-network-fields="xhttp"'),
            field('FinalMask (JSON)', 'finalmask', json.dumps(profile.get('xray-finalmask') or {}, ensure_ascii=False), extra=' data-engine-fields="xray"'),
            '<div class="vpn-editor-section">TLS / REALITY</div>',
            choice('TLS', 'tls_mode', mode, [('none', 'Нет', ''), ('tls', 'TLS', ''), ('reality', 'REALITY', '')]),
            field('SNI', 'servername', profile.get('servername', '')),
            choice('TLS-профиль (отпечаток)', 'fingerprint', fingerprint, [(fp, fp, '') for fp in vpn_clients.TLS_PROFILES]),
            field('Открытый ключ', 'public_key', reality.get('public-key', ''), extra=' data-tls-fields="reality"'),
            field('Short ID', 'short_id', reality.get('short-id', ''), extra=' data-tls-fields="reality"'),
            field('SpiderX', 'spider_x', reality.get('spider-x', ''), extra=' data-tls-fields="reality"'),
        ))
        editor = '<div class="vpn-editor-fields">' + ''.join(fields) + '</div>'
    else:
        editor = '<div class="vpn-editor-fields">' + client_field + '</div><label class="vpn-editor-json"><span>' + _ui('Конфигурация соединения JSON') + '</span><textarea name="profile" rows="18" spellcheck="false">' + e(json.dumps(profile, ensure_ascii=False, indent=2)) + '</textarea></label>'
    return ('<dialog class="vpn-editor" id="' + ident + '"><h2>' + _ui('Редактировать соединение') + '</h2>'
            + '<p class="vpn-editor-name" title="' + e(name) + '">' + e(name) + '</p>'
            + '<form method="post" action="/action"><input type="hidden" name="action" value="vpn_edit">'
            + '<input type="hidden" name="name" value="' + e(name) + '">' + editor
            + '<div class="vpn-editor-buttons"><button type="submit">' + _ui('Сохранить') + '</button>'
            + '<button type="button" data-close-editor="' + ident + '">' + _ui('Отмена') + '</button></div></form>'
            + '</dialog>')


def update(name, data):
    import proxy_manager as manager
    import vpn_clients as clients
    def value(key): return data.get(key, [''])[0].strip()
    with clients.LOCK:
        old = manager.read()
        changed = copy.deepcopy(old)
        node = next((item for item in changed['nodes'] if item['proxy']['name'] == name), None)
        if node is None:
            raise ValueError('Соединение не найдено')
        profile = clients.canonical(node)
        previous_engine = clients.current(node)
        engine = value('client')
        if engine not in clients.NAMES:
            raise ValueError('Неизвестный VPN-клиент')
        if not clients.binary(engine):
            raise ValueError('Сначала установите ' + clients.NAMES[engine] + ' во вкладке «Компоненты»')
        if profile.get('type') == 'vless' and 'xray_outbound' not in profile:
            server = value('server')
            if not server or len(server) > 253 or re.search(r'[\s/?#@]', server):
                raise ValueError('Проверьте адрес сервера')
            try:
                port = int(value('port'))
                uid = str(uuid.UUID(value('uuid')))
            except (ValueError, AttributeError):
                raise ValueError('Проверьте порт и UUID') from None
            if not 1 <= port <= 65535:
                raise ValueError('Порт должен быть от 1 до 65535')
            network, tls_mode = value('network'), value('tls_mode')
            networks = {'mihomo': {'tcp', 'ws', 'grpc', 'http', 'h2', 'xhttp'}, 'sing-box': {'tcp', 'ws', 'grpc', 'http', 'httpupgrade', 'quic'}, 'xray': {'tcp', 'ws', 'grpc', 'xhttp', 'mkcp', 'httpupgrade'}}
            if network not in networks[engine] or tls_mode not in {'none', 'tls', 'reality'}:
                raise ValueError('Неверный транспорт или режим TLS')
            old_network = profile.get('network', 'tcp')
            profile.update(server=server, port=port, uuid=uid, network=network)
            if value('flow') not in {'', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}:
                raise ValueError('Неизвестный режим Flow')
            if value('flow') == 'xtls-rprx-vision-udp443' and engine != 'xray':
                raise ValueError('Flow UDP443 доступен только для Xray')
            for key, source in (('flow', 'flow'), ('servername', 'servername'), ('client-fingerprint', 'fingerprint')):
                if value(source): profile[key] = value(source)
                else: profile.pop(key, None)
            if value('fingerprint') not in clients.TLS_PROFILES:
                raise ValueError('Неизвестный TLS-профиль')
            profile['encryption'] = 'none'
            if old_network != network:
                for key in ('ws-opts', 'grpc-opts', 'xhttp-opts', 'http-opts', 'xray-raw'):
                    profile.pop(key, None)
            if network == 'ws':
                opts = dict(profile.get('ws-opts') or {})
                opts['path'] = value('ws_path') or '/'
                headers = dict(opts.get('headers') or {})
                if value('ws_host'): headers['Host'] = value('ws_host')
                else: headers.pop('Host', None)
                if headers: opts['headers'] = headers
                else: opts.pop('headers', None)
                profile['ws-opts'] = opts
            if network == 'grpc':
                opts = dict(profile.get('grpc-opts') or {})
                opts['grpc-service-name'] = value('grpc_service')
                profile['grpc-opts'] = opts
            if network == 'xhttp':
                opts = dict(profile.get('xhttp-opts') or {})
                opts['path'] = value('xhttp_path') or '/'
                if value('xhttp_host'): opts['host'] = value('xhttp_host')
                else: opts.pop('host', None)
                profile['xhttp-opts'] = opts
            if network == 'http':
                opts = dict(profile.get('http-opts') or {})
                opts['path'] = [value('raw_path') or '/']
                headers = dict(opts.get('headers') or {})
                if value('raw_host'): headers['Host'] = [value('raw_host')]
                else: headers.pop('Host', None)
                if headers: opts['headers'] = headers
                else: opts.pop('headers', None)
                profile['http-opts'] = opts
            if network == 'tcp' and engine == 'xray' and value('raw_type') == 'http':
                profile['xray-raw'] = {'type': 'http', 'host': value('raw_host'), 'path': value('raw_path') or '/'}
            elif network == 'tcp': profile.pop('xray-raw', None)
            if engine == 'xray':
                try: mask = json.loads(value('finalmask') or '{}')
                except ValueError: raise ValueError('Некорректный JSON FinalMask') from None
                if not isinstance(mask, dict): raise ValueError('FinalMask должен быть объектом JSON')
                if mask: profile['xray-finalmask'] = mask
                else: profile.pop('xray-finalmask', None)
            if tls_mode == 'none':
                profile.pop('tls', None)
                profile.pop('reality-opts', None)
            else:
                profile['tls'] = True
                if tls_mode == 'reality':
                    if not value('public_key'):
                        raise ValueError('Укажите открытый ключ REALITY')
                    reality = dict(profile.get('reality-opts') or {})
                    reality['public-key'] = value('public_key')
                    reality['short-id'] = value('short_id')
                    if value('spider_x'): reality['spider-x'] = value('spider_x')
                    else: reality.pop('spider-x', None)
                    profile['reality-opts'] = reality
                else: profile.pop('reality-opts', None)
        else:
            try: profile = json.loads(value('profile'))
            except (ValueError, TypeError): raise ValueError('Некорректный JSON соединения') from None
            if not isinstance(profile, dict) or profile.get('name') != name:
                raise ValueError('Имя соединения в JSON должно совпадать с исходным')
        profile['name'] = name
        node['connection'] = profile
        node['client'] = engine
        node.pop('tls_fingerprint', None)
        if engine != 'xray':
            profile.pop('xray-raw', None)
            profile.pop('xray-finalmask', None)
        if previous_engine == 'sing-box' and 'sing-box' not in node.setdefault('client_proxies', {}):
            node['client_proxies']['sing-box'] = copy.deepcopy(node['proxy'])
        previous_file = None
        path = None
        if engine == 'mihomo':
            node['proxy'] = clients.convert(clients.effective_profile(node), engine)
            clients.validate(engine, {'proxies': [node['proxy']], 'rules': ['MATCH,DIRECT']})
        else:
            path, cfg, port = clients.build_external(node, engine)
            clients.validate(engine, cfg)
            previous_file = path.read_bytes() if path.exists() else None
            node.setdefault('client_ports', {})[engine] = port
            node['proxy'] = {'name': name, 'type': 'socks5', 'server': '127.0.0.1',
                             'port': port, 'udp': profile.get('udp', True)}
            node.setdefault('client_proxies', {})[engine] = copy.deepcopy(node['proxy'])
        try:
            if path:
                clients.write(path, json.dumps(cfg).encode(), 0o600)
                if engine != 'sing-box' or not clients.reload_sb():
                    clients.ensure_runtime(engine, force=True)
            manager.save(changed)
            manager.sync()
        except Exception:
            manager.save(old)
            if path:
                if previous_file is None: path.unlink(missing_ok=True)
                else: clients.write(path, previous_file, 0o600)
                try:
                    if engine != 'sing-box' or not clients.reload_sb():
                        clients.ensure_runtime(engine, force=True)
                except Exception: pass
            manager.sync()
            raise ValueError('Не удалось применить соединение; предыдущая конфигурация восстановлена') from None
        if previous_engine != engine:
            for unused in ('sing-box', 'xray'):
                if not clients.users(unused):
                    try: clients.pause_unused(unused)
                    except Exception: pass
        return 'Соединение «' + name + '» обновлено'
