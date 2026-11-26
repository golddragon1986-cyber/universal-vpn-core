"""Edit a managed VPN connection while retaining its existing client."""
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
body .proxy-manager .vpn-open-editor{display:block;width:100%;padding:0;border:0;background:transparent;color:inherit;text-align:left;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}
body .proxy-manager .vpn-open-editor:hover{text-decoration:underline;color:var(--ui-primary)}
body .proxy-manager .vpn-name-cell small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .proxy-manager .vpn-endpoint{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .proxy-manager .proxy-manager-table .vpn-status-button,body .proxy-manager .proxy-manager-table .proxy-health-btn{width:100%!important;min-width:0!important;margin:0;padding:7px 5px;min-height:38px;box-sizing:border-box}
body .proxy-manager .proxy-manager-table .vpn-traffic{font-size:12px;white-space:nowrap}
body .vpn-editor{width:min(760px,calc(100vw - 36px));max-height:calc(100vh - 40px);overflow:auto;box-sizing:border-box;padding:22px;background:var(--ui-surface,#171e2b);color:var(--ui-text,#f4f7ff);border:1px solid var(--ui-border,#344056);border-radius:12px}
body .vpn-editor::backdrop{background:rgba(0,0,0,.7)}
body .vpn-editor h2{margin:0 0 8px}
body .vpn-editor h3{margin:18px 0 8px}
body .vpn-editor-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body .vpn-editor-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
body .vpn-editor-fields label,body .vpn-editor-json{display:grid;gap:4px;min-width:0}
body .vpn-editor :is(input,select,textarea){width:100%;min-width:0;box-sizing:border-box;margin:0}
body .vpn-editor-json textarea{min-height:280px;font-family:monospace}
body .vpn-editor-buttons{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
body .vpn-editor .vpn-client-form{border-top:1px solid var(--ui-border);padding-top:10px}
</style><script>
document.addEventListener('click',event=>{
 const open=event.target.closest('[data-vpn-editor]');
 if(open){document.getElementById(open.dataset.vpnEditor)?.showModal();return;}
 const close=event.target.closest('[data-close-editor]');
 if(close)document.getElementById(close.dataset.closeEditor)?.close();
});
document.addEventListener('DOMContentLoaded',()=>{
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
    fields = []
    if profile.get('type') == 'vless' and 'xray_outbound' not in profile:
        reality = profile.get('reality-opts') or {}
        mode = 'reality' if reality else 'tls' if profile.get('tls') else 'none'
        def field(label, key, value, kind='text'):
            return '<label><span>' + _ui(label) + '</span><input type="' + kind + '" name="' + key + '" value="' + e(value) + '"></label>'
        def choice(label, key, current, values):
            options = ''.join('<option value="' + e(value) + '"' + (' selected' if value == current else '') + '>' + _ui(text) + '</option>' for value, text in values)
            return '<label><span>' + _ui(label) + '</span><select name="' + key + '">' + options + '</select></label>'
        fields.extend((
            field('Адрес', 'server', profile.get('server', '')),
            field('Порт', 'port', profile.get('port', ''), 'number'),
            field('UUID (id)', 'uuid', profile.get('uuid', '')),
            field('Управление потоком (Flow)', 'flow', profile.get('flow', '')),
            field('Шифрование', 'encryption', profile.get('encryption', 'none')),
            choice('Транспорт', 'network', profile.get('network', 'tcp'), [('tcp', 'raw / TCP'), ('ws', 'WebSocket'), ('grpc', 'gRPC')]),
            choice('TLS', 'tls_mode', mode, [('none', 'Нет'), ('tls', 'TLS'), ('reality', 'REALITY')]),
            field('SNI', 'servername', profile.get('servername', '')),
            field('Отпечаток', 'fingerprint', profile.get('client-fingerprint', '')),
            field('Открытый ключ', 'public_key', reality.get('public-key', '')),
            field('Short ID', 'short_id', reality.get('short-id', '')),
            field('SpiderX', 'spider_x', reality.get('spider-x', '')),
        ))
        editor = '<div class="vpn-editor-fields">' + ''.join(fields) + '</div>'
    else:
        editor = '<label class="vpn-editor-json"><span>' + _ui('Конфигурация соединения JSON') + '</span><textarea name="profile" rows="18" spellcheck="false">' + e(json.dumps(profile, ensure_ascii=False, indent=2)) + '</textarea></label>'
    return ('<dialog class="vpn-editor" id="' + ident + '"><h2>' + _ui('Редактировать соединение') + '</h2>'
            + '<p class="vpn-editor-name" title="' + e(name) + '">' + e(name) + '</p>'
            + '<form method="post" action="/action"><input type="hidden" name="action" value="vpn_edit">'
            + '<input type="hidden" name="name" value="' + e(name) + '">' + editor
            + '<div class="vpn-editor-buttons"><button type="submit">' + _ui('Сохранить') + '</button>'
            + '<button type="button" data-close-editor="' + ident + '">' + _ui('Отмена') + '</button></div></form>'
            + '<h3>' + _ui('Клиент VPN') + '</h3>' + vpn_clients.form(node) + '</dialog>')


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
            if network not in {'tcp', 'ws', 'grpc'} or tls_mode not in {'none', 'tls', 'reality'}:
                raise ValueError('Неверный транспорт или режим TLS')
            profile.update(server=server, port=port, uuid=uid, network=network)
            for key, source in (('flow', 'flow'), ('servername', 'servername'), ('client-fingerprint', 'fingerprint')):
                if value(source): profile[key] = value(source)
                else: profile.pop(key, None)
            if value('encryption') not in ('', 'none'):
                raise ValueError('VLESS encryption поддерживает только none')
            profile['encryption'] = 'none'
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
        engine = clients.current(node)
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
        return 'Соединение «' + name + '» обновлено'
