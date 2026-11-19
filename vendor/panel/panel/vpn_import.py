"""Connection import independent of the old VLESS-only form."""
import base64
import configparser
import ipaddress
import json
import re
import shlex
import urllib.parse

TYPES=('vless','vmess','ss','ssr','trojan','socks5','http','hysteria','hysteria2','tuic','wireguard','openvpn','ssh','snell','anytls','mieru','shadowquic','gost-relay','sudoku','masque','trusttunnel','tailscale','zerotier','easytier')


def decode(value):
    return base64.urlsafe_b64decode(value+'='*(-len(value)%4)).decode()


def unique(node, used):
    node=dict(node)
    name=re.sub(r'[^A-Za-z0-9_.-]+','-',str(node.get('name') or node.get('server') or node.get('type','VPN'))).strip('-.')[:55] or 'VPN'
    base=name;n=2
    while name in used:name=base+'-'+str(n);n+=1
    node['name']=name;used.add(name)
    if node.get('type') not in TYPES:
        raise ValueError('Неизвестный тип соединения: '+str(node.get('type')))
    return node


def wireguard(text, name):
    config=configparser.ConfigParser(interpolation=None,strict=True)
    config.read_string(text)
    if set(config.sections())!={'Interface','Peer'}:
        raise ValueError('Для одного соединения нужны ровно [Interface] и [Peer]')
    interface=config['Interface'];peer=config['Peer']
    if any(k.lower() in ('preup','postup','predown','postdown') for k in interface):
        raise ValueError('Shell-хуки в конфигурации не поддерживаются')
    endpoint=urllib.parse.urlsplit('//'+peer.get('Endpoint',''))
    if not endpoint.hostname or not endpoint.port:raise ValueError('Нужен Endpoint хост:порт')
    addresses=[ipaddress.ip_interface(x.strip()) for x in interface.get('Address','').split(',') if x.strip()]
    node={'name':name,'type':'wireguard','server':endpoint.hostname,'port':endpoint.port,
          'private-key':interface['PrivateKey'],'public-key':peer['PublicKey'],'udp':True}
    for address in addresses:node['ip' if address.version==4 else 'ipv6']=str(address.ip)
    if peer.get('PresharedKey'):node['pre-shared-key']=peer['PresharedKey']
    if peer.get('AllowedIPs'):node['allowed-ips']=[x.strip() for x in peer['AllowedIPs'].split(',')]
    if peer.get('PersistentKeepalive'):node['persistent-keepalive']=int(peer['PersistentKeepalive'])
    if interface.get('MTU'):node['mtu']=int(interface['MTU'])
    if interface.get('DNS'):
        node['dns']=[x.strip() for x in interface['DNS'].split(',')]
        node['remote-dns-resolve']=True
    fields={'jc':'jc','jmin':'jmin','jmax':'jmax','s1':'s1','s2':'s2','s3':'s3','s4':'s4',
            'h1':'h1','h2':'h2','h3':'h3','h4':'h4','i1':'i1','i2':'i2','i3':'i3','i4':'i4','i5':'i5',
            'headerprotectionkey':'header-protection-key','contentpaddingaddition':'content-padding-addition',
            'randomtrailers':'random-trailers','disablecookies':'disable-cookies','rekeyaftertime':'rekey-after-time',
            'rekeytimeout':'rekey-timeout','rejectaftertime':'reject-after-time','keepalivetimeout':'keepalive-timeout',
            'maxhandshakeattempts':'max-handshake-attempts'}
    awg={}
    unknown=set(interface)-set(fields)-{'privatekey','address','dns','mtu','listenport','version'}
    if unknown:raise ValueError('Неизвестные поля Interface: '+', '.join(sorted(unknown)))
    unknown=set(peer)-{'publickey','presharedkey','endpoint','allowedips','persistentkeepalive'}
    if unknown:raise ValueError('Неизвестные поля Peer: '+', '.join(sorted(unknown)))
    for key,value in interface.items():
        if key in fields:
            if key in ('jc','jmin','jmax','s1','s2','s3','s4'):value=int(value)
            elif key in ('randomtrailers','disablecookies'):value=interface.getboolean(key)
            awg[fields[key]]=value
    if awg:
        awg['version']=interface.getint('Version',fallback=3 if any(k in awg for k in ('header-protection-key','content-padding-addition','random-trailers','disable-cookies')) else 2)
        node['amnezia-wg-option']=awg
    return node


def parse(text, kind='auto', name='VPN', *, max_nodes=100):
    text=text.strip()
    if kind=='openvpn':return [openvpn(text,name)]
    if kind in ('wireguard','awg') or text.startswith('[Interface]'):
        return [wireguard(text,name)]
    if text.startswith(('{','[')):
        data=json.loads(text)
        if isinstance(data,dict):data=data.get('proxies',[data])
        if not isinstance(data,list) or not data or not all(isinstance(x,dict) for x in data):
            raise ValueError('Ожидается JSON-объект соединения или список proxies')
        if kind.startswith('json:') and any(node.get('type')!=kind[5:] for node in data):
            raise ValueError('Тип JSON должен соответствовать выбранному типу '+kind[5:])
        return data
    if '://' not in text:
        try:text=decode(text)
        except Exception:raise ValueError('Нужны URI, JSON или конфигурация WireGuard/AWG')
    nodes=[]
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        line=line.strip()
        if line.lower().startswith('vpn://'):
            payload, _, label = line[6:].partition('#')
            try:
                raw = base64.b64decode(payload + '=' * (-len(payload) % 4), altchars=b'-_', validate=True)
                config = raw.decode('utf-8-sig').strip()
                nodes.append(wireguard(config, urllib.parse.unquote(label) or 'AmneziaWG'))
            except (ValueError, KeyError, configparser.Error):
                raise ValueError('Запись vpn:// должна содержать конфигурацию WireGuard/AmneziaWG в Base64') from None
            continue
        p=urllib.parse.urlsplit(line);q=urllib.parse.parse_qs(p.query)
        if p.scheme=='vless':
            from proxy_manager import parse_uri
            nodes.append(parse_uri(line,set()));continue
        if p.scheme=='vmess':
            d=json.loads(decode(line[8:]));node={'type':'vmess','name':d.get('ps','VMess'),'server':d['add'],'port':int(d['port']),'uuid':d['id'],'alterId':int(d.get('aid',0)),'cipher':d.get('scy','auto'),'udp':True}
            if d.get('tls')=='tls':node.update({'tls':True,'servername':d.get('sni',d['add'])})
            if d.get('net') not in (None,'','tcp'):
                node['network']=d['net']
                if d['net']=='ws':node['ws-opts']={'path':d.get('path','/'),'headers':{'Host':d.get('host',d['add'])}}
            nodes.append(node);continue
        if p.scheme=='ss':
            raw=line[5:].split('#',1)[0];label=urllib.parse.unquote(p.fragment) or 'Shadowsocks'
            if '@' not in raw:raw=decode(raw)
            credentials,endpoint=raw.rsplit('@',1)
            if ':' not in credentials:credentials=decode(credentials)
            cipher,password=urllib.parse.unquote(credentials).split(':',1);host=urllib.parse.urlsplit('//'+endpoint.split('?',1)[0])
            if '?' in raw:raise ValueError('SS с плагином добавляйте через JSON, чтобы сохранить параметры')
            nodes.append({'name':label,'type':'ss','server':host.hostname,'port':host.port,'cipher':cipher,'password':password,'udp':True});continue
        typ={'socks':'socks5','socks5':'socks5','http':'http','https':'http','trojan':'trojan','hy2':'hysteria2','hysteria2':'hysteria2'}.get(p.scheme)
        if not typ:raise ValueError('Для этого URI используйте конфигурацию JSON: '+p.scheme)
        if not p.hostname or not p.port:raise ValueError('В URI нужны сервер и порт')
        node={'name':urllib.parse.unquote(p.fragment) or typ,'type':typ,'server':p.hostname,'port':p.port,'udp':True}
        if typ in ('trojan','hysteria2'):node['password']=urllib.parse.unquote(p.username or '')
        elif p.username is not None:node.update({'username':urllib.parse.unquote(p.username),'password':urllib.parse.unquote(p.password or '')})
        if p.scheme=='https':node['tls']=True
        if q.get('sni'):node['sni' if typ=='hysteria2' else 'servername']=q['sni'][0]
        if q.get('insecure'):node['skip-cert-verify']=q['insecure'][0] in ('1','true')
        # Never silently drop transport/obfuscation options.
        if set(q)-{'sni','insecure'}:raise ValueError('Дополнительные параметры URI задайте через JSON: '+', '.join(sorted(set(q)-{'sni','insecure'})))
        nodes.append(node)
    if not nodes or len(nodes)>max_nodes:raise ValueError(f'Можно добавить от 1 до {max_nodes} соединений')
    return nodes


def openvpn(text,name):
    node={'name':name,'type':'openvpn','proto':'udp','udp':True}
    blocks={}
    def block(match):
        key=match.group(1).lower()
        if key in blocks:raise ValueError('Повторный блок '+key)
        blocks[key]=match.group(2).strip()+'\n'
        return ''
    text=re.sub(r'<([\w-]+)>\s*\n(.*?)</\1>',block,text,flags=re.S)
    block_keys={'ca':'ca','cert':'cert','key':'key','tls-auth':'tls-auth','tls-crypt':'tls-crypt','tls-crypt-v2':'tls-crypt-v2'}
    for key,value in blocks.items():
        if key in block_keys:node[block_keys[key]]=value
        elif key=='auth-user-pass':
            values=value.splitlines()
            if len(values)!=2:raise ValueError('В auth-user-pass нужны две строки: логин и пароль')
            node.update(username=values[0],password=values[1])
        else:raise ValueError('Неизвестный inline-блок '+key)
    ignored={'client','nobind','persist-key','persist-tun','resolv-retry','verb','mute','auth-nocache'}
    scalar={'proto':'proto','dev':'dev','cipher':'cipher','auth':'auth','key-direction':'key-direction','data-ciphers-fallback':'data-cipher-fallback','comp-lzo':'comp-lzo'}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(('#',';')):continue
        parts=shlex.split(line,comments=True)
        if not parts:continue
        option=parts[0].lstrip('-');args=parts[1:]
        if option in ignored:continue
        if option=='remote-cert-tls' and args==['server']:continue
        if option=='remote':
            if 'server' in node or len(args)<2:raise ValueError('Нужен ровно один remote сервер порт')
            node['server']=args[0];node['port']=int(args[1])
            if len(args)>2:node['proto']=args[2]
        elif option in scalar:
            if len(args)!=1:raise ValueError('Неверный параметр '+option)
            node[scalar[option]]=args[0]
        elif option=='data-ciphers' and len(args)==1:node['data-ciphers']=args[0].split(':')
        elif option in block_keys or option=='auth-user-pass':
            if option not in blocks or args not in ([],['[inline]']):
                raise ValueError('Вставьте '+option+' inline-блоком; файлы с роутера не читаются')
        else:raise ValueError('Параметр .ovpn не поддерживается: '+option+'. Используйте JSON с поддерживаемыми ядром полями.')
    if not node.get('server') or not node.get('ca'):raise ValueError('Нужны remote и inline-блок <ca>')
    return node


def form():
    options=''.join('<option value="json:'+typ+'">'+typ+' · JSON</option>' for typ in TYPES)
    body='''<details class="proxy-import-spoiler"><summary>Добавить соединение</summary><form method="post" class="proxy-import-form"><input type="hidden" name="action" value="vpn_import"><p><label>Название для WireGuard/AWG <input name="vpn_name" value="VPN" maxlength="55"></label></p><p><label>Тип / формат <select name="vpn_format" id="vpn-format"><option value="auto">Авто: URI, подписка или JSON</option><option value="wireguard">WireGuard .conf</option><option value="awg">AmneziaWG .conf</option><option value="json">Произвольная конфигурация Mihomo JSON</option><optgroup label="Выбрать протокол">OPTIONS</optgroup></select></label></p><p>VLESS, VMess, Shadowsocks, Trojan, SOCKS5/HTTP и Hysteria2 принимают URI. Для любого другого типа вставьте JSON-конфигурацию Mihomo. WireGuard/AWG принимают [Interface]/[Peer]. Выбор протокола подставляет основу JSON; заполните параметры своего сервера. Конфигурация проверяется ядром до применения.</p><div class="proxy-import-box"><textarea name="source" id="vpn-source" rows="10" wrap="off" placeholder='URI, HTTPS-подписка, [Interface]… или JSON-конфигурация' required></textarea><div class="proxy-import-footer"><button type="submit">Добавить и применить</button></div></div></form></details>
<script>(()=>{const select=document.getElementById('vpn-format'),source=document.getElementById('vpn-source');let previous='';select.addEventListener('change',()=>{if(!select.value.startsWith('json:'))return;if(source.value.trim()&&source.value!==previous)return;const type=select.value.slice(5),node={name:'VPN',type,server:'vpn.example',port:443};if(['vmess','vless'].includes(type))node.uuid='ЗАПОЛНИТЕ-UUID';if(type==='vmess'){node.alterId=0;node.cipher='auto';}if(['ss','ssr','trojan','hysteria','hysteria2','tuic','anytls','ssh','socks5','http'].includes(type))node.password='ЗАПОЛНИТЕ';if(type==='ss')node.cipher='aes-128-gcm';if(type==='wireguard'){node.ip='10.0.0.2';node['private-key']='ЗАПОЛНИТЕ';node['public-key']='ЗАПОЛНИТЕ';}if(type==='openvpn'){node.proto='udp';node.ca='ВСТАВЬТЕ PEM CA';}previous=JSON.stringify(node,null,2);source.value=previous;});})();</script>'''
    body=body.replace('<option value="awg">AmneziaWG .conf</option>','<option value="awg">AmneziaWG .conf</option><option value="openvpn">OpenVPN .ovpn (сертификаты inline)</option>')
    body=body.replace('Название для WireGuard/AWG','Название для WireGuard/AWG/OpenVPN')
    import vpn_clients
    clients=''.join('<option value="'+key+'"'+(' disabled' if not vpn_clients.binary(key) else '')+'>'+label+(' · не установлен' if not vpn_clients.binary(key) else '')+'</option>' for key,label in vpn_clients.NAMES.items())
    body=body.replace('<p><label>Тип / формат','<p><label>Клиент VPN <select name="client">'+clients+'</select></label></p><p><label>Тип / формат')
    return body.replace('OPTIONS',options)
