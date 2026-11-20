from ui_i18n import text as _ui
"""Per-connection client selection. Reject lossy conversions before changing traffic."""
import copy, hashlib, html, json, os, re, shutil, signal, subprocess, tempfile, threading, time
from pathlib import Path
from durable_io import write

ROOT=Path('/etc/mihomo/clients')
SB=ROOT/'sing-box.json'
XR=ROOT/'panel-xray.json'
LOCK=threading.RLock()
IDLE=Path('/tmp/sing-box-idle')
NAMES={'mihomo':'Mihomo','sing-box':'sing-box','xray':'Xray'}
TLS_PROFILES=('chrome','firefox','safari','edge','randomized','randomizednoalpn')

def users(engine):
    import proxy_manager
    nodes=proxy_manager.read()['nodes']
    path=SB if engine=='sing-box' else XR
    cfg=json.loads(path.read_text()) if path.exists() else {}
    ports={int(x.get('listen_port',x.get('port',0))) for x in cfg.get('inbounds',[]) if x.get('listen') in ('127.0.0.1','localhost','::1')}
    return [n['proxy']['name'] for n in nodes if n.get('client')==engine or
            (n['proxy'].get('type') in ('socks5','http') and n['proxy'].get('server') in ('127.0.0.1','localhost','::1') and int(n['proxy'].get('port',0)) in ports)]

def pause_unused(engine):
    if users(engine):raise ValueError('Клиент '+NAMES[engine]+' используется соединениями: '+', '.join(users(engine)))
    if engine=='sing-box':
        import sing_box_update
        write(IDLE,b'1\n')
        try:state=sing_box_update.supervisor()
        except (OSError,ValueError):state=None
        if state and not state.get('idle'):os.kill(state['pid'],signal.SIGHUP)
        deadline=time.monotonic()+10
        while subprocess.run(['pidof','sing-box'],capture_output=True).returncode==0:
            if time.monotonic()>deadline:raise ValueError('Не удалось остановить неиспользуемый sing-box; файл клиента сохранён')
            time.sleep(.2)
    else:
        previous=PROCESSES.pop(engine,None)
        if previous and previous[0].poll() is None:
            previous[0].terminate()
            try:previous[0].wait(timeout=5)
            except subprocess.TimeoutExpired:previous[0].kill();previous[0].wait()

def binary(engine):
    return shutil.which({'mihomo':'mihomo','sing-box':'sing-box','xray':'xray'}[engine])

def legacy(node):
    p=node['proxy']
    if p.get('server') not in ('127.0.0.1','localhost','::1') or p.get('type') not in ('socks5','http') or not SB.exists():return None
    cfg=json.loads(SB.read_text())
    for inbound in cfg.get('inbounds',[]):
        if inbound.get('listen_port')!=int(p['port']):continue
        for rule in cfg.get('route',{}).get('rules',[]):
            if rule.get('inbound') not in (inbound.get('tag'),[inbound.get('tag')]):continue
            out=next((o for o in cfg.get('outbounds',[]) if o.get('tag')==rule.get('outbound')),None)
            if out:return copy.deepcopy(out)

def current(node):
    return node.get('client') or ('sing-box' if legacy(node) else 'mihomo')

def canonical(node):
    if node.get('connection'):return copy.deepcopy(node['connection'])
    out=legacy(node)
    if not out:return copy.deepcopy(node['proxy'])
    # Adopt existing bridges without rewriting their original sing-box configuration.
    allowed(out,{'tag','type','server','server_port','uuid','flow','tls'})
    if out.get('type')!='vless':raise ValueError('Для этого существующего клиента требуется исходная конфигурация Mihomo')
    p={'name':node['proxy']['name'],'type':'vless','server':out['server'],'port':out['server_port'],'uuid':out['uuid'],'udp':True}
    if out.get('flow'):p['flow']=out['flow']
    tls=out.get('tls',{});allowed(tls,{'enabled','server_name','insecure','utls','reality'})
    if tls.get('enabled'):
        p['tls']=True;p['servername']=tls.get('server_name','')
        if tls.get('insecure'):p['skip-cert-verify']=True
        u=tls.get('utls',{});allowed(u,{'enabled','fingerprint'})
        if u.get('enabled'):p['client-fingerprint']=u.get('fingerprint','chrome')
        r=tls.get('reality',{});allowed(r,{'enabled','public_key','short_id','enable_mlkem'})
        if r.get('enabled'):
            p['reality-opts']={'public-key':r['public_key'],'short-id':r.get('short_id','')}
            if r.get('enable_mlkem'):p['reality-opts']['support-x25519mlkem768']=True
    return p

def allowed(obj,keys):
    unknown=set(obj)-set(keys)
    if unknown:raise ValueError('Перенос этих параметров между клиентами пока не поддерживается: '+', '.join(sorted(unknown)))

def xray_mlkem_supported(fingerprint):
    # Xray 26.10.31 Firefox negotiates the hybrid share and passed repeated
    # live probes; randomized does not reliably offer it on that version.
    if fingerprint not in ('firefox','chrome'):return False
    executable=binary('xray')
    if not executable:return False
    try:
        result=subprocess.run([executable,'version'],capture_output=True,text=True,timeout=10)
        match=re.search(r'^Xray (\d+)\.(\d+)\.(\d+)',result.stdout)
        return result.returncode==0 and match is not None and tuple(map(int,match.groups()))>=(26,10,31)
    except (OSError,subprocess.TimeoutExpired):return False

def xray_reality_fingerprint(p):
    fingerprint=p.get('client-fingerprint','chrome')
    if p.get('reality-opts',{}).get('support-x25519mlkem768') and fingerprint in ('randomized','randomizednoalpn'):
        return 'firefox'
    return fingerprint

def convert(p,engine):
    if 'xray_outbound' in p:
        if engine != 'xray':
            raise ValueError('This native Xray profile requires Xray.')
        return copy.deepcopy(p['xray_outbound'])
    if engine=='mihomo':return copy.deepcopy(p)
    typ=p['type']
    # VLESS `encryption=none` is explicit in imported URI profiles but
    # implicit in sing-box. Reject other values instead of silently dropping them.
    if typ=='vless' and 'encryption' in p:
        if p['encryption']!='none':
            raise ValueError('Перенос VLESS encryption поддерживается только для значения none')
        p=copy.deepcopy(p)
        p.pop('encryption')
    if typ not in ('vless','vmess','trojan','ss','socks5','http','hysteria2','anytls'):
        raise ValueError('Перенос протокола '+typ+' в '+NAMES[engine]+' пока не поддерживается')
    allowed(p,{'name','type','server','port','uuid','flow','udp','tls','servername','sni','client-fingerprint','skip-cert-verify','reality-opts','network','ws-opts','grpc-opts','password','username','cipher','alterId'})
    net=p.get('network','tcp')
    if net not in ('tcp','ws','grpc'):raise ValueError('Транспорт '+net+' нельзя перенести в выбранный клиент')
    reality=p.get('reality-opts',{})
    allowed(reality,{'public-key','short-id','support-x25519mlkem768'})
    if engine=='sing-box':
        out={'type':{'ss':'shadowsocks','socks5':'socks'}.get(typ,typ),'server':p['server'],'server_port':int(p['port'])}
        for key in ('uuid','flow','password','username'):
            if key in p:out[key]=p[key]
        if typ=='ss':out['method']=p['cipher']
        if typ=='vmess':
            out['security']=p.get('cipher','auto');out['alter_id']=p.get('alterId',0)
        if typ=='socks5':out['version']='5'
        if p.get('tls') or typ in ('trojan','hysteria2','anytls'):
            tls={'enabled':True,'server_name':p.get('servername',p.get('sni',p['server']))}
            if p.get('skip-cert-verify'):tls['insecure']=True
            if p.get('client-fingerprint'):tls['utls']={'enabled':True,'fingerprint':p['client-fingerprint']}
            if reality:
                tls['reality']={'enabled':True,'public_key':reality['public-key'],'short_id':reality.get('short-id','')}
                if reality.get('support-x25519mlkem768'):tls['reality']['enable_mlkem']=True
            out['tls']=tls
        if net=='ws':
            w=p.get('ws-opts',{});allowed(w,{'path','headers'})
            out['transport']={'type':'ws',**w}
        if net=='grpc':
            g=p.get('grpc-opts',{});allowed(g,{'grpc-service-name'})
            out['transport']={'type':'grpc','service_name':g.get('grpc-service-name','')}
        return out
    if engine!='xray':raise ValueError('Неизвестный клиент')
    if typ in ('hysteria2','anytls'):raise ValueError('Этот протокол не поддерживается адаптером Xray')
    if reality.get('support-x25519mlkem768') and not xray_mlkem_supported(xray_reality_fingerprint(p)):
        raise ValueError('Для REALITY/ML-KEM нужен Xray 26.10.31+ с проверенным TLS-профилем Firefox или Chrome; используйте sing-box или Mihomo для остальных профилей')
    out={'protocol':{'ss':'shadowsocks','socks5':'socks'}.get(typ,typ)}
    if typ in ('vless','vmess'):
        user={'id':p['uuid']}
        if typ=='vless':user['encryption']='none'
        else:user.update(security=p.get('cipher','auto'),alterId=p.get('alterId',0))
        if p.get('flow'):user['flow']=p['flow']
        out['settings']={'vnext':[{'address':p['server'],'port':int(p['port']),'users':[user]}]}
    else:
        server={'address':p['server'],'port':int(p['port'])}
        if typ in ('trojan','ss'):server['password']=p['password']
        if typ=='ss':server['method']=p['cipher']
        if typ in ('socks5','http') and p.get('username'):server['users']=[{'user':p['username'],'pass':p.get('password','')}]
        out['settings']={'servers':[server]}
    stream={'network':net,'security':'none'}
    if p.get('tls') or typ=='trojan':
        stream['security']='reality' if reality else 'tls'
        opts={'serverName':p.get('servername',p.get('sni',p['server'])),'fingerprint':xray_reality_fingerprint(p)}
        if reality:opts.update(password=reality['public-key'],shortId=reality.get('short-id',''))
        elif p.get('skip-cert-verify'):opts['allowInsecure']=True
        stream['realitySettings' if reality else 'tlsSettings']=opts
    if net=='ws':
        w=p.get('ws-opts',{});allowed(w,{'path','headers'});stream['wsSettings']=copy.deepcopy(w)
    if net=='grpc':
        g=p.get('grpc-opts',{});allowed(g,{'grpc-service-name'});stream['grpcSettings']={'serviceName':g.get('grpc-service-name','')}
    out['streamSettings']=stream
    return out

def validate(engine,cfg):
    executable=binary(engine)
    if not executable:raise ValueError('Сначала установите '+NAMES[engine]+' во вкладке «Компоненты»')
    ROOT.mkdir(parents=True,exist_ok=True)
    fd,path=tempfile.mkstemp(prefix='.client-check-',suffix='.json' if engine=='xray' else '',dir=ROOT)
    try:
        with os.fdopen(fd,'w') as f:json.dump(cfg,f)
        args=([executable,'-t','-d','/etc/mihomo','-f',path] if engine=='mihomo' else [executable,'check','-c',path] if engine=='sing-box' else [executable,'run','-test','-config',path])
        r=subprocess.run(args,capture_output=True,timeout=45)
        if r.returncode:raise ValueError(NAMES[engine]+' отклонил параметры соединения. Работающий клиент сохранён; проверьте совместимость протокола и настроек')
    finally:os.unlink(path)

def effective_profile(node):
    profile=canonical(node)
    fingerprint=node.get('tls_fingerprint')
    if fingerprint:
        if not profile.get('tls') or 'xray_outbound' in profile:
            raise ValueError('TLS-профиль можно менять для переносимой конфигурации с TLS или REALITY')
        profile['client-fingerprint']=fingerprint
    return profile


def build_external(node,engine,cfg=None):
    p=effective_profile(node);key=hashlib.sha256(p['name'].encode()).hexdigest()[:16];tag='panel-'+key
    path=SB if engine=='sing-box' else XR
    if cfg is None:cfg=json.loads(path.read_text()) if path.exists() else ({'log':{'level':'warn'},'inbounds':[],'outbounds':[],'route':{'rules':[]}} if engine=='sing-box' else {'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}})
    used={x.get('listen_port',x.get('port')) for x in cfg.get('inbounds',[]) if x.get('tag')!=tag}
    port=node.get('client_ports',{}).get(engine)
    if not port:
        port=next((x for x in range(18200 if engine=='sing-box' else 18400,18400 if engine=='sing-box' else 18600) if x not in used),None)
    if port is None:raise ValueError('Нет свободных портов клиентов')
    out=convert(p,engine);out['tag']=tag
    cfg['outbounds']=[x for x in cfg.get('outbounds',[]) if x.get('tag')!=tag]+[out]
    inbound=({'type':'mixed','tag':tag,'listen':'127.0.0.1','listen_port':port} if engine=='sing-box' else {'protocol':'socks','tag':tag,'listen':'127.0.0.1','port':port,'settings':{'udp':True}})
    cfg['inbounds']=[x for x in cfg.get('inbounds',[]) if x.get('tag')!=tag]+[inbound]
    route=cfg.setdefault('route' if engine=='sing-box' else 'routing',{})
    route['rules']=[x for x in route.get('rules',[]) if x.get('inbound' if engine=='sing-box' else 'inboundTag') not in (tag,[tag])]+[({'inbound':[tag],'action':'route','outbound':tag} if engine=='sing-box' else {'type':'field','inboundTag':[tag],'outboundTag':tag})]
    return path,cfg,port

def reload_sb():
    import sing_box_update as updater
    IDLE.unlink(missing_ok=True)
    try:state=updater.supervisor()
    except (OSError,ValueError):return False
    os.kill(state['pid'],signal.SIGHUP)
    updater.wait_ready(state,subprocess.check_output([binary('sing-box'),'version'],text=True).splitlines()[0].removeprefix('sing-box version '))
    return True

def select(name,engine,fingerprint=None):
    import proxy_manager as manager
    if engine not in NAMES:raise ValueError('Неизвестный VPN-клиент')
    with LOCK:
        d=manager.read();old=copy.deepcopy(d)
        node=next((n for n in d['nodes'] if n['proxy']['name']==name),None)
        if node is None:raise ValueError('Сначала импортируйте соединение в управляемый список VPN')
        if not binary(engine):raise ValueError('Сначала установите '+NAMES[engine]+' во вкладке «Компоненты»')
        previous=current(node)
        if fingerprint == 'source':
            fingerprint = ''
        if fingerprint is not None and fingerprint not in ('',*TLS_PROFILES):
            raise ValueError('Неизвестный TLS-профиль')
        if previous==engine and (fingerprint is None or fingerprint==node.get('tls_fingerprint','')):
            return 'Для «'+name+'» уже выбран '+NAMES[engine]
        original=canonical(node);node['connection']=original
        if fingerprint:
            node['tls_fingerprint']=fingerprint
        elif fingerprint is not None:
            node.pop('tls_fingerprint',None)
        effective=effective_profile(node)
        if previous=='sing-box' and 'sing-box' not in node.setdefault('client_proxies',{}):node['client_proxies']['sing-box']=copy.deepcopy(node['proxy'])
        old_file=None;path=None
        if engine=='mihomo':
            profile=convert(effective,engine)
            validate(engine,{'proxies':[profile],'rules':['MATCH,DIRECT']});node['proxy']=profile
        else:
            path,cfg,port=build_external(node,engine);validate(engine,cfg)
            old_file=path.read_bytes() if path.exists() else None
            write(path,json.dumps(cfg).encode(),0o600)
            try:
                if engine=='sing-box' and reload_sb():pass
                else:ensure_runtime(engine,force=True)
            except Exception:
                if old_file is None:path.unlink(missing_ok=True)
                else:write(path,old_file,0o600)
                if engine=='sing-box':
                    try:reload_sb()
                    except Exception:pass
                raise
            node.setdefault('client_ports',{})[engine]=port
            node['proxy']={'name':name,'type':'socks5','server':'127.0.0.1','port':port,'udp':original.get('udp',True)}
            node.setdefault('client_proxies',{})[engine]=copy.deepcopy(node['proxy'])
        node['client']=engine
        if engine=='sing-box' and IDLE.exists():
            if not reload_sb():ensure_runtime(engine,force=True)
        stage='применение конфигурации Mihomo'
        try:
            manager.save(d);manager.sync()
        except Exception as error:
            reason=type(error).__name__+': '+str(error)
            def redact(obj):
                nonlocal reason
                if isinstance(obj,dict):
                    for key,value in obj.items():
                        if key in ('uuid','password','username','public-key','short-id','server','servername','sni') and isinstance(value,str) and value:
                            reason=reason.replace(value,'[скрыто]')
                        else:redact(value)
                elif isinstance(obj,list):
                    for item in obj:redact(item)
            redact(original)
            manager.save(old)
            if path:
                if old_file is None:path.unlink(missing_ok=True)
                else:write(path,old_file,0o600)
            try:
                if path and (engine!='sing-box' or not reload_sb()):
                    ensure_runtime(engine)
            finally:
                manager.sync()
            raise ValueError('Не удалось применить смену клиента. Предыдущий клиент и настройки восстановлены. Этап: '+stage+'. Причина: '+reason[:900]) from error
        for unused in ('sing-box','xray'):
            if not users(unused):pause_unused(unused)
        note=' Для REALITY/ML-KEM Xray использует TLS-профиль '+xray_reality_fingerprint(effective)+'; исходный профиль сохранён.' if engine=='xray' and xray_reality_fingerprint(effective)!=effective.get('client-fingerprint','chrome') else ''
        return 'Для «'+name+'» выбран '+NAMES[engine]+'. Конфигурация применена. Доступность можно проверить кнопкой «Проверить»'+note

PROCESSES={}
def ensure_runtime(engine,force=False,restart=False):
    if not force and not users(engine):
        pause_unused(engine)
        return
    if engine=='sing-box':IDLE.unlink(missing_ok=True)
    path=SB if engine=='sing-box' else XR
    if not path.exists():
        previous=PROCESSES.pop(engine,None)
        if previous and previous[0].poll() is None:
            previous[0].terminate()
            try:previous[0].wait(timeout=5)
            except subprocess.TimeoutExpired:previous[0].kill();previous[0].wait()
        return
    if engine=='sing-box':
        import sing_box_update
        try:sing_box_update.supervisor();return
        except (OSError,ValueError):pass
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    previous=PROCESSES.get(engine)
    if previous and previous[0].poll() is None and previous[1]==digest and not restart:return
    if previous and previous[0].poll() is None:
        previous[0].terminate()
        try:previous[0].wait(timeout=5)
        except subprocess.TimeoutExpired:previous[0].kill();previous[0].wait()
    executable=binary(engine)
    if not executable:raise ValueError('VPN-клиент не установлен')
    command=([os.sys.executable,'-u','/etc/mihomo/rules/sing_box_supervisor.py',executable,str(path)] if engine=='sing-box' else [executable,'run','-config',str(path)])
    proc=subprocess.Popen(command,env={**os.environ,'GOMEMLIMIT':'60MiB','GOGC':'50'})
    PROCESSES[engine]=(proc,digest);time.sleep(.5)
    if proc.poll() is not None:raise ValueError('VPN-клиент не запустился')

def start():
    def loop():
        while True:
            with LOCK:
                for engine in ('sing-box','xray'):
                    try:ensure_runtime(engine)
                    except Exception:pass
            time.sleep(5)
    threading.Thread(target=loop,name='vpn-clients',daemon=True).start()

def without_bridges(engine,cfg,names):
    tags={'panel-'+hashlib.sha256(name.encode()).hexdigest()[:16] for name in names}
    cfg=copy.deepcopy(cfg)
    for key in ('inbounds','outbounds'):
        cfg[key]=[x for x in cfg.get(key,[]) if x.get('tag') not in tags]
    route=cfg.setdefault('route' if engine=='sing-box' else 'routing',{})
    key='inbound' if engine=='sing-box' else 'inboundTag'
    route['rules']=[x for x in route.get('rules',[]) if not any(x.get(key) in (tag,[tag]) for tag in tags)]
    return cfg


def remove_unused(names):
    """Drop generated bridges only; never remove administrator-owned legacy routes."""
    with LOCK:
        for engine,path in (('sing-box',SB),('xray',XR)):
            if not path.exists():continue
            before=json.loads(path.read_text())
            cfg=without_bridges(engine,before,names)
            if before==cfg:continue
            # The image watches the original sing-box supervisor. Keep its last
            # idle bridge until shutdown rather than terminate the container.
            if not cfg.get('inbounds'):continue
            original=path.read_bytes()
            try:
                validate(engine,cfg);write(path,json.dumps(cfg).encode(),0o600)
                if engine=='sing-box':reload_sb()
                else:ensure_runtime(engine)
            except Exception:
                write(path,original,0o600)
                if engine=='sing-box':reload_sb()
                else:ensure_runtime(engine)
                raise

def form(node):
    engine=current(node);e=lambda x:html.escape(str(x),quote=True)
    options=''.join('<option value="'+key+'"'+(' selected' if key==engine else '')+(' disabled' if not binary(key) else '')+'>'+label+(_ui(' · не установлен') if not binary(key) else '')+'</option>' for key,label in NAMES.items())
    profile=canonical(node)
    tls=''
    if profile.get('tls') and 'xray_outbound' not in profile:
        selected=node.get('tls_fingerprint','')
        fingerprints=''.join(f'<option value="{fp}" {"selected" if fp==selected else ""}>{fp}</option>' for fp in TLS_PROFILES)
        tls=_ui('<details><summary>TLS-профиль</summary><select name="fingerprint" aria-label="TLS-профиль"><option value="source">Из источника</option>')+fingerprints+'</select></details>'
    return '<form method="post" class="vpn-client-form"><input type="hidden" name="action" value="vpn_client"><input type="hidden" name="name" value="'+e(node['proxy']['name'])+_ui('"><select name="client" aria-label="Клиент ')+e(node['proxy']['name'])+'">'+options+'</select>'+tls+_ui('<button type="submit">Применить</button></form>')
