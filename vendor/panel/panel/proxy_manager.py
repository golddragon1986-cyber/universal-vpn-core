from ui_i18n import text as _ui
from durable_io import replace as durable_replace
from pathlib import Path
#!/usr/bin/env python3
import base64, ipaddress, json, os, re, socket, tempfile, urllib.parse, urllib.request, subprocess, shutil, time
B='/etc/mihomo/rules'; DB=B+'/managed-proxies.json'; PF=B+'/user-proxies.yaml'; API='http://127.0.0.1:9090'; TEST='https://www.gstatic.com/generate_204'
def read():
 if not os.path.exists(DB): return {'nodes':[]}
 d=json.load(open(DB,encoding='utf-8'))
 if not isinstance(d.get('nodes'),list): raise ValueError('Invalid proxy database')
 return d
def put(path,obj):
 fd,t=tempfile.mkstemp(prefix='.proxy-',dir=B)
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(obj,f,ensure_ascii=False,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
  durable_replace(t,path)
 finally:
  if os.path.exists(t): os.unlink(t)
def save(d):
 put(DB,d); put(PF,{'proxies':[x['proxy'] for x in d['nodes']]})
def fetch(url):
 u=urllib.parse.urlsplit(url)
 if u.scheme!='https' or not u.hostname or u.username or u.password: raise ValueError('Only credential-free HTTPS sources are accepted')
 for x in socket.getaddrinfo(u.hostname,u.port or 443,type=socket.SOCK_STREAM):
  if not ipaddress.ip_address(x[4][0]).is_global: raise ValueError('Source resolves to a non-public IP')
 req=urllib.request.Request(url,headers={'User-Agent':'Mihomo-Control/1.0'})
 with urllib.request.urlopen(req,timeout=15) as r:
  if urllib.parse.urlsplit(r.geturl()).hostname!=u.hostname or not r.geturl().startswith('https://'): raise ValueError('Unsafe redirect refused')
  b=r.read(2*1024*1024+1)
 if len(b)>2*1024*1024: raise ValueError('Source exceeds 2 MiB')
 s=b.decode('utf-8-sig','replace').strip()
 if 'vless://' not in s:
  try:s=base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','replace')
  except Exception:pass
 return s
def parse_uri(u,used):
 p=urllib.parse.urlsplit(u); q=urllib.parse.parse_qs(p.query)
 if p.scheme!='vless' or not p.hostname or not p.port: raise ValueError('Invalid VLESS URI')
 uid=urllib.parse.unquote(p.username or '')
 if not re.fullmatch(r'[0-9a-fA-F-]{32,36}',uid): raise ValueError('Invalid VLESS UUID')
 nm=re.sub(r'[^A-Za-z0-9_.-]+','-',urllib.parse.unquote(p.fragment)).strip('-.') or p.hostname
 nm=nm[:55]; base=nm; k=2
 while nm in used: nm=f'{base}-{k}'; k+=1
 g=lambda key,default='':q.get(key,[default])[0]
 x={'name':nm,'type':'vless','server':p.hostname,'port':p.port,'uuid':uid,'udp':True}
 if g('flow'):x['flow']=g('flow')
 sec=g('security','none').lower(); net=g('type','tcp').lower()
 if sec in ('tls','reality'):
  x['tls']=True
  if g('sni'):x['servername']=g('sni')
  if g('fp'):x['client-fingerprint']=g('fp')
 if sec=='reality':
  ro={}
  if g('pbk'):ro['public-key']=g('pbk')
  if g('sid'):ro['short-id']=g('sid')
  if os.environ.get('MIHOMO_REALITY_COMPAT')=='1':
   # Keep the imported fingerprint: fixed Chrome is not reliable for these peers.
   # core-supervisor retries the specific unsupported-curve randomized failure.
   ro['support-x25519mlkem768']=True
  if ro:x['reality-opts']=ro
 if net in ('ws','grpc','http','h2','xhttp'):x['network']='ws' if net=='ws' else net
 if net=='ws':
  o={}
  if g('path'):o['path']=urllib.parse.unquote(g('path'))
  if g('host'):o['headers']={'Host':g('host')}
  if o:x['ws-opts']=o
 if net=='grpc' and g('serviceName'):x['grpc-opts']={'grpc-service-name':g('serviceName')}
 if g('encryption'):x['encryption']=g('encryption')
 return x
def sync():
 for p in ('/etc/mihomo/rules/build-service-routes.py','/etc/mihomo/rules/apply-service-routes.py'):
  r=subprocess.run(['python3',p],capture_output=True,text=True,timeout=90)
  if r.returncode:raise RuntimeError((r.stderr or r.stdout)[-1200:])
def import_source(src):
 src=fetch(src.strip()) if src.strip().startswith('https://') else src.strip()
 if 'vless://' not in src:
  try:src=base64.b64decode(src+'='*(-len(src)%4)).decode('utf-8','replace')
  except Exception:pass
 lines=[x.strip() for x in src.splitlines() if x.strip() and not x.lstrip().startswith('#')]
 if not lines or any(not x.startswith('vless://') for x in lines):raise ValueError('Provide VLESS URI lines or an HTTPS link returning a plain/base64 VLESS list')
 if len(lines)>100:raise ValueError('Maximum import size is 100 proxies')
 d=read(); old=json.loads(json.dumps(d)); used={x['proxy']['name'] for x in d['nodes']}; new=[]
 for line in lines:
  x=parse_uri(line,used); used.add(x['name']); new.append({'proxy':x,'balance':False})
 d['nodes']+=new
 try:save(d); sync()
 except Exception:
  save(old)
  try:sync()
  except Exception:pass
  raise
 return [x['proxy']['name'] for x in new]

def import_connections(src,kind='auto',name='VPN',client='mihomo'):
 import vpn_clients
 if client not in vpn_clients.NAMES or not vpn_clients.binary(client):raise ValueError('Выбранный VPN-клиент не установлен')
 from vpn_import import parse,unique
 src=fetch(src.strip()) if src.strip().startswith('https://') and not urllib.parse.urlsplit(src.strip()).username else src
 old=read();new=json.loads(json.dumps(old))
 used={x['proxy']['name'] for x in new['nodes']}|{'DIRECT','REJECT','GLOBAL','SELECTOR','LOADBALANCE','PASS','COMPATIBLE'}
 nodes=[unique(x,used) for x in parse(src,kind,name)]
 if not nodes or len(nodes)>100:raise ValueError('Можно добавить от 1 до 100 соединений')
 # Validate before writing the managed database, without exposing credentials in errors.
 fd,filename=tempfile.mkstemp(prefix='.vpn-validate-',suffix='.json',dir=B)
 try:
  with os.fdopen(fd,'w') as out:json.dump({'proxies':[x['proxy'] for x in old['nodes']]+nodes,'rules':['MATCH,DIRECT']},out)
  checked=subprocess.run(['mihomo','-t','-d','/etc/mihomo','-f',filename],capture_output=True,text=True,timeout=60)
  if checked.returncode:
   message=(checked.stderr or checked.stdout)[-1200:]
   for node in nodes:
    for key in ('password','uuid','private-key','pre-shared-key','key'):
     if isinstance(node.get(key),str) and node[key]:message=message.replace(node[key],'***')
   raise ValueError('Ядро отклонило конфигурацию: '+message)
 finally:
  if os.path.exists(filename):os.unlink(filename)
 new['nodes'] += [{'proxy':node,'balance':False} for node in nodes]
 snapshots={path:path.read_bytes() if path.exists() else None for path in (vpn_clients.SB,vpn_clients.XR)}
 try:
  save(new);sync()
  if client!='mihomo':
   for node in nodes:vpn_clients.select(node['name'],client)
 except Exception:
  save(old)
  for path,raw in snapshots.items():
   if raw is None:path.unlink(missing_ok=True)
   elif not path.exists() or path.read_bytes()!=raw:vpn_clients.write(path,raw,0o600)
  if client=='sing-box' and snapshots[vpn_clients.SB] is not None:
   try:vpn_clients.reload_sb()
   except Exception:pass
  try:sync()
  except Exception:pass
  raise
 return [x['name'] for x in nodes]
def set_balance(name,on):
 d=read(); old=json.loads(json.dumps(d)); x=next((x for x in d['nodes'] if x['proxy']['name']==name),None)
 if x: x['balance']=bool(on)
 else: d.setdefault('balance_overrides',{})[name]=bool(on)
 try:save(d); sync()
 except Exception:
  save(old)
  try:sync()
  except Exception:pass
  raise

def set_balance_many(names,on=True):
 names=list(dict.fromkeys(x for x in names if x))
 if not names: raise ValueError("Не выбраны прокси для включения")
 d=read(); old=json.loads(json.dumps(d)); selected=set(names)
 for node in d['nodes']:
  if node['proxy']['name'] in selected: node['balance']=bool(on)
 managed={node['proxy']['name'] for node in d['nodes']}
 overrides=d.setdefault('balance_overrides',{})
 for name in names:
  if name in managed: overrides.pop(name,None)
  else: overrides[name]=bool(on)
 try: save(d); sync()
 except Exception:
  save(old)
  try: sync()
  except Exception: pass
  raise
 return len(names)

def remove_yaml_proxy(text,name):
 pat=re.compile(r"(?m)^  - name:\s*[\"']?"+re.escape(name)+r"[\"']?\s*$")
 m=pat.search(text)
 if not m: raise ValueError("Proxy is not present in startup provider: "+name)
 nxt=re.search(r"(?m)^(?:  - name:|YAML\s*$)",text[m.end():])
 end=m.end()+nxt.start() if nxt else len(text)
 return text[:m.start()]+text[end:]

def write_text_atomic(path,text):
 fd,tmp=tempfile.mkstemp(prefix=".proxy-delete-",dir=os.path.dirname(path))
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as f:
   f.write(text); f.flush(); os.fsync(f.fileno())
  durable_replace(tmp,path)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)

def delete_many(names=(), *, subscription=None):
 d=read(); old=json.loads(json.dumps(d))
 if subscription is not None:
  if subscription not in d.get('subscriptions',{}):raise ValueError('Подписка не найдена')
  names=[n['proxy']['name'] for n in d['nodes'] if n.get('subscription')==subscription]
  del d['subscriptions'][subscription]
 else:
  names=list(dict.fromkeys(x for x in names if x))
  if not names: raise ValueError("Не выбраны прокси для удаления")
 managed_names={x['proxy']['name'] for x in d['nodes']}
 native=[x for x in names if x not in managed_names]
 d['nodes']=[x for x in d['nodes'] if x['proxy']['name'] not in names]
 for name in names: d.setdefault('balance_overrides',{}).pop(name,None)
 startup='/etc/mihomo/user_sh/10-reality.sh'
 active='/etc/mihomo/srv.yaml'
 old_start=Path(startup).read_text(encoding='utf-8') if native else None
 old_active=Path(active).read_text(encoding='utf-8') if native else None
 new_start=old_start; new_active=old_active
 for name in native:
  new_start=remove_yaml_proxy(new_start,name)
  new_active=remove_yaml_proxy(new_active,name)
 stamp=time.strftime('%Y%m%d-%H%M%S')
 if native:
  shutil.copy2(startup,startup+'.bak-proxy-delete-'+stamp)
  shutil.copy2(active,active+'.bak-proxy-delete-'+stamp)
 import vpn_clients
 client_configs={path:path.read_bytes() if path.exists() else None for path in (vpn_clients.SB,vpn_clients.XR)}
 try:
  if native:
   write_text_atomic(startup,new_start)
   write_text_atomic(active,new_active)
  save(d)
  if names:
   sync()
   from vpn_clients import remove_unused
   remove_unused(names)
 except Exception:
  for path,raw in client_configs.items():
   if raw is None:path.unlink(missing_ok=True)
   else:vpn_clients.write(path,raw,0o600)
  if client_configs[vpn_clients.SB] is not None:
   try:vpn_clients.reload_sb()
   except Exception:pass
  if native:
   write_text_atomic(startup,old_start)
   write_text_atomic(active,old_active)
  save(old)
  try: sync()
  except Exception: pass
  raise
 return len(names)

def delete(name):
 return delete_many([name])

def delay(name, url=TEST, timeout_ms=5000, expected=None):
 from urllib.parse import quote
 query={'url':url,'timeout':timeout_ms}
 if expected is not None:query['expected']=expected
 path='/providers/proxies/USER-MANAGED/'+quote(name,safe='')+'/healthcheck?'+urllib.parse.urlencode(query)
 with urllib.request.urlopen(API+path,timeout=timeout_ms/1000+3) as r:return json.load(r).get('delay',-1)
def client_endpoints():
 # Resolve local sing-box bridges to display-only remote endpoint metadata.
 # Never copy client credentials into the proxy provider or the HTML.
 try:
  with open('/etc/mihomo/clients/sing-box.json',encoding='utf-8') as source:config=json.load(source)
  outbounds={x.get('tag'):x for x in config.get('outbounds',[]) if isinstance(x,dict)}
  endpoints={}
  for inbound in config.get('inbounds',[]):
   if inbound.get('listen') not in ('127.0.0.1','::1','localhost'):continue
   matches=[r for r in config.get('route',{}).get('rules',[]) if r.get('inbound') in (inbound.get('tag'),[inbound.get('tag')]) and r.get('action','route')=='route']
   if len(matches)!=1:continue
   outbound=outbounds.get(matches[0].get('outbound'),{})
   if outbound.get('server') and outbound.get('server_port'):
    endpoints[str(inbound.get('listen_port'))]={'server':outbound['server'],'port':outbound['server_port'],'type':outbound.get('type','')}
  return endpoints
 except (OSError,ValueError,TypeError,AttributeError):return {}

def render(navigation="", *, subscription_controls=None, subscription_groups=None):
 import html
 import vpn_editor
 subscriptions=subscription_controls is not None
 db=read(); managed={n['proxy']['name']:n for n in db['nodes']}
 hosts={}
 # Read only endpoint metadata from the current SRV provider; credentials are not rendered.
 try:
  in_proxies=False; current=None
  for line in open('/etc/mihomo/srv.yaml',encoding='utf-8'):
   if line.strip()=='proxies:': in_proxies=True; continue
   if in_proxies:
    m=re.match(r'^\s*-\s+name:\s*["\']?([^"\'\s]+)',line)
    if m: current=m.group(1); hosts.setdefault(current,{})
    elif current:
     m=re.match(r'^\s+(server|port):\s*["\']?([^"\'\s]+)',line)
     if m: hosts[current][m.group(1)]=m.group(2)
 except Exception: pass
 try:
  px=json.load(urllib.request.urlopen(API+'/proxies',timeout=5))['proxies']
  names=list(dict.fromkeys([x[len('CHANNEL-'):] for x in px if x.startswith('CHANNEL-')]+list(managed)))
 except Exception: names=list(managed)
 bridges=client_endpoints()
 rows=[];dialogs=[]
 grouped_rows={sid:[] for sid in (subscription_groups or {})}
 filters={key:{} for key in ('subscription','type','client','status')}
 for name in names:
  n=managed.get(name); proxy=n['proxy'] if n else {}
  subscription=n.get('subscription') if n else None
  if bool(subscription)!=subscriptions:continue
  host=proxy.get('server') or hosts.get(name,{}).get('server','')
  port=proxy.get('port') or hosts.get(name,{}).get('port','')
  remote=bridges.get(str(port),{}) if host in ('127.0.0.1','::1','localhost') and proxy.get('type') in ('socks5','http') else {}
  if remote:host,port=remote['server'],remote['port']
  if ':' in str(host):host='['+str(host)+']'
  enabled=db.get('balance_overrides',{}).get(name,n.get('balance',True) if n else True)
  e=lambda value: html.escape(str(value),quote=True)
  toggle=(_ui('Включено') if enabled else _ui('Отключено'))
  color='#16803c' if enabled else '#c62828'
  delete='<input type="checkbox" form="delete-selected-form" name="selected" value="'+e(name)+'" data-balance-enabled="'+('1' if enabled else '0')+_ui('" aria-label="Выбрать прокси ')+e(name)+'">'

  type_label=proxy.get('type','')
  if remote:type_label=remote['type']+' · sing-box'
  if proxy.get('amnezia-wg-option'):type_label='AmneziaWG '+str(proxy['amnezia-wg-option'].get('version',''))
  import vpn_clients
  if n and n.get('connection'):
   endpoint=n['connection'];host=endpoint.get('server',host);port=endpoint.get('port',port);type_label=endpoint.get('type',type_label)
  row_attrs=''
  if subscriptions:
   sub_name=db.get('subscriptions',{}).get(subscription,{}).get('name') or _ui('Неизвестная подписка')
   engine=vpn_clients.current(n)
   values={'subscription':(subscription,sub_name), 'type':(type_label or '—',type_label or '—'),
           'client':(engine,vpn_clients.NAMES.get(engine,engine)), 'status':('1' if enabled else '0',toggle)}
   for key,(value,label) in values.items():filters[key][value]=label
   row_attrs=''.join(f' data-{key}="{e(value)}"' for key,(value,label) in values.items())
   stale=_ui('<br><small>Исчез из ответа</small>') if n.get('stale') else ''
  if not subscriptions:stale=''
  editor_id=vpn_editor.dialog_id(name) if n else ''
  if n:dialogs.append(vpn_editor.render(n))
  name_cell=('<button type="button" class="vpn-open-editor" data-vpn-editor="'+e(editor_id)+'" title="'+e(name)+'">'+e(name)+'</button>' if n else '<span title="'+e(name)+'">'+e(name)+'</span>')
  country_host=str((n.get('connection') or {}).get('server') or host).strip('[]') if n else str(host).strip('[]')
  rows.append('<tr'+row_attrs+'><td class="proxy-select-cell">'+delete+'</td><td class="vpn-country" data-vpn-host="'+e(country_host)+'" title="Страна сервера">🌐</td><td class="vpn-name-cell">'+name_cell+'<small>'+e(type_label)+'</small>'+stale+'</td><td class="vpn-endpoint" title="'+e(host)+((':'+e(port)) if port else '')+'">'+e(host)+((':'+e(port)) if port else '')+'</td><td><form method="post"><input type="hidden" name="action" value="proxy_balance"><input type="hidden" name="name" value="'+e(name)+'"><button type="submit" name="enabled" value="'+('0' if enabled else '1')+'" class="vpn-status-button" style="background:'+color+';color:white;font-weight:700">'+toggle+'</button></form></td><td><button type="button" class="proxy-health-btn proxy-row-health" data-node="'+e(name)+_ui('" onclick="checkProxyHealth(this)">Проверить <span class="proxy-health-result">—</span></button></td></tr>'))
  rows[-1]=rows[-1].removesuffix('</tr>')+'<td class="vpn-traffic" data-vpn-traffic="'+e(name)+'" style="white-space:nowrap">—</td></tr>'
  if subscriptions:
   row=rows.pop().replace('<tr ', '<tr hidden ', 1)
   grouped_rows.setdefault(subscription,[]).append(row)
 if subscriptions:
  for sid,connections in grouped_rows.items():
   escaped=html.escape(sid,quote=True)
   group=(subscription_groups or {}).get(sid)
   title,metadata,refresh,remove,automation=group if group else (_ui('Неизвестная подписка'),'','','','')
   label=html.escape(title)
   count=len(connections)
   filters['subscription'][sid]=title
   rows.append(''.join(('<tbody data-vpn-group="', f'{escaped}', '"><tr class="vpn-group-heading"><th scope="rowgroup" colspan="7"><div class="vpn-group-bar"><button type="button" class="vpn-group-toggle" aria-expanded="false"><span><strong>', f'{label}', '</strong> <small>(', f'{count}', ')</small>', f'{metadata}', '</span></button><div class="vpn-group-actions">', f'{refresh}', '<button type="button" data-subscription="', f'{escaped}', _ui('" onclick="checkAllProxyRows(this)">Проверка серверов</button>'), f'{remove}', '</div></div>', f'{automation}', '</th></tr>'))
               +''.join(connections)+'</tbody>')
 script = _ui('<script>\ndocument.addEventListener(\'DOMContentLoaded\',()=>{\n const cells=[...document.querySelectorAll(\'[data-vpn-traffic]\')];let pending=false;\n const size=n=>{const units=[\'Б\',\'КБ\',\'МБ\',\'ГБ\',\'ТБ\'];let i=0;while(n>=1024&&i<units.length-1){n/=1024;i++;}return n.toLocaleString(\'ru-RU\',{maximumFractionDigits:i?2:0})+\' \'+units[i];};\n async function traffic(){if(pending)return;pending=true;try{\n  const response=await fetch(\'/api/vpn-traffic\',{cache:\'no-store\'});if(!response.ok)throw Error();const data=await response.json();\n  for(const cell of cells){const value=data.servers[cell.dataset.vpnTraffic]||{download:0,upload:0};cell.textContent=\'↓ \'+size(value.download)+\' / ↑ \'+size(value.upload);cell.title=data.status+\' · Учёт с \'+data.since;}\n }catch(e){for(const cell of cells)cell.title=\'Нет связи со счётчиками трафика\';}finally{pending=false;}}\n traffic();const timer=setInterval(traffic,30000);window.addEventListener(\'pagehide\',()=>clearInterval(timer));\n});\nfunction updateSubscriptionGroups(panel){\n const filters=[...panel.querySelectorAll(\'[data-vpn-filter]\')].filter(filter=>filter.value);\n const subscriptionFilter=filters.find(filter=>filter.dataset.vpnFilter===\'subscription\');\n for(const group of panel.querySelectorAll(\'[data-vpn-group]\')){\n  const toggle=group.querySelector(\'.vpn-group-toggle\');\n  const expanded=toggle.getAttribute(\'aria-expanded\')===\'true\';\n  const rows=[...group.querySelectorAll(\'tr[data-subscription]\')];\n  let matching=0;\n  for(const row of rows){\n   const checkbox=row.querySelector(\'input[name="selected"]\');\n   row.dataset.status=checkbox.dataset.balanceEnabled;\n   const matches=filters.every(filter=>filter.value===row.dataset[filter.dataset.vpnFilter]);\n   if(matches)matching++;\n   row.hidden=!expanded || !matches;\n   if(row.hidden)checkbox.checked=false;\n  }\n  group.hidden=(subscriptionFilter && subscriptionFilter.value!==group.dataset.vpnGroup)\n   || (filters.some(filter=>filter!==subscriptionFilter) && matching===0);\n }\n}\ndocument.addEventListener(\'DOMContentLoaded\',()=>{\n const panel=document.querySelector(\'.subscription-table\')?.closest(\'.proxy-manager\');\n if(panel)updateSubscriptionGroups(panel);\n});\ndocument.addEventListener(\'change\',event=>{\n if(!event.target.matches(\'[data-vpn-filter]\'))return;\n const panel=event.target.closest(\'.proxy-manager\');\n if(event.target.value){\n  for(const toggle of panel.querySelectorAll(\'.vpn-group-toggle\'))toggle.setAttribute(\'aria-expanded\',\'true\');\n }\n updateSubscriptionGroups(panel);\n});\ndocument.addEventListener(\'click\',event=>{\n const toggle=event.target.closest(\'.vpn-group-toggle\');\n if(!toggle)return;\n toggle.setAttribute(\'aria-expanded\',String(toggle.getAttribute(\'aria-expanded\')!==\'true\'));\n updateSubscriptionGroups(toggle.closest(\'.proxy-manager\'));\n});\nfunction enableSelectedProxies() {\n const boxes=Array.from(document.querySelectorAll(\'input[name="selected"]:checked\'));\n if(!boxes.length)return;\n const form=document.getElementById("delete-selected-form");\n form.querySelector(\'input[name="action"]\').value="proxy_enable_selected";\n form.requestSubmit();\n form.querySelector(\'input[name="action"]\').value="proxy_delete_selected";\n}\nfunction selectInactiveProxies() {\n const boxes=Array.from(document.querySelectorAll(\'input[name="selected"]\'));\n for(const box of boxes) box.checked=!box.closest("tr").hidden && box.dataset.balanceEnabled==="0";\n}\nasync function checkAllProxyRows(button, selectAvailable=false) {\n const label=button.textContent;\n const rows=Array.from(document.querySelectorAll(".proxy-row-health")).filter(row=>{\n  const tr=row.closest(\'tr\');\n  return button.dataset.subscription ? tr.dataset.subscription===button.dataset.subscription : !tr.hidden;\n });\n let next=0,done=0;\n button.disabled=true;\n button.textContent="Проверено 0 из "+rows.length;\n async function worker() {\n  while(true) {\n   const index=next++;\n   if(index>=rows.length)return;\n   await checkProxyHealth(rows[index]);\n   done++;\n   button.textContent="Проверено "+done+" из "+rows.length;\n  }\n }\n await Promise.all(Array.from({length:Math.min(30,rows.length)},worker));\n if(selectAvailable) {\n  for(const row of rows) {\n   const value=Number.parseInt(row.querySelector(".proxy-health-result")?.textContent,10);\n   const box=row.closest("tr")?.querySelector(\'input[name="selected"]\');\n   if(box) box.checked=!box.closest("tr").hidden && Number.isFinite(value) && value>0;\n  }\n }\n if(selectAvailable) button.innerHTML="Проверить все и выбрать<br>доступные";\n else button.textContent=label;\n button.disabled=false;\n}\n</script>')
 result = script + '<section class="routing-panel proxy-manager">' + navigation + _ui('<details class="proxy-import-spoiler"><summary>Добавить прокси</summary><form method="post" class="proxy-import-form"><input type="hidden" name="action" value="proxy_import"><div class="proxy-import-box"><textarea name="source" rows="8" wrap="off" placeholder="vless://… либо HTTPS-ссылка на список VLESS URI" required></textarea><div class="proxy-import-footer"><button type="submit">Импортировать и применить</button></div></div></form></details><div class="proxy-check-select-toolbar"><button type="button" onclick="checkAllProxyRows(this,true)">Проверить все и выбрать<br>доступные</button><button type="button" onclick="enableSelectedProxies()">Включить<br>выбранные</button><button type="button" onclick="selectInactiveProxies()">Выбрать<br>неактивные</button><form id="delete-selected-form" method="post"><input type="hidden" name="action" value="proxy_delete_selected"><button type="submit">Удалить<br>выбранные</button></form></div><div class="proxy-table-wrap"><table class="proxy-manager-table"><thead><tr><th class="proxy-select-cell"><span class="proxy-visually-hidden">Выбор</span></th><th>Прокси</th><th>Сервер</th><th>Статус</th><th><button type="button" id="check-all-proxies" onclick="checkAllProxyRows(this)">Проверить все</button></th></tr></thead><tbody>')+''.join(rows)+'</tbody></table></div></section><style>.proxy-import-spoiler>summary{cursor:pointer;display:flex;align-items:center;gap:9px;list-style:none;font-size:18px;font-weight:700}.proxy-import-spoiler>summary::-webkit-details-marker{display:none}.proxy-import-spoiler>summary::before{content:"";width:0;height:0;border-top:5px solid transparent;border-bottom:5px solid transparent;border-left:7px solid currentColor;flex:none}.proxy-import-spoiler[open]>summary{margin-bottom:14px}.proxy-import-spoiler[open]>summary::before{transform:rotate(90deg)}.proxy-import-box{width:100%;box-sizing:border-box;border:1px solid #b8c2d3;border-radius:8px;overflow:hidden}.proxy-import-box textarea{display:block;width:100%;height:10em;min-height:10em;max-height:10em;box-sizing:border-box;resize:none;overflow:auto;white-space:pre;border:0!important;border-radius:0!important}.proxy-import-footer{display:flex;justify-content:flex-end;padding:8px 10px;border-top:1px solid #b8c2d3}.proxy-table-wrap{width:100%;box-sizing:border-box;margin-top:16px;padding:8px;border:1px solid #b8c2d3;border-radius:10px;overflow-x:auto}.proxy-check-select-toolbar{display:flex;align-items:stretch;justify-content:flex-start;gap:8px;margin:16px 0 0}.proxy-check-select-toolbar button{min-height:52px;height:auto;box-sizing:border-box;padding:8px 12px;line-height:1.2;text-align:center;white-space:normal}.proxy-manager-table{width:100%;min-width:100%;table-layout:auto;margin:0;border-collapse:collapse;text-align:left}.proxy-manager-table th,.proxy-manager-table td{text-align:left!important;vertical-align:middle;padding:10px 12px;border-bottom:1px solid #d8deea}.proxy-manager-table thead th{white-space:nowrap}.proxy-manager-table thead th:last-child{white-space:normal}.proxy-bulk-actions{display:flex;align-items:center;justify-content:center;gap:8px;white-space:normal}.proxy-bulk-actions form{margin:0}.proxy-bulk-actions button{min-height:38px;white-space:normal;line-height:1.15}.proxy-manager-table tbody tr:last-child td{border-bottom:0}.proxy-manager-table th:last-child,.proxy-manager-table td:last-child{text-align:left!important}.proxy-manager-table th:last-child{min-width:150px}body .proxy-check-select-toolbar{flex-wrap:wrap;align-items:stretch}body .proxy-check-select-toolbar form{display:flex;margin:0;align-items:stretch}body .routing-panel .proxy-check-select-toolbar button{display:block;min-height:56px;height:auto;margin:0;padding:8px 14px;border:1px solid #315ee8;border-radius:8px;background:#315ee8;color:#fff;font:inherit;font-weight:700;line-height:1.25;text-align:center;white-space:normal;box-sizing:border-box}body .routing-panel .proxy-check-select-toolbar button:disabled{opacity:.55;cursor:wait}body .routing-panel .proxy-check-select-toolbar button:not(:disabled):hover{background:#244dcc;border-color:#244dcc}.proxy-manager-table .proxy-select-cell{width:44px;text-align:center!important}.proxy-select-cell input[type="checkbox"]{width:18px;height:18px;min-width:18px;padding:0;margin:0;vertical-align:middle;accent-color:#315ee8}.proxy-visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}</style>'

 result=result.replace(_ui('<th>Прокси</th>'),_ui('<th>Страна</th><th>VPN / тип</th>'),1)
 result+=''.join(dialogs)+vpn_editor.assets()
 from vpn_import import form
 result=result.replace('</tr></thead>',_ui('<th title="Принято / отправлено через этот VPN">Трафик ↓ / ↑</th></tr></thead>'))
 result+=_ui('<p class="vpn-traffic-note">Суммарный объём: ↓ принято / ↑ отправлено. Обновление раз в 30 секунд. Счётчики сохраняются между перезапусками. Учёт приблизительный: короткие соединения между опросами могут не учитываться.</p>')
 if subscriptions:
  labels={'subscription':_ui('Подписка'),'type':_ui('Тип соединения'),'client':_ui('Клиент'),'status':_ui('Статус')}
  controls=[]
  for key,label in labels.items():
   options=''.join(f'<option value="{html.escape(value,quote=True)}">{html.escape(text)}</option>'
                   for value,text in sorted(filters[key].items(),key=lambda item:item[1].casefold()))
   controls.append(''.join(('<label>', f'{label}', '<select data-vpn-filter="', f'{key}', _ui('"><option value="">Все</option>'), f'{options}', '</select></label>')))
  filters_html='<div class="vpn-subscription-filters">'+''.join(controls)+'</div>'
  result=re.sub(r'<details class="proxy-import-spoiler">.*?</details>',
                lambda match:subscription_controls+filters_html,result,count=1,flags=re.S)
  result=re.sub(r'<thead>.*?</thead>', '', result, count=1)
  result=result.replace('<tbody>'+''.join(rows)+'</tbody>', ''.join(rows),1)
  result=result.replace('class="proxy-manager-table">','class="proxy-manager-table subscription-table">'
    '<colgroup><col style="width:4%"><col style="width:5%"><col style="width:19%">'
    '<col style="width:20%"><col style="width:14%"><col style="width:14%"><col style="width:24%"></colgroup>',1)
  result+='''<style>.vpn-subscription-add{margin-bottom:16px}
.vpn-subscription-add summary{cursor:pointer;font-weight:700;padding:6px 0}
.vpn-subscription-form,.vpn-subscription-filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.vpn-subscription-form{margin-top:10px}
.vpn-subscription-form label,.vpn-subscription-filters label{display:grid;gap:4px;min-width:0;font-size:13px;color:var(--ui-muted)}
body .proxy-manager :is(.vpn-subscription-form,.vpn-subscription-filters) :is(input,select){width:100%;min-width:0;box-sizing:border-box}
.vpn-auto{margin-top:8px;font-weight:400}
.vpn-auto summary{cursor:pointer}
body .proxy-manager .vpn-auto input[type=checkbox]{width:auto}
body .proxy-manager .vpn-auto[open]{display:flex;align-items:center;gap:10px;min-width:0}
body .proxy-manager .vpn-auto[open] summary{flex:none;white-space:nowrap}
body .proxy-manager .vpn-auto .vpn-subscription-form{display:flex;align-items:center;gap:6px;margin:0;min-width:0;flex:1}
body .proxy-manager .vpn-auto .vpn-subscription-form label{display:flex;align-items:center;gap:3px;flex:none;width:auto;min-width:0;white-space:nowrap;font-size:12px}
body .proxy-manager .vpn-auto .vpn-subscription-form input[type=number]{width:58px;min-width:58px;height:34px;margin:0;padding:5px}
body .proxy-manager .vpn-auto .vpn-subscription-form button{flex:none;width:102px!important;min-width:102px!important;min-height:34px;margin:0;padding:5px 6px;white-space:nowrap!important}
.subscription-table [hidden]{display:none!important}
body .proxy-manager-table.subscription-table .vpn-group-heading th{width:auto;background:var(--ui-surface-alt);padding:10px 12px}
.vpn-group-bar,.vpn-group-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.vpn-group-bar{justify-content:space-between}
body .proxy-manager .subscription-table .vpn-group-delete button{background:#c62828;border-color:#c62828;color:#fff}
body .proxy-manager .subscription-table .vpn-group-delete button:hover{background:#a91f1f;border-color:#a91f1f}
body .proxy-manager .subscription-table .vpn-group-bar button{width:auto!important;padding:8px 12px}
body .proxy-manager .subscription-table .vpn-group-toggle{display:flex;align-items:center;gap:8px;text-align:left;background:transparent;border-color:transparent;min-height:40px}
.vpn-group-toggle::before{content:"▸"}.vpn-group-toggle[aria-expanded=true]::before{content:"▾"}
.vpn-group-meta{display:block;margin-top:3px;color:var(--ui-muted);font-weight:400}
@media(max-width:850px){.vpn-subscription-form,.vpn-subscription-filters{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:600px){body .subscription-table tbody tr.vpn-group-heading,body .subscription-table .vpn-group-heading th{display:block}body .subscription-table colgroup{display:none}}

</style>'''
 else:
  result=re.sub(r'<details class="proxy-import-spoiler">.*?</details>',lambda match:form(),result,count=1,flags=re.S)
 result+=_ui('<style>.vpn-client-form{display:flex;flex-direction:column;gap:7px;min-width:130px}.vpn-client-form select{width:145px;padding:8px;border-radius:7px;background:#202a3b;color:inherit;border:1px solid #526078}.vpn-client-form button{min-height:34px;padding:6px 10px}</style><p>Откройте соединение по названию, чтобы изменить его параметры или выбрать клиент. Доступность проверьте кнопкой «Проверить».</p>')
 return result.replace(_ui('<th>Прокси</th>'),_ui('<th>VPN / тип</th>')).replace(_ui('Выбрать прокси '),_ui('Выбрать VPN '))
