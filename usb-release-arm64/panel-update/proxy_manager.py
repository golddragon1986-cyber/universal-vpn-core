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

def delete_many(names):
 names=list(dict.fromkeys(x for x in names if x))
 if not names: raise ValueError("Не выбраны прокси для удаления")
 d=read(); old=json.loads(json.dumps(d))
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

def delay(name):
 from urllib.parse import quote
 path='/providers/proxies/USER-MANAGED/'+quote(name,safe='')+'/healthcheck?url='+urllib.parse.quote(TEST)+'&timeout=5000'
 with urllib.request.urlopen(API+path,timeout=8) as r:return json.load(r).get('delay',-1)
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

def render():
 import html
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
 rows=[]
 for name in names:
  n=managed.get(name); proxy=n['proxy'] if n else {}
  host=proxy.get('server') or hosts.get(name,{}).get('server','')
  port=proxy.get('port') or hosts.get(name,{}).get('port','')
  remote=bridges.get(str(port),{}) if host in ('127.0.0.1','::1','localhost') and proxy.get('type') in ('socks5','http') else {}
  if remote:host,port=remote['server'],remote['port']
  if ':' in str(host):host='['+str(host)+']'
  enabled=db.get('balance_overrides',{}).get(name,n.get('balance',True) if n else True)
  e=lambda value: html.escape(str(value),quote=True)
  toggle=('Включено' if enabled else 'Отключено')
  color='#16803c' if enabled else '#c62828'
  delete='<input type="checkbox" form="delete-selected-form" name="selected" value="'+e(name)+'" data-balance-enabled="'+('1' if enabled else '0')+'" aria-label="Выбрать прокси '+e(name)+'">'

  type_label=proxy.get('type','')
  if remote:type_label=remote['type']+' · sing-box'
  if proxy.get('amnezia-wg-option'):type_label='AmneziaWG '+str(proxy['amnezia-wg-option'].get('version',''))
  import vpn_clients
  if n and n.get('connection'):
   endpoint=n['connection'];host=endpoint.get('server',host);port=endpoint.get('port',port);type_label=endpoint.get('type',type_label)
  rows.append('<tr><td class="proxy-select-cell">'+delete+'</td><td>'+e(name)+'<br><small>'+e(type_label)+'</small></td><td>'+e(host)+((':'+e(port)) if port else '')+'</td><td><form method="post"><input type="hidden" name="action" value="proxy_balance"><input type="hidden" name="name" value="'+e(name)+'"><button type="submit" name="enabled" value="'+('0' if enabled else '1')+'" style="background:'+color+';color:white;font-weight:700;width:130px;min-width:130px;box-sizing:border-box;text-align:center;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center">'+toggle+'</button></form></td><td><button type="button" class="proxy-health-btn proxy-row-health" data-node="'+e(name)+'" onclick="checkProxyHealth(this)">Проверить <span class="proxy-health-result">—</span></button></td></tr>')
  rows[-1]=rows[-1].removesuffix('</tr>')+'<td class="vpn-traffic" data-vpn-traffic="'+e(name)+'" style="white-space:nowrap">—</td></tr>'
  rows[-1]=rows[-1].replace('<td>'+e(host),'<td>'+ (vpn_clients.form(n) if n else 'Mihomo · встроенное соединение')+'</td><td>'+e(host),1)
 script = """<script>
document.addEventListener('DOMContentLoaded',()=>{
 const cells=[...document.querySelectorAll('[data-vpn-traffic]')];let pending=false;
 const size=n=>{const units=['Б','КБ','МБ','ГБ','ТБ'];let i=0;while(n>=1024&&i<units.length-1){n/=1024;i++;}return n.toLocaleString('ru-RU',{maximumFractionDigits:i?2:0})+' '+units[i];};
 async function traffic(){if(pending)return;pending=true;try{
  const response=await fetch('/api/vpn-traffic',{cache:'no-store'});if(!response.ok)throw Error();const data=await response.json();
  for(const cell of cells){const value=data.servers[cell.dataset.vpnTraffic]||{download:0,upload:0};cell.textContent='↓ '+size(value.download)+' / ↑ '+size(value.upload);cell.title=data.status+' · Учёт с '+data.since;}
 }catch(e){for(const cell of cells)cell.title='Нет связи со счётчиками трафика';}finally{pending=false;}}
 traffic();const timer=setInterval(traffic,30000);window.addEventListener('pagehide',()=>clearInterval(timer));
});
function enableSelectedProxies() {
 const boxes=Array.from(document.querySelectorAll('input[name="selected"]:checked'));
 if(!boxes.length)return;
 const form=document.getElementById("delete-selected-form");
 form.querySelector('input[name="action"]').value="proxy_enable_selected";
 form.requestSubmit();
}
function selectInactiveProxies() {
 const boxes=Array.from(document.querySelectorAll('input[name="selected"]'));
 for(const box of boxes) box.checked=box.dataset.balanceEnabled==="0";
}
async function checkAllProxyRows(button, selectAvailable=false) {
 const rows=Array.from(document.querySelectorAll(".proxy-row-health"));
 let next=0,done=0;
 button.disabled=true;
 button.textContent="Проверено 0 из "+rows.length;
 async function worker() {
  while(true) {
   const index=next++;
   if(index>=rows.length)return;
   await checkProxyHealth(rows[index]);
   done++;
   button.textContent="Проверено "+done+" из "+rows.length;
  }
 }
 await Promise.all(Array.from({length:Math.min(30,rows.length)},worker));
 if(selectAvailable) {
  for(const row of rows) {
   const value=Number.parseInt(row.querySelector(".proxy-health-result")?.textContent,10);
   const box=row.closest("tr")?.querySelector('input[name="selected"]');
   if(box) box.checked=Number.isFinite(value) && value>0;
  }
 }
 if(selectAvailable) button.innerHTML="Проверить все и выбрать<br>доступные";
 else button.textContent="Проверить все";
 button.disabled=false;
}
</script>"""
 result = script + '<section class="routing-panel proxy-manager"><details class="proxy-import-spoiler"><summary>Добавить прокси</summary><form method="post" class="proxy-import-form"><input type="hidden" name="action" value="proxy_import"><div class="proxy-import-box"><textarea name="source" rows="8" wrap="off" placeholder="vless://… либо HTTPS-ссылка на список VLESS URI" required></textarea><div class="proxy-import-footer"><button type="submit">Импортировать и применить</button></div></div></form></details><div class="proxy-check-select-toolbar"><button type="button" onclick="checkAllProxyRows(this,true)">Проверить все и выбрать<br>доступные</button><button type="button" onclick="enableSelectedProxies()">Включить<br>выбранные</button><button type="button" onclick="selectInactiveProxies()">Выбрать<br>неактивные</button><form id="delete-selected-form" method="post"><input type="hidden" name="action" value="proxy_delete_selected"><button type="submit">Удалить<br>выбранные</button></form></div><div class="proxy-table-wrap"><table class="proxy-manager-table"><thead><tr><th class="proxy-select-cell"><span class="proxy-visually-hidden">Выбор</span></th><th>Прокси</th><th>Сервер</th><th>Статус</th><th><button type="button" id="check-all-proxies" onclick="checkAllProxyRows(this)">Проверить все</button></th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></div></section><style>.proxy-import-spoiler>summary{cursor:pointer;display:flex;align-items:center;gap:9px;list-style:none;font-size:18px;font-weight:700}.proxy-import-spoiler>summary::-webkit-details-marker{display:none}.proxy-import-spoiler>summary::before{content:"";width:0;height:0;border-top:5px solid transparent;border-bottom:5px solid transparent;border-left:7px solid currentColor;flex:none}.proxy-import-spoiler[open]>summary{margin-bottom:14px}.proxy-import-spoiler[open]>summary::before{transform:rotate(90deg)}.proxy-import-box{width:100%;box-sizing:border-box;border:1px solid #b8c2d3;border-radius:8px;overflow:hidden}.proxy-import-box textarea{display:block;width:100%;height:10em;min-height:10em;max-height:10em;box-sizing:border-box;resize:none;overflow:auto;white-space:pre;border:0!important;border-radius:0!important}.proxy-import-footer{display:flex;justify-content:flex-end;padding:8px 10px;border-top:1px solid #b8c2d3}.proxy-table-wrap{width:100%;box-sizing:border-box;margin-top:16px;padding:8px;border:1px solid #b8c2d3;border-radius:10px;overflow-x:auto}.proxy-check-select-toolbar{display:flex;align-items:stretch;justify-content:flex-start;gap:8px;margin:16px 0 0}.proxy-check-select-toolbar button{min-height:52px;height:auto;box-sizing:border-box;padding:8px 12px;line-height:1.2;text-align:center;white-space:normal}.proxy-manager-table{width:100%;min-width:100%;table-layout:auto;margin:0;border-collapse:collapse;text-align:left}.proxy-manager-table th,.proxy-manager-table td{text-align:left!important;vertical-align:middle;padding:10px 12px;border-bottom:1px solid #d8deea}.proxy-manager-table thead th{white-space:nowrap}.proxy-manager-table thead th:last-child{white-space:normal}.proxy-bulk-actions{display:flex;align-items:center;justify-content:center;gap:8px;white-space:normal}.proxy-bulk-actions form{margin:0}.proxy-bulk-actions button{min-height:38px;white-space:normal;line-height:1.15}.proxy-manager-table tbody tr:last-child td{border-bottom:0}.proxy-manager-table th:last-child,.proxy-manager-table td:last-child{text-align:left!important}.proxy-manager-table th:last-child{min-width:150px}body .proxy-check-select-toolbar{flex-wrap:wrap;align-items:stretch}body .proxy-check-select-toolbar form{display:flex;margin:0;align-items:stretch}body .routing-panel .proxy-check-select-toolbar button{display:block;min-height:56px;height:auto;margin:0;padding:8px 14px;border:1px solid #315ee8;border-radius:8px;background:#315ee8;color:#fff;font:inherit;font-weight:700;line-height:1.25;text-align:center;white-space:normal;box-sizing:border-box}body .routing-panel .proxy-check-select-toolbar button:disabled{opacity:.55;cursor:wait}body .routing-panel .proxy-check-select-toolbar button:not(:disabled):hover{background:#244dcc;border-color:#244dcc}.proxy-manager-table .proxy-select-cell{width:44px;text-align:center!important}.proxy-select-cell input[type="checkbox"]{width:18px;height:18px;min-width:18px;padding:0;margin:0;vertical-align:middle;accent-color:#315ee8}.proxy-visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}</style>'

 from vpn_import import form
 result=result.replace('</tr></thead>','<th title="Принято / отправлено через этот VPN">Трафик ↓ / ↑</th></tr></thead>')
 result+='<p class="vpn-traffic-note">Суммарный объём: ↓ принято / ↑ отправлено. Обновление раз в 30 секунд. Счётчики сохраняются между перезапусками. Учёт приблизительный: короткие соединения между опросами могут не учитываться.</p>'
 result=re.sub(r'<details class="proxy-import-spoiler">.*?</details>',lambda match:form(),result,count=1,flags=re.S)
 result=result.replace('<th>Сервер</th>','<th>Клиент</th><th>Сервер</th>')
 result+='<style>.vpn-client-form{display:flex;flex-direction:column;gap:7px;min-width:130px}.vpn-client-form select{width:145px;padding:8px;border-radius:7px;background:#202a3b;color:inherit;border:1px solid #526078}.vpn-client-form button{min-height:34px;padding:6px 10px}.proxy-manager-table{min-width:1050px}</style><p>Клиент выбирается отдельно для каждого соединения. Изменение применяется кнопкой и проверяется через выбранный клиент; при неудаче возвращаются предыдущие настройки. Неустановленные клиенты доступны после установки в разделе «Компоненты».</p>'
 return result.replace('<th>Прокси</th>','<th>VPN / тип</th>').replace('Выбрать прокси ','Выбрать VPN ')
