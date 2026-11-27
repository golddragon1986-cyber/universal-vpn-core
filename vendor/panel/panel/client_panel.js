(()=>{
const layout=document.createElement('style');layout.textContent=`
body .unified-main .clients-table{min-width:700px;table-layout:fixed}
body .unified-main .clients-table :is(th,td){padding:9px 6px}
body .unified-main .clients-table :is(input,select){width:100%;min-width:0;max-width:100%;height:40px;margin:0}
body .unified-main .clients-table :is(th,td):nth-child(1){width:150px}
body .unified-main .clients-table :is(th,td):nth-child(2){width:125px}
body .unified-main .clients-table :is(th,td):nth-child(3){width:200px;min-width:0}
body .unified-main .clients-table :is(th,td):nth-child(4){width:170px;min-width:0;white-space:nowrap}
body .unified-main .clients-table td:last-child button{font-size:13px;padding:8px;margin-right:4px}
body .unified-main .dhcp-panel{margin-top:16px}
body .unified-main .dhcp-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:10px 0}
body .unified-main .dhcp-toolbar p{margin:0}
body .unified-main #dhcp-search{display:grid;grid-template-columns:minmax(150px,1.4fr) repeat(3,minmax(110px,1fr)) auto auto;gap:8px}
body .unified-main #dhcp-search :is(input,select,button){min-width:0;width:100%;margin:0}
body .unified-main .dhcp-table{width:100%;table-layout:fixed;border-collapse:collapse}
body .unified-main .dhcp-table :is(th,td){padding:9px 6px;text-align:left;border-bottom:1px solid var(--ui-border);vertical-align:middle;overflow-wrap:anywhere}
body .unified-main .dhcp-table :is(th,td):nth-child(1){width:19%}
body .unified-main .dhcp-table :is(th,td):nth-child(2){width:12%}
body .unified-main .dhcp-table :is(th,td):nth-child(3){width:14%}
body .unified-main .dhcp-table :is(th,td):nth-child(4){width:13%}
body .unified-main .dhcp-table :is(th,td):nth-child(5){width:18%}
body .unified-main .dhcp-table :is(th,td):nth-child(6){width:24%}
body .unified-main .dhcp-table select{width:100%;min-width:0;margin:0;height:40px}
body .unified-main .dhcp-actions{display:flex;gap:5px;align-items:stretch}
body .unified-main .dhcp-actions button{flex:1;min-width:0;min-height:40px;margin:0;padding:7px 5px;white-space:normal}
body .unified-main .dhcp-table small{display:block;color:var(--ui-muted);font-size:12px}
body .unified-main .dhcp-name{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
`;document.head.append(layout);
const seed=JSON.parse(document.getElementById('clients-data').textContent),body=document.getElementById('clients-table-body'),search=document.getElementById('clients-search');
const legacyAdd=document.getElementById('client-add-form');
if(legacyAdd)legacyAdd.closest('details').remove();
const header=document.querySelector('.clients-table thead tr');
if(header.cells.length===6){header.cells[2].remove();header.cells[2].remove();}
const clone=value=>JSON.parse(JSON.stringify(value));
const original=seed.state.rows,old=new Map(original.map(row=>[row.id,row]));
let rows=clone(seed.pending?.rows||original),leaseRequests=clone(seed.pending?.lease_requests||[]),leaseActions=clone(seed.pending?.lease_actions||[]),view={...seed.view,page:1},error='',dhcpLeases=[];
const baseline=seed.pending?.baseline||seed.baseline,stale=baseline!==seed.baseline;
const signature=row=>JSON.stringify({id:row.id,list:row.list,address:row.address,label:row.label,name:(row.name||'').trim(),route:row.route||'RULES',enabled:row.enabled,dhcp_owner:row.dhcp_owner||''});
const ip=value=>{const parts=value.split('.');if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))throw Error('Укажите IPv4-адрес');return parts.reduce((n,p)=>n*256+Number(p),0);};
function canonical(value){
 value=value.trim();
 if(value.includes('-')){const parts=value.split('-');if(parts.length!==2||ip(parts[0])>ip(parts[1]))throw Error('Некорректный диапазон IPv4');return parts.map(p=>p.split('.').map(Number).join('.')).join('-');}
 const [host,prefix='32',extra]=value.split('/'),bits=Number(prefix),n=ip(host);
 if(extra!==undefined||!Number.isInteger(bits)||bits<1||bits>32||n%2**(32-bits)!==0)throw Error('Укажите адрес сети с правильной маской');
 return host.split('.').map(Number).join('.')+(bits===32?'':'/'+bits);
}
function interval(value){if(value.includes('-'))return value.split('-').map(ip);const [host,prefix='32']=value.split('/'),size=2**(32-Number(prefix)),start=Math.floor(ip(host)/size)*size;return [start,start+size-1];}
function matches(row){
 if(view.source&&view.source!==row.list)return false;
 if(view.status&&((view.status==='enabled')!==!!row.enabled))return false;
 const q=(view.q||'').trim().toLowerCase();if(!q)return true;
 try{const [a,b]=interval(row.address),[c,d]=interval(q);return a<=d&&c<=b;}catch(e){return [row.address,row.name,row.label,row.list].some(v=>String(v).toLowerCase().includes(q));}
}
function persist(){
 error='';window.configurationDraft?.set('clients',new URLSearchParams({action:'client_apply',client_token:seed.token,baseline,rows_baseline:seed.rows_baseline,clients:JSON.stringify(rows),lease_requests:JSON.stringify(leaseRequests),lease_actions:JSON.stringify(leaseActions)}));
}
function button(text,fn,danger=false){const b=document.createElement('button');b.type='button';b.textContent=text;if(danger)b.className='danger';b.addEventListener('click',fn);b.disabled=!seed.state.live;return b;}
function input(value,label,change){const field=document.createElement('input');field.value=value;field.setAttribute('aria-label',label);field.disabled=!seed.state.live;field.addEventListener('input',()=>{change(field.value);persist();updateStatus();});return field;}
function rowChanged(row){return !old.has(row.id)||signature(row)!==signature(old.get(row.id));}
function status(row,removed,readonly){
 if(removed)return 'Будет удалён';
 if(!readonly&&rowChanged(row))return old.has(row.id)?(row.enabled?'Включён · ожидает':'Отключён · ожидает'):'Ожидает добавления';
 if(!row.enabled)return 'Отключён';
 return seed.state.lists[row.list]?.active?'Активен':'Маршрутизация отключена';
}
function updateStatus(){
 const byId=new Map(rows.map(row=>[row.id,row]));
 for(const tr of body.rows){const row=byId.get(tr.dataset.clientId);if(row){const pending=rowChanged(row)||leaseRequests.some(request=>request.client_row_id===row.id);tr.classList.toggle('client-pending',pending);tr.title=status(row,false,false);const toggle=tr.querySelector('[data-toggle-on]');if(toggle){toggle.dataset.togglePending=pending?'1':'0';window.paintToggle?.(toggle,row.enabled,pending);}}}
 document.getElementById('clients-inline-status').textContent=error||(stale?'Список RouterOS изменился. Отмените черновик и повторите изменения.':!seed.state.live?'RouterOS недоступен; показан последний сохранённый список.':'');
}
function draw(){
 const ids=new Set(rows.map(row=>row.id));
 const dhcpOwners=new Set(dhcpLeases.map(leaseOwner).filter(Boolean));
 const list=[...rows.map(row=>({row,removed:false,readonly:false})),...original.filter(row=>!ids.has(row.id)).map(row=>({row,removed:true,readonly:false})),...seed.state.readonly.map(row=>({row,removed:false,readonly:true}))].filter(item=>!dhcpOwners.has(item.row.dhcp_owner)&&matches(item.row));
 list.sort((a,b)=>{if(!a.row.address||!b.row.address)return Number(!a.row.address)-Number(!b.row.address);try{return interval(a.row.address)[0]-interval(b.row.address)[0]||a.row.address.localeCompare(b.row.address);}catch(e){return a.row.address.localeCompare(b.row.address);}});
 const pages=Math.max(1,Math.ceil(list.length/25));view.page=Math.min(view.page,pages);body.replaceChildren();
 for(const {row,removed,readonly} of list.slice((view.page-1)*25,view.page*25)){
  const tr=body.insertRow();tr.dataset.clientId=row.id;tr.classList.toggle('client-removed',removed);tr.classList.toggle('client-pending',removed||!readonly&&rowChanged(row));
  if(removed||readonly){tr.insertCell().textContent=row.address;tr.insertCell().textContent=row.name||'—';}
  else{
   const field=input(row.address,'Адрес клиента '+(row.address||'(новый)'),value=>{row.address=value;});
   field.placeholder='IPv4-адрес или сеть/маска';field.required=true;
   field.addEventListener('change',()=>{try{row.address=canonical(field.value);field.value=row.address;persist();}catch(e){error=e.message;updateStatus();}});tr.insertCell().append(field);
   const label=input(row.name||'','Внутреннее имя клиента '+row.address,value=>{row.name=value;});label.maxLength=100;tr.insertCell().append(label);
  }
  tr.title=status(row,removed,readonly);
  const routeCell=tr.insertCell(),routeSelect=document.createElement('select');routeSelect.setAttribute('aria-label','Маршрут клиента '+row.address);if(old.has(row.id))routeSelect.dataset.activeRoute=old.get(row.id).route||'RULES';
  const labels={RULES:'По общим правилам',BYPASS:'Через RouterOS (NAT)',SELECTOR:'Основной маршрут',LOADBALANCE:'Балансировка'};
  for(const value of seed.routes){const option=document.createElement('option');option.value=value;option.textContent=labels[value]||value.replace(/^CHANNEL-/,'');routeSelect.append(option);}
  if(!seed.routes.includes(row.route||'RULES')){const option=document.createElement('option');option.value=row.route;option.textContent=row.route+' (недоступен)';routeSelect.append(option);}
  routeSelect.value=row.route||'RULES';routeSelect.disabled=removed||readonly||!seed.state.live;routeSelect.addEventListener('change',()=>{row.route=routeSelect.value;persist();updateStatus();});routeCell.append(routeSelect);
  const actions=tr.insertCell();
  if(readonly)actions.textContent='Динамическая / внешняя запись';
  else if(removed)actions.append(button('Вернуть',()=>{rows.push(clone(row));persist();draw();}));
  else{
   const toggle=button(row.enabled?'Включено':'Отключено',()=>{row.enabled=!row.enabled;persist();draw();});toggle.dataset.toggleOn=row.enabled?'1':'0';toggle.dataset.togglePending=rowChanged(row)?'1':'0';window.paintToggle?.(toggle,row.enabled,rowChanged(row));actions.append(toggle);
   actions.append(button('Удалить',()=>{rows=rows.filter(value=>value.id!==row.id);leaseRequests=leaseRequests.filter(request=>request.client_row_id!==row.id);persist();draw();},true));
  }
 }
 if(!list.length){const cell=body.insertRow().insertCell();cell.colSpan=4;cell.textContent='Нет клиентов по заданному запросу';}
 document.getElementById('clients-count').textContent='Найдено: '+list.length;
 const pagination=document.getElementById('clients-pages');pagination.replaceChildren();const label=document.createElement('span');label.textContent='Страница '+view.page+' из '+pages;
 const prev=button('Назад',()=>{view.page--;draw();});prev.disabled=view.page===1;
 const next=button('Далее',()=>{view.page++;draw();});next.disabled=view.page===pages;pagination.append(prev,label,next);
 updateStatus();
 renderDhcp();
}
const addRow=document.getElementById('client-add-row')||button('Добавить клиента',()=>{});
addRow.id='client-add-row';addRow.disabled=!seed.state.live||!Object.keys(seed.state.lists).length;
if(!addRow.parentElement)document.querySelector('.clients-scroll').after(addRow);
addRow.addEventListener('click',()=>{
 const names=Object.keys(seed.state.lists),source=names.includes('uvpn-main-lan')?'uvpn-main-lan':names[0];
 const row={id:'new-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8),list:source,address:'',label:'',name:'Новый клиент',route:'RULES',enabled:true};
 rows.push(row);search.reset();find();view.page=Math.ceil((rows.length+seed.state.readonly.length+original.filter(r=>!rows.some(v=>v.id===r.id)).length)/25);persist();draw();
 const tr=Array.from(body.rows).find(tr=>tr.dataset.clientId===row.id);tr?.querySelector('input')?.focus();
});
for(const key of ['q','source','status'])search.elements[key].value=view[key]||'';
function find(){const values=new FormData(search);for(const key of ['q','source','status'])view[key]=String(values.get(key)||'');view.page=1;draw();const url=new URL(location.href);for(const key of ['q','source','status']){if(view[key])url.searchParams.set(key,view[key]);else url.searchParams.delete(key);}history.replaceState(null,'',url);}
search.addEventListener('submit',event=>{event.preventDefault();find();});
document.getElementById('clients-search-reset').addEventListener('click',()=>{search.reset();find();});
const dhcpBody=document.getElementById('dhcp-table-body'),dhcpStatus=document.getElementById('dhcp-status'),dhcpSearch=document.getElementById('dhcp-search');
let dhcpFilter={q:'',server:'',status:'',type:''};
function filteredLeases(){return dhcpLeases.filter(lease=>{
 const q=dhcpFilter.q.toLocaleLowerCase(),haystack=[lease.comment,lease.host,lease.mac,lease.ip,lease.active_ip,lease.server,linkedRow(lease)?.name].filter(Boolean).join(' ').toLocaleLowerCase();
 if(q&&!haystack.includes(q))return false;
 if(dhcpFilter.server&&lease.server!==dhcpFilter.server)return false;
 const active=lease.status==='bound'&&!lease.disabled;
 if(dhcpFilter.status&&dhcpFilter.status!==(active?'active':'off'))return false;
 if(dhcpFilter.type&&dhcpFilter.type!==(lease.dynamic?'dynamic':'static'))return false;
 return true;
});}
function updateDhcpServers(){
 const select=dhcpSearch.elements.server,selected=select.value;
 const servers=[...new Set(dhcpLeases.map(lease=>lease.server).filter(Boolean))].sort();
 select.replaceChildren(new Option('Все DHCP-серверы',''),...servers.map(server=>new Option(server,server)));
 select.value=servers.includes(selected)?selected:'';
 if(selected&&!select.value)dhcpFilter.server='';
}
dhcpSearch.addEventListener('submit',event=>{event.preventDefault();const values=new FormData(dhcpSearch);for(const key of ['q','server','status','type'])dhcpFilter[key]=String(values.get(key)||'').trim();renderDhcp();});
document.getElementById('dhcp-search-reset').addEventListener('click',()=>{dhcpSearch.reset();dhcpFilter={q:'',server:'',status:'',type:''};renderDhcp();});
const routeLabels={RULES:'По общим правилам',BYPASS:'Через RouterOS (NAT)',SELECTOR:'Основной маршрут',LOADBALANCE:'Балансировка'};
function assignedRoute(address){
 let best=null;
 try{
  const number=ip(address);
  for(const row of rows){
   if(!row.enabled||!row.address)continue;
   const [start,end]=interval(row.address);
   if(start<=number&&number<=end&&(!best||end-start<best.size))best={route:row.route||'RULES',size:end-start};
  }
 }catch(e){}
 return best?.route||'RULES';
}
const leaseAddress=lease=>lease.active_ip||lease.ip;
const leaseIdentity=lease=>({id:lease.id,ip:lease.ip,mac:lease.mac,server:lease.server,client_id:lease.client_id});
const leaseOwner=lease=>leaseAddress(lease)&&lease.mac?JSON.stringify([lease.server||'',String(lease.mac).toUpperCase(),lease.client_id||'',leaseAddress(lease)]):'';
const linkedRow=lease=>{
 const request=leaseRequests.find(item=>item.id===lease.id);
 if(request?.client_row_id){const pending=rows.find(row=>row.id===request.client_row_id);if(pending)return pending;}
 const owner=leaseOwner(lease);
 return owner?rows.find(row=>row.dhcp_owner===owner):undefined;
};
function pinLease(lease){
 if(!lease.dynamic||leaseRequests.some(request=>request.id===lease.id))return;
 leaseRequests.push({...leaseIdentity(lease),client_row_id:''});
}
function configureLease(lease,route){
 const address=leaseAddress(lease);
 if(!address||!seed.state.live)return;
 const names=Object.keys(seed.state.lists),source=names.includes('uvpn-main-lan')?'uvpn-main-lan':names[0];
 if(!source){dhcpStatus.textContent='Список клиентов контейнера в RouterOS не найден';return;}
 const leaseName=String(lease.comment||lease.host||'').replace(/[\x00-\x1f]/g,' ').trim().slice(0,100);
 let row=linkedRow(lease);
 if(!row){
  row=rows.find(item=>!item.dhcp_owner&&item.address===address);
  if(!row){
   row={id:'new-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8),list:source,address,label:'',name:leaseName,route,enabled:!lease.disabled,dhcp_owner:leaseOwner(lease)};
   rows.push(row);
  }else{row.route=route;}
 }else{row.route=route;if(!row.name)row.name=leaseName;}
 pinLease(lease);
 const request=leaseRequests.find(request=>request.id===lease.id);
 if(request)request.client_row_id=row.id;
 persist();draw();
}
function setLeaseAction(lease,action){
 leaseActions=leaseActions.filter(request=>request.id!==lease.id);
 if(action)leaseActions.push({...leaseIdentity(lease),action});
}
function toggleLease(lease){
 const current=leaseActions.find(request=>request.id===lease.id);
 const disabled=current?.action==='disable'?true:current?.action==='enable'?false:lease.disabled;
 const next=!disabled;
 setLeaseAction(lease,next===lease.disabled?null:next?'disable':'enable');
 if(lease.dynamic&&next)pinLease(lease);
 const row=linkedRow(lease);if(row?.dhcp_owner===leaseOwner(lease))row.enabled=!next;
 persist();draw();
}
function togglePin(lease){
 const pending=leaseRequests.find(request=>request.id===lease.id);
 const action=leaseActions.find(request=>request.id===lease.id);
 if(lease.dynamic){
  if(pending){leaseRequests=leaseRequests.filter(request=>request.id!==lease.id);setLeaseAction(lease,null);
   const row=rows.find(item=>item.id===pending.client_row_id);
   if(row?.id.startsWith('new-')&&row.dhcp_owner===leaseOwner(lease))rows=rows.filter(item=>item!==row);
  }else pinLease(lease);
 }else if(action?.action==='unpin'){
  setLeaseAction(lease,null);
  const owner=leaseOwner(lease),saved=owner?original.find(row=>row.dhcp_owner===owner):null;
  if(saved&&!rows.some(row=>row.id===saved.id))rows.push(clone(saved));
 }else{
  setLeaseAction(lease,'unpin');
  const owner=leaseOwner(lease);
  if(owner)rows=rows.filter(row=>row.dhcp_owner!==owner);
 }
 persist();draw();
}
function renderDhcp(){
 if(!dhcpBody)return;
 dhcpBody.replaceChildren();
 const visible=filteredLeases();dhcpStatus.textContent='Аренд DHCP: '+dhcpLeases.length+(Object.values(dhcpFilter).some(Boolean)?' · Найдено: '+visible.length:'');
 if(!visible.length){const cell=dhcpBody.insertRow().insertCell();cell.colSpan=6;cell.textContent=dhcpLeases.length?'Совпадений не найдено':'Аренд DHCP пока нет';return;}
 for(const lease of visible){
  const tr=dhcpBody.insertRow();
  const device=tr.insertCell(),displayName=linkedRow(lease)?.name||lease.comment||lease.host||lease.mac||'—';
  const name=document.createElement('span');name.className='dhcp-name';name.textContent=displayName;name.title=displayName;device.append(name);
  if(lease.comment&&lease.host&&lease.comment!==lease.host){const host=document.createElement('small');host.className='dhcp-name';host.textContent=lease.host;host.title=lease.host;device.append(host);}
  const server=document.createElement('small');server.textContent=lease.server||'—';device.append(server);
  tr.insertCell().textContent=leaseAddress(lease)||'—';
  tr.insertCell().textContent=lease.mac||'—';
  const state=tr.insertCell(),active=lease.status==='bound'&&!lease.disabled;
  const pending=leaseRequests.some(request=>request.id===lease.id),action=leaseActions.find(request=>request.id===lease.id);
  const effectiveDisabled=action?.action==='disable'?true:action?.action==='enable'?false:lease.disabled;
  state.append(document.createTextNode(active?(lease.dynamic?'Динамическая':'Закреплена'):'off'));
  if(active){const seen=document.createElement('small');seen.textContent=lease.last_seen||lease.expires_after||'';state.append(seen);
  }
  if(pending){const note=document.createElement('small');note.textContent='Станет статической после применения';state.append(note);}
  const select=document.createElement('select');select.setAttribute('aria-label','Маршрут DHCP-клиента '+(lease.ip||lease.mac));
  for(const value of seed.routes){const option=document.createElement('option');option.value=value;option.textContent=routeLabels[value]||value.replace(/^CHANNEL-/,'');select.append(option);}
  select.value=linkedRow(lease)?.route||assignedRoute(leaseAddress(lease));
  select.disabled=!leaseAddress(lease)||effectiveDisabled||action?.action==='unpin'||!seed.state.live;
  select.addEventListener('change',()=>configureLease(lease,select.value));tr.insertCell().append(select);
  const actions=tr.insertCell(),buttons=document.createElement('div');buttons.className='dhcp-actions';actions.append(buttons);
  if(active){const pin=button(lease.dynamic?(pending?'Отменить закрепление':'Закрепить'):(action?.action==='unpin'?'Отменить отвязку':'Отвязать'),()=>togglePin(lease));pin.disabled=!seed.state.live;buttons.append(pin);}
  const toggle=button(effectiveDisabled?'Отключено':'Включено',()=>toggleLease(lease));
  toggle.dataset.toggleOn=effectiveDisabled?'0':'1';toggle.dataset.togglePending=action?'1':'0';window.paintToggle?.(toggle,!effectiveDisabled,!!action);
  toggle.disabled=!seed.state.live||action?.action==='unpin';buttons.append(toggle);
 }
}
let dhcpLoading=false;
async function refreshDhcp(){
 if(dhcpLoading||document.visibilityState==='hidden')return;
 dhcpLoading=true;
 try{
  const response=await fetch('/api/clients/dhcp',{cache:'no-store'}),data=await response.json();
  if(!response.ok||!data.ok)throw Error(data.message||'RouterOS не ответил');
  const before=dhcpLeases.map(lease=>leaseAddress(lease)).join('|');
  dhcpLeases=data.leases||[];updateDhcpServers();
  if(before!==dhcpLeases.map(lease=>leaseAddress(lease)).join('|'))draw();else renderDhcp();
 }catch(e){dhcpStatus.textContent='Не удалось прочитать DHCP-аренды: '+e.message;}
 finally{dhcpLoading=false;}
}
draw();
refreshDhcp();
document.getElementById('dhcp-refresh')?.addEventListener('click',refreshDhcp);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')refreshDhcp();});
setInterval(refreshDhcp,30000);
})();
