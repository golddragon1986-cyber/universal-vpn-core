(()=>{
const storageKey='uvpnc-manual-route-draft-v1';
let working=JSON.parse(document.getElementById('route-draft-data').textContent);
const clone=v=>JSON.parse(JSON.stringify(v));
let original=clone(working.rows),baseline=working.baseline,draft=clone(original),busy=false,lastError='';
const applyForm=document.getElementById('route-apply-form'),apply=applyForm.querySelector('button[type=submit]'),cancel=document.getElementById('route-draft-cancel'),message=document.getElementById('route-draft-message'),addForm=document.querySelector('.route-add-form');
const clean=rows=>rows.map(r=>({net:r.net,label:r.label.trim()||'Маршрут',target:r.target,metric:Number(r.metric),enabled:!!r.enabled})).sort((a,b)=>a.net.localeCompare(b.net));
const signature=rows=>JSON.stringify(clean(rows));
try{const saved=working.pending?{original:working.rows,baseline:working.pending.baseline,draft:working.pending.rows}:null;if(saved&&signature(saved.draft)!==signature(working.rows)){original=saved.original;baseline=saved.baseline;draft=saved.draft;}}catch(e){}
const originalMap=()=>new Map(original.map(r=>[r.net,r]));
function update(){
 const changed=signature(draft)!==signature(original),stale=baseline!==working.baseline;
 const valid=draft.every(r=>Number.isInteger(Number(r.metric))&&Number(r.metric)>=1&&Number(r.metric)<=254);
 apply.disabled=busy||!changed||stale||!valid;cancel.disabled=busy||!changed;
 message.textContent=busy?'Применение набора маршрутов…':lastError||(stale&&changed?'Конфигурация изменилась. Отмените черновик и повторите изменения.':!valid?'Укажите целую метрику от 1 до 254.':changed?'Есть неприменённые изменения':'');
 if(changed){applyForm.dataset.queueDirty='1';try{sessionStorage.setItem(storageKey,JSON.stringify({baseline,original,draft}));}catch(e){}}
 else{delete applyForm.dataset.queueDirty;try{sessionStorage.removeItem(storageKey);}catch(e){}}
 const oldMap=new Map(original.map(r=>[r.net,r])),newMap=new Map(draft.map(r=>[r.net,r]));
 for(const tr of document.querySelectorAll('tr[data-manual-net]')){
  const old=oldMap.get(tr.dataset.manualNet),row=newMap.get(tr.dataset.manualNet),isDirty=!old||!row||signature([row])!==signature([old]);
  tr.classList.toggle('route-pending',isDirty);tr.inert=busy;
  const toggle=tr.cells[4].querySelector('button');if(toggle&&row){toggle.dataset.togglePending=isDirty?'1':'0';window.paintToggle?.(toggle,row.enabled,isDirty);}else tr.cells[4].textContent=!row?'Будет удалён':(row.enabled?'Активен':'Отключён');
 }
 const found=document.querySelector('#route-results>p');
 if(found){if(!found.dataset.routeBaseCount)found.dataset.routeBaseCount=String(Number(found.textContent.match(/\d+/)?.[0]||0));const eligible=r=>visible(r)&&(!working.view.status||working.view.status==='all'||(working.view.status==='enabled')===!!r.enabled);found.textContent='Найдено: '+(Number(found.dataset.routeBaseCount)-working.rows.filter(eligible).length+draft.filter(eligible).length);}
 addForm.inert=busy;
}
function changed(){lastError='';update();window.configurationDraft?.set('routes',new URLSearchParams({action:'route_apply',route_token:applyForm.elements.route_token.value,baseline,draft:JSON.stringify(clean(draft))}));}
function button(text,fn){const b=document.createElement('button');b.type='button';b.textContent=text;b.addEventListener('click',fn);return b;}
function ipNumber(value){return value.split('.').reduce((n,p)=>n*256+Number(p),0);}
function canonical(value){const [address,prefix='32']=value.trim().split('/');const parts=address.split('.');const bits=Number(prefix);if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255)||!Number.isInteger(bits)||bits<1||bits>32)throw Error('Укажите публичную IPv4-сеть/маску');const n=ipNumber(address);const step=2**(32-bits);if(n%step!==0)throw Error('Адрес сети не соответствует маске');return parts.map(Number).join('.')+'/'+bits;}
function visible(row){const view=working.view;if(view.source&&view.source!=='all'&&view.source!=='local')return false;const q=(view.q||'').trim().toLowerCase();if(!q)return true;try{const query=canonical(q);const [a,p]=row.net.split('/'),[b,qp]=query.split('/');const as=ipNumber(a),bs=ipNumber(b);return as<bs+2**(32-Number(qp))&&bs<as+2**(32-Number(p));}catch(e){return row.net.includes(q)||row.label.toLowerCase().includes(q);}}
function makeRow(net,row,old){
 const removed=!row,value=row||old,dirty=!old||removed||signature([value])!==signature([old]);
 const tr=document.createElement('tr');tr.dataset.manualNet=net;tr.classList.toggle('route-pending',dirty);tr.classList.toggle('route-removed',removed);
 tr.insertCell().textContent=net;
 const label=document.createElement('input');label.dataset.routeField='label';label.value=value.label;label.maxLength=80;label.disabled=removed;label.setAttribute('aria-label','Название маршрута '+net);label.addEventListener('input',()=>{row.label=label.value;tr.classList.add('route-pending');changed();});tr.insertCell().append(label);
 const select=document.createElement('select');select.setAttribute('aria-label','Маршрут сети '+net);if(old)select.dataset.activeRoute=old.target;select.disabled=removed;
 for(const route of [...new Set([...working.routes,value.target])]){const option=document.createElement('option');option.value=route;option.textContent=route==='SELECTOR'?'Основной маршрут':route==='DIRECT'?'Напрямую (DIRECT)':route==='LOADBALANCE'?'Балансировка (LOADBALANCE)':route.replace(/^CHANNEL-/,'');if(!working.routes.includes(route))option.textContent+=' (недоступен)';option.selected=route===value.target;select.append(option);}select.addEventListener('change',()=>{row.target=select.value;draw();changed();});tr.insertCell().append(select);
 const metric=document.createElement('input');metric.dataset.routeField='metric';metric.type='number';metric.min='1';metric.max='254';metric.value=value.metric;metric.disabled=removed;metric.setAttribute('aria-label','Метрика сети '+net);metric.addEventListener('input',()=>{row.metric=metric.value;tr.classList.add('route-pending');changed();});metric.addEventListener('change',()=>draw());tr.insertCell().append(metric);
 const state=tr.insertCell();if(removed)state.textContent='Будет удалён';else{const toggle=button(value.enabled?'Включено':'Отключено',()=>{row.enabled=!row.enabled;draw();changed();});toggle.dataset.toggleOn=value.enabled?'1':'0';toggle.dataset.togglePending=dirty?'1':'0';window.paintToggle?.(toggle,value.enabled,dirty);state.append(toggle);}
 const actions=document.createElement('div');actions.className='route-row-actions';
 if(removed)actions.append(button('Вернуть',()=>{draft.push(clone(old));draw();changed();}));
 else{const remove=button('Удалить',()=>{draft=draft.filter(r=>r.net!==net);draw();changed();});remove.className='danger';actions.append(remove);}
 tr.insertCell().append(actions);tr.inert=busy;return tr;
}
function draw(){
 const body=document.querySelector('.routes-table tbody');if(!body)return;
 const shown=new Set([...body.querySelectorAll('tr[data-manual-net]')].map(r=>r.dataset.manualNet));
 const old=originalMap(),current=new Map(draft.map(r=>[r.net,r]));
 for(const row of draft)if(!old.has(row.net)&&visible(row))shown.add(row.net);
 for(const row of body.querySelectorAll('tr[data-manual-net]'))row.remove();
 for(const net of shown){if(current.has(net)||old.has(net))body.append(makeRow(net,current.get(net),old.get(net)));}
 for(const row of [...body.rows])if(row.cells.length===1&&row.cells[0].colSpan===6&&body.rows.length>1)row.remove();
 if(!body.rows.length){const row=body.insertRow();const cell=row.insertCell();cell.colSpan=6;cell.textContent='Нет маршрутов по заданному запросу';}
 const rows=[...body.rows];rows.sort((a,b)=>{
  const an=a.cells[0]?.textContent,bn=b.cells[0]?.textContent;
  if(!an?.includes('/')||!bn?.includes('/'))return 0;
  const metric=row=>row.querySelector('input[data-route-field=metric]')?.value??row.cells[3]?.textContent;
  const am=Number(metric(a))||100,bm=Number(metric(b))||100;
  return am-bm||Number(bn.split('/')[1])-Number(an.split('/')[1])||ipNumber(an.split('/')[0])-ipNumber(bn.split('/')[0]);
 });for(const row of rows)body.append(row);update();
}
addForm.addEventListener('submit',event=>{
 event.preventDefault();if(busy)return;
 try{const data=new FormData(addForm),net=canonical(String(data.get('destination')));if(draft.some(r=>r.net===net))throw Error('Такая ручная запись уже существует');const old=originalMap().get(net);const row={net,label:String(data.get('label')).trim()||'Маршрут',target:String(data.get('target')),metric:Number(data.get('metric')),enabled:true,override:old?.override||false};draft.push(row);addForm.elements.destination.value='';addForm.elements.label.value='';delete addForm.dataset.queueDirty;draw();changed();}catch(error){lastError=error.message;update();}
});
applyForm.addEventListener('submit',event=>{if(apply.disabled){event.preventDefault();return;}applyForm.elements.baseline.value=baseline;applyForm.elements.draft.value=JSON.stringify(clean(draft));window.routeDraftBusy(true);});
cancel.addEventListener('click',()=>{baseline=working.baseline;original=clone(working.rows);draft=clone(original);lastError='';addForm.reset();delete addForm.dataset.queueDirty;draw();});
window.routeDraftBusy=value=>{busy=value;update();};
window.routeDraftError=value=>{lastError=value;update();};
window.routeDraftRefresh=(seed,committed)=>{working=seed;if(committed){baseline=seed.baseline;original=clone(seed.rows);draft=clone(original);lastError='';}draw();};
draw();
})();
