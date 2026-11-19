"""DNS table editing; changes are committed together by dns_save."""
import html
import json


def render_settings(values, choices):
    seed = json.dumps({'rows': values['servers'], 'routes': list(dict.fromkeys(choices + [r['route'] for r in values['servers']]))}, ensure_ascii=False).replace('<', '\\u003c')
    checked = ' checked' if values['fake_ip'] else ''
    return '''<div class="panel dns-table-panel"><form method="post" action="/action" id="dns-table-form">
<input type="hidden" name="action" value="dns_save"><input type="hidden" name="servers" value="">
<div class="dns-table-toolbar"><h2>DNS-серверы</h2><label class="dns-fake-toggle"><input type="checkbox" name="fake_ip" value="1"''' + checked + '''> FakeIP</label><button type="submit" hidden disabled>Применить</button><span id="dns-dirty" role="status"></span></div>
<p class="hint">Включённые DNS проверяются сверху вниз. Следующий используется при ошибке или таймауте. NXDOMAIN считается ответом. Изменения применяются общей кнопкой.</p>
<div class="dns-table-scroll"><table class="dns-servers-table"><thead><tr><th>Порядок</th><th>Название</th><th>Адрес</th><th>Маршрут</th><th>Состояние</th><th>Действия</th></tr></thead><tbody id="dns-table-body"></tbody></table></div>
<div class="dns-actions"><button type="button" id="dns-add-row">Добавить DNS</button><button type="submit" form="dns-cache-form" formnovalidate>Очистить DNS Cache</button></div>
</form><form method="post" class="runtime-action" id="dns-cache-form"><input type="hidden" name="action" value="dns_flush"></form><script type="application/json" id="dns-table-data">''' + seed + '''</script></div>
<style>
body .unified-main .dns-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
body .unified-main .dns-actions button{margin:0;height:40px;white-space:nowrap}
body .unified-main .dns-table-toolbar{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:12px}
body .unified-main .dns-table-toolbar h2{margin:0;margin-right:auto}
body .unified-main .dns-fake-toggle{display:flex;align-items:center;gap:8px;margin:0;white-space:nowrap}
body .unified-main .dns-fake-toggle input{width:18px;height:18px;margin:0}
body .unified-main .dns-table-scroll{overflow:auto;margin:12px 0}
body .unified-main .dns-servers-table{width:100%;table-layout:auto}
body .unified-main .dns-servers-table td,body .unified-main .dns-servers-table th{padding:8px;vertical-align:middle}
body .unified-main .dns-servers-table input,body .unified-main .dns-servers-table select{box-sizing:border-box;width:100%;height:40px;margin:0}
body .unified-main .dns-servers-table input[data-key=name]{min-width:110px}
body .unified-main .dns-servers-table input[data-key=address]{min-width:200px}
body .unified-main .dns-servers-table select{min-width:150px;max-width:200px}
body .unified-main .dns-order{display:flex;align-items:center;gap:4px;white-space:nowrap}
body .unified-main .dns-order button{padding:0;width:28px;height:36px;min-width:28px}
body .unified-main .dns-servers-table button{white-space:nowrap;margin:0}
body .unified-main .dns-state.on{background:#128038;color:white;border-color:#128038}
body .unified-main #dns-dirty{font-size:12px;color:var(--ui-muted)}
</style><script>(()=>{
const form=document.getElementById('dns-table-form'),body=document.getElementById('dns-table-body'),data=JSON.parse(document.getElementById('dns-table-data').textContent);let rows=data.rows;
const signature=()=>JSON.stringify({fake_ip:form.elements.fake_ip.checked,servers:rows.map(r=>({name:r.name.trim(),address:r.address.trim(),route:r.route,enabled:r.enabled}))});const baseline=signature();const apply=form.querySelector('button[type=submit]');
const dirty=()=>{const changed=signature()!==baseline;document.getElementById('dns-dirty').textContent=changed?'Есть неприменённые изменения':'';apply.disabled=!changed;};
let draftReady=false;const syncDraft=()=>{if(!draftReady)return;const payload=new URLSearchParams({action:'dns_save',servers:JSON.stringify(rows)});if(form.elements.fake_ip.checked)payload.set('fake_ip','1');window.configurationDraft?.set('dns',payload);};
form.addEventListener('input',()=>setTimeout(syncDraft,0));form.addEventListener('change',()=>setTimeout(syncDraft,0));form.addEventListener('click',event=>{if(event.target.closest('button[type=button]'))setTimeout(syncDraft,0);});
function button(text,click){const b=document.createElement('button');b.type='button';b.textContent=text;b.addEventListener('click',click);return b;}
function draw(){body.replaceChildren();rows.forEach((row,index)=>{const tr=body.insertRow();tr.dataset.dnsId=row.id;const order=document.createElement('div');order.className='dns-order';const num=document.createElement('span');num.textContent=index+1;order.append(num);
for(const [label,offset] of [['↑',-1],['↓',1]]){const b=button(label,()=>{const j=index+offset;[rows[index],rows[j]]=[rows[j],rows[index]];draw();dirty();});b.disabled=index+offset<0||index+offset>=rows.length;b.setAttribute('aria-label',offset<0?'DNS выше':'DNS ниже');order.append(b);}tr.insertCell().append(order);
for(const key of ['name','address']){const input=document.createElement('input');input.dataset.key=key;input.value=row[key];input.required=true;input.maxLength=key==='name'?100:2048;input.setAttribute('aria-label',key==='name'?'Название DNS':'Адрес DNS');input.addEventListener('input',()=>{row[key]=input.value;dirty();});tr.insertCell().append(input);}
const select=document.createElement('select');select.setAttribute('aria-label','Маршрут DNS');for(const route of data.routes){const option=document.createElement('option');option.value=route;option.textContent=route==='SELECTOR'?'Основной маршрут':route==='DIRECT'?'Напрямую (DIRECT)':route==='LOADBALANCE'?'Балансировка':route.replace(/^CHANNEL-/,'');option.selected=route===row.route;select.append(option);}select.addEventListener('change',()=>{row.route=select.value;dirty();});tr.insertCell().append(select);
const state=button(row.enabled?'Включено':'Отключено',()=>{row.enabled=!row.enabled;draw();dirty();});state.className='dns-state '+(row.enabled?'on':'off');state.dataset.toggleOn=row.enabled?'1':'0';state.dataset.togglePending=(window.activeToggleStates?.dns[row.id]!==row.enabled)?'1':'0';window.paintToggle?.(state,row.enabled,state.dataset.togglePending==='1');state.setAttribute('aria-pressed',String(row.enabled));tr.insertCell().append(state);
const remove=button('Удалить',()=>{rows.splice(index,1);draw();dirty();});remove.className='danger';tr.insertCell().append(remove);
});}
document.getElementById('dns-add-row').addEventListener('click',()=>{rows.push({id:'dns-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8),name:'Новый DNS',address:'',route:'SELECTOR',enabled:true});draw();dirty();body.lastElementChild.querySelector('input').focus();});
form.elements.fake_ip.addEventListener('change',dirty);form.addEventListener('submit',event=>{if(signature()===baseline){event.preventDefault();return;}form.elements.servers.value=JSON.stringify(rows);});draw();dirty();draftReady=true;})();</script>'''
