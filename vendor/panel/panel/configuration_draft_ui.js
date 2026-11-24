(()=>{
const initial=document.getElementById('configuration-state');
let state=initial?JSON.parse(initial.textContent):{pending:false,revision:0};
let chain=Promise.resolve(),timer=null,busy=false,applying=false,error='',orderBefore=null;
const edits=new Map();
const isDraft=action=>['routing_save','dns_save','domain_dns','filter_save','clear_auto_domains','add','enable','disable','delete','route_apply','client_apply'].includes(action)||(
 action?.startsWith('service_')&&!['service_refresh_geodata','service_update_source'].includes(action));
function controls(){
 const apply=document.getElementById('configuration-apply'),cancel=document.getElementById('configuration-cancel'),message=document.getElementById('configuration-message');
 const pending=state.pending||edits.size>0;
 if(apply)apply.disabled=applying||busy||!pending;
 if(cancel)cancel.disabled=applying||busy||!pending;
 if(message)message.textContent=error||(applying?'Применение конфигурации…':busy?'Сохранение черновика…':pending?'Есть неприменённые изменения':'');
}
async function post(path,data){
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:data});
 const result=await response.json();if(!response.ok||!result.ok)throw Error(result.message||'Не удалось сохранить изменения');return result;
}
function stage(data){
 const task=async()=>{
  busy=true;controls();
  try{
   if(data.get('action')==='service_reorder'&&orderBefore)data.set('order_before',orderBefore);
   state=await post('/api/configuration/stage',data);
   if(data.get('action')==='service_reorder')orderBefore=data.get('order');
   error='';
  }catch(e){error=e.message;throw e;}
  finally{busy=false;controls();}
 };
 const next=chain.then(task,task);chain=next.catch(()=>{});return next;
}
async function flush(){
 clearTimeout(timer);timer=null;
 const pending=[...edits];edits.clear();
 for(const [key,payload] of pending){
  try{await stage(payload);}catch(e){if(!edits.has(key))edits.set(key,payload);controls();throw e;}
 }
 await chain;
 if(error)throw Error(error);
}
window.configurationDraft={
 set(key,payload){edits.set(key,new URLSearchParams(payload));error='';controls();clearTimeout(timer);timer=setTimeout(()=>flush().catch(()=>{}),300);},
 flush,
 applyFailed(message){applying=false;error=message||'';controls();}
};
document.addEventListener('submit',async event=>{
 const form=event.target;if(event.defaultPrevented||form.method?.toLowerCase()!=='post')return;
 const data=new URLSearchParams(new FormData(form,event.submitter));
 if(!isDraft(data.get('action')))return;
 event.preventDefault();event.stopImmediatePropagation();
 const geodataImport=data.get('action')==='service_geodata_import';
 const button=geodataImport?event.submitter:null;
 let status;
 if(geodataImport){
  if(form.dataset.saving==='1')return;
  form.dataset.saving='1';
  if(button)button.disabled=true;
  status=form.querySelector('[data-import-status]');
  if(!status){
   status=document.createElement('p');
   status.dataset.importStatus='';
   status.setAttribute('role','status');
   form.append(status);
  }
  status.textContent='Сохранение черновика…';
 }
 error='';
 try{await flush();await stage(data);location.reload();}
 catch(e){
  if(status)status.textContent=window.uiText?.(e.message)||e.message;
  controls();
 }finally{
  if(geodataImport)delete form.dataset.saving;
  if(button)button.disabled=false;
 }
});
document.addEventListener('click',async event=>{
 const link=event.target.closest('a[href]');
 if(!link||event.defaultPrevented||event.ctrlKey||event.metaKey||event.shiftKey||event.button!==0)return;
 const url=new URL(link.href,location.href);
 if(url.origin!==location.origin||url.pathname!=='/'||(!edits.size&&!busy))return;
 event.preventDefault();
 try{await flush();location.href=link.href;}catch(e){controls();}
});
document.addEventListener('DOMContentLoaded',()=>{
 const style=document.createElement('style');style.textContent='[hidden]{display:none!important} #dns-dirty{display:none} body .routing-panel .routing-grid{grid-template-columns:220px 130px minmax(0,1fr);width:100%} body .routing-panel .routing-heading{text-align:left} body .routing-panel form.routing-controls{display:flex;grid-column:1/-1;align-items:center;gap:20px;flex-wrap:wrap} #configuration-message:not(:empty){flex-basis:100%} #configuration-cancel{background:var(--ui-button);border-color:var(--ui-border);color:var(--ui-text)} #configuration-message{font-size:12px;color:var(--ui-muted)} @media(max-width:600px){body .routing-panel .routing-grid{grid-template-columns:1fr}}';document.head.append(style);
 const routing=document.querySelector('form.routing-controls');
 if(routing){
  routing.elements.main_proxy.addEventListener('change',()=>window.configurationDraft.set('routing',new URLSearchParams(new FormData(routing))));
  const toggle=routing.querySelector('button[name=services_enabled]');
  toggle?.addEventListener('click',event=>{
   event.preventDefault();const on=toggle.value==='1';routing.querySelector('input[name=services_enabled]').value=on?'1':'0';
   toggle.value=on?'0':'1';toggle.textContent=on?'Включено':'Отключено';toggle.classList.toggle('service-on',on);toggle.classList.toggle('service-off',!on);
   window.configurationDraft.set('routing',new URLSearchParams(new FormData(routing)));
  });
 }
 document.getElementById('configuration-apply')?.addEventListener('click',async()=>{
  try{
   await flush();if(!state.pending||applying)return;
   applying=true;controls();
   const form=document.createElement('form');form.method='post';form.action='/action';
   for(const [name,value] of Object.entries({action:'configuration_apply',revision:String(state.revision)})){
    const input=document.createElement('input');input.type='hidden';input.name=name;input.value=value;form.append(input);
   }
   document.body.append(form);form.requestSubmit();
  }catch(e){controls();}
 });
 document.getElementById('configuration-cancel')?.addEventListener('click',async()=>{
  clearTimeout(timer);edits.clear();await chain;
  try{await post('/api/configuration/discard',new URLSearchParams({discard:'1'}));sessionStorage.removeItem('uvpnc-manual-route-draft-v1');location.reload();}catch(e){error=e.message;controls();}
 });
 controls();
});
})();
