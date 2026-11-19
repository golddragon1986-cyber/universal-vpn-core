(()=>{
window.paintToggle=(button,on,pending=false)=>{
 const content='<span>'+(on?'Включено':'Отключено')+'</span>'+(pending?'<small>ожидает применения</small>':'');
 if(button.innerHTML!==content)button.innerHTML=content;
 button.classList.add('state-toggle');button.classList.toggle('state-on',on);button.classList.toggle('state-off',!on);
 button.setAttribute('aria-pressed',String(on));
};
function refresh(){
 for(const button of document.querySelectorAll("button[data-toggle-on]"))window.paintToggle(button,button.dataset.toggleOn==='1',button.dataset.togglePending==='1');
 for(const select of document.querySelectorAll('select[aria-label^="Маршрут"],select[aria-label^="Группа правила"],#main_proxy')){
  let active=select.dataset.activeRoute;
  if(select.id==='main_proxy')active=window.activeRouteStates?.mainRoute;
  else if(select.getAttribute('aria-label')==='Маршрут DNS'){
   const id=select.closest('tr')?.dataset.dnsId;active=window.activeRouteStates?.dnsRoutes?.[id];
  }else if(select.getAttribute('aria-label')?.startsWith('Группа правила')){
   const id=select.closest('form')?.querySelector('[name="service_id"]')?.value;active=window.activeRouteStates?.serviceRoutes?.[id];
  }else if(select.getAttribute('aria-label')?.startsWith('Маршрут правила')){
   const id=select.closest('form')?.querySelector('[name="service_id"]')?.value;active=window.activeRouteStates?.serviceRoutes?.[id];
  }
  for(const option of select.options){
   option.classList.remove('current-route');
   const isActive=active!==undefined&&active!==null&&option.value===String(active);
   option.style.color=isActive?'#6fdf99':'#e8edf7';option.style.fontWeight=isActive?'700':'400';
  }
  const isActive=active!==undefined&&active!==null&&select.value===String(active);
  select.classList.toggle('chosen-route',isActive);
 }
 for(const form of document.querySelectorAll('form:has(input[value="service_toggle"])')){
  const button=form.querySelector('button'),id=form.querySelector('[name=service_id]')?.value;
  if(button){const on=button.querySelector('span')?.textContent==='Включено'||(!button.querySelector('span')&&button.textContent.trim()==='Включено');window.paintToggle(button,on,on!==window.activeToggleStates?.services[id]);}
 }
 const routing=document.querySelector('form.routing-controls'),toggle=routing?.querySelector('button[name=services_enabled]');
 if(toggle){const on=routing.querySelector('input[name=services_enabled]').value==='1';window.paintToggle(toggle,on,on!==window.activeToggleStates.routing);}
}
const style=document.createElement('style');style.textContent=`
body .unified-main .state-toggle{display:inline-flex;flex-direction:column;justify-content:center;min-height:40px;line-height:18px;transition:background-color .18s,border-color .18s,box-shadow .18s,transform .1s}
body .unified-main .state-toggle:active{transform:scale(.96)}
body .unified-main .state-toggle.state-on{background:#16803c!important;border-color:#16803c!important;color:#fff!important}
body .unified-main .state-toggle.state-off{background:#a52e36!important;border-color:#a52e36!important;color:#fff!important}
body .unified-main .state-toggle small{font-size:10px;line-height:13px;font-weight:400;white-space:nowrap;color:inherit}
body .unified-main select.chosen-route{color:#6fdf99!important;font-weight:700!important}
body .unified-main select:not(.chosen-route)[aria-label^="Маршрут"],body .unified-main select:not(.chosen-route)[aria-label^="Группа правила"],body .unified-main #main_proxy{color:var(--ui-text);font-weight:400}
`;document.head.append(style);
let scheduled=false;const schedule=()=>{if(scheduled)return;scheduled=true;queueMicrotask(()=>{scheduled=false;refresh();});};
new MutationObserver(schedule).observe(document.querySelector('main')||document.body,{childList:true,subtree:true});
document.addEventListener('change',schedule);document.addEventListener('DOMContentLoaded',refresh);refresh();
})();
