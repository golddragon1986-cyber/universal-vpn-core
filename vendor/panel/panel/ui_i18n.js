(()=>{
 'use strict';
 const language=(()=>{const match=document.cookie.match(/(?:^|;\s*)ui_language=(ru|en)(?:;|$)/);return match?match[1]:'en';})();
 const escape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 const phrases=new RegExp('(?<![А-Яа-яЁё])(?:'+Object.keys(window.uiCatalog).sort((a,b)=>b.length-a.length).map(escape).join('|')+')(?![А-Яа-яЁё])','g');
 document.documentElement.lang=language;
 window.uiText=value=>{
  if(language==='ru'||typeof value!=='string')return value;
  const translate=part=>part.replace(/[А-Яа-яЁё][А-Яа-яЁё\s.,:;!?()«»—–…/+-]*/g,raw=>{
   const key=raw.trimEnd();return (window.uiCatalog[key]??key.replace(phrases,item=>window.uiCatalog[item]))+raw.slice(key.length);
  });
  const parts=value.split(/(«[^»]*»)/g);
  return parts.map((part,index)=>index%2?part:index+1<parts.length?translate(part+'«').slice(0,-1):translate(part)).join('');
 };
 document.addEventListener('click',event=>{
  const button=event.target.closest('#ui-language-toggle');if(!button)return;
  document.cookie='ui_language='+(language==='en'?'ru':'en')+'; Path=/; Max-Age=31536000; SameSite=Lax';
  window.location.reload();
 });
})();
