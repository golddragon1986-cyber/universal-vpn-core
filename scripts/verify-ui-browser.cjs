const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {chromium}=require('playwright');
const root=path.resolve(process.argv[2]||path.join(__dirname,'../build/ui-fixtures'));
const pages=fs.readdirSync(path.join(root,'en')).filter(n=>n.endsWith('.html'));
let syntax=0;
let activeBrowser;
for(const language of ['en','ru'])for(const name of pages){
 const html=fs.readFileSync(path.join(root,language,name),'utf8');
 for(const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)){
  if(match[1].includes('application/json'))continue;
  new vm.Script(match[2],{filename:language+'/'+name+'#'+syntax});syntax++;
 }
}
(async()=>{
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 activeBrowser=browser;
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const results=[],errors=[],semantics={};let writes=0;
 await context.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(request.method()!=='GET')writes++;
  if(request.isNavigationRequest()){
   const language=(await context.cookies()).some(c=>c.name==='ui_language'&&c.value==='ru')?'ru':'en';
   const name=url.searchParams.get('fixture')||'domains';
   return route.fulfill({contentType:'text/html; charset=utf-8',body:fs.readFileSync(path.join(root,language,name+'.html'),'utf8')});
  }
  let data={ok:true};
  if(url.pathname==='/api/configuration/status')data={dirty:false};
  if(url.pathname==='/api/actions/status')data={running:0,queued:0,jobs:[]};
  if(url.pathname==='/api/actions/history')data={jobs:[],has_more:false};
  if(url.pathname==='/api/logs')data={cursor:0,first:0,rows:[],level:'info',vpns:[],protocols:[],status:'Подключено'};
  if(url.pathname==='/api/components/versions')data={items:{},errors:{},architecture:'arm64',checked_at:'test'};
  if(url.pathname==='/api/vpn-traffic')data={nodes:{},total:{rx:0,tx:0}};
  return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
 });
 const page=await context.newPage();
 page.on('pageerror',error=>errors.push({url:page.url(),message:error.message}));
 for(const language of ['en','ru']){
  await context.addCookies([{name:'ui_language',value:language,url:'http://ui.test'}]);
  for(const filename of pages){
   const name=filename.replace('.html','');
   await page.goto('http://ui.test/?fixture='+name);
   await page.waitForTimeout(150);
   await page.evaluate(()=>{for(const details of document.querySelectorAll('details'))details.open=true;});
   await page.waitForTimeout(150);
   const result=await page.evaluate(()=>({lang:document.documentElement.lang,button:document.getElementById('ui-language-toggle')?.innerText,
    restart:document.querySelector('button[form="core-restart-form"]')?.textContent,
    visible:document.body.innerText,
    attributes:[...document.querySelectorAll('[title],[aria-label],[placeholder]')].flatMap(el=>['title','aria-label','placeholder'].map(a=>el.getAttribute(a)).filter(Boolean)),
    semantics:[...document.querySelectorAll('input,select,option,textarea')].map(el=>[el.tagName,el.name,el.type,el.value]),
    seeds:[...document.querySelectorAll('script[type="application/json"]')].map(el=>[el.id,el.textContent])}));
   if(result.lang!==language)throw Error('Wrong language '+name);
   const stableSeeds=result.seeds.map(([id,raw])=>[id,JSON.stringify(JSON.parse(raw),(key,value)=>key==='observed'?undefined:value)]);
   if(language==='en')semantics[name]=JSON.stringify([result.semantics,stableSeeds]);
   else if(semantics[name]!==JSON.stringify([result.semantics,stableSeeds]))throw Error('Form values or JSON seeds changed with language: '+name);
   const russian=language==='en'?[...result.visible.matchAll(/[А-Яа-яЁё][^\n]*/g)].map(m=>m[0]).filter(s=>!s.startsWith('Пользовательск')):[];
   const attrs=language==='en'?result.attributes.filter(s=>/[А-Яа-яЁё]/.test(s)&&!s.includes('Пользовательск')):[];
   results.push({language,name,russian,attrs});
  }
 }
 await context.addCookies([{name:'ui_language',value:'en',url:'http://ui.test'}]);
 await page.goto('http://ui.test/?fixture=domains');
 await page.getByRole('button',{name:'Switch to Russian'}).click();
 await page.waitForFunction(()=>document.documentElement.lang==='ru');
 await page.getByRole('button',{name:'Переключить на английский'}).click();
 await page.waitForFunction(()=>document.documentElement.lang==='en');
 await page.screenshot({path:path.resolve(__dirname,'../build/ui-en-preview.png'),fullPage:true});
 const failures=results.filter(r=>r.russian.length||r.attrs.length);
 const report={syntax,screens:results.length,errors,failures,languageRoundTrip:true,writes};
 fs.writeFileSync(path.resolve(__dirname,'../build/ui-browser-report.json'),JSON.stringify(report,null,2));
 console.log(JSON.stringify(report));
 await browser.close();
 if(errors.length||failures.length||writes)process.exitCode=1;
})().catch(async error=>{console.error(error);await activeBrowser?.close();process.exitCode=1;});
