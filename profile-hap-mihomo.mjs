import {spawn} from 'node:child_process';
import fs from 'node:fs';
import {analyze} from './analyze-pprof.mjs';
const folder='build/hap-ac3-clean/cpu-profile-20261107';fs.mkdirSync(folder,{recursive:true});
const host='speedtest.selectel.ru',api='http://192.168.99.1:19090';
function run(cmd,args,timeout){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);const timer=timeout?setTimeout(()=>p.kill(),timeout):null;p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>{if(timer)clearTimeout(timer);resolve({code,out,err});});});}
const command=cmd=>run(process.execPath,['router-ssh.mjs','hap',cmd]);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const results=[];
try{
 let ready=false;
 for(let attempt=0;attempt<40;attempt++){
  try{const p=await fetch(api+'/debug/pprof/',{signal:AbortSignal.timeout(2000)});const provider=await fetch(api+'/providers/proxies/USER-MANAGED',{signal:AbortSignal.timeout(2000)});if(p.ok&&provider.ok){ready=true;break;}}catch{}
  await sleep(500);
 }
 if(!ready)throw Error('Profiling API not ready');
 for(const count of [1,16]){
  console.log(JSON.stringify({starting_connections:count}));let finished=false;const start=performance.now();
  const transfers=Promise.all(Array.from({length:count},()=>run('curl.exe',['--proxy','http://192.168.99.1:11080','--connect-timeout','10','--max-time','20','--silent','--show-error','--write-out','%{json}\n',...Array.from({length:10},()=>['--output','NUL',`http://${host}/100MB`]).flat()],25000))).then(r=>{finished=true;return r;});
  let active=[];
  for(let attempt=0;attempt<30&&!finished;attempt++){
   await sleep(500);let state;try{const response=await fetch(api+'/connections',{signal:AbortSignal.timeout(3000)});state=await response.json();}catch{continue;}
   active=(state.connections||[]).filter(c=>c.metadata?.host===host&&c.chains?.includes('SV-inbound'));
   if(active.length&&active.some(c=>c.download>0))break;
  }
  if(finished||!active.length){const diagnostics=await transfers;console.log(JSON.stringify({diagnostics}));throw Error('No sustained VPN download to profile');}
  const profilePath=`${folder}/cpu-${count}.pb.gz`;
  let profiled=false;
  const profile=run('curl.exe',['--fail','--silent','--show-error','--max-time','15','--output',profilePath,api+'/debug/pprof/profile?seconds=8']).then(r=>{profiled=true;return r;});
  const cpu=[];
  while(!profiled){
   const sample=await command(':put ("total=" . [/system resource get cpu-load]); /system resource cpu print');
   const total=Number(sample.out.match(/total=(\d+)/)?.[1]);if(Number.isFinite(total))cpu.push({total,cores:[...sample.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]))});
   if(!profiled)await sleep(1500);
  }
  const captured=await profile;if(captured.code)throw Error(JSON.stringify(captured));
  const streams=(await transfers).map(r=>{const completed=r.out.trim().split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line));return {exit:r.code,http:completed.at(-1)?.http_code,bytes:completed.reduce((s,c)=>s+c.size_download,0),completed_requests:completed.length};});
  const seconds=(performance.now()-start)/1000;
  const analysis=analyze(profilePath);const result={connections:count,seconds,mbps:streams.reduce((s,r)=>s+r.bytes,0)*8/seconds/1e6,streams,cpu,profile:analysis,verified_connections:active.length};
  results.push(result);fs.writeFileSync(folder+'/results.json',JSON.stringify(results,null,2));console.log(JSON.stringify({...result,profile:{...analysis,flat:analysis.flat.slice(0,12),cumulative:analysis.cumulative.slice(0,12)}}));
 }
}finally{
 const restore=await command('/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-mihomo-profile.py restore"');console.log(JSON.stringify({restore}));
}
