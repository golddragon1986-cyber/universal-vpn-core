import {spawn} from 'node:child_process';
import fs from 'node:fs';
import {analyze} from './analyze-pprof.mjs';
const directory='build/hap-ac3-clean/cpu-profile-20261107';fs.mkdirSync(directory,{recursive:true});
const api='http://192.168.99.1:19090';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const child=spawn(cmd,args);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.on('close',code=>resolve({code,out,err}));});}
const command=cmd=>run(process.execPath,['router-ssh.mjs','hap',cmd]);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const results=[];
try{
 let ready=false;
 for(let i=0;i<50;i++){try{if((await fetch(api+'/debug/pprof/',{signal:AbortSignal.timeout(2000)})).ok){ready=true;break;}}catch{}await sleep(500);}
 if(!ready)throw Error('pprof not ready');
 for(const threads of [1,16]){
  console.log(JSON.stringify({starting:threads}));let done=false;
  const test=run('build/tools/speedtest-go/speedtest-go.exe',['--proxy=http://192.168.99.1:11080','--server=32926',`--thread=${threads}`,'--ping-mode=http','--protocol=http','--no-upload','--json']).then(result=>{done=true;return result;});
  await sleep(4000);
  const path=directory+`/cpu-${threads}.pb.gz`;
  let captured=false;
  const capture=run('curl.exe',['--fail','--silent','--show-error','--max-time','30','--output',path,api+'/debug/pprof/profile?seconds=20']).then(result=>{captured=true;return result;});
  const samples=[];let verified=0;
  while(!captured||!done){
   const cpu=await command(':put ("total=" . [/system resource get cpu-load]); /system resource cpu print');
   const total=Number(cpu.out.match(/total=(\d+)/)?.[1]);if(Number.isFinite(total))samples.push({total,cores:[...cpu.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]))});
   try{const connections=(await(await fetch(api+'/connections',{signal:AbortSignal.timeout(2000)})).json()).connections||[];verified=Math.max(verified,connections.filter(c=>c.metadata?.host==='server-32926.prod.hosts.ooklaserver.net'&&c.chains?.includes('SV-inbound')&&c.download>0).length);}catch{}
   if(!captured||!done)await sleep(2000);
  }
  const [transfer,profile]=await Promise.all([test,capture]);
  if(profile.code||transfer.code)throw Error(JSON.stringify({profile,transfer}));
  const measurement=JSON.parse(transfer.out);if(!(measurement.servers[0].dl_speed>0)||!verified)throw Error('No valid VPN download');
  const report=analyze(path);const result={threads,measurement,samples,verified,profile:report};results.push(result);
  fs.writeFileSync(directory+'/speedtest-results.json',JSON.stringify(results,null,2));console.log(JSON.stringify({...result,profile:{...report,flat:report.flat.slice(0,15),cumulative:report.cumulative.slice(0,12)}}));
 }
}finally{
 const restore=await command('/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-mihomo-profile.py restore"');console.log(JSON.stringify({restore}));
}
