import {spawn} from 'node:child_process';
import fs from 'node:fs';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const command=cmd=>run(process.execPath,['router-ssh.mjs','hap',cmd]);
const helper=action=>command(`/container shell universal-vpn-core cmd="python3 /etc/mihomo/rb4011-cloudflare-test.py ${action}"`);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const results=[];let reason='maximum 128 connections';
try{
 const setup=await helper('setup');if(!setup.out.includes('routed'))throw Error(JSON.stringify(setup));
 for(const count of [1,4,8,16,32,64,128]){
  console.log(JSON.stringify({starting:count}));
  let done=false;const start=performance.now();
  const transfers=Promise.all(Array.from({length:count},(_,i)=>run('curl.exe',['--ssl-revoke-best-effort','--proxy','http://192.168.99.1:11080','--connect-timeout','10','--max-time','25','--silent','--output','NUL','--write-out','%{json}',`https://speed.cloudflare.com/__down?bytes=33554432&test=${Date.now()}-${i}`]))).then(rows=>{done=true;return rows;});
  const samples=[];await sleep(2500);
  const path=await helper('status');
  while(!done){
   const row=await command(':put ("total=" . [/system resource get cpu-load]); /system resource cpu print');
   const total=Number(row.out.match(/total=(\d+)/)?.[1]);
   const cores=[...row.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]));
   if(Number.isFinite(total))samples.push({total,cores});
   if(!done)await sleep(2500);
  }
  const rows=await transfers;const seconds=(performance.now()-start)/1000;
  const streams=rows.map(row=>{try{const c=JSON.parse(row.out);return {exit:row.code,http:c.http_code,bytes:c.size_download};}catch{return {exit:row.code,http:0,bytes:0};}});
  const bytes=streams.reduce((n,s)=>n+s.bytes,0);
  const result={connections:count,seconds,mbps:bytes*8/seconds/1e6,bytes,successful_streams:streams.filter(s=>s.http===200&&s.bytes>0).length,total_cpu_peak:Math.max(...samples.map(s=>s.total)),total_cpu_average:samples.reduce((n,s)=>n+s.total,0)/samples.length,core_peak:Math.max(...samples.flatMap(s=>s.cores)),samples,path_verified:path.code===0&&path.out.includes('SV-inbound'),streams};
  results.push(result);fs.writeFileSync('build/hap-ac3-clean/cloudflare-ramp.json',JSON.stringify({results,reason:'running'},null,2));console.log(JSON.stringify(result));
  if(!result.path_verified||result.successful_streams===0)throw Error('VPN-path or data transfer failed');
  if(result.total_cpu_peak>90){reason='total CPU exceeded 90%';break;}
 }
}finally{
 const restore=await helper('restore');console.log(JSON.stringify({reason,restore}));
 fs.writeFileSync('build/hap-ac3-clean/cloudflare-ramp.json',JSON.stringify({results,reason,restore},null,2));
}

