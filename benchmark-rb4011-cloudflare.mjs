import {spawn} from 'node:child_process';
import fs from 'node:fs';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const ssh=action=>run(process.execPath,['router-ssh.mjs','4011',`/container shell universal-vpn-core cmd="python3 /etc/mihomo/rb4011-cloudflare-test.py ${action}"`]);
let results=[];
try{
 const setup=await ssh('setup');if(setup.code||!setup.out.includes('routed'))throw Error(JSON.stringify(setup));
 for(const count of [1,4]){
  const start=performance.now();
  const downloads=Promise.all(Array.from({length:count},(_,i)=>run('curl.exe',['--ssl-revoke-best-effort','--proxy','http://10.0.0.3:11080','--max-time','100','--silent','--show-error','--output','NUL','--write-out','%{json}',`https://speed.cloudflare.com/__down?bytes=33554432&test=${Date.now()}-${i}`])));
  await new Promise(resolve=>setTimeout(resolve,2000));
  const path=await ssh('status');
  const streams=await downloads;const seconds=(performance.now()-start)/1000;
  const parsed=streams.map(s=>{const c=JSON.parse(s.out);return {exit:s.code,http:c.http_code,bytes:c.size_download,seconds:c.time_total,error:s.err};});
  const bytes=parsed.reduce((sum,s)=>sum+s.bytes,0);
  const result={connections:count,seconds,mbps:bytes*8/seconds/1e6,bytes,streams:parsed,path};results.push(result);console.log(JSON.stringify(result));
  if(parsed.some(s=>s.exit||s.http!==200||s.bytes!==33554432)||path.code||!path.out.includes('SV-inbound'))throw Error('Download or VPN-path validation failed');
 }
}finally{
 const restore=await ssh('restore');console.log(JSON.stringify({restore}));
 fs.mkdirSync('build/rb4011-ac3-settings',{recursive:true});fs.writeFileSync('build/rb4011-ac3-settings/cloudflare-results.json',JSON.stringify(results,null,2));
}

