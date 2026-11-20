import {spawn} from 'node:child_process';
import fs from 'node:fs';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const command=cmd=>run(process.execPath,['router-ssh.mjs','hap',cmd]);
const helper=action=>command(`/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-stockholm-retn-test.py ${action}"`);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const results=[];let before,after;
try{
 const setup=await helper('setup');if(!setup.out.includes('routed'))throw Error(JSON.stringify(setup));
 before=await helper('io');console.log(JSON.stringify({io_before:before}));
 for(const threads of [16]){
  console.log(JSON.stringify({starting:threads,server:'32926 RETN, Stockholm'}));let done=false;
  const test=run('build/tools/speedtest-go/speedtest-go.exe',['--proxy=http://192.168.99.1:11080','--server=32926',`--thread=${threads}`,'--ping-mode=http','--protocol=http','--json']).then(r=>{done=true;return r;});
  const samples=[];let path=null;await sleep(4000);
  while(!done){
   const sample=await command(':put ("total=" . [/system resource get cpu-load]); /system resource cpu print');
   const total=Number(sample.out.match(/total=(\d+)/)?.[1]);if(Number.isFinite(total))samples.push({total,cores:[...sample.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]))});
   if(!path){const probe=await helper('status');if(probe.out.includes('CHANNEL-SV-inbound')&&!probe.out.includes('Traceback'))path=probe;}
   if(!done)await sleep(3000);
  }
  const testResult=await test;const result={threads,test:testResult,samples,path};results.push(result);console.log(JSON.stringify(result));
  fs.writeFileSync('build/hap-ac3-clean/stockholm-retn-16-mihomo-speedtest.json',JSON.stringify({before,results},null,2));
  if(testResult.code||!path)throw Error('Speedtest failed or VPN path not verified');
 }
 after=await helper('io');console.log(JSON.stringify({io_after:after}));
}finally{
 const restore=await helper('restore');console.log(JSON.stringify({restore}));
 fs.writeFileSync('build/hap-ac3-clean/stockholm-retn-16-mihomo-speedtest.json',JSON.stringify({before,after,results,restore},null,2));
}



