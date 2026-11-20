import fs from 'node:fs';
import {spawn} from 'node:child_process';
const folder='build/hap-ac3-clean/http-https-main-20261107';fs.mkdirSync(folder,{recursive:true});
const api='http://192.168.99.1:19090',host='server-32926.prod.hosts.ooklaserver.net',address='139.45.201.129';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function launch(cmd,args){let out='',err='';const child=spawn(cmd,args);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);return {child,done:new Promise(resolve=>child.on('close',code=>resolve({code,out,err})))};}
const command=cmd=>launch(process.execPath,['router-ssh.mjs','hap',cmd]).done;
const helper=action=>command(`/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-main-http-https-route.py ${action}"`);
const results=[];let transfer;
try{
 const setup=await helper('setup');if(!setup.out.includes('"setup": true'))throw Error(JSON.stringify(setup));
 for(const scheme of ['http','https']){
  const port=48000+Math.floor(Math.random()*10000);const url=`${scheme}://${host}:8080/speedtest/random4000x4000.jpg`;
  console.log(JSON.stringify({starting:scheme,port}));
  transfer=launch('curl.exe',['--proxy','http://192.168.99.1:11080','--proxytunnel','--connect-to',`${host}:8080:${address}:8080`,'--local-port',String(port),'--http1.1','--tlsv1.3','--tls-max','1.3','--ssl-no-revoke','--no-buffer','--connect-timeout','8','--max-time','25','--silent','--show-error','--write-out','%{json}\n',...Array.from({length:100},()=>['--output','NUL',url]).flat()]);
  let done=false;transfer.done.then(()=>done=true);const last=new Map(),samples=[],cpu=[];let ready=false,startTime,initial,maxActive=0;
  async function snapshot(){const rows=(await(await fetch(api+'/connections',{signal:AbortSignal.timeout(2500)})).json()).connections||[];const mine=rows.filter(c=>Number(c.metadata?.sourcePort)===port);for(const c of mine){if(!c.chains.includes('SV-inbound'))throw Error('Not VPN');last.set(c.id,c.download);}maxActive=Math.max(maxActive,mine.length);const total=[...last.values()].reduce((s,n)=>s+n,0);samples.push({time:Date.now(),bytes:total,ids:mine.map(c=>c.id),chains:mine.map(c=>c.chains)});return total;}
  for(let i=0;i<40&&!done;i++){const bytes=await snapshot();if(bytes>1048576){ready=true;initial=bytes;startTime=Date.now();break;}await sleep(250);}
  if(!ready)throw Error('No payload '+scheme);
  let sampling=true;
  const cpuTask=(async()=>{while(sampling){const row=await command(':put ("cpu=" . [/system resource get cpu-load]); /system resource cpu print');const total=Number(row.out.match(/cpu=(\d+)/)?.[1]);if(Number.isFinite(total))cpu.push({total,cores:[...row.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]))});if(sampling)await sleep(1200);}})();
  while(Date.now()-startTime<8000&&!done){await sleep(300);await snapshot();}
  sampling=false;await cpuTask;const final=await snapshot();const seconds=(Date.now()-startTime)/1000;
  transfer.child.kill();const raw=await transfer.done;transfer=null;
  const parsed=raw.out.split(/\r?\n/).filter(x=>x.startsWith('{')).flatMap(x=>{try{const c=JSON.parse(x);return [{http:c.http_code,bytes:c.size_download,connects:c.num_connects}];}catch{return [];}});
  const result={scheme,address,seconds,bytes:final-initial,mbps:(final-initial)*8/seconds/1e6,maxActive,cpu,samples,completed:parsed};results.push(result);fs.writeFileSync(folder+'/results.json',JSON.stringify(results,null,2));console.log(JSON.stringify({scheme,mbps:result.mbps,cpu,maxActive,completed:parsed}));
 }
}finally{
 if(transfer){transfer.child.kill();await transfer.done;}
 console.log(JSON.stringify({restore:await helper('restore')}));
}
