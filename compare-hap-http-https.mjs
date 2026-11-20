import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {analyze} from './analyze-pprof.mjs';
const isolated=process.env.HTTPHTTPS_ISOLATED==='1';
const localTunnel=process.env.HTTPHTTPS_LOCAL_TUNNEL==='1';
const forceTLS13=process.env.HTTPHTTPS_FORCE_TLS13==='1';
const tls13Pair=process.env.HTTPHTTPS_TLS13_PAIR==='1';
const folder='build/hap-ac3-clean/http-https-'+(isolated?'isolated-':'')+(forceTLS13?(tls13Pair?'tls13-pair-':'tls13-'):'')+'20261107';fs.mkdirSync(folder,{recursive:true});
const target=localTunnel?'127.0.0.1':'192.168.99.1';
const host='server-32926.prod.hosts.ooklaserver.net',address='139.45.201.129',api='http://'+target+':'+(isolated?'19094':'19090');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function launch(cmd,args){let out='',err='';const child=spawn(cmd,args);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);return {child,done:new Promise(resolve=>child.on('close',code=>resolve({code,out,err})))};}
const command=cmd=>launch(process.execPath,['router-ssh.mjs','hap',cmd]).done;
const helper=action=>command(`/container shell universal-vpn-core cmd="python3 /etc/mihomo/${isolated?'hap-isolated-http-https.py':'hap-http-https-profile.py'} ${action} ${address}"`);
async function connections(){for(let i=0;i<5;i++){try{const response=await fetch(api+'/connections',{signal:AbortSignal.timeout(2500)});return (await response.json()).connections||[];}catch(error){if(i===4)throw error;await sleep(400);}}}
const results=[];
let transfer=null;
try{
 const setup=await helper(isolated?'status':'setup');console.log(JSON.stringify({setup}));if(!setup.out.includes(isolated?'"alive": true':'"setup": true'))throw Error('Setup failed');
 let ready=false;
 for(let i=0;i<4;i++){try{if((await fetch(api+'/debug/pprof/',{signal:AbortSignal.timeout(2000)})).ok){ready=true;break;}}catch{}await sleep(500);}
 if(!ready&&!isolated){console.log(JSON.stringify({activate:await helper('activate')}));await sleep(3000);for(let i=0;i<40;i++){try{if((await fetch(api+'/debug/pprof/',{signal:AbortSignal.timeout(2000)})).ok){ready=true;break;}}catch{}await sleep(500);}}
 if(!ready)throw Error('pprof unavailable after API rebind');
 for(const [index,scheme] of (forceTLS13&&!tls13Pair?['https']:['http','https']).entries()){
  const port=48000+Math.floor(Math.random()*10000);console.log(JSON.stringify({starting:scheme,source_port:port,address}));
  const url=`${scheme}://${host}:8080/speedtest/random4000x4000.jpg`;
  const args=['--proxy','http://'+target+':'+(isolated?'19093':'11080'),'--proxytunnel','--connect-to',`${host}:8080:${address}:8080`,'--local-port',String(port),'--http1.1','--ssl-no-revoke','--no-buffer','--connect-timeout','8','--max-time','30','--silent','--show-error','--write-out','%{json}\n',...Array.from({length:100},()=>['--output','NUL',url]).flat()];
  if(forceTLS13&&scheme==='https')args.unshift('--tlsv1.3','--tls-max','1.3');
  transfer=launch('curl.exe',args);let finished=false;transfer.done.then(()=>finished=true);
  const timer=setTimeout(()=>transfer?.child.kill(),22000);
  const lastBytes=new Map(),records=[];let maxSimultaneous=0;
  function observe(rows){
   const mine=rows.filter(c=>isolated?Number(c.metadata?.destinationPort)===8080:Number(c.metadata?.sourcePort)===port);
   maxSimultaneous=Math.max(maxSimultaneous,mine.length);
   for(const c of mine){if(!c.chains?.includes('SV-inbound'))throw Error('Unexpected route');lastBytes.set(c.id,c.download);}
   const otherVideos=rows.filter(c=>/googlevideo\.com$/.test(c.metadata?.host||''));
   records.push({at:Date.now(),own:mine.map(c=>({id:c.id,bytes:c.download,chains:c.chains,network:c.metadata.network,host:c.metadata.host})),video_bytes:otherVideos.reduce((s,c)=>s+c.download,0)});
   return mine;
  }
  let active=[];
  for(let i=0;i<50&&!finished;i++){await sleep(250);active=observe(await connections());if(active.some(c=>c.download>1048576))break;}
  if(!active.some(c=>c.download>1048576)){
   transfer.child.kill();const diagnostics=await transfer.done;transfer=null;clearTimeout(timer);
   fs.writeFileSync(folder+'/failed-'+scheme+'.json',JSON.stringify({records,diagnostics},null,2));
   console.log(JSON.stringify({diagnostics:{code:diagnostics.code,error:diagnostics.err.slice(0,400)},observations:records.slice(-3)}));throw Error('No payload transfer for '+scheme);
  }
  const byteSum=()=>[...lastBytes.values()].reduce((s,n)=>s+n,0);
  const initial=byteSum(),profileStart=Date.now(),profileFile=`${folder}/${scheme}.pb.gz`;
  let captured=false;
  const capture=launch('curl.exe',['--fail','--silent','--show-error','--max-time','14','--output',profileFile,api+'/debug/pprof/profile?seconds=8']).done.then(r=>{captured=true;return r;});
  const cpu=[];
  const sampler=(async()=>{while(!captured){const r=await command(':put ("cpu=" . [/system resource get cpu-load]); /system resource cpu print');const total=Number(r.out.match(/cpu=(\d+)/)?.[1]);if(Number.isFinite(total))cpu.push({total,cores:[...r.out.matchAll(/cpu\d+\s+(\d+)%/g)].map(m=>Number(m[1]))});if(!captured)await sleep(1000);}})();
  while(!captured){observe(await connections());await sleep(300);}
  const capturedResult=await capture;await sampler;observe(await connections());
  const elapsed=(Date.now()-profileStart)/1000,bytes=byteSum()-initial;
  if(capturedResult.code)throw Error(JSON.stringify(capturedResult));
  transfer.child.kill();const curl=await transfer.done;clearTimeout(timer);transfer=null;
  const completed=curl.out.split(/\r?\n/).filter(line=>line.startsWith('{')).flatMap(line=>{try{const c=JSON.parse(line);return [{http:c.http_code,bytes:c.size_download,seconds:c.time_total,connects:c.num_connects}];}catch{return [];}});
  const profile=analyze(profileFile);
  const crypto=profile.cumulative.find(r=>r.name==='golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305).Open');
  const result={scheme,address,port,maxSimultaneous,measurement_seconds:elapsed,measurement_bytes:bytes,mbps:bytes*8/elapsed/1e6,cpu,completed,profile,crypto_open_percent:crypto?.percent||0,records};
  results.push(result);fs.writeFileSync(folder+'/results.json',JSON.stringify(results,null,2));
  console.log(JSON.stringify({scheme,mbps:result.mbps,measurement_bytes:bytes,cpu,maxSimultaneous,completed_requests:completed.length,crypto_open_percent:result.crypto_open_percent,profile_cpu_seconds:profile.cpu_seconds,flat:profile.flat.slice(0,8)}));
  if(maxSimultaneous!==1||!bytes)throw Error('Invalid single-connection run');
  await sleep(1000);
 }
}finally{
 if(transfer){transfer.child.kill();await transfer.done;}
 const restore=await helper(isolated?'stop':'restore');console.log(JSON.stringify({restore}));
 fs.writeFileSync(folder+'/results.json',JSON.stringify(results,null,2));
}
