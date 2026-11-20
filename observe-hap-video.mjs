import fs from 'node:fs';
import {spawn} from 'node:child_process';
const path='build/hap-ac3-clean/video-observation-20261107.json';
const api='http://192.168.99.1:19090';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function command(cmd){return new Promise(resolve=>{let out='',err='';const p=spawn(process.execPath,['router-ssh.mjs','hap',cmd]);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const samples=[];let previous=new Map(),previousTime=null;
for(let round=0;round<24;round++){
 const start=Date.now();
 try{
  const response=await fetch(api+'/connections',{signal:AbortSignal.timeout(2500)});const state=await response.json();
  const videos=(state.connections||[]).filter(c=>/googlevideo\.com$/.test(c.metadata?.host||''));
  const current=new Map();
  const rows=videos.map(c=>{
   const m=c.metadata;const old=previous.get(c.id);current.set(c.id,c.download);
   return {id:c.id,source:m.sourceIP,source_port:m.sourcePort,host:m.host,destination:m.destinationIP,network:m.network,inbound:m.type,chains:c.chains,rule:c.rule,rule_payload:c.rulePayload,download:c.download,mbps:old!==undefined&&previousTime?(c.download-old)*8/((start-previousTime)/1000)/1e6:null};
  });
  const batch=round%2===0?await command(':put ("cpu=" . [/system resource get cpu-load]); :put [:serialize [/interface print stats as-value where name="ether1" or name="veth-universal"] to=json]; :put [:serialize [/ip firewall connection print as-value where dst-address~"89.22.227.150"] to=json]'):null;
  let router=null;
  if(batch){
   const lines=batch.out.split(/\r?\n/);const total=Number(lines.find(s=>s.startsWith('cpu='))?.split('=')[1]);
   const lists=lines.filter(s=>s.startsWith('[')||s.startsWith('{')).map(s=>{try{return JSON.parse(s);}catch{return null;}});
   router={cpu:total,interfaces:lists[0],vpn_connections:lists[1],command_error:batch.code?batch.err:null};
  }
  const sample={time:new Date(start).toISOString(),videos:rows,router};samples.push(sample);fs.writeFileSync(path,JSON.stringify(samples,null,2));
  console.log(JSON.stringify({round:round+1,cpu:router?.cpu,videos:rows.map(({host,source,network,inbound,chains,mbps})=>({host,source,network,inbound,chains,mbps}))}));
  previous=current;previousTime=start;
 }catch(error){samples.push({time:new Date(start).toISOString(),error:String(error)});console.log(JSON.stringify({round:round+1,error:String(error)}));}
 await sleep(Math.max(100,2500-(Date.now()-start)));
}
