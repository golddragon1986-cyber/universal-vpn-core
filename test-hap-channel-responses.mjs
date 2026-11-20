import {spawn} from 'node:child_process';
import fs from 'node:fs';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const helper=action=>run(process.execPath,['router-ssh.mjs','hap',`/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-channel-response-probe.py ${action}"`]);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const series=[];
try{
 const setup=await helper('setup');if(!setup.out.includes('routed'))throw Error(JSON.stringify(setup));
 for(let round=1;round<=4;round++){
  console.log(JSON.stringify({starting_series:round}));let done=false;const seen=new Map();
  const downloads=Promise.all(Array.from({length:8},(_,i)=>{
   const port=46000+(round-1)*8+i;
   return run('curl.exe',['--proxy','http://192.168.99.1:11080','--local-port',String(port),'--range','0-262143','--limit-rate','16k','--connect-timeout','10','--max-time','25','--silent','--output','NUL','--write-out','%{json}',`http://speedtest.selectel.ru/100MB?probe=${Date.now()}-${round}-${i}`]).then(row=>{
    try{const c=JSON.parse(row.out);return {request:i+1,port,actual_local_port:c.local_port,exit:row.code,http:c.http_code,bytes:c.size_download,seconds:c.time_total};}
    catch{return {request:i+1,port,exit:row.code,http:0,bytes:0};}
   });
  })).then(rows=>{done=true;return rows;});
  await sleep(1000);
  while(!done){
   const probe=await helper('status');
   const line=probe.out.split(/\r?\n/).find(s=>s.startsWith('['));
   if(line)for(const row of JSON.parse(line)){
    const channel=['SV-inbound','FL'].find(c=>row.chains?.includes(c));
    if(channel)seen.set(Number(row.source_port),channel);
   }
   if(!done)await sleep(1500);
  }
  const rows=(await downloads).map(row=>({...row,channel:seen.get(row.port)||'unattributed',success:row.http===206&&row.bytes===262144&&row.exit===0}));
  const summary=Object.fromEntries(['SV-inbound','FL','unattributed'].map(channel=>{const subset=rows.filter(r=>r.channel===channel);return [channel,{total:subset.length,success:subset.filter(r=>r.success).length,http:subset.map(r=>r.http)}];}));
  const result={series:round,summary,rows};series.push(result);console.log(JSON.stringify(result));
  fs.writeFileSync('build/hap-ac3-clean/channel-responses-4x8.json',JSON.stringify({series},null,2));
 }
}finally{
 const restore=await helper('restore');console.log(JSON.stringify({restore}));
 fs.writeFileSync('build/hap-ac3-clean/channel-responses-4x8.json',JSON.stringify({series,restore},null,2));
}
