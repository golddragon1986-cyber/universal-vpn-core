const base='http://192.168.99.1:19091';
const engine=process.argv[2]||'xray';
let ready=false;
for(let i=0;i<50;i++){
 try{const r=await fetch(base+'/api/actions/status',{signal:AbortSignal.timeout(3000)});if(r.ok){ready=true;break;}}catch{}
 await new Promise(r=>setTimeout(r,3000));
}
if(!ready)throw Error('Panel not ready');
for(const name of ['FL','SV-inbound']){
 const res=await fetch(base+'/api/actions/queue',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({action:'vpn_client',name,client:engine})});
 const queued=await res.json();if(!queued.ok)throw Error(JSON.stringify(queued));
 console.log(JSON.stringify({name,job:queued.job_id,state:'queued'}));
 let completed=false;
 for(let i=0;i<40;i++){
  await new Promise(r=>setTimeout(r,3000));
  const state=await(await fetch(base+'/api/actions/status')).json();
  const job=state.jobs.find(x=>x.id===queued.job_id);
  if(job&&['done','failed'].includes(job.status)){
   console.log(JSON.stringify({name,id:job.id,status:job.status,message:job.message,duration:job.duration}));
   if(job.status!=='done')process.exit(1);
   completed=true;break;
  }
 }
 if(!completed)throw Error('Action timeout');
}
