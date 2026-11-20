const base='http://192.168.99.1:19091';
let ready=false;
for(let i=0;i<30;i++){
 try{const response=await fetch(base+'/api/actions/status',{signal:AbortSignal.timeout(3000)});if(response.ok){ready=true;break;}}catch{}
 await new Promise(resolve=>setTimeout(resolve,2000));
}
if(!ready)throw Error('Panel not ready');
const response=await fetch(base+'/api/actions/queue',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({action:'vpn_client',name:'SV-inbound',client:'xray'})});
const queued=await response.json();if(!queued.ok)throw Error(JSON.stringify(queued));
console.log(JSON.stringify({job:queued.job_id,state:'queued'}));
for(let i=0;i<50;i++){
 await new Promise(resolve=>setTimeout(resolve,2500));
 const state=await(await fetch(base+'/api/actions/status')).json();
 const job=state.jobs.find(job=>job.id===queued.job_id);
 if(job&&['done','failed'].includes(job.status)){
  console.log(JSON.stringify({id:job.id,status:job.status,message:job.message,duration:job.duration}));
  if(job.status!=='done')process.exitCode=1;
  break;
 }
 if(i===49)throw Error('Action timeout');
}
