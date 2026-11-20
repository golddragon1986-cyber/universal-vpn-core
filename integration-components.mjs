import fs from 'node:fs/promises';
const base='http://10.0.0.3:19091';
const results=[];
for(const operation of ['install','update','remove']){
  const r=await fetch(base+'/api/actions/queue',{method:'POST',body:new URLSearchParams({action:'component_change',component:'wireguard-tools',operation})});
  const queued=await r.json();if(r.status!==202)throw Error(JSON.stringify(queued));
  let result;
  for(let n=0;n<240;n++){
    const data=await(await fetch(base+'/api/actions/status')).json();
    result=data.jobs.find(j=>j.id===queued.job_id&&['done','failed'].includes(j.status));
    if(result)break;await new Promise(r=>setTimeout(r,500));
  }
  results.push(result);console.log(JSON.stringify({operation,status:result?.status,message:result?.message}));
  await fs.writeFile('build/components-integration.json',JSON.stringify(results,null,2));
  if(result?.status!=='done')throw Error('Component lifecycle failed');
}
