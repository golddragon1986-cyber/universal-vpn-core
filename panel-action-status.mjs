const data=await (await fetch('http://192.168.99.1:19091/api/actions/status')).json();
console.log(JSON.stringify({running:data.running,queued:data.queued,jobs:data.jobs.slice(0,3).map(({id,status,message,duration,subject})=>({id,status,message,duration,subject}))},null,2));
