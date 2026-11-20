import fs from 'node:fs/promises';
import crypto from 'node:crypto';
const root='http://10.0.0.3:19091';
async function job(data, expectFailure=false){
  const r=await fetch(root+'/api/actions/queue',{method:'POST',body:new URLSearchParams(data)});
  const queued=await r.json();if(r.status!==202)throw Error(JSON.stringify(queued));
  for(let n=0;n<120;n++){
    const history=await(await fetch(root+'/api/actions/status')).json();
    const done=history.jobs.find(j=>j.id===queued.job_id);
    if(done&&['done','failed'].includes(done.status)){
      if((done.status==='failed')!==expectFailure)throw Error(JSON.stringify(done));
      console.log(JSON.stringify({id:done.id,status:done.status,message:done.message}));return done;
    }
    await new Promise(r=>setTimeout(r,500));
  }throw Error('Job timeout');
}
const report=[];
try{
  report.push(await job({action:'vpn_import',source:JSON.stringify({name:'TEST-SOCKS',type:'socks5',server:'192.0.2.1',port:1080})}));
  const key=crypto.randomBytes(32).toString('base64'),peer=crypto.randomBytes(32).toString('base64');
  let config=`[Interface]\nPrivateKey = ${key}\nAddress = 10.254.0.2/32\n[Peer]\nPublicKey = ${peer}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n`;
  report.push(await job({action:'vpn_import',vpn_format:'wireguard',vpn_name:'TEST-WG',source:config}));
  config=config.replace('[Peer]',`HeaderProtectionKey = ${crypto.randomBytes(32).toString('base64')}\nContentPaddingAddition = 16\nRandomTrailers = true\nDisableCookies = true\n[Peer]`);
  report.push(await job({action:'vpn_import',vpn_format:'awg',vpn_name:'TEST-AWG3',source:config}));
  const page=await(await fetch(root+'/?tab=vpn')).text();
  if(!['TEST-SOCKS','TEST-WG','TEST-AWG3'].every(name=>page.includes(name)))throw Error('Inactive imported profiles are missing from VPN table');
  report.push(await job({action:'vpn_import',source:JSON.stringify({name:'TEST-BAD',type:'socks5',server:'192.0.2.1',port:'invalid'})},true));
}finally{
  const names=report.filter(j=>j.status==='done'&&j.message.startsWith('VPN-соединения добавлены: ')).map(j=>j.message.split(': ')[1]);
  if(names.length){
    const body=new URLSearchParams({action:'proxy_delete_selected'});names.forEach(n=>body.append('selected',n));
    report.push(await job(body));
  }
  await fs.writeFile('build/vpn-integration.json',JSON.stringify(report,null,2));
}
