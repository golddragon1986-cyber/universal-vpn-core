import fs from 'node:fs/promises';
import dgram from 'node:dgram';
import http from 'node:http';
const base='http://10.0.0.3:19090';
const report={time:new Date().toISOString(),checks:{}};
for(const [name,url] of Object.entries({panel:'http://10.0.0.3:19091/',version:base+'/version',configs:base+'/configs',proxies:base+'/proxies'})) {
  const response=await fetch(url,{signal:AbortSignal.timeout(8000)});
  if(response.status!==200) throw Error(name+': '+response.status);
  const body=await response.text();
  report.checks[name]=name==='panel'?{status:200,bytes:body.length}:JSON.parse(body);
}
report.checks.dns=await new Promise((resolve,reject)=>{
  const socket=dgram.createSocket('udp4');
  const timer=setTimeout(()=>{socket.close();reject(Error('DNS timeout'));},5000);
  const name=Buffer.concat('example.com'.split('.').map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s)])));
  const packet=Buffer.concat([Buffer.from('abcd01000001000000000000','hex'),name,Buffer.from('0000010001','hex')]);
  socket.on('message',data=>{clearTimeout(timer);socket.close();let i=12;
    const skip=()=>{while(data[i]){if((data[i]&192)===192){i+=2;return;}i+=1+data[i];}i++;};
    for(let n=0;n<data.readUInt16BE(4);n++){skip();i+=4;}
    const addresses=[];
    for(let n=0;n<data.readUInt16BE(6);n++){skip();const type=data.readUInt16BE(i),len=data.readUInt16BE(i+8);i+=10;if(type===1&&len===4)addresses.push([...data.subarray(i,i+4)].join('.'));i+=len;}
    resolve({rcode:data.readUInt16BE(2)&15,addresses,fakeIP:addresses.some(a=>a.startsWith('198.18.'))});
  });
  socket.send(packet,15353,'10.0.0.3');
});
report.checks.proxy=await new Promise((resolve,reject)=>{
  const req=http.get({hostname:'10.0.0.3',port:11080,path:'http://example.com/',headers:{Host:'example.com'},timeout:10000},res=>{let bytes=0;res.on('data',d=>bytes+=d.length);res.on('end',()=>resolve({status:res.statusCode,bytes}));});
  req.on('error',reject);req.on('timeout',()=>req.destroy(Error('Proxy timeout')));
});
await fs.writeFile('build/verification.json',JSON.stringify(report,null,2));
console.log(JSON.stringify({panel:report.checks.panel,version:report.checks.version,dns:report.checks.dns,proxy:report.checks.proxy}));
if(!report.checks.dns.fakeIP||report.checks.proxy.status!==200)process.exitCode=1;

