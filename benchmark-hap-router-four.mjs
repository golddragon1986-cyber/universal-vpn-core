import {spawn} from 'node:child_process';
import fs from 'node:fs';
const router=process.env.BENCH_ROUTER||'hap';
const sourceAddress=router==='4011'?'10.0.0.3':'192.168.99.1';
function run(command,onData){let out='',err='';const p=spawn(process.execPath,['router-ssh.mjs',router,command]);return new Promise(resolve=>{p.stdout.on('data',b=>{out+=b;onData?.(out)});p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
let ready;
const started=new Promise(resolve=>ready=resolve);
const monitor=run('/container shell universal-vpn-core cmd="python3 -u /etc/mihomo/hap-tun-optimize.py monitor router-tcpproxy-four"',out=>{if(out.includes('READY'))ready()});
await Promise.race([started,monitor.then(x=>{throw Error('Monitor exited '+JSON.stringify(x))})]);
const command=':local start [:timestamp]; :local r [/tool fetch url="http://speedtest.selectel.ru/100MB" src-address='+sourceAddress+' http-header-field="Range:bytes=0-33554431" output=none as-value]; :put [:serialize $r to=json]; :put ([:timestamp]-$start)';
const start=performance.now();
const streams=await Promise.all(Array.from({length:4},()=>run(command)));
const seconds=(performance.now()-start)/1000;
await run('/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-tun-optimize.py stop router-tcpproxy-four"');
const stats=await monitor;
const parsed=streams.map(x=>{
 const line=x.out.split(/\r?\n/).find(s=>s.startsWith('{'));
 return {...JSON.parse(line),exit:x.code};
});
const bytes=parsed.reduce((sum,x)=>sum+x.downloaded*1024,0);
const result={origin:router,channel:router==='4011'?'SV-inbound/Mihomo':'SV-inbound/sing-box',streams,bytes,seconds,mbps:bytes*8/seconds/1e6,stats:JSON.parse(stats.out.split(/\r?\n/).find(s=>s.startsWith('{')))};
fs.writeFileSync('build/hap-ac3-clean/'+(router==='4011'?'rb4011-':'')+'tcp-proxy-router-four-result.json',JSON.stringify(result,null,2));console.log(JSON.stringify(result));
if(parsed.some(x=>x.exit!==0||x.code!==206||x.downloaded!==32768))process.exit(1);
