import {spawn} from 'node:child_process';
import fs from 'node:fs';
const phase=process.argv[2]||'gvisor';
const router=process.env.BENCH_ROUTER||'hap';
const sourceAddress=router==='4011'?'10.0.0.3':'192.168.99.1';
function run(cmd,onData){
 let p=spawn(process.execPath,['router-ssh.mjs',router,cmd]),out='',err='';
 let done=new Promise(resolve=>{p.stdout.on('data',b=>{out+=b;if(onData)onData(out)});p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});
 return {done,p};
}
function localCurl(){return new Promise(resolve=>{
 const p=spawn('curl.exe',['--proxy','http://192.168.99.1:11080','--range','0-33554431','--max-time','90','--silent','--show-error','--output','NUL','--write-out','{"code":%{http_code},"size_download":%{size_download},"time_total":%{time_total}}','http://speedtest.selectel.ru/100MB']);
 let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));
});}
let ready;
const isReady=new Promise(resolve=>ready=resolve);
const mon=run(`/container shell universal-vpn-core cmd="python3 -u /etc/mihomo/hap-tun-optimize.py monitor ${phase}"`,text=>{if(text.includes('READY'))ready()});
await Promise.race([isReady,mon.done.then(x=>{throw Error('Monitor exited: '+JSON.stringify(x))}),new Promise((_,reject)=>setTimeout(()=>reject(Error('Monitor timeout')),20000))]);
const start=performance.now();
const fetch=phase==='proxy'?await localCurl():await run(':local start [:timestamp]; :local r [/tool fetch url="http://speedtest.selectel.ru/100MB" src-address='+sourceAddress+' http-header-field="Range:bytes=0-33554431" output=none as-value]; :put [:serialize $r to=json]; :put ([:timestamp]-$start)').done;
const wall=(performance.now()-start)/1000;
await run(`/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-tun-optimize.py stop ${phase}"`).done;
const monitor=await mon.done;
const result={phase,fetch,wall_seconds:wall,monitor};
try{
 const data=JSON.parse(fetch.out.split(/\r?\n/).find(x=>x.startsWith('{')));
 const elapsed=fetch.out.match(/(?:^|\n)(\d+):(\d+):(\d+(?:\.\d+)?)/);
 const seconds=elapsed?Number(elapsed[1])*3600+Number(elapsed[2])*60+Number(elapsed[3]):wall;
 result.bytes=phase==='proxy'?data.size_download:Number(data.downloaded)*1024;result.seconds=phase==='proxy'?data.time_total:seconds;result.mbps=result.bytes*8/result.seconds/1e6;
 const stats=JSON.parse(monitor.out.split(/\r?\n/).find(x=>x.startsWith('{')));
 result.stats=stats;result.host_cpu_seconds_per_mib=stats.host_busy_cpu_seconds/(result.bytes/1048576);
}catch(error){result.parse_error=String(error)}
fs.writeFileSync(`build/hap-ac3-clean/tun-${phase}-result.json`,JSON.stringify(result,null,2));
console.log(JSON.stringify(result));
if(fetch.code!==0||result.parse_error)process.exit(1);
