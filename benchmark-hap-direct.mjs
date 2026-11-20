import {spawn} from 'node:child_process';
import fs from 'node:fs';
const command=':local start [:timestamp]; :local r [/tool fetch url="http://188.93.16.211/100MB" http-header-field="Host:speedtest.selectel.ru" src-address=5.23.108.48 output=none as-value]; :put [:serialize $r to=json]; :put ([:timestamp]-$start)';
function run(cmd){return new Promise(resolve=>{const p=spawn(process.execPath,['router-ssh.mjs','hap',cmd]);let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const monitor=run(':for i from=1 to=25 do={ :put [/system clock get time]; :put [/system resource get cpu-load]; :put [/system resource get free-memory]; :put [:serialize [/system resource cpu print as-value] to=json]; :delay 1s }');
const start=performance.now();
const streams=await Promise.all(Array.from({length:4},()=>run(command)));
const seconds=(performance.now()-start)/1000;
const successes=streams.filter(x=>x.code===0&&x.out.includes('"status":"finished"')).length;
const result={source:'http://188.93.16.211/100MB (Host: speedtest.selectel.ru)',path:'RouterOS fetch, src=5.23.108.48; no container',streams,seconds,mbps:successes*104857636*8/seconds/1e6};
fs.writeFileSync('build/hap-ac3-clean/direct-no-container.json',JSON.stringify(result,null,2));
console.log(JSON.stringify(result));
const stats=await monitor;
fs.writeFileSync('build/hap-ac3-clean/direct-no-container-cpu.txt',stats.out);
console.log(stats.out);
