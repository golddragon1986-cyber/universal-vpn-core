import {spawn} from 'node:child_process';
function run(cmd,args){return new Promise(resolve=>{let out='',err='';const p=spawn(cmd,args);p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('close',code=>resolve({code,out,err}));});}
const api='http://192.168.99.1:19090';
const original=await(await fetch(api+'/configs')).json();
const patch=body=>fetch(api+'/configs',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
try{
 await run(process.execPath,['router-ssh.mjs','hap','/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-main-http-https-route.py setup"']);
 await patch({'log-level':'debug'});
 console.log(JSON.stringify(await run('curl.exe',['--proxy','http://192.168.99.1:11080','--proxytunnel','--connect-to','server-32926.prod.hosts.ooklaserver.net:8080:139.45.201.129:8080','--tlsv1.3','--tls-max','1.3','--ssl-no-revoke','--head','--max-time','8','--silent','--show-error','--output','NUL','--write-out','%{http_code}','https://server-32926.prod.hosts.ooklaserver.net:8080/speedtest/random4000x4000.jpg'])));
 console.log(JSON.stringify(await run(process.execPath,['router-ssh.mjs','hap','/log print where message~"XTLS Vision found|XTLS Vision stop filtering"'])));
}finally{
 await patch({'log-level':original['log-level']});
 console.log(JSON.stringify({restore:await run(process.execPath,['router-ssh.mjs','hap','/container shell universal-vpn-core cmd="python3 /etc/mihomo/hap-main-http-https-route.py restore"'])}));
}
