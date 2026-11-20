import {spawn} from 'node:child_process';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const command=cmd=>new Promise(resolve=>{let out='';const p=spawn(process.execPath,['router-ssh.mjs','hap',cmd]);p.stdout.on('data',b=>out+=b);p.on('close',code=>resolve({code,out}));});
let tunnel;
try{
 const changed=await command('/ip ssh set forwarding-enabled=local');if(changed.code)throw Error('SSH forwarding setup failed');
 tunnel=spawn('ssh',['-N','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=10','-i','C:/Users/gunikov/.ssh/mikrotik_ed25519','-o','HostKeyAlias=5.23.108.48','-L','127.0.0.1:19093:172.31.41.2:18881','-L','127.0.0.1:19094:172.31.41.2:18882','dragon@192.168.99.1'],{stdio:['ignore','ignore','pipe'],windowsHide:true});
 tunnel.stderr.on('data',b=>process.stderr.write(b));await sleep(1500);
 if(tunnel.exitCode!==null)throw Error('SSH tunnel exited');
 const test=spawn(process.execPath,['compare-hap-http-https.mjs'],{stdio:'inherit',env:{...process.env,HTTPHTTPS_ISOLATED:'1',HTTPHTTPS_LOCAL_TUNNEL:'1'}});
 const code=await new Promise(resolve=>test.on('close',resolve));if(code)process.exitCode=code;
}finally{
 if(tunnel)tunnel.kill();
 console.log(JSON.stringify({ssh_restored:await command('/ip ssh set forwarding-enabled=no')}));
}
