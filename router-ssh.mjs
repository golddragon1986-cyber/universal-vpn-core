import {spawnSync} from 'node:child_process';
const target=process.argv[2];
const border=target==='4011';
const args=border?['-i','C:/Users/gunikov/.ssh/mikrotik_border_rsa','-o','UserKnownHostsFile=C:/Users/gunikov/Documents/ChatGPT/Ротеры/work/routeros-upgrade/known_hosts_v7','Edinstvo@10.0.0.3']:['-i','C:/Users/gunikov/.ssh/mikrotik_ed25519','-o','HostKeyAlias=5.23.108.48','dragon@192.168.99.1'];
const r=spawnSync('ssh',['-o','BatchMode=yes','-o','ConnectTimeout=10',...args,process.argv[3]],{stdio:'inherit'});
process.exit(r.status??1);
