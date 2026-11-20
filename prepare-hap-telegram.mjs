import fs from 'node:fs';
const dir='build/hap-ac3-clean';
const nets=fs.readFileSync(dir+'/telegram-cidr.txt','utf8').trim().split(/\s+/).filter(x=>/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(x));
if(nets.length<5||nets.length>30)throw Error('Unexpected Telegram network list');
const domains=fs.readFileSync(dir+'/telegram-domains.txt','utf8').split(/\r?\n/).map(x=>x.split('#')[0].trim()).filter(Boolean);
if(domains.some(x=>!/^[-a-z0-9.]+$/.test(x)))throw Error('Unexpected Telegram domain format');
fs.writeFileSync(dir+'/telegram-public-data.json',JSON.stringify({nets,domains}));
const lines=[
'/routing table add name=uvpn-direct fib',
'/ip route add dst-address=0.0.0.0/0 gateway=5.23.104.1@main routing-table=uvpn-direct distance=1 comment="Universal VPN container return path WAN"',
'/ip route add dst-address=0.0.0.0/0 gateway=lte1 routing-table=uvpn-direct distance=2 comment="Universal VPN container return path LTE"',
'/ip firewall filter add chain=forward action=accept src-address=192.168.99.0/24 out-interface=container-universal place-before=0 comment="Universal VPN LAN bypass FastTrack"',
'/ip firewall filter add chain=forward action=accept dst-address=192.168.99.0/24 in-interface=container-universal connection-state=established,related place-before=0 comment="Universal VPN return bypass FastTrack"',
];
for(const net of nets){
lines.push(`/routing rule add src-address=172.31.41.2/32 dst-address=${net} action=lookup-only-in-table table=uvpn-direct comment="universal-vpn: return path"`);
lines.push(`/ip route add dst-address=${net} gateway=172.31.41.2 comment="universal-vpn: Telegram"`);
}
fs.writeFileSync(dir+'/telegram-routes.rsc',lines.join('\n')+'\n');
console.log('Prepared',nets.length,'IPv4 routes and',domains.length,'domain rules');
