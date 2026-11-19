"""Optional legacy REDIRECT for routed LAN TCP; UDP keeps the existing TUN path."""
import ipaddress,json,re,shutil,subprocess,sys
from pathlib import Path
CONFIG=Path('/etc/mihomo/rules/transparent-tcp.json')
CHAIN='UVPN_TCP';BACKEND='iptables-legacy'
def run(args,check=True):
    p=subprocess.run([BACKEND,'-t','nat',*args],capture_output=True,text=True,timeout=15)
    if check and p.returncode:raise RuntimeError('Legacy TCP redirect failed: '+p.stderr[-500:])
    return p
def remove():
    if not shutil.which(BACKEND):return
    # Only remove jumps targeting our own chain; leave unrelated NAT untouched.
    rules=run(['-S','PREROUTING'],False)
    if rules.returncode:return
    import shlex
    for line in rules.stdout.splitlines():
        args=shlex.split(line)
        if len(args)>2 and args[:2]==['-A','PREROUTING'] and args[-2:]==['-j',CHAIN]:
            run(['-D',*args[1:]])
    if run(['-S',CHAIN],False).returncode==0:
        run(['-F',CHAIN]);run(['-X',CHAIN])
def apply():
    settings=json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    if not settings.get('enabled'):
        remove();return {'enabled':False}
    interface=settings.get('interface','veth-universal')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):raise ValueError('Invalid redirect interface')
    local=str(ipaddress.IPv4Address(settings['container_address']))
    clients=[str(ipaddress.IPv4Network(x,strict=True)) for x in settings['clients']]
    if not clients or len(clients)>16:raise ValueError('Invalid redirect client list')
    if any(not ipaddress.ip_network(x).is_private for x in clients):raise ValueError('Redirect requires private client subnets')
    port=int(settings.get('port',7893))
    if not 1024<=port<=65535:raise ValueError('Invalid redirect port')
    if not shutil.which(BACKEND):raise RuntimeError('Install iptables-legacy for transparent TCP')
    remove()
    try:
        run(['-N',CHAIN])
        run(['-A',CHAIN,'-d',local+'/32','-j','RETURN'])
        for subnet in clients:
            run(['-A',CHAIN,'-p','tcp','-s',subnet,'-j','REDIRECT','--to-ports',str(port)])
        run(['-I','PREROUTING','1','-i',interface,'-p','tcp','-j',CHAIN])
    except Exception:
        remove();raise
    return {'enabled':True,'port':port,'tcp':'legacy redirect','udp':'existing TUN'}
if __name__=='__main__':
    print(json.dumps(apply()),flush=True)
