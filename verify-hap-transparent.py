import collections,ipaddress,json,os,socket,struct,subprocess,time
from pathlib import Path
from urllib.request import urlopen
def api(path):
    with urlopen('http://127.0.0.1:9090'+path,timeout=10) as r:return json.load(r)
def skip_name(data,pos):
    while True:
        size=data[pos]
        if size&192==192:return pos+2
        pos+=1
        if not size:return pos
        pos+=size
def fake_ip(host):
    ident=os.urandom(2);name=b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\0'
    packet=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+name+b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(5);s.sendto(packet,('127.0.0.1',53));data,_=s.recvfrom(4096)
    if data[:2]!=ident:raise RuntimeError('DNS transaction mismatch')
    qd,an=struct.unpack('!HH',data[4:8]);pos=12
    for _ in range(qd):pos=skip_name(data,pos)+4
    for _ in range(an):
        pos=skip_name(data,pos);typ,cls,ttl,size=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
        value=data[pos:pos+size];pos+=size
        if typ==1 and size==4:
            result=socket.inet_ntoa(value)
            if ipaddress.ip_address(result) not in ipaddress.ip_network('198.18.0.0/16'):raise RuntimeError('DNS did not return Fake IP')
            return result
    raise RuntimeError('No Fake IP answer')
udp=[]
for host,port in [('stun.cloudflare.com',3478),('stun.l.google.com',19302)]:
    row={'host':host}
    try:
        target=fake_ip(host);transaction=os.urandom(12)
        request=b'\x00\x01\x00\x00\x21\x12\xa4\x42'+transaction
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(7);s.connect((target,port));source_port=s.getsockname()[1];s.send(request);response=s.recv(2048)
        row.update(fake_ip=True,stun_success=response[:2]==b'\x01\x01' and response[4:8]==b'\x21\x12\xa4\x42' and response[8:20]==transaction)
        rows=api('/connections').get('connections',[])
        row['inbound_types']=list({c.get('metadata',{}).get('type') for c in rows if str(c.get('metadata',{}).get('sourcePort'))==str(source_port) and c.get('metadata',{}).get('network')=='udp'})
    except Exception as error:row['error']=type(error).__name__
    udp.append(row)
    if row.get('stun_success'):break
config=api('/configs');counts=collections.Counter()
for conn in api('/connections').get('connections',[]):
    m=conn.get('metadata',{});counts[str(m.get('type'))+'/'+str(m.get('network'))]+=1
rule=subprocess.run(['iptables-legacy','-t','nat','-L','UVPN_TCP','-n','-v','-x'],capture_output=True,text=True,timeout=10)
report={'redir_port':config.get('redir-port'),'tun_stack':config.get('tun',{}).get('stack'),'udp':udp,'active_connection_types':dict(counts),'nat_rules':rule.stdout,'nat_returncode':rule.returncode}
Path('/etc/mihomo/tcp-redirect-20261106/functional-verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
assert config.get('redir-port')==7893 and rule.returncode==0
assert any(r.get('stun_success') and any(str(t).lower()=='tun' for t in r.get('inbound_types',[])) for r in udp)
