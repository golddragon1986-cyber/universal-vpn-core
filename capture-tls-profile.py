"""Project ClientHello metadata only; never persist packets, random or session ID."""
import hashlib,json,socket,struct,time
from pathlib import Path

cfg=json.loads(Path('/etc/mihomo/clients/sing-box.json').read_text())
targets={x['server']:{'tag':x['tag'],'server':x['server'],'port':x['server_port'],'configured_fingerprint':x['tls']['utls']['fingerprint'],'sni':x['tls']['server_name']} for x in cfg['outbounds'] if x.get('type')=='vless'}
def words(b):return [int.from_bytes(b[i:i+2],'big') for i in range(0,len(b)-1,2)]
def grease(x):return x>>8==x&255 and x&0x0f0f==0x0a0a
def parse(b):
 if len(b)<9 or b[0]!=22 or b[5]!=1:return
 size=int.from_bytes(b[3:5],'big')+5
 if len(b)<size:return
 h=b[9:size];version=int.from_bytes(h[:2],'big');i=34;i+=1+h[i]
 length=int.from_bytes(h[i:i+2],'big');i+=2;ciphers=words(h[i:i+length]);i+=length;i+=1+h[i];length=int.from_bytes(h[i:i+2],'big');i+=2;end=i+length
 extensions=[];groups=[];shares=[];versions=[];alpn=[];formats=[]
 while i+4<=end:
  typ=int.from_bytes(h[i:i+2],'big');n=int.from_bytes(h[i+2:i+4],'big');i+=4;data=h[i:i+n];i+=n;extensions.append(typ)
  if typ==10:groups=words(data[2:])
  elif typ==11:formats=list(data[1:])
  elif typ==43:versions=words(data[1:])
  elif typ==51:
   j=2
   while j+4<=len(data):
    group=int.from_bytes(data[j:j+2],'big');size=int.from_bytes(data[j+2:j+4],'big');shares.append({'group':group,'public_key_bytes':size});j+=4+size
  elif typ==16:
   j=2
   while j<len(data):n=data[j];j+=1;alpn.append(data[j:j+n].decode('ascii','replace'));j+=n
 ja3=','.join([str(version),'-'.join(str(x) for x in ciphers if not grease(x)),'-'.join(str(x) for x in extensions if not grease(x)),'-'.join(str(x) for x in groups if not grease(x)),'-'.join(map(str,formats))])
 return {'legacy_version':version,'supported_versions':versions,'cipher_suites':[hex(x) for x in ciphers],'extension_ids':extensions,'supported_groups':groups,'key_shares':shares,'alpn':alpn,'ja3':ja3,'ja3_md5':hashlib.md5(ja3.encode()).hexdigest()}

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0003));s.bind(('veth-universal',0));s.settimeout(1)
flows={};found={};end=time.monotonic()+18;counts={'frames':0,'target_tcp':0,'hello_starts':0}
try:
 while time.monotonic()<end and len(found)<len(targets):
  try:p=s.recv(65535)
  except TimeoutError:continue
  counts['frames']+=1
  if len(p)<54 or p[12:14]!=b'\x08\x00' or p[23]!=6:continue
  ihl=(p[14]&15)*4;ipend=14+int.from_bytes(p[16:18],'big');dst=socket.inet_ntoa(p[30:34]);t=14+ihl
  if dst not in targets or dst in found or int.from_bytes(p[t+2:t+4],'big')!=targets[dst]['port']:continue
  counts['target_tcp']+=1
  seq=int.from_bytes(p[t+4:t+8],'big');off=t+(p[t+12]>>4)*4;data=p[off:ipend]
  if not data:continue
  key=(p[26:30],int.from_bytes(p[t:t+2],'big'),dst)
  if key not in flows:
   if not data.startswith(b'\x16\x03'):continue
   counts['hello_starts']+=1
   flows[key]={'start':seq,'chunks':{}}
  f=flows[key];f['chunks'][seq]=data;buf=b'';expected=f['start']
  for number,chunk in sorted(f['chunks'].items()):
   if number<expected:continue
   if number!=expected:break
   buf+=chunk;expected+=len(chunk)
  try:profile=parse(buf)
  except (IndexError,ValueError):continue
  if profile:found[dst]={**targets[dst],**profile};print(json.dumps(found[dst]),flush=True)
finally:s.close()
print(json.dumps({'capture_counts':counts}),flush=True)
Path('/etc/mihomo/bad-tls-profile-public.json').write_text(json.dumps({'time':time.strftime('%Y-%m-%d %H:%M:%S'),'profiles':list(found.values())},indent=2))
if not found:raise RuntimeError('No complete outbound ClientHello captured')
