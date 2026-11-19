"""Bounded in-memory TLS metadata capture. Never retain auth/random/key bytes."""
import hashlib,json,os,socket,threading,time
from pathlib import Path

ARCHIVE=Path('/etc/mihomo/diagnostics/failed-tls-profiles.jsonl')
def words(b):return [int.from_bytes(b[i:i+2],'big') for i in range(0,len(b)-1,2)]
def grease(x):return x>>8==x&255 and x&0x0f0f==0x0a0a

def parse_hello(b):
    if len(b)<9 or b[0]!=22 or b[5]!=1:return None
    size=int.from_bytes(b[3:5],'big')+5
    if len(b)<size:return None
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

class Capture:
    def __init__(self,config):
        self.targets={};self.found={};self.flows={};self.error=None;self.stop=threading.Event();self.thread=None;self.sock=None
        for x in config.get('outbounds',[]):
            if x.get('type')!='vless':continue
            for address in socket.getaddrinfo(x['server'],None,socket.AF_INET):
                self.targets[address[4][0]]={'tag':x['tag'],'server':x['server'],'port':x['server_port'],'configured_fingerprint':x['tls']['utls']['fingerprint'],'sni':x['tls']['server_name']}
    def start(self):
        try:
            self.sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));self.sock.bind(('veth-universal',0));self.sock.settimeout(.3)
            self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
        except OSError:self.error='Raw socket capture unavailable'
        return self
    def run(self):
        while not self.stop.is_set() and len(self.found)<len(self.targets):
            try:p=self.sock.recv(65535)
            except TimeoutError:continue
            except OSError:break
            try:
                if len(p)<54 or p[12:14]!=b'\x08\x00' or p[23]!=6:continue
                t=14+(p[14]&15)*4;dst=socket.inet_ntoa(p[30:34]);ipend=14+int.from_bytes(p[16:18],'big')
                if dst not in self.targets or dst in self.found or int.from_bytes(p[t+2:t+4],'big')!=self.targets[dst]['port']:continue
                seq=int.from_bytes(p[t+4:t+8],'big');data=p[t+(p[t+12]>>4)*4:ipend]
                if not data:continue
                key=(p[26:30],int.from_bytes(p[t:t+2],'big'),dst)
                if key not in self.flows:
                    if len(self.flows)>=128 or not data.startswith(b'\x16\x03'):continue
                    self.flows[key]={'start':seq,'chunks':{}}
                f=self.flows[key]
                if sum(map(len,f['chunks'].values()))+len(data)>65536:continue
                f['chunks'][seq]=data;buf=b'';expected=f['start']
                for number,chunk in sorted(f['chunks'].items()):
                    if number<expected:continue
                    if number!=expected:break
                    buf+=chunk;expected+=len(chunk)
                profile=parse_hello(buf)
                if profile:self.found[dst]={**self.targets[dst],**profile}
            except (IndexError,ValueError):continue
    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(timeout=1)
        if self.sock:self.sock.close()
        self.flows.clear()
        return {'profiles':list(self.found.values()),'configured_endpoints':list(self.targets.values()),'capture_error':self.error or (None if self.found else 'No complete ClientHello observed; handshake may have failed locally')}

def save_failure(data):
    ARCHIVE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    item={'schema':1,'time':time.strftime('%Y-%m-%dT%H:%M:%S%z'),**data}
    raw=(json.dumps(item,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    fd=os.open(ARCHIVE,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:
        with os.fdopen(fd,'ab') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    except Exception:
        try:os.close(fd)
        except OSError:pass
        raise
