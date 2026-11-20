import concurrent.futures,http.client,importlib.util,json,os,socket,ssl,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager
spec=importlib.util.spec_from_file_location('vpn_clients_xray','/etc/mihomo/fix-check/vpn_clients_xray.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
nodes=[(v.canonical(n),18751+i) for i,n in enumerate(proxy_manager.read()['nodes']) if n['proxy']['name'] in ('SV-inbound','FL')]
test_fingerprint=os.environ.get('XRAY_TEST_FINGERPRINT')
if test_fingerprint:
    for p,_ in nodes:p['client-fingerprint']=test_fingerprint
    v.xray_mlkem_supported=lambda fp:fp==test_fingerprint
cfg={'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
for p,port in nodes:
    tag='isolated-'+str(port);out=v.convert(p,'xray');out['tag']=tag
    out['streamSettings']['realitySettings']['show']=True
    cfg['outbounds'].append(out)
    cfg['inbounds'].append({'tag':tag,'protocol':'socks','listen':'127.0.0.1','port':port,'settings':{'udp':False}})
    cfg['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':tag})
def recv(sock,n):
    out=b''
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part:raise OSError('SOCKS connection closed')
        out+=part
    return out
def probe(item):
    p,port=item;statuses=[]
    def connect(address,timeout=None,source_address=None):
        sock=socket.create_connection(('127.0.0.1',port),timeout=8)
        sock.sendall(b'\x05\x01\x00')
        if recv(sock,2)!=b'\x05\x00':raise OSError('SOCKS auth rejected')
        host=address[0].encode();sock.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+int(address[1]).to_bytes(2,'big'))
        reply=recv(sock,4)
        if reply[1]!=0:raise OSError('SOCKS connect rejected')
        size=4 if reply[3]==1 else 16 if reply[3]==4 else recv(sock,1)[0]
        recv(sock,size+2)
        return sock
    for _ in range(3):
        conn=None
        try:
            conn=http.client.HTTPSConnection(os.environ.get('XRAY_TEST_HOST','www.gstatic.com'),timeout=20,context=ssl.create_default_context())
            conn._create_connection=connect
            conn.request('GET','/generate_204');response=conn.getresponse();response.read(1024);statuses.append(response.status)
        except Exception as e:statuses.append(type(e).__name__)
        finally:
            if conn:conn.close()
    return {'name':p['name'],'statuses':statuses}
fd,path=tempfile.mkstemp(prefix='.isolated-xray-',suffix='.json',dir='/etc/mihomo/clients')
with os.fdopen(fd,'w') as out:json.dump(cfg,out)
results=[]
try:
    checked=subprocess.run([v.binary('xray'),'run','-test','-config',path],capture_output=True,text=True,timeout=30)
    if checked.returncode:
        diagnostic=checked.stdout+checked.stderr
        for p,_ in nodes:
            for value in (p.get('uuid'),p.get('server'),p.get('servername'),p.get('reality-opts',{}).get('public-key'),p.get('reality-opts',{}).get('short-id')):
                if value:diagnostic=diagnostic.replace(str(value),'[redacted]')
        print(diagnostic[-2000:],flush=True)
        raise RuntimeError('Xray rejected isolated config')
    for attempt in range(1,3):
        log=Path('/tmp/isolated-xray.log')
        with log.open('w') as stream:
            proc=subprocess.Popen([v.binary('xray'),'run','-config',path],stdout=stream,stderr=subprocess.STDOUT,env={**os.environ,'GOMEMLIMIT':'40MiB','GOGC':'50'})
        try:
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                try:
                    for _,port in nodes:
                        with socket.create_connection(('127.0.0.1',port),timeout=.3):pass
                    break
                except OSError:
                    if proc.poll() is not None:raise RuntimeError('Xray exited before listening')
                    time.sleep(.2)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:checks=list(pool.map(probe,nodes))
            text=log.read_text()
            hybrid=[line.rsplit(':',1)[-1].strip() for line in text.splitlines() if "is using X25519MLKEM768 for TLS' communication" in line]
            diagnostic=[line for line in text.splitlines() if any(word in line.lower() for word in ('failed','unsupported','invalid','rejected','error'))][-8:]
            for p,_ in nodes:
                for value in (p.get('uuid'),p.get('server'),p.get('servername'),p.get('reality-opts',{}).get('public-key'),p.get('reality-opts',{}).get('short-id')):
                    if value:diagnostic=[line.replace(str(value),'[redacted]') for line in diagnostic]
            result={'attempt':attempt,'nodes':checks,'negotiated_mlkem':hybrid,'diagnostic':diagnostic,'memory_events':Path('/sys/fs/cgroup/memory.events').read_text()}
            results.append(result);print(json.dumps(result),flush=True)
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    Path('/etc/mihomo/xray-isolated-verified.json').write_text(json.dumps(results,indent=2))
    assert all(c['statuses']==[204]*3 for r in results for c in r['nodes'])
    assert all(len(r['negotiated_mlkem'])>=6 and all(x=='true' for x in r['negotiated_mlkem']) for r in results)
finally:Path(path).unlink(missing_ok=True)
