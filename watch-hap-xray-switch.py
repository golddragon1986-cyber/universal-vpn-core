import concurrent.futures,http.client,json,socket,ssl,time
from pathlib import Path
from urllib.request import urlopen
ROOT=Path('/etc/mihomo')
def recv(s,n):
    b=b''
    while len(b)<n:
        chunk=s.recv(n-len(b))
        if not chunk:raise OSError('SOCKS closed')
        b+=chunk
    return b
def direct(port):
    def connect(addr,timeout=None,source_address=None):
        s=socket.create_connection(('127.0.0.1',port),timeout=5);s.sendall(b'\x05\x01\x00')
        if recv(s,2)!=b'\x05\x00':raise OSError('SOCKS auth')
        host=addr[0].encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+addr[1].to_bytes(2,'big'))
        r=recv(s,4)
        if r[1]:raise OSError('SOCKS rejected '+str(r[1]))
        recv(s,(4 if r[3]==1 else 16 if r[3]==4 else recv(s,1)[0])+2);return s
    c=http.client.HTTPSConnection('www.gstatic.com',timeout=8,context=ssl.create_default_context());c._create_connection=connect
    try:c.request('GET','/generate_204');r=c.getresponse();r.read(1024);return r.status
    except Exception as e:return type(e).__name__
    finally:c.close()
start=time.monotonic();records=[]
while time.monotonic()-start<100:
    path=ROOT/'clients/panel-xray.json';row={'elapsed':round(time.monotonic()-start,1),'config':path.exists()}
    if path.exists():
        try:
            cfg=json.loads(path.read_text());ports=[i['port'] for i in cfg['inbounds']]
            row['ports']=ports
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:row['direct_socks_https']=list(pool.map(direct,ports))
        except Exception as e:row['error']=type(e).__name__
    records.append(row);print(json.dumps(row),flush=True)
    if len(records)>3 and not path.exists() and any(r['config'] for r in records):break
    time.sleep(3)
(ROOT/'xray-switch-watch.json').write_text(json.dumps(records,indent=2))
