"""Isolated connectivity comparison via the healthy VPN, without changing live routing."""
import json,socket,ssl,subprocess,tempfile,time
from pathlib import Path

nodes={x['proxy']['name']:x['proxy'] for x in json.loads(Path('/etc/mihomo/rules/managed-proxies.json').read_text())['nodes']}
good=dict(nodes['SB-SV']);good['name']='probe-good'
bad=nodes['SB-FL'];port=18891

def exact(c,n):
    data=b''
    while len(data)<n:
        block=c.recv(n-len(data))
        if not block:raise ConnectionError('closed')
        data+=block
    return data

def tls(host,server_name):
    c=socket.create_connection(('127.0.0.1',port),3);c.settimeout(8)
    try:
        c.sendall(b'\x05\x01\x00');assert exact(c,2)==b'\x05\x00'
        address=host.encode();c.sendall(b'\x05\x01\x00\x03'+bytes([len(address)])+address+b'\x01\xbb')
        head=exact(c,4)
        if head[1]!=0:raise ConnectionError('socks reply')
        length=4 if head[3]==1 else 16 if head[3]==4 else exact(c,1)[0]
        exact(c,length+2)
        try:
            s=ssl.create_default_context().wrap_socket(c,server_hostname=server_name)
            s.close();return 'TLS response'
        except ssl.SSLCertVerificationError:return 'TLS response, certificate mismatch'
    finally:c.close()

with tempfile.TemporaryDirectory(prefix='peer-probe-',dir='/tmp') as directory:
    path=Path(directory);cfg=path/'config.json';log=path/'private.log'
    cfg.write_text(json.dumps({'socks-port':port,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'error','proxies':[good],'rules':['MATCH,probe-good']}));cfg.chmod(0o600)
    for attempt in range(3):
        with log.open('w') as out:
            process=subprocess.Popen(['/mihomo','-d',directory,'-f',str(cfg)],stdout=out,stderr=out,env={'PATH':'/usr/local/bin:/usr/bin:/bin','GOMEMLIMIT':'60MiB','GOGC':'50'})
            try:
                time.sleep(.8)
                try:control=tls('www.gstatic.com','www.gstatic.com')
                except Exception as e:
                    print(json.dumps({'attempt':attempt+1,'control':type(e).__name__}),flush=True)
                    continue
                try:result=tls(bad['server'],bad.get('servername',bad['server']))
                except Exception as e:result=type(e).__name__
                print(json.dumps({'control_via_SB_SV':control,'SB_FL_via_SB_SV':result}),flush=True)
                break
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
    chained=dict(bad);chained['name']='probe-bad';chained['dialer-proxy']='probe-good'
    cfg.write_text(json.dumps({'socks-port':port,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'error','proxies':[good,chained],'rules':['MATCH,probe-bad']}))
    for attempt in range(3):
        with log.open('w') as out:
            process=subprocess.Popen(['/mihomo','-d',directory,'-f',str(cfg)],stdout=out,stderr=out,env={'PATH':'/usr/local/bin:/usr/bin:/bin','GOMEMLIMIT':'60MiB','GOGC':'50'})
            try:
                time.sleep(.8)
                try:result=tls('www.gstatic.com','www.gstatic.com')
                except Exception as e:
                    print(json.dumps({'chain_attempt':attempt+1,'SB_FL_VLESS_via_SB_SV':type(e).__name__}),flush=True)
                    continue
                print(json.dumps({'SB_FL_VLESS_via_SB_SV':result}),flush=True);break
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
