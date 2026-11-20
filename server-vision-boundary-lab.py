"""Loopback-only reproduction; never reads or changes production credentials."""
import contextlib,hashlib,json,os,re,socket,ssl,subprocess,tempfile,threading,time,uuid
from pathlib import Path
XRAY='/usr/local/x-ui/bin/xray-linux-amd64';TOTAL=32*1024*1024
def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def proc_cpu(pid):
    fields=Path(f'/proc/{pid}/stat').read_text().split();return (int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK')
def wait_port(value,process):
    for _ in range(80):
        if process.poll() is not None:raise RuntimeError('Lab Xray exited')
        for path in ('/proc/net/tcp','/proc/net/tcp6'):
            for line in Path(path).read_text().splitlines()[1:]:
                fields=line.split()
                if int(fields[1].rsplit(':',1)[1],16)==value and fields[3]=='0A':return
        time.sleep(.05)
    raise RuntimeError('Lab port not ready')
results=[]
with tempfile.TemporaryDirectory(prefix='vision-boundary-lab-') as directory:
    root=Path(directory);cert=root/'cert.pem';key=root/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=lab.test','-addext','subjectAltName=DNS:lab.test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    for prelude in (False,True):
        outer,entry,backend=port(),port(),port();identity=str(uuid.uuid4());release=threading.Event();backend_error=[]
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(cert,key)
        listener=socket.socket();listener.bind(('127.0.0.1',backend));listener.listen(1);listener.settimeout(15)
        def serve():
            try:
                raw,_=listener.accept()
                with context.wrap_socket(raw,server_side=True) as stream:
                    remaining=TOTAL
                    if prelude:
                        time.sleep(.05);stream.sendall(b'P'*100);remaining-=100;time.sleep(.05)
                    block=b'X'*16384
                    while remaining:
                        size=min(remaining,len(block));stream.sendall(block[:size]);remaining-=size
                    release.wait(10)
            except Exception as error:backend_error.append(type(error).__name__+': '+str(error))
            finally:listener.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        server={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':outer,'protocol':'vless','settings':{'clients':[{'id':identity,'flow':'xtls-rprx-vision'}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}}}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1']}]}}]}
        client={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':entry,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1','port':backend,'network':'tcp'}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':outer,'users':[{'id':identity,'flow':'xtls-rprx-vision','encryption':'none'}]}]},'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'serverName':'lab.test','pinnedPeerCertSha256':pin}}}]}
        paths=[]
        for label,config in (('server',server),('client',client)):
            path=root/(label+'.json');path.write_text(json.dumps(config));path.chmod(0o600);paths.append(path)
        processes=[]
        with (root/'server.log').open('w') as server_log,(root/'client.log').open('w') as client_log:
            try:
                for path,log in zip(paths,(server_log,client_log)):
                    proc=subprocess.Popen([XRAY,'run','-config',str(path)],stdin=subprocess.DEVNULL,stdout=log,stderr=log);processes.append(proc)
                wait_port(outer,processes[0]);wait_port(entry,processes[1])
                # Readiness probes do not establish an inner TLS session.
                tls_client=ssl.create_default_context(cafile=str(cert));tls_client.minimum_version=tls_client.maximum_version=ssl.TLSVersion.TLSv1_3
                before=[proc_cpu(proc.pid) for proc in processes];start=time.monotonic();count=0
                with socket.create_connection(('127.0.0.1',entry),timeout=15) as raw:
                    with tls_client.wrap_socket(raw,server_hostname='lab.test') as stream:
                        while count<TOTAL:
                            data=stream.recv(min(65536,TOTAL-count))
                            if not data:raise RuntimeError('Early EOF')
                            count+=len(data)
                        elapsed=time.monotonic()-start;time.sleep(.2)
                        cpu=[proc_cpu(proc.pid)-value for proc,value in zip(processes,before)]
                        server_log.flush();client_log.flush();text=(root/'server.log').read_text();client_text=(root/'client.log').read_text()
                        result={'prelude':prelude,'bytes':count,'seconds':round(elapsed,4),'mbps':round(count*8/elapsed/1e6,2),'server_cpu_seconds':round(cpu[0],3),'client_cpu_seconds':round(cpu[1],3),'server_tls13_events':text.count('found tls 1.3'),'server_padding_direct_before_close':len(re.findall(r'XtlsPadding\s+\d+\s+\d+\s+2\b',text)),'server_splice_before_close':text.count('CopyRawConn splice'),'server_padding_continue_before_close':len(re.findall(r'XtlsPadding\s+\d+\s+\d+\s+0\b',text)),'client_direct_read_before_close':client_text.count('CopyRawConn splice'),'backend_errors':backend_error}
                        results.append(result);print(json.dumps(result),flush=True)
            except Exception as error:
                # Logs contain only fresh laboratory credentials; return errors, not config.
                logs={name:(root/(name+'.log')).read_text()[-1500:].replace(identity,'[lab-id]') for name in ('server','client')}
                print(json.dumps({'prelude':prelude,'error':type(error).__name__+': '+str(error),'process_exits':[p.poll() for p in processes],'backend_errors':backend_error,'lab_logs':logs}),flush=True)
                raise
            finally:
                release.set();thread.join(timeout=2)
                for proc in processes:
                    proc.terminate()
                for proc in processes:
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
print(json.dumps({'complete':True,'results':results}),flush=True)
