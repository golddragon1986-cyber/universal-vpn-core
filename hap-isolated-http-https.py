import json,os,signal,socket,subprocess,sys,time,http.client
from pathlib import Path
from urllib.request import ProxyHandler,build_opener
sys.path.insert(0,'/etc/mihomo/rules')
import proxy_manager,vpn_clients
WORK=Path('/etc/mihomo/http-https-isolated-20261107');WORK.mkdir(mode=0o700,exist_ok=True)
action=sys.argv[1]
if action=='secure':
    command=['iptables-legacy']
    if subprocess.run(command+['-nL','UVPN_DIAG_IN'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        subprocess.run(command+['-N','UVPN_DIAG_IN'],check=True)
        subprocess.run(command+['-A','UVPN_DIAG_IN','-s','127.0.0.0/8','-j','ACCEPT'],check=True)
        subprocess.run(command+['-A','UVPN_DIAG_IN','-s','172.31.41.1/32','-j','ACCEPT'],check=True)
        subprocess.run(command+['-A','UVPN_DIAG_IN','-j','DROP'],check=True)
    rule=['INPUT','-p','tcp','-m','multiport','--dports','18881,18882','-j','UVPN_DIAG_IN']
    if subprocess.run(command+['-C',*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:subprocess.run(command+['-I',*rule],check=True)
    print(json.dumps({'restricted_to_router_and_loopback':True}))
if action=='start':
    assert not (WORK/'pid').exists(),'Diagnostic process already recorded'
    profile=vpn_clients.canonical(next(n for n in proxy_manager.read()['nodes'] if n['proxy']['name']=='SV-inbound'))
    if len(sys.argv)>2:
        assert sys.argv[2] in ('chrome','randomized')
        profile['client-fingerprint']=sys.argv[2]
    cfg={'mixed-port':18881,'external-controller':'0.0.0.0:18882','bind-address':'0.0.0.0','allow-lan':True,'log-level':'debug','proxies':[profile],'rules':['MATCH,SV-inbound']}
    config=WORK/'config.json';config.write_text(json.dumps(cfg));config.chmod(0o600)
    with (WORK/'log').open('w') as log:
        process=subprocess.Popen(['mihomo','-d',str(WORK),'-f',str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,close_fds=True,env={**os.environ,'GOMEMLIMIT':'30MiB','GOGC':'50'})
    (WORK/'pid').write_text(str(process.pid))
    for _ in range(30):
        if process.poll() is not None:raise RuntimeError('Diagnostic core exited')
        try:
            with socket.create_connection(('127.0.0.1',18881),timeout=.3):break
        except OSError:time.sleep(.1)
    print(json.dumps({'started':True,'pid':process.pid,'engine':'mihomo','fingerprint':profile.get('client-fingerprint')}))
elif action=='status':
    pid=int((WORK/'pid').read_text());cmd=Path(f'/proc/{pid}/cmdline').read_bytes()
    print(json.dumps({'alive':str(WORK/'config.json').encode() in cmd,'pid':pid}))
elif action=='probe':
    result={}
    opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:18881'}))
    try:
        with opener.open('https://www.gstatic.com/generate_204',timeout=8) as response:response.read(1024);result['vpn_https']=response.status
    except Exception as error:result['vpn_https']=type(error).__name__
    connection=http.client.HTTPConnection('127.0.0.1',18881,timeout=8)
    try:
        connection.set_tunnel('139.45.201.129',8080)
        connection.request('HEAD','/speedtest/random4000x4000.jpg',headers={'Host':'server-32926.prod.hosts.ooklaserver.net:8080'})
        response=connection.getresponse();result['pinned_http']=response.status;result['content_length']=response.getheader('Content-Length');response.read()
    except Exception as error:result['pinned_http']=type(error).__name__
    finally:connection.close()
    print(json.dumps(result),flush=True)
elif action=='vision':
    text=(WORK/'log').read_text()
    lines=[line[:line.find(' level=')]+': '+line[line.find('XTLS Vision'):] for line in text.splitlines() if any(value in line for value in ('XTLS Vision found TLS','XTLS Vision stop filtering','XTLS Vision direct read start','XTLS Vision direct write start','XTLS Vision read padding: command='))]
    significant=[line for line in lines if 'read padding' not in line]
    print(json.dumps({'vision_events':significant[-20:],'direct_read_count':text.count('XTLS Vision direct read start'),'direct_write_count':text.count('XTLS Vision direct write start'),'padding_command_0':text.count('read padding: command=0'),'padding_command_1':text.count('read padding: command=1'),'padding_command_2':text.count('read padding: command=2')}))
elif action=='stop':
    path=WORK/'pid'
    if path.exists():
        pid=int(path.read_text())
        try:
            if str(WORK/'config.json').encode() in Path(f'/proc/{pid}/cmdline').read_bytes():os.kill(pid,signal.SIGTERM)
        except (FileNotFoundError,ProcessLookupError):pass
        path.unlink()
    print(json.dumps({'stopped':True}))
    rule=['INPUT','-p','tcp','-m','multiport','--dports','18881,18882','-j','UVPN_DIAG_IN']
    subprocess.run(['iptables-legacy','-D',*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['iptables-legacy','-F','UVPN_DIAG_IN'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['iptables-legacy','-X','UVPN_DIAG_IN'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
