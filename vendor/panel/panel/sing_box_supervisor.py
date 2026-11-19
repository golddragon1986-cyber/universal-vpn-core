"""Bounded startup compatibility retries; never restart on ordinary network timeout."""
import concurrent.futures,json,os,platform,signal,socket,subprocess,sys,threading,time,urllib.request
from pathlib import Path
from tls_profile_capture import Capture,save_failure

child=None
reload_pending=False
STATE=Path('/tmp/sing-box-supervisor.json')
def reload_client(*args):
    global reload_pending
    reload_pending=True
    if child is not None and child.poll() is None:child.terminate()
def stop(*args):
    if child is not None and child.poll() is None:child.terminate()
    raise SystemExit(143)
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)

def probe(port):
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({'https':'http://127.0.0.1:'+str(port)}))
        with opener.open('https://www.gstatic.com/generate_204',timeout=5) as response:
            response.read();return response.status==204
    except Exception:return False

def terminate(process):
    if process.poll() is None:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()

def wait_listeners(process,ports,timeout=20):
    """An alive Go process does not mean its proxy listeners are ready yet."""
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline and process.poll() is None:
        ready=True
        for port in ports:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.25):pass
            except OSError:
                ready=False;break
        if ready:return True
        time.sleep(.15)
    return False

def run_cycle(generation):
    global child
    cfg=json.loads(Path(sys.argv[2]).read_text())
    version=subprocess.run([sys.argv[1],'version'],capture_output=True,text=True,timeout=5).stdout.splitlines()[0]
    ports=[x['listen_port'] for x in cfg.get('inbounds',[]) if x.get('type') in ('http','mixed') and x.get('listen')=='127.0.0.1']
    if not ports or len(ports)>16:raise ValueError('Expected bounded local sing-box bridge inputs')
    for attempt in range(1,9):
        flags={'curve':False,'auth':False}
        capture=Capture(cfg).start()
        child=subprocess.Popen([sys.argv[1],'run','-c',sys.argv[2]],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        process=child
        def logs(process=process,flags=flags):
            for line in process.stdout:
                if 'tls: CurvePreferences includes unsupported curve' in line:flags['curve']=True
                if 'reality verification failed' in line:flags['auth']=True
                print(line.rstrip(),flush=True)
        reader=threading.Thread(target=logs,daemon=True);reader.start()
        try:
            if not wait_listeners(process,ports):
                print('SING-BOX STARTUP: local proxy listeners did not become ready',flush=True)
                return 1
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4,len(ports))) as pool:results=list(pool.map(probe,ports))
            if not any(results):time.sleep(.2)
            # A fixed randomized seed is shared by the process. Only retry a
            # local unsupported-curve error or all bridges failing REALITY at startup.
            incompatible=flags['curve'] or (not any(results) and flags['auth'])
            profile=capture.close()
            if incompatible:
                try:save_failure({'engine':'sing-box','engine_version':version,'architecture':platform.machine(),'attempt':attempt,'reason':'unsupported_curve' if flags['curve'] else 'reality_verification_failed','errors':dict(flags),'probe_results':results,**profile})
                except OSError:print('TLS PROFILE ARCHIVE: cannot write diagnostic record',flush=True)
                print('STARTUP RECOVERY: incompatible randomized sing-box TLS profile; attempt '+str(attempt)+'/8',flush=True)
                terminate(process);reader.join(timeout=1)
                if attempt==8:return 1
                time.sleep(.3);continue
            print('SING-BOX STARTUP: '+str(sum(results))+'/'+str(len(results))+' bridge probes passed; normal network failures do not trigger restart',flush=True)
            STATE.write_text(json.dumps({'pid':os.getpid(),'generation':generation,'ready':True,'healthy':sum(results),'total':len(results),'version':version.removeprefix('sing-box version ')}))
            return process.wait()
        finally:
            capture.close()
            terminate(process)
    return 1

def main():
    global reload_pending
    signal.signal(signal.SIGHUP,reload_client)
    generation=0
    while True:
        generation+=1;reload_pending=False
        if Path('/tmp/sing-box-idle').exists():
            version=''
            if Path(sys.argv[1]).is_file():
                version=subprocess.run([sys.argv[1],'version'],capture_output=True,text=True,timeout=5).stdout.splitlines()[0].removeprefix('sing-box version ')
            STATE.write_text(json.dumps({'pid':os.getpid(),'generation':generation,'ready':True,'idle':True,'healthy':0,'total':0,'version':version}))
            while Path('/tmp/sing-box-idle').exists() and not reload_pending:time.sleep(.3)
            continue
        STATE.write_text(json.dumps({'pid':os.getpid(),'generation':generation,'ready':False}))
        result=run_cycle(generation)
        if result and generation>1 and not reload_pending:
            # Keep the panel alive so the updater can restore the previous binary.
            STATE.write_text(json.dumps({'pid':os.getpid(),'generation':generation,'ready':False,'failed':True}))
            while not reload_pending:time.sleep(.5)
        if not reload_pending:return result

if __name__=='__main__':sys.exit(main())
