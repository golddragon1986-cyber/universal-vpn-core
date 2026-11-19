"""Bounded per-leaf VPN traffic estimates from Mihomo connection snapshots."""
import json
import threading
import time
from urllib.request import urlopen
from pathlib import Path
from durable_io import write

LOCK=threading.Lock()
PERSIST_LOCK=threading.RLock()
TOTALS={}
PREVIOUS={}
STARTED=False
SINCE=time.strftime('%Y-%m-%d %H:%M:%S')
STATUS='Запуск сбора'
STATE=Path('/etc/mihomo/rules/vpn-traffic-totals.json')
INTERVAL=30

def restore():
    global SINCE,PREVIOUS
    try:
        if STATE.stat().st_size>1024*1024:return
        data=json.loads(STATE.read_text())
        totals=data.get('servers',{})
        if not isinstance(totals,dict) or len(totals)>512:return
        restored={name:{k:max(0,int(v.get(k,0))) for k in ('upload','download')} for name,v in totals.items()}
        previous={key:tuple(value) for key,value in data.get('previous',{}).items()}
        if len(previous)>4096:return
        TOTALS.update(restored);PREVIOUS=previous;SINCE=str(data.get('since',SINCE))
    except (OSError,ValueError,TypeError,AttributeError):pass

def persist():
    with PERSIST_LOCK:
        with LOCK:data={'servers':TOTALS,'previous':PREVIOUS,'since':SINCE};raw=json.dumps(data).encode()
        write(STATE,raw)

def update(connections):
    global PREVIOUS
    current={}
    with LOCK:
        for item in connections[:4096]:
            chain=item.get('chains') or []
            if not chain or chain[0] in ('DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE'):continue
            name=str(chain[0]);key=item.get('id')
            if not key or (name not in TOTALS and len(TOTALS)>=512):continue
            now=(max(0,int(item.get('upload',0))),max(0,int(item.get('download',0))))
            before=PREVIOUS.get(key,(0,0))
            totals=TOTALS.setdefault(name,{'upload':0,'download':0})
            totals['upload']+=max(0,now[0]-before[0])
            totals['download']+=max(0,now[1]-before[1])
            current[key]=now
        PREVIOUS=current

def collect():
    global STATUS
    while True:
        try:
            with urlopen('http://127.0.0.1:9090/connections',timeout=3) as response:data=json.load(response)
            update(data.get('connections') or [])
            persist()
            STATUS='Обновляется'
        except Exception:STATUS='Нет связи с ядром'
        time.sleep(INTERVAL)

def start():
    global STARTED
    if not STARTED:
        STARTED=True
        restore()
        threading.Thread(target=collect,name='vpn-traffic',daemon=True).start()

def snapshot():
    with LOCK:return {'servers':{name:dict(value) for name,value in TOTALS.items()},'since':SINCE,'status':STATUS,'estimated':True,'interval_seconds':INTERVAL}
