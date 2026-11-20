import json
import os
import sqlite3
from contextlib import contextmanager
from urllib.parse import parse_qs
from runtime_actions import ACTIONS as RUNTIME_ACTIONS
import threading
import time

LABELS = {
 "client_apply":"Сохранение клиентов в черновик",
 "panel_update_install":"Обновление панели из GitHub",
 "dns_flush":"Очистка DNS Cache", "core_restart":"Перезапуск VPN-ядер",
 "configuration_apply":"Применение конфигурации",
 "subscription_add":"Добавление VPN-подписки",
 "subscription_refresh":"Обновление VPN-подписки",
 "subscription_delete":"Удаление VPN-подписки",
 "subscription_automation":"Настройки автобалансировки подписки",
 "vpn_client":"Выбор VPN-клиента",
 "route_apply":"Применение набора маршрутов", "route_metric":"Метрика маршрута", "route_toggle":"Включение/отключение маршрута", "route_target":"Изменение маршрута сети", "route_add":"Добавление маршрута RouterOS", "route_delete":"Удаление маршрута RouterOS",
 "vpn_import":"Добавление VPN-соединений", "component_change":"Компоненты",
 "proxy_import":"Добавление прокси", "proxy_delete_selected":"Удаление выбранных прокси",
 "proxy_enable_selected":"Включение выбранных прокси", "proxy_balance":"Статус прокси",
 "proxy_delete":"Удаление прокси", "routing_save":"Основной маршрут и правила",
 "service_save":"Сохранение правила", "service_toggle":"Статус правила",
 "service_set_target":"Смена группы правила",
 "service_move":"Порядок правил",
 "service_reorder":"Применение порядка правил",
 "service_delete":"Удаление правила", "service_catalog_import":"Загрузка правил",
 "service_geodata_import":"Создание правила из GeoDAT",
 "service_refresh_geodata":"Обновление правила GeoDAT",
 "service_update_source":"Обновление правила", "filter_save":"Фильтры загрузки доменов",
 "geodata_source_download":"Скачивание источника GeoDAT",
 "clear_auto_domains":"Очистка списка доменов", "refresh":"Обновление доменов",
 "add":"Добавление доменов", "enable":"Включение домена",
 "domain_dns":"DNS локального домена",
 "dns_save":"Настройки DNS-сервера",
 "disable":"Отключение домена", "delete":"Удаление домена", "restore":"Восстановление копии",
}

def component_name(payload):
 if payload.get('path') != '/action':return ''
 data=parse_qs(payload.get('body',''))
 if data.get('action',[''])[0] != 'component_change':return ''
 return data.get('component',[''])[0]

class ActionQueue:
 def __init__(self,path,execute,start=True,describe=None,recovery=None):
  self.path=path;self.execute=execute;self.describe=describe;self.recovery=recovery;self.wake=threading.Event();self.stop=threading.Event()
  fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600);os.close(fd);os.chmod(path,0o600)
  with self.db() as db:
   db.execute("CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT NOT NULL,payload TEXT,status TEXT NOT NULL,message TEXT NOT NULL DEFAULT '',created REAL NOT NULL,updated REAL NOT NULL)")
   columns={r["name"] for r in db.execute("PRAGMA table_info(jobs)")}
   for name,kind in (("started","REAL"),("finished","REAL"),("duration","REAL"),("subject","TEXT"),("change_text","TEXT")):
    if name not in columns:db.execute("ALTER TABLE jobs ADD COLUMN "+name+" "+kind)
   now=time.time()
   db.execute("UPDATE jobs SET status='failed',payload=NULL,message=?,updated=?,finished=?,duration=CASE WHEN started IS NOT NULL THEN ?-started ELSE NULL END WHERE status='running'",
    ("Выполнение прервано перезапуском панели. Проверьте состояние и повторите действие при необходимости.",now,now,now))
  self.worker=None;self.live_lock=threading.Lock();self.live_messages={}
  if start:self.start()
 @contextmanager
 def db(self):
  db=sqlite3.connect(self.path,timeout=10)
  try:
   db.row_factory=sqlite3.Row
   db.execute("PRAGMA synchronous=EXTRA")
   with db:
    yield db
  finally:
   db.close()
 def start(self):
  self.worker=threading.Thread(target=self.run,name="configuration-queue",daemon=True);self.worker.start()
 def active_components(self,db):
  rows=db.execute("SELECT payload FROM jobs WHERE label=? AND status IN ('queued','running')",(LABELS['component_change'],))
  return sorted({name for row in rows if (name:=component_name(json.loads(row['payload'])))})
 def submit(self,label,payload):
  with self.db() as db:
   db.execute("BEGIN IMMEDIATE")
   if label==LABELS['component_change'] and component_name(payload) in self.active_components(db):
    raise ValueError('Для этого компонента уже есть действие в очереди')
   action=parse_qs(payload.get("body","")).get("action",[""])[0]
   if action in RUNTIME_ACTIONS and db.execute("SELECT 1 FROM jobs WHERE label=? AND status IN ('queued','running')",(label,)).fetchone():
    raise ValueError("Эта служебная команда уже выполняется или ожидает в очереди")
   count=db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
   if count>=200:raise ValueError("Очередь заполнена. Дождитесь выполнения нескольких действий.")
   now=time.time()
   job=db.execute("INSERT INTO jobs(label,payload,status,created,updated) VALUES (?,?,'queued',?,?)",(label,json.dumps(payload,ensure_ascii=False),now,now)).lastrowid
  self.wake.set();return job
 def history(self,before=0,limit=50):
  fields="id,label,status,message,created,updated,started,finished,duration,subject,change_text"
  limit=max(1,min(100,int(limit)))
  with self.db() as db:
   if before:rows=db.execute("SELECT "+fields+" FROM jobs WHERE id<? ORDER BY id DESC LIMIT ?",(int(before),limit)).fetchall()
   else:rows=db.execute("SELECT "+fields+" FROM jobs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
   total=db.execute("SELECT count(*) FROM jobs").fetchone()[0]
  jobs=[dict(r) for r in rows]
  with self.live_lock:
   for job in jobs:
    live=self.live_messages.get(job["id"])
    if live:job["message"],job["updated"]=live
  return {"jobs":jobs,"total":total}
 def status(self):
  with self.db() as db:
   counts={r["status"]:r["n"] for r in db.execute("SELECT status,count(*) n FROM jobs GROUP BY status")}
   components=self.active_components(db)
  history=self.history(limit=30)
  return dict(history,queued=counts.get("queued",0),running=counts.get("running",0),active_components=components)
 def run(self):
  while not self.stop.is_set():
   with self.db() as db:
    db.execute("BEGIN IMMEDIATE")
    row=db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
    started=time.time()
    if row:db.execute("UPDATE jobs SET status='running',started=?,updated=? WHERE id=?",(started,started,row["id"]))
   if not row:self.wake.wait(.5);self.wake.clear();continue
   clock=time.monotonic();subject=row["label"];change="";after_commit=[]
   transactional=True
   try:
    payload=json.loads(row["payload"])
    action=parse_qs(payload.get("body","")).get("action",[""])[0]
    transactional=action not in RUNTIME_ACTIONS and action!="geodata_source_download"
    if self.recovery and transactional:self.recovery.begin(row["id"],payload)
    if self.describe:
     try:subject,change=self.describe(payload)
     except Exception:subject=row["label"];change="Применение настроек"
    with self.db() as db:db.execute("UPDATE jobs SET subject=?,change_text=? WHERE id=?",(subject,change,row["id"]))
    def report(stage):
     with self.live_lock:self.live_messages[row["id"]]=(str(stage),time.time())
    if parse_qs(payload.get("body","")).get("action",[""])[0] in {"service_refresh_geodata","geodata_source_download","route_apply","configuration_apply","panel_update_install",*RUNTIME_ACTIONS}:
     payload["_job_id"]=row["id"]
     payload["_progress"]=report
     payload["_after_commit"]=after_commit.append
    message=self.execute(payload)
    if self.recovery and transactional:self.recovery.flush(row["id"])
    state="done";message=str(message or "Изменения применены")
   except Exception as error:
    state="failed";message=str(error) or type(error).__name__
    if self.recovery and transactional:
     try:self.recovery.abort(row["id"])
     except Exception as rollback_error:message+="; ошибка отката: "+str(rollback_error)
   duration=time.monotonic()-clock;finished=time.time()
   with self.db() as db:
    db.execute("UPDATE jobs SET status=?,message=?,payload=NULL,updated=?,finished=?,duration=? WHERE id=?",(state,message,finished,finished,duration,row["id"]))
   with self.live_lock:self.live_messages.pop(row["id"],None)
   if self.recovery and transactional:
    try:self.recovery.finish(row["id"],state)
    except Exception as journal_error:
     print("Journal cleanup error:",journal_error,flush=True)
     continue
   if state=="done":
    for cleanup in after_commit:
     try:cleanup()
     except OSError as cleanup_error:print("Service file cleanup error:",cleanup_error,flush=True)
 def close(self):
  self.stop.set();self.wake.set()
  if self.worker:self.worker.join(timeout=5)
