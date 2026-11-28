from ui_i18n import text as _ui, message as _ui_message
from durable_io import replace as durable_replace
from pathlib import Path
from configuration_draft import state_path
#!/usr/bin/env python3
import html
import json
import os
import re
import subprocess
import tempfile
import shutil
import time
import threading
from urllib.parse import parse_qs, urlencode, quote, urlsplit
from urllib.request import urlopen
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from service_routes_panel import render_services, handle_action, route_targets, read_services, service_rule_count, service_domains_for_listing, service_edit_url, effective_domain_rules
from routing_panel import render_routing_panel, handle_routing_action, restore_routing_settings

BASE = "/etc/mihomo/rules"
SOURCE = os.path.join(BASE, "ru-blocked-source.txt")
SOURCE_NAME = os.path.splitext(os.path.basename(SOURCE))[0]
ADDS = os.path.join(BASE, "ru-blocked-local-add.txt")
REMOVES = os.path.join(BASE, "ru-blocked-local-remove.txt")
DELETED = os.path.join(BASE, "ru-blocked-local-delete.txt")
BUILD = os.path.join(BASE, "update-ru-blocked.sh")
REFRESH = os.path.join(BASE, "refresh-ru-blocked.sh")
FILTER_FILE = os.path.join(BASE, "ru-blocked-filters.txt")
PORT = 9091
FAVICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
               '<rect width="64" height="64" rx="12" fill="#3565e8"/>'
               '<path d="M19 17v20c0 9 5 13 13 13s13-4 13-13V17" '
               'fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round"/>'
               '</svg>')
FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,' + quote(FAVICON_SVG, safe='') + '">'
PAGE_SIZE = 25
BACKUP_LIMIT = 32 * 1024 * 1024
BACKUP_FORMAT = "mihomo-control-backup"

DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+"
)


def read_service_domain_states(query=""):
    services_enabled = True
    settings_path = state_path(os.path.join(BASE, "routing-settings.json"))
    if os.path.isfile(settings_path):
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)
        services_enabled = bool(settings.get("services_enabled", True))

    states = {}
    for service in read_services():
        if not isinstance(service, dict):
            continue
        name = str(service.get("name", "")).strip() or "Правило"
        active = services_enabled and bool(service.get("enabled", True))
        state = {"names": [name], "enabled": active}
        for raw in service_domains_for_listing(service):
            domain = str(raw).strip().lower().rstrip(".")
            if not domain or not (query in domain or query.endswith("." + domain)):
                continue
            item = states.setdefault(domain, state)
            if name not in item["names"]:
                states[domain] = {"names": [*item["names"], name], "enabled": item["enabled"] or active}
    return states


def read_source():
    result = set()
    with open(state_path(SOURCE), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("domain:"):
                result.add(line[7:].strip().lower())
    return result


def read_local(path):
    path = state_path(path)
    result = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                value = line.strip().lower()
                if value and not value.startswith("#"):
                    result.add(value)
    return result


def write_local(path, values):
    fd, temp = tempfile.mkstemp(prefix=".domains-", dir=BASE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for value in sorted(values):
                f.write(value + "\n")
        durable_replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def valid_domain(value):
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("Некорректное доменное имя: " + value)
    return value


def set_local_domain_dns(domain, mode):
    from durable_io import write
    from service_routes_panel import apply_services

    path = Path(BASE) / "local-domain-dns.json"
    previous = state_path(path).read_bytes() if state_path(path).exists() else None
    values = json.loads(previous) if previous else {}
    if mode is None:
        if domain not in values:
            return ""
        del values[domain]
    else:
        if mode not in {"FakeIP", "RealIP", "NODOMAIN"}:
            raise ValueError("Недопустимый режим DNS")
        values[domain] = mode
    write(path, json.dumps(values, ensure_ascii=False).encode())
    try:
        items = read_services()
        return apply_services(items, items, "DNS домена обновлён.")
    except Exception:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            write(path, previous)
        raise


def run_script(path):
    result = subprocess.run(
        [path], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=240
    )
    output = result.stdout.strip()
    if result.returncode:
        raise RuntimeError(output or "Команда завершилась с ошибкой")
    return output


def change_domains(action, old_value, new_value=""):
    source = read_source()
    adds = read_local(ADDS)
    removes = read_local(REMOVES)
    deleted = read_local(DELETED)

    old_adds = set(adds)
    old_removes = set(removes)
    old_deleted = set(deleted)

    domain = valid_domain(old_value) if old_value else ""

    if action == "add":
        raw_domains = [value.strip() for value in re.split(r"[;\r\n]+", new_value) if value.strip()]
        if not raw_domains:
            raise ValueError("Укажите хотя бы один домен")
        new_domains = {valid_domain(value) for value in raw_domains}
        local_before = len(adds)
        for new_domain in new_domains:
            deleted.discard(new_domain)
            removes.discard(new_domain)
            if new_domain not in source:
                adds.add(new_domain)
        added_count = len(adds) - local_before

    elif action == "enable":
        if not domain:
            raise ValueError("Не указан домен")
        deleted.discard(domain)
        removes.discard(domain)
        if domain not in source:
            adds.add(domain)

    elif action == "disable":
        if not domain:
            raise ValueError("Не указан домен")
        removes.add(domain)

    elif action == "delete":
        if not domain:
            raise ValueError("Не указан домен")
        adds.discard(domain)
        removes.discard(domain)
        if domain in source:
            deleted.add(domain)
        else:
            deleted.discard(domain)

    else:
        raise ValueError("Неизвестное действие")

    try:
        from domain_provider import update_split
        edited = [(path, previous) for path, previous, current in
                  ((ADDS, old_adds, adds), (REMOVES, old_removes, removes), (DELETED, old_deleted, deleted))
                  if previous != current]
        current_values = {ADDS: adds, REMOVES: removes, DELETED: deleted}
        for path, _ in edited:
            write_local(path, current_values[path])
        output = update_split()
    except Exception:
        for path, previous in edited:
            write_local(path, previous)
        raise

    if action == "add":
        output += "\nDomains submitted: %d; new local domains: %d; already in source: %d." % (
            len(new_domains), added_count, len(new_domains & source)
        )
    return output


def clear_auto_domains():
    from configuration_draft import staging, capture_write
    if staging():
        capture_write(SOURCE,b" ")
        return "Очистка списка доменов сохранена в черновик"
    domains = read_source()
    if not domains:
        return "Автоматически загруженных доменов нет."

    backup = SOURCE + ".bak-before-clear-" + time.strftime("%Y%m%d-%H%M%S")
    fd, temp_path = tempfile.mkstemp(prefix=".ru-blocked-empty-source-", dir=BASE)
    os.close(fd)
    try:
        shutil.copy2(SOURCE, backup)
        durable_replace(temp_path, SOURCE)
        try:
            output = run_script(BUILD)
        except Exception:
            shutil.copy2(backup, SOURCE)
            raise
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return "Очищено автозагруженных доменов: %d. Локальные домены сохранены. Резервная копия: %s\n%s" % (
        len(domains), os.path.basename(backup), output
    )



def _optional_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f: return f.read()
    except FileNotFoundError: return ""


def _create_data_backup():
    import proxy_manager
    from service_routes_panel import DATA as SERVICES_FILE
    from routing_panel import SETTINGS as ROUTING_SETTINGS_FILE
    with open(SERVICES_FILE, encoding="utf-8") as f: services=json.load(f)
    try:
        with open(ROUTING_SETTINGS_FILE, encoding="utf-8") as f: routing=json.load(f)
    except FileNotFoundError: routing={}
    return {"format":BACKUP_FORMAT,"version":1,"created_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
      "data":{"domains":{"source":_optional_text(SOURCE),"added":_optional_text(ADDS),"disabled":_optional_text(REMOVES),
      "deleted":_optional_text(DELETED),"filters":_optional_text(FILTER_FILE)},"services":services,
      "proxies":proxy_manager.read(),"routing_settings":routing}}


def render_backup_page():
    return _ui('\n<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Резервная копия</title><style></style></head><body>\n<section class="panel backup-panel"><h2>Резервная копия</h2>\n<p>Сохраняются полные настройки Mihomo: активная и стартовая конфигурации, шаблон, настройки DNS, маршрутов и прокси, базы доменов и правил, ручные изменения и фильтры загрузки.</p>\n<p>Конфигурация RouterOS и DHCP-аренды требуют отдельной резервной копии RouterOS.</p>\n<p class="backup-note"><strong>Важно:</strong> файл содержит адреса серверов и данные доступа к прокси. Храните его в безопасном месте.</p>\n<div class="backup-actions"><a class="backup-download" href="/?download=backup">Скачать резервную копию</a></div>\n<hr><h3>Восстановить из файла</h3>\n<p>Выберите ранее сохранённый JSON-файл. Текущие настройки Mihomo, базы доменов и правил будут заменены данными из файла.</p>\n<div class="backup-actions"><input id="backup-file" type="file" accept=".json,application/json">\n<button id="backup-restore" type="button" disabled>Восстановить из файла</button></div>\n<div id="backup-result" role="status" aria-live="polite"></div></section>\n<style>\n.backup-panel{width:100%;max-width:none;box-sizing:border-box;padding:24px;margin:0 0 18px}.backup-panel p{line-height:1.55}\nbody .backup-panel .backup-note{padding:12px 14px;border-left:4px solid #315ee8;background:#eef3ff;color:#182033;border-radius:7px}body .backup-panel .backup-note strong{color:inherit}\n.backup-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:14px 0}\nbody .backup-panel .backup-download,body .backup-panel #backup-restore{display:inline-flex;align-items:center;justify-content:center;min-height:40px;margin:0;padding:8px 14px;box-sizing:border-box;border:1px solid #315ee8;border-radius:7px;background:#315ee8;color:#fff;text-decoration:none;font:inherit;font-weight:700;line-height:1.4;cursor:pointer}body .backup-panel #backup-restore:disabled{opacity:.5;cursor:not-allowed}body .backup-panel .backup-download:hover,body .backup-panel #backup-restore:not(:disabled):hover{background:#244dcc;border-color:#244dcc}@media(prefers-color-scheme:dark){body .backup-panel .backup-note{background:#202a3b;color:#edf1fa;border-left-color:#8aa9ff}}\n.backup-panel hr{border:0;border-top:1px solid #d8deea;margin:22px 0}\n#backup-result{margin-top:12px;white-space:pre-wrap}#backup-result.error{color:#b42318}#backup-result.success{color:#087443}\n</style>\n<script>\nconst bf=document.getElementById("backup-file"),br=document.getElementById("backup-restore"),out=document.getElementById("backup-result");\nbf.addEventListener("change",()=>{br.disabled=!bf.files.length;out.textContent="";out.className="";});\nbr.addEventListener("click",async()=>{const file=bf.files[0];if(!file)return;\n if(file.size>32*1024*1024){out.textContent="Файл превышает допустимый размер 32 МБ.";out.className="error";return;}\n if(!confirm("Настройки Mihomo и базы доменов и правил будут заменены. Продолжить восстановление?"))return;\n br.disabled=true;out.textContent="Проверка и восстановление…";out.className="";\n try{const r=await fetch("/api/backup/restore",{method:"POST",headers:{"Content-Type":"application/json"},body:file});\n const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||"Не удалось восстановить данные");\n const jobId=Number(j.job_id);if(!Number.isSafeInteger(jobId)||jobId<1)throw new Error("Панель не вернула номер задания");\n bf.disabled=true;out.textContent="Восстановление в очереди. Задание №"+jobId+".";\n const deadline=Date.now()+15*60*1000;\n while(Date.now()<deadline){\n  await new Promise(resolve=>setTimeout(resolve,1500));\n  let job;\n  try{\n   const status=await fetch("/api/actions/history?before="+(jobId+1),{cache:"no-store",signal:AbortSignal.timeout(6000)});\n   if(!status.ok)throw new Error();\n   job=(await status.json()).jobs.find(item=>item.id===jobId);\n  }catch(e){out.textContent="Ожидаем связь с панелью. Задание №"+jobId+".";continue;}\n  if(job?.status==="failed")throw new Error(job.message||"Не удалось восстановить данные");\n  if(job?.status==="done"){out.textContent=job.message||"Восстановление завершено.";out.className="success";bf.disabled=false;bf.value="";return;}\n  if(job?.status==="running")out.textContent=job.message||"Выполняется восстановление…";\n }\n out.textContent="Результат ещё не получен. Проверьте задание №"+jobId+" в очереди.";out.className="";\n }catch(e){out.textContent="Ошибка восстановления: "+e.message;out.className="error";bf.disabled=false;br.disabled=false;}});\n</script>\n</body></html>\n')


def _atomic_write(path, content):
    fd,tmp=tempfile.mkstemp(prefix=".backup-restore-",dir=os.path.dirname(path))
    try:
        with os.fdopen(fd,"wb") as f: f.write(content); f.flush(); os.fsync(f.fileno())
        durable_replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def _restore_data_backup(payload):
    import proxy_manager, service_routes_panel, routing_panel
    if not isinstance(payload,dict) or payload.get("format")!=BACKUP_FORMAT or payload.get("version")!=1:
        raise ValueError("Неподдерживаемый формат резервной копии")
    data=payload.get("data")
    if not isinstance(data,dict): raise ValueError("В резервной копии отсутствуют данные")
    domains,services,proxies=data.get("domains"),data.get("services"),data.get("proxies")
    routing=data.get("routing_settings",{})
    keys=("source","added","disabled","deleted","filters")
    if not isinstance(domains,dict) or any(not isinstance(domains.get(k),str) for k in keys):
        raise ValueError("Некорректный раздел доменов или фильтров")
    if not isinstance(services,list) or any(not isinstance(x,dict) for x in services):
        raise ValueError("Некорректный список правил")
    if not isinstance(proxies,dict) or not isinstance(proxies.get("nodes"),list):
        raise ValueError("Некорректная база прокси")
    if not isinstance(routing,dict): raise ValueError("Некорректные настройки маршрута")
    nodes=proxies["nodes"]
    if any(not isinstance(n,dict) or not isinstance(n.get("proxy"),dict) or not n["proxy"].get("name") for n in nodes):
        raise ValueError("В резервной копии есть прокси без имени или настроек")
    if len({n["proxy"]["name"] for n in nodes})!=len(nodes): raise ValueError("В резервной копии есть повторяющиеся имена прокси")
    if domains["filters"].strip():
        import domain_filter
        domain_filter.parse_patterns(domains["filters"].strip())
    services=service_routes_panel.ensure_service_ids(services)
    files={SOURCE:domains["source"].encode(),ADDS:domains["added"].encode(),REMOVES:domains["disabled"].encode(),
      DELETED:domains["deleted"].encode(),FILTER_FILE:domains["filters"].encode(),
      service_routes_panel.DATA:(json.dumps(services,ensure_ascii=False,indent=2)+"\n").encode(),
      proxy_manager.DB:(json.dumps(proxies,ensure_ascii=False,indent=2)+"\n").encode(),
      proxy_manager.PF:(json.dumps({"proxies":[n["proxy"] for n in nodes]},ensure_ascii=False,indent=2)+"\n").encode(),
      routing_panel.SETTINGS:(json.dumps(routing,ensure_ascii=False,indent=2)+"\n").encode()}
    if sum(map(len,files.values()))>BACKUP_LIMIT: raise ValueError("Резервная копия превышает допустимый размер 32 МБ")
    snapshots={path:Path(path).read_bytes() if os.path.exists(path) else None for path in files}
    try:
        for path,content in files.items(): _atomic_write(path,content)
        output=run_script(BUILD); proxy_manager.sync(); routing_panel.restore_routing_settings()
        return "Восстановление завершено. "+output
    except Exception:
        for path,content in snapshots.items():
            if content is None:
                try: os.unlink(path)
                except FileNotFoundError: pass
            else: _atomic_write(path,content)
        try: run_script(BUILD); proxy_manager.sync(); routing_panel.restore_routing_settings()
        except Exception: pass
        raise


def create_backup():
    from config_backup import export
    return export(_create_data_backup())

def restore_backup(payload):
    from config_backup import restore
    return restore(payload, _restore_data_backup, create_backup)

def esc(value):
    return html.escape(str(value), quote=True)



MIHOMO_API = "http://127.0.0.1:9090"
DELAY_TEST_URL = "https://www.gstatic.com/generate_204"


def get_proxy_nodes():
    try:
        with urlopen(MIHOMO_API + "/proxies", timeout=3) as response:
            proxies = json.loads(response.read().decode("utf-8"))["proxies"]
        return [
            name[len("CHANNEL-"):] for name in proxies
            if name.startswith("CHANNEL-")
        ]
    except Exception:
        return []


def get_active_proxy_nodes():
    """Return only CHANNEL nodes enabled for load balancing in the proxy panel."""
    names = get_proxy_nodes()
    try:
        with open(os.path.join(BASE, "managed-proxies.json"), encoding="utf-8") as f:
            db = json.load(f)
        managed = {
            item.get("proxy", {}).get("name"): item
            for item in db.get("nodes", [])
            if isinstance(item, dict) and isinstance(item.get("proxy"), dict)
        }
        overrides = db.get("balance_overrides", {})
        return [
            name for name in names
            if bool(overrides.get(name, managed.get(name, {}).get("balance", True)))
        ]
    except Exception:
        return []


def check_proxy_delay(name):
    if name in get_proxy_nodes():
        prefix="/proxies/"+quote("CHANNEL-"+name,safe="")+"/delay?"
    else:
        import proxy_manager
        if name not in {item['proxy']['name'] for item in proxy_manager.read()['nodes']}:
            raise ValueError("Unknown VPN connection")
        prefix="/providers/proxies/USER-MANAGED/"+quote(name,safe="")+"/healthcheck?"
    path = prefix + urlencode({
        "url": DELAY_TEST_URL,
        "timeout": 5000,
    })
    with urlopen(MIHOMO_API + path, timeout=7) as response:
        result = json.loads(response.read().decode("utf-8"))

    delay = result.get("delay")
    if not isinstance(delay, (int, float)) or isinstance(delay, bool) or delay <= 0:
        raise ValueError("Invalid delay response")
    return int(delay)


_DOMAIN_COUNTS_LOCK = threading.Lock()
_DOMAIN_COUNTS_CACHE = None


def domain_counts_signature():
    result = []
    for path in (SOURCE, ADDS, REMOVES, DELETED, os.path.join(BASE, "service-routes.json")):
        try:
            stat = os.stat(state_path(path))
            result.append((stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
        except FileNotFoundError:
            result.append(None)
    return tuple(result)


def get_domain_counts(data=None, expected_signature=None, service_domains=None):
    """Cache the counts without retaining domain sets between requests."""
    global _DOMAIN_COUNTS_CACHE
    with _DOMAIN_COUNTS_LOCK:
        signature = domain_counts_signature()
        if _DOMAIN_COUNTS_CACHE is not None:
            saved_signature, counts = _DOMAIN_COUNTS_CACHE
            if saved_signature == signature:
                return counts
        if data is None:
            source = read_source()
            adds = read_local(ADDS)
            removes = read_local(REMOVES)
            deleted = read_local(DELETED)
            expected_signature = signature
        else:
            source, adds, removes, deleted = data
        total = enabled = 0
        for group in (source, (d for d in adds if d not in source)):
            for domain in group:
                if domain not in deleted:
                    total += 1
                    enabled += domain not in removes
        if service_domains is None:
            service_domains = read_service_domain_states()
        total += sum(domain in deleted or (domain not in source and domain not in adds)
                     for domain in service_domains)
        counts = (total, enabled)
        if expected_signature == signature == domain_counts_signature():
            _DOMAIN_COUNTS_CACHE = (signature, counts)
        return counts


_DOMAIN_REFRESH_LOCK = threading.Lock()
_DOMAIN_REFRESH_RUNNING = False
_DOMAIN_REFRESH_SIGNATURE = None


def refresh_domain_counts(signature):
    global _DOMAIN_REFRESH_RUNNING
    try:
        get_domain_counts()
    except Exception as error:
        print(f"Domain counts unavailable: {error}", flush=True)
    finally:
        with _DOMAIN_REFRESH_LOCK:
            _DOMAIN_REFRESH_RUNNING = False


def cached_domain_counts():
    global _DOMAIN_REFRESH_RUNNING, _DOMAIN_REFRESH_SIGNATURE
    signature = domain_counts_signature()
    with _DOMAIN_REFRESH_LOCK:
        cached = _DOMAIN_COUNTS_CACHE
        if cached is not None and cached[0] == signature:
            return cached[1]
        if not _DOMAIN_REFRESH_RUNNING and _DOMAIN_REFRESH_SIGNATURE != signature:
            _DOMAIN_REFRESH_SIGNATURE = signature
            _DOMAIN_REFRESH_RUNNING = True
            threading.Thread(target=refresh_domain_counts, args=(signature,),
                             name="domain-counts", daemon=True).start()
        return cached[1] if cached is not None else ("—", "—")


def group_rule_creation_panels(page):
    """Present the three existing creation methods in one stable panel."""
    editor_marker = '<div class="panel">\n<details id="service-editor"'
    option_marker = '<div class="panel"><details class="panel-spoiler"><summary>'
    list_marker = '<div class="panel"><div class="configured-services-header"'
    try:
        editor_start = page.index(editor_marker)
        file_start = page.index(option_marker, editor_start)
        index_start = page.index(option_marker, file_start + len(option_marker))
        list_start = page.index(list_marker, index_start)
    except ValueError:
        return page
    english = '<summary>Add rule</summary>' in page[editor_start:file_start]
    labels = (('Create rule', 'Manually', 'From MetaCubeX index', 'From GeoDAT file') if english else
              ('Создать правило', 'Вручную', 'Из индекса MetaCubeX', 'Из файла GeoDAT'))
    editor = page[editor_start:file_start].replace('<div class="panel">', '<div class="rule-create-option">', 1)
    editor = re.sub(r'<summary>.*?</summary>', '<summary>' + labels[1] + '</summary>', editor, count=1, flags=re.S)
    index = page[index_start:list_start].replace('<div class="panel">', '<div class="rule-create-option">', 1)
    index = re.sub(r'<summary>.*?</summary>', '<summary>' + labels[2] + '</summary>', index, count=1, flags=re.S)
    source_file = page[file_start:index_start].replace('<div class="panel">', '<div class="rule-create-option">', 1)
    source_file = re.sub(r'<summary>.*?</summary>', '<summary>' + labels[3] + '</summary>', source_file, count=1, flags=re.S)
    editing = bool(re.search(r'<details id="service-editor"[^>]*\bopen\b', editor))
    tab_buttons = ''.join(
        '<button type="button" role="tab" data-rule-tab="' + key + '" aria-controls="rule-create-' + key + '">' + label + '</button>'
        for key, label in zip(('manual', 'index', 'file'), labels[1:])
    )
    sections = ''.join(
        section.replace('class="rule-create-option"', 'class="rule-create-option" id="rule-create-' + key + '" role="tabpanel"', 1)
        for key, section in (('manual', editor), ('index', index), ('file', source_file))
    )
    tabs_script = '''<script>
(()=>{
 const panel=document.querySelector('.rule-create-panel');
 if(!panel)return;
 const buttons=[...panel.querySelectorAll('[data-rule-tab]')];
 const sections=[...panel.querySelectorAll('.rule-create-option')];
 sections.forEach(section=>{const details=section.querySelector('details');if(details)details.open=true;});
 panel.classList.add('js-tabs');
 function select(key){
  buttons.forEach(button=>{const active=button.dataset.ruleTab===key;button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;});
  sections.forEach(section=>{const active=section.id==='rule-create-'+key;section.classList.toggle('active',active);section.hidden=!active;});
 }
 buttons.forEach((button,index)=>{
  button.addEventListener('click',()=>select(button.dataset.ruleTab));
  button.addEventListener('keydown',event=>{
   if(event.key!=='ArrowRight'&&event.key!=='ArrowLeft')return;
   event.preventDefault();
   const step=event.key==='ArrowRight'?1:-1;
   const next=buttons[(index+step+buttons.length)%buttons.length];next.focus();select(next.dataset.ruleTab);
  });
 });
 select('manual');
})();
</script>'''
    return (page[:editor_start] + '<div class="panel rule-create-panel"><details class="panel-spoiler rule-create-disclosure"' +
            (' open' if editing else '') + '><summary>' + labels[0] + '</summary><div class="rule-create-tabs" role="tablist" aria-label="' +
            labels[0] + '">' + tab_buttons + '</div>' + sections + '</details></div>\n' + tabs_script + page[list_start:])


def decorate_page(page, active_tab, targets=None, domain_counts=None):
    _ui('Добавляет общую оболочку к существующей странице.')
    missing_providers = []
    try:
        domain_count, enabled_domains = domain_counts if domain_counts is not None else cached_domain_counts()
    except Exception:
        domain_count = enabled_domains = 0
    try:
        services = read_services()
        service_count = len(services)
    except Exception:
        service_count = 0
    try:
        proxy_names = set()
        for provider_name in ("SRV", "USER-MANAGED"):
            try:
                with urlopen(MIHOMO_API + "/providers/proxies/" + provider_name, timeout=5) as response:
                    provider = json.loads(response.read().decode("utf-8"))
            except Exception as provider_error:
                if getattr(provider_error, "code", None) == 404:
                    missing_providers.append(provider_name)
                    continue
                raise
            for proxy in provider.get("proxies", []):
                name = proxy.get("name")
                if isinstance(name, str) and name and name not in {"DIRECT", "REJECT", "PASS", "COMPATIBLE"}:
                    proxy_names.add(name)
        proxy_count = len(proxy_names)
        proxy_active_count = len(set(get_active_proxy_nodes()) & proxy_names)
        api_ok = True
    except Exception:
        proxy_count = proxy_active_count = 0
        api_ok = False

    from router_routes import route_count
    ip_route_count = route_count()
    if ip_route_count is None:ip_route_count = '—'
    try:
        with urlopen(MIHOMO_API + "/version", timeout=3) as response:
            api_ok = response.status == 200
    except Exception:
        api_ok = False
    api_label = _ui('API Mihomo доступен') if api_ok else _ui('API Mihomo недоступен')
    if api_ok and missing_providers:
        api_label += _ui(' · конфигурация неполная')
    api_dot = "#35c58a" if api_ok else "#e0a33e"

    proxy_buttons = "".join(
        '<button type="button" class="proxy-health-btn" '
        'data-node="' + html.escape(name, quote=True) + '" '
        'onclick="checkProxyHealth(this)">'
        + html.escape(name)
        + '<span class="proxy-health-result">—</span></button>'
        for name in get_active_proxy_nodes()
    )

    health_script = """
<script>
const proxyHealthStorageKey = "mihomo-proxy-health-v1";
function readProxyHealthCache() {
  try { return JSON.parse(localStorage.getItem(proxyHealthStorageKey) || "{}"); }
  catch (e) { return {}; }
}
function renderProxyHealth(button, value) {
  const result = button.querySelector(".proxy-health-result");
  button.classList.remove("health-ok", "health-error");
  if (Number.isFinite(value) && value > 0) {
    result.textContent = value + " ms";
    button.classList.add("health-ok");
  } else {
    result.textContent = "−1";
    button.classList.add("health-error");
  }
}
function restoreProxyHealth() {
  const cache = readProxyHealthCache();
  for (const button of document.querySelectorAll(".proxy-health-btn[data-node]")) {
    const saved = cache[button.dataset.node];
    if (saved && Number.isFinite(saved.delay)) renderProxyHealth(button, saved.delay);
  }
}
async function checkProxyHealth(button) {
  if (button.dataset.checking === "1") return;
  button.dataset.checking = "1";
  button.classList.add("health-checking");
  const result = button.querySelector(".proxy-health-result");
  if (result.textContent === "—") result.textContent = "…";
  let delay = -1;
  try {
    const response = await fetch(
      "/api/proxy-delay?name=" + encodeURIComponent(button.dataset.node),
      {cache: "no-store"}
    );
    const data = await response.json();
    if (!response.ok || !Number.isFinite(data.delay) || data.delay < 1) {
      throw new Error("Delay check failed");
    }
    delay = data.delay;
  } catch (e) {
    delay = -1;
  } finally {
    renderProxyHealth(button, delay);
    try {
      const cache = readProxyHealthCache();
      cache[button.dataset.node] = {delay: delay, checkedAt: Date.now()};
      localStorage.setItem(proxyHealthStorageKey, JSON.stringify(cache));
    } catch (e) {}
    button.classList.remove("health-checking");
    button.dataset.checking = "0";
  }
}
function refreshProxyHealth() {
  for (const button of document.querySelectorAll(".unified-topbar .proxy-health-btn[data-node]")) {
    checkProxyHealth(button);
  }
}
const proxyTabNavigationKey = "mihomo-proxy-tab-navigation";
let arrivedByTabNavigation = false;
try {
  arrivedByTabNavigation = sessionStorage.getItem(proxyTabNavigationKey) === "1";
  sessionStorage.removeItem(proxyTabNavigationKey);
} catch (e) {}
document.addEventListener("click", function(event) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const link = event.target.closest(".unified-tabs a");
  if (link && (!link.target || link.target === "_self")) {
    try { sessionStorage.setItem(proxyTabNavigationKey, "1"); } catch (e) {}
  }
}, true);
restoreProxyHealth();
if (!arrivedByTabNavigation) refreshProxyHealth();
setInterval(refreshProxyHealth, 120000);
</script>
"""

    shell = ''.join(('\n<header class="unified-topbar">\n  <div class="unified-brand">\n    <div class="unified-logo" aria-hidden="true">UvpnC</div>\n    <div>\n      <div class="unified-brand-title">Universal VPN Core</div>\n    </div>\n  </div>\n  <div class="unified-status">\n    <div class="unified-health-group">', f'{proxy_buttons}', '</div>\n  </div>\n</header>\n', f'{health_script}', '\n<main class="unified-main">\n  <section class="unified-metrics">\n    <div class="unified-metric"><div>VPN</div><strong>', f'{proxy_active_count}', '/', f'{proxy_count}', _ui('</strong><small>Активные / всего в конфигурации</small></div>\n    <div class="unified-metric"><div>Правила</div><strong>'), f'{service_count}', _ui('</strong><small>В пользовательском списке</small></div>\n    <div class="unified-metric"><div>Домены</div><strong>'), f'{domain_count}', _ui('</strong><small>В текущем списке</small></div>\n    <div class="unified-metric"><div>Маршруты</div><strong>'), f'{ip_route_count}', _ui('</strong><small>IP-маршруты через контейнер</small></div>\n  </section>\n  <!--CONFIG_QUEUE_SLOT-->\n  '), f'{render_routing_panel()}', _ui('\n  <nav class="unified-tabs" aria-label="Разделы">\n    <a class="'), f"{('active' if active_tab == 'proxies' else '')}", '" href="/?tab=vpn">VPN</a>\n    <a class="', f"{('active' if active_tab == 'services' else '')}", _ui('" href="/?tab=services">Правила</a>\n    <a class="'), f"{('active' if active_tab == 'geodata' else '')}", '" href="/?tab=geodata">GeoDAT</a>\n    <a class="', f"{('active' if active_tab == 'domains' else '')}", '" href="/">DNS</a>\n    <a class="', f"{('active' if active_tab == 'routes' else '')}", _ui('" href="/?tab=routes">Маршруты</a>\n    <a class="'), f"{('active' if active_tab == 'clients' else '')}", _ui('" href="/?tab=clients">Клиенты</a>\n    <a class="'), f"{('active' if active_tab == 'components' else '')}", _ui('" href="/?tab=components">Компоненты</a>\n    <a class="'), f"{('active' if active_tab == 'logs' else '')}", _ui('" href="/?tab=logs">Логи</a>\n    <a class="'), f"{('active' if active_tab == 'backup' else '')}", _ui('" href="/?tab=backup">Резервная копия</a>\n  </nav>\n')))
    queue_html = _ui(Path(os.path.join(BASE, "action_queue_ui.html")).read_text(encoding="utf-8"))
    shell = shell.replace("<!--CONFIG_QUEUE_SLOT-->", "", 1)
    shell = re.sub(r'(</section>)(\s*<nav class="unified-tabs")', lambda match: queue_html + match.group(1) + match.group(2), shell, count=1)
    # Общие стили макета поверх прежних стилей страниц.
    css = _ui('\n.unified-topbar{width:calc(100% - 32px);max-width:1100px;box-sizing:border-box;margin:0 auto;\nbackground:#17243d;color:#f7f9ff;padding:18px clamp(16px,4vw,48px);\ndisplay:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}\n.unified-brand{display:flex;align-items:center;gap:12px}\n.unified-logo{height:40px;padding:0 9px;border-radius:13px;display:grid;place-items:center;\nbackground:#315ee8;color:white;font-weight:800;font-size:13px}\n.unified-brand-title{font-size:18px;font-weight:800;letter-spacing:-.4px}\n.unified-brand-sub{font-size:12px;color:#b9c5dd;margin-top:3px}\n.unified-api{display:flex;align-items:center;gap:8px;font-size:12px;color:#dce5f8;\nborder:1px solid #3c4a64;border-radius:999px;padding:8px 12px}\n.unified-api span{width:7px;height:7px;border-radius:50%;display:inline-block}\n.unified-main{width:calc(100% - 32px);max-width:1100px;box-sizing:border-box;margin:0 auto;padding:0 clamp(14px,3vw,32px) 44px}\n.unified-heading{margin-bottom:20px}\n.unified-eyebrow{font-size:11px;font-weight:800;letter-spacing:1.3px;color:#315ee8}\n.unified-title{font-size:28px;letter-spacing:-.8px;margin:7px 0}\n.unified-lead{font-size:14px;line-height:1.5;color:#69758a;margin:0}\n.unified-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}\n.unified-metric{background:var(--surface,#fff);border:1px solid var(--border,#e0e5ef);\nborder-radius:14px;padding:15px;box-shadow:0 8px 28px #18203312;min-width:0}\n.unified-metric div{font-size:12px;color:#69758a}\n.unified-metric strong{display:block;font-size:25px;letter-spacing:-.8px;margin-top:6px}\n.unified-metric small{display:block;font-size:11px;color:#69758a;margin-top:4px}\n.routing-panel{\n  color:#182033;background:#fff;border:1px solid #d5dbe5;\n  border-radius:14px;padding:16px;margin:16px 0;\n  box-shadow:0 8px 28px #1820330b;box-sizing:border-box;\n}\n.routing-panel .routing-heading{\n  font-size:16px;font-weight:700;line-height:24px;margin:0 0 12px;\n}\n.routing-panel .routing-grid{\n  display:grid;\n  grid-template-columns:max-content max-content max-content;\n  column-gap:20px;\n  row-gap:12px;\n  align-items:start;\n  justify-content:start;\n}\n.routing-panel .routing-heading{\n  font-size:16px;font-weight:400;line-height:24px;\n  margin:0;color:inherit;white-space:nowrap;\n}\n.routing-panel form.routing-controls{\n  display:contents;\n}\n.routing-panel select option.current-route{color:#16803c;font-weight:700}\n.routing-panel select{\n  display:block;width:220px;max-width:100%;height:40px;\n  margin:0;padding:0 10px;box-sizing:border-box;line-height:20px;\n}\n.routing-panel button{\n  display:block;background:#315ee8;color:#fff;border:1px solid #315ee8;\n  border-radius:8px;padding:0 15px;height:40px;min-height:40px;\n  margin:0;box-sizing:border-box;line-height:20px;white-space:nowrap;\n}\n.routing-panel button.service-toggle{\n  min-width:130px;height:40px;padding:0 16px;\n  color:#fff;border:0;border-radius:8px;font-weight:400;\n}\n.routing-panel button.service-on{background:#16803c;border-color:#16803c}\n.routing-panel button.service-off{background:#c62828;border-color:#c62828}\n@media(max-width:600px){\n  .routing-panel .routing-grid{grid-template-columns:1fr;row-gap:10px}\n  .routing-panel .routing-heading:nth-child(1){grid-column:1;grid-row:1}\n  .routing-panel .routing-heading:nth-child(2){grid-column:1;grid-row:3}\n  .routing-panel .routing-heading:nth-child(3){display:none}\n  .routing-panel select{grid-column:1}\n  .routing-panel button.service-toggle{grid-column:1}\n  .routing-panel form.routing-controls > button[type="submit"]:last-child{grid-column:1}\n}\n.routing-panel .routing-error{color:#b42318}\n\n.routing-panel button.service-toggle{\n  min-width:130px;height:40px;padding:0 16px;\n  color:#fff;border:0;border-radius:8px;font-weight:700;\n}\n.routing-panel button.service-on{background:#16803c;border-color:#16803c}\n.routing-panel button.service-off{background:#c62828;border-color:#c62828}\n\n@media(prefers-color-scheme:dark){\n  .routing-panel{color:#edf1fa;background:#171d29;border-color:#343d4c}\n  .routing-panel .routing-check{color:#edf1fa}\n  .routing-panel button{color:#fff;background:#315ee8;border-color:#315ee8}\n}\n.unified-tabs{display:flex;gap:5px;border-bottom:1px solid #e0e5ef;margin:0 0 18px}\n.unified-tabs a{padding:12px 17px;border-bottom:3px solid transparent;margin-bottom:-1px;\ncolor:#69758a;text-decoration:none;font-weight:750}\n.unified-tabs a.active{color:#315ee8;border-bottom-color:#315ee8}\nbody{width:100%;max-width:none;box-sizing:border-box;margin:0;padding:0;background:#f3f5fa;color:#182033;font-family:Inter,ui-sans-serif,system-ui,sans-serif}\nbody>h1,body>p,body>div.panel,body>form{margin-left:auto;margin-right:auto;max-width:1200px}\nbutton,input,select,textarea{font:inherit}\ninput:not([type="hidden"]),select,textarea{\n  color:#182033;background-color:#fff;border:1px solid #b8c2d3;\n  border-radius:7px;padding:9px 10px;box-sizing:border-box;\n}\ninput:not([type="hidden"])::placeholder,textarea::placeholder{\n  color:#69758a;opacity:1;\n}\ninput:not([type="hidden"]):focus,select:focus,textarea:focus{\n  outline:2px solid #8aa9ff;outline-offset:1px;border-color:#315ee8;\n}\ninput:disabled,select:disabled,textarea:disabled{\n  color:#69758a;background-color:#edf0f5;opacity:1;\n}\nbutton{cursor:pointer;border-radius:8px}\n.panel{background:var(--surface,#fff);border-color:var(--border,#e0e5ef);border-radius:14px;\nbox-shadow:0 8px 28px #1820330b}\ntable{border-collapse:collapse}\nth{background:#f7f8fc}\na{color:#315ee8}\n\n/* Контраст старой и новой разметки */\nbody{color:#182033}\nbody h1,body h2,body h3,body p,body b,body strong,\nbody label,body td,body th,body .panel,body .msg{\n  color:#182033;\n}\nbody .panel{\n  color:#182033;background-color:#fff;border-color:#d5dbe5;\n}\nbody .msg{\n  color:#182033;background-color:#eef3ff;\n}\nbody table{background-color:#fff}\nbody th{color:#182033;background-color:#e9eef6}\nbody td{color:#182033}\nbody .unified-lead,body .unified-metric div,\nbody .unified-metric small{\n  color:#475569;\n}\nbody .unified-tabs a{color:#475569}\nbody .unified-tabs a.active{color:#244dcc}\nbody button{\n  color:#182033;background-color:#eef1f6;border-color:#aab4c4;\n}\nbody button.danger{color:#8b1e1e;background-color:#fee2e2;border-color:#efb4b4}\nbody .on{color:#176b35}\nbody .off{color:#8a4b00}\n\n@media(max-width:760px){\n.unified-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}\n.unified-title{font-size:24px}\n.unified-main{padding-top:18px}\n}\n@media(prefers-color-scheme:dark){\nbody{background:#10141d;color:#edf1fa}\n.unified-title{color:#edf1fa}\n.unified-lead,.unified-metric div,.unified-metric small{color:#a0abc0}\n.unified-metric{background:#171b24;border-color:#343d4c}\n.unified-tabs{border-color:#343d4c}\nth{background:#202633}\ninput:not([type="hidden"]),select,textarea{\n  color:#edf1fa;background-color:#1b2230;border-color:#465168;\n}\ninput:not([type="hidden"])::placeholder,textarea::placeholder{\n  color:#a0abc0;\n}\ninput:disabled,select:disabled,textarea:disabled{\n  color:#a0abc0;background-color:#252d3b;\n}\nbody{color:#edf1fa}\nbody h1,body h2,body h3,body p,body b,body strong,\nbody label,body td,body th,body .panel,body .msg{\n  color:#edf1fa;\n}\nbody .panel{\n  color:#edf1fa;background-color:#171d29;border-color:#343d4c;\n}\nbody .msg{color:#edf1fa;background-color:#202a3b}\nbody table{background-color:#171d29}\nbody th{color:#edf1fa;background-color:#202633}\nbody td{color:#edf1fa}\nbody .unified-lead,body .unified-metric div,\nbody .unified-metric small{color:#b3bfd3}\nbody .unified-tabs a{color:#b3bfd3}\nbody .unified-tabs a.active{color:#9bb4ff}\nbody button{\n  color:#edf1fa;background-color:#252d3b;border-color:#465168;\n}\nbody button.danger{\n  color:#ffd1d1;background-color:#48272b;border-color:#754047;\n}\nbody .on{color:#78d99b}\nbody .off{color:#ffc66d}\n\n.unified-status{display:flex;align-items:center;justify-content:flex-end;\ngap:10px;flex-wrap:wrap;margin-left:auto}\n.unified-health-group{display:flex;align-items:center;gap:8px;flex-wrap:wrap}\nbody button.proxy-health-btn{\n  display:inline-flex;align-items:center;justify-content:center;gap:9px;\n  min-height:36px;padding:8px 12px;border:1px solid #465168;border-radius:999px;\n  color:#edf1fa;background:#252d3b;font-size:12px;font-weight:700;\n  cursor:pointer;white-space:nowrap\n}\nbody button.proxy-health-btn .proxy-health-result{\n  display:inline-block;min-width:42px;text-align:center;font-variant-numeric:tabular-nums;\n  color:#b3bfd3;font-weight:800\n}\nbody button.proxy-health-btn.health-ok{border-color:#35c58a;color:#a6f0c9}\nbody button.proxy-health-btn.health-ok .proxy-health-result{color:#35c58a}\nbody button.proxy-health-btn.health-error{border-color:#ef626c;color:#ff858d}\nbody button.proxy-health-btn.health-error .proxy-health-result{color:#ff858d}\nbody button.proxy-health-btn.health-checking{opacity:.75;cursor:wait}\n@media(max-width:620px){\n  .unified-status{width:100%;justify-content:flex-start}\n  .unified-health-group{width:100%}\n}\n}\n')
    if "</style>" in page:
        page = page.replace("</style>", css + "\n</style>", 1)

    # Страница правил в текущем renderer не содержит явных body-тегов.
    if "<body" not in page.lower():
        if "</style>" in page:
            page = page.replace("</style>", "</style><body>", 1)
        else:
            page = page.replace("</html>", "<body></body></html>", 1)

    body_match = re.search(r"<body[^>]*>", page, flags=re.I)
    if body_match:
        page = page[:body_match.end()] + shell + page[body_match.end():]

    if not re.search(r"</body\s*>", page, flags=re.I):
        page = re.sub(r"</html\s*>", "</main></body></html>", page, flags=re.I)
    else:
        page = re.sub(r"</body\s*>", "</main></body>", page, count=1, flags=re.I)

    if active_tab != "proxies":
        page = re.sub(r"(<table\b[^>]*>.*?</table>)", lambda match: '<div class="ui-table-scroll">' + match.group(0) + '</div>', page, flags=re.S|re.I)
    page = re.sub(r"<body\b([^>]*)>", lambda match: '<body' + match.group(1) + ' data-page="' + html.escape(active_tab, quote=True) + '">', page, count=1, flags=re.I)
    common_css = Path(os.path.join(BASE, "control_shared.css")).read_text(encoding="utf-8")
    from interaction_ui import render as render_interaction
    page = re.sub(r'(<body\b[^>]*>)',lambda match:match[1]+render_interaction(BASE),page,count=1,flags=re.I)
    page = page.replace("</body>", '<style id="control-shared-style">' + common_css + '</style></body>', 1)
    # The router panel uses the dark palette regardless of the browser theme.
    return re.sub(
        r"<style\b[^>]*>.*?</style>",
        lambda match: match.group(0)
        .replace("@media(prefers-color-scheme:dark)", "@media all")
        .replace("@media(prefers-color-scheme:light)", "@media not all"),
        page,
        flags=re.S|re.I,
    )


QUEUE = None

def execute_queued_action(payload):
    action=parse_qs(payload.get("body","")).get("action",[""])[0]
    if action in {"geodata_source_download", "service_refresh_geodata", "service_update_source"}:
        return _execute_queued_action(payload)
    from configuration_draft import LOCK
    with LOCK:return _execute_queued_action(payload)

def _execute_queued_action(payload):
    if "subscription_automation" in payload:
        import subscription_automation
        return subscription_automation.apply(payload["subscription_automation"],
                                             before_apply=payload.get("_before_subscription_apply"),
                                             report=payload.get("_progress"))
    import io
    from types import MethodType
    handler=object.__new__(Handler)
    body=payload["body"].encode("utf-8")
    handler.path=payload["path"]
    handler.action_progress=payload.get("_progress", lambda _stage: None)
    handler.before_subscription_apply=payload.get("_before_subscription_apply")
    handler.after_commit=payload.get("_after_commit")
    handler.action_job_id=payload.get("_job_id")
    handler.headers={"Content-Length":str(len(body))}
    handler.rfile=io.BytesIO(body)
    outcome={}
    def redirect(message, tab=None, view=None):
        message=str(message)
        outcome.update(ok=not message.startswith(("Ошибка", "Неизвестное")),message=message)
    def json_result(result, status=200):
        outcome.update(ok=status<400 and bool(result.get("ok")),message=result.get("message",""))
    handler.redirect_message=redirect
    handler.send_json=json_result
    handler._execute_post()
    if not outcome.get("ok"):
        raise RuntimeError(outcome.get("message") or "Действие не выполнено")
    return outcome["message"]

class Handler(BaseHTTPRequestHandler):
    server_version = "RUBlockedPanel/2.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.client_address[0], fmt % args))

    def send_html(self, body, status=200):
        from ui_i18n import bootstrap, LANGUAGE, localize_page_scripts
        body = localize_page_scripts(body)
        try:
            panel_host = urlsplit('http://' + self.headers.get('Host', '')).hostname or ''
        except ValueError:
            panel_host = ''
        title = '<title>UvpnC' + (' - ' + html.escape(panel_host) if panel_host else '') + '</title>'
        body = re.sub(r'<title\b[^>]*>.*?</title>', lambda _: title + FAVICON_LINK,
                      body, count=1, flags=re.I | re.S)
        body = body.replace('lang="ru"', 'lang="' + LANGUAGE.get() + '"', 1)
        init = bootstrap()
        body = body.replace('<head>', '<head>' + init, 1) if '<head>' in body else init + body
        from configuration_draft import status as draft_status
        seed=json.dumps(draft_status()).replace("<","\\u003c")
        script="<script id=configuration-state type=application/json>"+seed+"</script><script>"+_ui(Path(BASE,"configuration_draft_ui.js").read_text(encoding="utf-8"))+"</script>"
        body=body.replace("</head>",script+"</head>",1) if "</head>" in body else script+body
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # The whole UI, including its CSS and JavaScript, is embedded in this dynamic HTML.
        # Prevent browsers from reusing an older shell after a panel update or language change.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Vary", "Cookie")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def redirect_message(self, message, tab=None, view=None):
        params = {"msg": message[:1200]}
        if tab:
            params["tab"] = tab
        if view:
            params["view"] = view
        query = urlencode(params)
        self.send_response(303)
        self.send_header("Location", "/?" + query)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        from ui_i18n import select_language
        select_language('ui_language=ru' if (self.path.startswith('/api/') and not self.path.startswith('/api/subscription-usage')) or 'download=backup' in self.path else self.headers.get('Cookie', ''))
        from configuration_draft import preview, status
        path = self.path.split("?",1)[0]
        if path == "/api/configuration/status":
            self.send_json({"ok":True, **status()});return
        if path == "/api/panel-update/check":
            try:
                from panel_updater import check
                self.send_json(check())
            except Exception as error:
                self.send_json({"ok":False,"message":str(error)},503)
            return
        if path.startswith("/api/") or "download=backup" in self.path:return self._get()
        with preview():return self._get()

    def _get(self):
        params = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        if self.path.split('?', 1)[0] == '/api/clients/dhcp':
            try:
                from dhcp_leases import snapshot
                self.send_json(snapshot())
            except Exception as error:
                self.send_json({'ok': False, 'message': str(error)}, 503)
            return
        if self.path.split("?", 1)[0] == "/api/dns/probe":
            from dns_panel import probe
            try:
                self.send_json(probe(params))
            except (ValueError, OSError) as error:
                self.send_json({"message": str(error)}, 400)
            return
        if self.path.split("?", 1)[0] == "/api/geodata/search":
            from geodata_search import search
            try:
                self.send_json(search(params.get("q", [""])[0]))
            except ValueError as error:
                self.send_json({"message": str(error)}, 400)
            return
        if self.path.split("?", 1)[0] == "/api/geodata/catalog/search":
            from geodata_catalog import search
            try:
                query = params.get("q", [""])[0]
                source_id = params.get("source", [""])[0]
                if source_id:
                    from geodata_search import search as search_source
                    result = search_source(query, source_id)
                    for item in result["results"]:
                        item["local_source"] = True
                        item["kind"] = {"domain": "geosite", "ipcidr": "geoip"}[item["kind"]]
                    self.send_json(result)
                else:
                    self.send_json(search(query))
            except ValueError as error:
                self.send_json({"message": str(error)}, 400)
            except Exception as error:
                self.send_json({"message": str(error)}, 503)
            return
        if self.path.split("?", 1)[0] == "/api/geodata/catalog/category":
            from geodata_catalog import preview
            try:
                self.send_json(preview(params.get("kind", [""])[0], params.get("name", [""])[0],
                                       int(params.get("offset", ["0"])[0])))
            except ValueError as error:
                self.send_json({"message": str(error)}, 400)
            except Exception as error:
                self.send_json({"message": str(error)}, 503)
            return
        if self.path.split("?", 1)[0] == "/api/geodata/category":
            from geodata_search import preview_category
            try:
                result = preview_category(params.get("source", [""])[0], params.get("name", [""])[0],
                                          int(params.get("offset", ["0"])[0]))
                self.send_json(result)
            except ValueError as error:
                self.send_json({"message": str(error)}, 400)
            return
        if params.get("tab") == ["geodata"]:
            import geodata_panel
            self.send_html(decorate_page(geodata_panel.render(_ui_message(params.get("msg", [""])[0])), "geodata"))
            return
        if self.path.split('?',1)[0]=='/api/components/versions':
            try:
                from component_versions import public_catalog
                self.send_json(public_catalog(params.get('refresh',['0'])[0]=='1'))
            except Exception as error:self.send_json({'message':str(error)},503)
            return
        if params.get('tab',[''])[0]=='clients':
            import client_panel
            self.send_html(decorate_page(client_panel.render(params),'clients'))
            return
        if params.get('tab',[''])[0]=='routes':
            import router_routes
            self.send_html(decorate_page(router_routes.render(params),'routes'))
            return
        if self.path.split('?',1)[0] == '/api/vpn-traffic':
            import vpn_traffic
            self.send_json(vpn_traffic.snapshot())
            return
        if self.path.split('?',1)[0] == '/api/subscription-usage':
            import vpn_subscriptions
            self.send_json(vpn_subscriptions.usage_snapshot())
            return
        if self.path.split('?',1)[0] == '/api/vpn-countries':
            import proxy_manager, vpn_clients, vpn_geoip
            hosts = {str(vpn_clients.canonical(node).get('server', ''))
                     for node in proxy_manager.read()['nodes']}
            self.send_json({'countries': vpn_geoip.countries(hosts)})
            return
        if params.get('tab',[''])[0]=='components':
            try:
                import vpn_components
                self.send_html(decorate_page(vpn_components.render(),'components'))
            except Exception as error:
                self.send_html(_ui('<h1>Компоненты</h1><pre>')+esc(_ui_message(error))+'</pre>',503)
            return
        if self.path.split('?',1)[0] == '/api/logs':
            try:
                import log_panel
                self.send_json(log_panel.snapshot(max(0,int(params.get('after',['0'])[0]))))
            except (ValueError, TypeError):
                self.send_json({'message':_ui('Некорректный курсор')},400)
            except Exception:
                self.send_json({'message':_ui('Ядро временно недоступно')},503)
            return
        if params.get('tab',[''])[0] == 'logs':
            import log_panel
            self.send_html(decorate_page(log_panel.render(),'logs'))
            return

        if params.get("download", [""])[0]=="backup" and (QUEUE.status()["queued"]+QUEUE.status()["running"]):
            self.redirect_message(_ui('Дождитесь завершения очереди перед созданием резервной копии.'),tab="backup")
            return
        if params.get("download", [""])[0] == "backup":
            try:
                payload=json.dumps(create_backup(),ensure_ascii=False,indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type","application/json; charset=utf-8")
                self.send_header("Content-Disposition",'attachment; filename="mihomo-backup-'+time.strftime("%Y%m%d-%H%M%S")+'.json"')
                self.send_header("Cache-Control","no-store")
                self.send_header("Content-Length",str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
            except Exception as e: self.send_html(_ui('<h1>Ошибка создания резервной копии</h1><pre>')+esc(_ui_message(e))+"</pre>",500)
            return
        if params.get("tab", [""])[0] == "backup":
            message=_ui_message(params.get("msg", [""])[0]); page=render_backup_page()
            if message: page='<div class="msg">'+esc(message)+'</div>'+page
            self.send_html(decorate_page(page,"backup")); return

        if self.path.split("?",1)[0]=="/api/actions/history":
            try:
                before=max(0,int(params.get("before",["0"])[0]))
                self.send_json(QUEUE.history(before=before))
            except (ValueError,TypeError):
                self.send_json({"message":_ui('Некорректный номер действия')},400)
            return
        if self.path.split("?",1)[0]=="/api/actions/status":
            self.send_json(QUEUE.status())
            return
        if self.path.split("?", 1)[0] == "/api/proxy-delay":
            name = params.get("name", [""])[0]
            try:
                delay = check_proxy_delay(name)
                self.send_json({"node": name, "delay": delay})
            except Exception:
                self.send_json({"node": name, "delay": -1})
            return

        if params.get("tab", [""])[0] in ("proxies","vpn"):
            try:
                from proxy_manager import render as render_proxy_manager
                import vpn_subscriptions
                fragment = (vpn_subscriptions.render() if params.get("view") == ["subscriptions"]
                            else render_proxy_manager(vpn_subscriptions.navigation(False)))
                page = '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VPN</title><style></style></head><body>' + fragment + '</body></html>'
                message = _ui_message(params.get("msg", [""])[0])
                if message:
                    page = page.replace("<body>", "<body><p role=\"status\">" + esc(message) + "</p>", 1)
                self.send_html(decorate_page(page, "proxies"))
            except Exception as e:
                self.send_html(_ui('<h1>Ошибка раздела прокси</h1><pre>') + esc(_ui_message(e)) + "</pre>", 500)
            return

        if params.get("tab", [""])[0] == "services":
            try:
                targets = route_targets()
                page = group_rule_creation_panels(render_services(params, targets=targets))
                self.send_html(decorate_page(page, "services", targets=targets))
            except Exception as e:
                self.send_html(_ui('<h1>Ошибка раздела правил</h1><pre>') + esc(_ui_message(e)) + "</pre>", 500)
            return
        params = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
        query = params.get("q", [""])[0].strip().lower()
        source_filter = params.get("source", ["all"])[0]
        status_filter = params.get("status", ["all"])[0]
        if source_filter not in ("all", "rkn", "local", "service") and not source_filter.startswith("service:"):
            source_filter = "all"
        if status_filter not in ("all", "enabled", "disabled"):
            status_filter = "all"
        try:
            page = max(1, int(params.get("page", ["1"])[0]))
        except ValueError:
            page = 1
        message = _ui_message(params.get("msg", [""])[0])

        load_domains = params.get("load") == ["1"] or any(key in params for key in ("q", "source", "status", "page"))
        source = adds = removes = deleted = effective = set()
        service_domains = {}
        domain_counts = None
        matches = shown = []
        pages = 1
        if load_domains:
            try:
                counts_signature = domain_counts_signature()
                source = read_source()
                service_domains = read_service_domain_states(query)
                adds = read_local(ADDS)
                removes = read_local(REMOVES)
                deleted = read_local(DELETED)
    
                domain_counts = get_domain_counts(
                    (source, adds, removes, deleted), expected_signature=counts_signature,
                    service_domains=service_domains if not query else None,
                )
    
                # Service domains are shown once and remain owned by their service.
                effective = ((source | adds) - deleted) | set(service_domains)
                matches = sorted(
                    d for d in effective
                    if (query in d or query.endswith("." + d))
                    and (
                        source_filter == "all"
                        or (source_filter == "rkn" and d in source and d not in service_domains)
                        or (source_filter == "local" and d not in source and d not in service_domains)
                        or (source_filter == "service" and d in service_domains)
                        or (source_filter.startswith("service:") and source_filter[8:] in service_domains.get(d, {}).get("names", []))
                    )
                    and (
                        status_filter == "all"
                        or (status_filter == "disabled" and (not service_domains[d]["enabled"] if d in service_domains else d in removes))
                        or (status_filter == "enabled" and (service_domains[d]["enabled"] if d in service_domains else d not in removes))
                    )
                )
                pages = max(1, (len(matches) + PAGE_SIZE - 1) // PAGE_SIZE)
                page = min(page, pages)
                shown = matches[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
            except Exception as e:
                self.send_html(_ui('<h1>Ошибка чтения данных</h1><pre>') + esc(_ui_message(e)) + "</pre>", 500)
                return

        settings_path = state_path(Path(BASE) / "routing-settings.json")
        settings = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
        owners = effective_domain_rules(read_services(), shown) if settings.get("services_enabled", True) else {}
        local_dns_path = state_path(Path(BASE) / "local-domain-dns.json")
        local_dns = json.loads(local_dns_path.read_text()) if local_dns_path.exists() else {}
        runtime = Path(BASE).parent / "default_config.yaml"
        dns_config = runtime.read_text(encoding="utf-8") if shown else ""
        fake_mode = bool(re.search(r"(?m)^\s*enhanced-mode:\s*fake-ip\s*(?:#.*)?$", dns_config))
        legacy_domains = source | adds
        excluded_domains = removes | deleted
        rows = []
        for domain in shown:
            owner = owners.get(domain)
            from routing_panel import resolve_target
            target = resolve_target(owner.get("target")).upper() if owner else ""
            labels = domain.split(".")
            suffixes = {".".join(labels[index:]) for index in range(len(labels))}
            legacy_fake = bool(suffixes & legacy_domains) and not bool(suffixes & excluded_domains)
            dns_label = "RealIP"
            if target in {"REJECT", "BLOCK"}:
                dns_label = "NODOMAIN"
            elif fake_mode and ((owner is not None and target not in {"DIRECT", "TRANSIT"}) or (owner is None and legacy_fake and resolve_target() not in {"DIRECT", "TRANSIT"})):
                dns_label = "FakeIP"
            if owner is None and domain in local_dns and settings.get("services_enabled", True):
                dns_label = local_dns[domain]
                if dns_label == "FakeIP" and not fake_mode:
                    dns_label = "RealIP"
            status_class = "off" if dns_label == "NODOMAIN" else "on" if dns_label == "FakeIP" else ""
            if owner is not None:
                origin = '<a href="' + esc(service_edit_url(owner)) + '">' + esc(owner["name"]) + '</a>'
                disabled = False
                actions = _ui('<span>Управляется правилом</span>')
                status_control = f'<span class="{status_class}">{dns_label}</span>'
            elif domain in service_domains:
                origin = _ui('Основной маршрут')
                status_control = f'<span class="{status_class}">{dns_label}</span>'
                actions = ""
            else:
                origin = esc(SOURCE_NAME if domain in source else _ui('Локальный'))
                disabled = domain in removes
                selected_mode = local_dns.get(domain, dns_label)
                dns_options = "".join(
                    f'<option value="{mode}"{" selected" if mode == selected_mode else ""}>{mode}</option>'
                    for mode in ("FakeIP", "RealIP", "NODOMAIN")
                )
                status_control = ''.join(('<form method="post" action="/action" class="inline domain-toggle">\n<input type="hidden" name="action" value="domain_dns">\n<input type="hidden" name="old" value="', f'{esc(domain)}', _ui('">\n<select name="dns_mode" aria-label="DNS домена '), f'{esc(domain)}', '" onchange="this.form.requestSubmit()">', f'{dns_options}', '</select>\n</form>'))
                actions = _ui('<form method="post" action="/action" class="inline" onsubmit="return confirm(\'Удалить {domain} из панели?\')">\n<input type="hidden" name="action" value="delete">\n<input type="hidden" name="old" value="{domain}">\n<button class="danger" type="submit">Удалить</button>\n</form>').format(
                    domain=esc(domain)
                )
            rows.append("""
<tr>
<td class="domain">{domain}</td>
<td>{origin}</td>
<td>{status_control}</td>
<td class="actions">{actions}</td>
</tr>""".format(
                domain=esc(domain), origin=origin, status_control=status_control, actions=actions
            ))

        def page_link(number, label):
            link_params = {"page": number, "load": "1"}
            if query:
                link_params["q"] = query
            if source_filter != "all":
                link_params["source"] = source_filter
            if status_filter != "all":
                link_params["status"] = status_filter
            return '<a href="/?%s">%s</a>' % (esc(urlencode(link_params)), label)

        nav = ""
        if page > 1:
            nav += page_link(page - 1, _ui('← Назад')) + " "
        nav += _ui('Страница %d из %d') % (page, pages)
        if page < pages:
            nav += " " + page_link(page + 1, _ui('Вперёд →'))

        service_names = sorted({item["name"] for item in read_services() if item.get("name")}, key=str.casefold)
        service_filter_options = [
            _ui('<option value="service" %s>S:Все правила</option>') % (
                "selected" if source_filter == "service" else ""
            )
        ]
        for service_name in service_names:
            service_value = "service:" + service_name
            selected = " selected" if source_filter == service_value else ""
            service_filter_options.append(
                '<option value="%s"%s>S:%s</option>' % (
                    esc(service_value), selected, esc(service_name)
                )
            )

        body = _ui('<!doctype html>\n<html lang="ru">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Universal VPN Core — DNS</title>\n<style>\nbody{{font:16px system-ui,sans-serif;max-width:1250px;margin:24px auto;padding:0 14px;color:#222}}\ninput,button{{font:inherit;padding:8px}}input{{max-width:100%;box-sizing:border-box}}\nbutton{{cursor:pointer;border:1px solid #999;border-radius:5px;background:#eee}}\nbutton:disabled{{opacity:.4;cursor:default}}\n.danger{{background:#fee}}\n.panel{{border:1px solid #ccc;border-radius:8px;padding:14px;margin:14px 0}}\n.panel-spoiler>summary{{cursor:pointer;font-size:1.25em;font-weight:700;list-style:none;display:flex;align-items:center;gap:9px}}\n.panel-spoiler>summary::-webkit-details-marker{{display:none}}\n.panel-spoiler>summary::before{{content:"";width:0;height:0;border-top:5px solid transparent;border-bottom:5px solid transparent;border-left:7px solid currentColor;flex:none}}\n.panel-spoiler[open]>summary{{margin-bottom:14px}}\n.panel-spoiler[open]>summary::before{{transform:rotate(90deg)}}\ntable{{width:100%;border-collapse:collapse}}\nth,td{{text-align:left;border-bottom:1px solid #ddd;padding:8px;overflow-wrap:anywhere}}\nth{{background:#f4f4f4}}\n.inline{{display:inline-block;margin:2px}}\n.actions{{min-width:260px}}\n.domain{{font-weight:500}}\n.on{{color:#176b35;font-weight:600}}\n.off{{color:#a45b00;font-weight:600}}\n.msg{{white-space:pre-wrap;background:#f3f6ff;padding:12px;overflow-wrap:anywhere}}\nnav{{margin:18px 0}}form.search{{display:flex;gap:8px;flex-wrap:wrap}}\n.domain-filter-form{{width:100%;margin:0}}\n.domain-filter-box{{width:100%;box-sizing:border-box;border:1px solid #b8c2d3;border-radius:8px;overflow:hidden}}\n.domain-filter-box textarea{{display:block;width:100%;height:10em;min-height:10em;max-height:10em;box-sizing:border-box;resize:none;overflow:auto;white-space:pre;border:0!important;border-radius:0!important}}\n.domain-filter-footer{{display:flex;justify-content:flex-end;padding:8px 10px;border-top:1px solid #b8c2d3}}\n.domain-refresh-row{{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:12px}}\n.domain-refresh-row p{{margin:0}}\n.domain-refresh-row form{{flex:0 0 auto;margin:0}}\n@media(max-width:760px){{.domain-refresh-row{{align-items:stretch;flex-direction:column}}.domain-refresh-row form button{{width:100%}}}}\n@media(max-width:760px){{\n table{{font-size:14px}}\n th,td{{padding:5px}}\n .actions{{min-width:190px}}\n}}\n</style>\n</head>\n<body>\n{message}\n<div class="panel">\n<details class="panel-spoiler"><summary>Добавить локальные домены</summary>\n<form method="post" action="/action" class="domain-filter-form">\n<input type="hidden" name="action" value="add">\n<div class="domain-filter-box">\n<textarea name="new" rows="8" wrap="off" placeholder="example.com; example.org&#10;example.net" required></textarea>\n<div class="domain-filter-footer"><button type="submit">Добавить и включить домены</button></div>\n</div>\n</form>\n<p>Перечислите домены через точку с запятой или каждый с новой строки. Для каждого домена сразу создаётся правило <code>DOMAIN-SUFFIX</code>, поэтому оно распространяется и на все его поддомены. Домены получают источник «Локальный».</p>\n</details>\n</div>\n<div class="panel">\n<details class="panel-spoiler" id="domain-list"{list_open}><summary>Список доменов</summary>\n<div id="domain-list-content">\n<form id="clear-auto-domains-form" method="post" action="/action"\nonsubmit="return confirm(\'Очистить все автоматически загруженные домены? Локальные домены останутся.\')">\n<input type="hidden" name="action" value="clear_auto_domains">\n</form>\n<form class="search" method="get" action="/">\n<input type="hidden" name="load" value="1">\n<input name="q" value="{query}" placeholder="Поиск по домену">\n<select name="source">\n<option value="all" {source_all}>Все источники</option>\n<option value="rkn" {source_rkn}>{source_name}</option>\n<option value="local" {source_local}>Локальный</option>\n{service_filter_options}\n</select>\n<select name="status">\n<option value="all" {status_all}>Все статусы</option>\n<option value="enabled" {status_enabled}>Включено</option>\n<option value="disabled" {status_disabled}>Отключено</option>\n</select>\n<button type="submit">Найти</button>\n<button type="button" onclick="window.location.href=\'/?load=1\'">Сбросить поиск</button>\n<button type="submit" form="clear-auto-domains-form" class="danger" style="font-weight:700">Очистить список доменов</button>\n</form>\n<p>Найдено: {match_count}</p>\n<table>\n<thead><tr><th>Домен</th><th>Источник</th><th>Статус</th><th>Действия</th></tr></thead>\n<tbody>{rows}</tbody>\n</table>\n<nav>{nav}</nav>\n</div></details></div>\n</body>\n</html>').format(
            source_count=len(source),
            add_count=len(adds - source),
            remove_count=len(removes & effective),
            deleted_count=len(deleted),
            total=len(effective),
            message=('<div class="msg">' + esc(message) + '</div>') if message else "",
            query=esc(query),
            source_name=esc(SOURCE_NAME),
            source_all="selected" if source_filter == "all" else "",
            source_rkn="selected" if source_filter == "rkn" else "",
            source_local="selected" if source_filter == "local" else "",
            service_filter_options="".join(service_filter_options),
            status_all="selected" if status_filter == "all" else "",
            status_enabled="selected" if status_filter == "enabled" else "",
            status_disabled="selected" if status_filter == "disabled" else "",
            match_count=len(matches),
            rows="".join(rows) or _ui('<tr><td colspan="4">Нет доменов по заданному запросу</td></tr>'),
            nav=nav
            ,list_open=" open" if load_domains else ""
        )
        if params.get("fragment") == ["domains"]:
            fragment = body.split('<div id="domain-list-content">', 1)[1].split('</div></details></div>', 1)[0]
            self.send_html(fragment)
            return
        if not load_domains:
            start = body.index('<div id="domain-list-content">') + len('<div id="domain-list-content">')
            end = body.index('</div></details></div>', start)
            body = body[:start] + _ui('<p role="status">Раскройте список для загрузки.</p>') + body[end:]
        body = body.replace('</body>', _ui('<script>\n(()=> {\n const details=document.getElementById("domain-list"),content=document.getElementById("domain-list-content");\n let loaded=details.open,busy=false;\n async function load() {\n  if(loaded||busy)return;\n  busy=true;content.textContent="Загрузка доменов…";\n  try {\n   const url=new URL(location.href);url.searchParams.set("load","1");url.searchParams.set("fragment","domains");\n   const response=await fetch(url,{cache:"no-store"});\n   if(!response.ok)throw new Error("Не удалось загрузить список доменов.");\n   content.innerHTML=await response.text();loaded=true;\n  } catch(error) {\n   content.replaceChildren(document.createTextNode(error.message+" "));\n   const retry=document.createElement("button");retry.type="button";retry.textContent="Повторить";\n   retry.addEventListener("click",load);content.append(retry);\n  } finally {busy=false;}\n }\n details.addEventListener("toggle",()=>{if(details.open)load();});\n})();\n</script></body>'))
        from dns_panel import render as render_dns
        marker = _ui('<div class="panel">\n<details class="panel-spoiler"><summary>Добавить локальные домены')
        body = body.replace(marker, render_dns() + marker, 1)
        self.send_html(decorate_page(body, "domains", domain_counts=domain_counts))

    def do_POST(self):
        from ui_i18n import select_language
        select_language('ui_language=ru')
        if self.path.split("?",1)[0] in ("/api/configuration/stage", "/api/configuration/discard"):
            from configuration_draft import stage, discard
            try:
                length=int(self.headers.get("Content-Length","0"))
                if not 0 < length <= 512*1024:raise ValueError("Недопустимый размер запроса")
                raw=self.rfile.read(length).decode("utf-8")
                self.send_json(discard() if self.path.endswith("/discard") else stage(raw,execute_queued_action))
            except Exception as error:self.send_json({"ok":False,"message":str(error)},400)
            return
        if self.path.split("?", 1)[0] == "/api/geodata":
            import geodata_panel
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= geodata_panel.MAX_UPLOAD + 16384:
                    self.close_connection = True
                    raise ValueError("Размер файла должен быть не больше 160 МиБ.")
                with geodata_panel.read_request(self.headers.get('Content-Type',''),self.rfile,length) as form:
                    message = geodata_panel.handle(form)
            except ValueError as error:
                self.close_connection = True
                message = "Ошибка: " + str(error)
            except OSError:
                message = "Ошибка: не удалось сохранить источник на носителе."
            self.redirect_message(message, "geodata")
            return
        if self.path.split('?',1)[0] == '/api/logs/settings':
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0 < length <= 100: raise ValueError('Недопустимый размер запроса')
                data=parse_qs(self.rfile.read(length).decode('utf-8'))
                import log_panel
                log_panel.set_level(data.get('level',[''])[0])
                self.send_json({'ok':True})
            except (ValueError, UnicodeError) as error:
                self.send_json({'message':str(error)},400)
            except Exception:
                self.send_json({'message':'Не удалось сохранить уровень'},503)
            return
        from action_queue import LABELS
        try:
            path=self.path.split("?",1)[0]
            is_restore=path=="/api/backup/restore"
            length=int(self.headers.get("Content-Length","0"))
            limit=BACKUP_LIMIT if is_restore else 512*1024
            if length<=0 or length>limit:
                self.send_json({"ok":False,"message":"Недопустимый размер запроса"},413)
                return
            raw=self.rfile.read(length).decode("utf-8-sig")
            if is_restore:
                uploaded=json.loads(raw)
                if not isinstance(uploaded,dict) or uploaded.get("format")!=BACKUP_FORMAT:
                    raise ValueError("Неподдерживаемый формат резервной копии")
                action="restore"
                target="/api/backup/restore"
            else:
                data=parse_qs(raw)
                action=data.get("action",[""])[0]
                if action not in LABELS or action=="restore":
                    raise ValueError("Неизвестное действие")
                if action.startswith('route_'):
                    import router_routes
                    router_routes.check_token(data.get('route_token',[''])[0])
                if action.startswith("service_") and int(data.get("index",["-1"])[0])>=0 and not data.get("service_id",[""])[0]:
                    raise ValueError("Обновите страницу правил перед изменением")
                from configuration_draft import staged_action, stage
                if staged_action(action):
                    result=stage(raw,execute_queued_action)
                    if path=="/api/actions/queue":self.send_json(result)
                    else:self.redirect_message("Изменения сохранены в черновик", "services" if action.startswith("service_") else "routes" if action.startswith("route_") else "domains")
                    return
                target="/action"
            job=QUEUE.submit(LABELS[action],{"path":target,"body":raw})
            message="Действие №"+str(job)+" добавлено в очередь"
            if path in ("/api/actions/queue","/api/backup/restore"):
                self.send_json({"ok":True,"message":message,"job_id":job},202)
            else:
                tab="routes" if action.startswith('route_') else "components" if action=='component_change' else "services" if action.startswith("service_") else "vpn" if action.startswith(("proxy_","vpn_","subscription_")) else "domains"
                self.redirect_message(message,tab,view="subscriptions" if action.startswith("subscription_") else None)
        except Exception as error:
            self.send_json({"ok":False,"message":str(error)},400)


    def _execute_post(self):
        try:
            if self.path.split("?",1)[0] == "/api/backup/restore":
                length=int(self.headers.get("Content-Length","0"))
                if length<=0 or length>BACKUP_LIMIT:
                    self.send_json({"ok":False,"message":"Размер файла должен быть не более 32 МБ"},413); return
                try:
                    payload=json.loads(self.rfile.read(length).decode("utf-8-sig"))
                    self.send_json({"ok":True,"message":restore_backup(payload)})
                except Exception as e: self.send_json({"ok":False,"message":str(e)[:1500]},400)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length > 512*1024:
                self.redirect_message("Ошибка: слишком большой запрос")
                return

            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = parse_qs(raw)
            action = data.get("action", [""])[0]
            if action == "geodata_source_download":
                import geodata_panel
                form={key:values[0] for key,values in data.items()}
                message=geodata_panel.handle(form,getattr(self,"action_progress",lambda _stage:None))
                self.redirect_message(message,tab="geodata")
                return
            if action in ("dns_flush","core_restart"):
                from runtime_actions import execute
                self.redirect_message(execute(action,getattr(self,"action_progress",lambda _:None)));return
            if action == "configuration_apply":
                from configuration_draft import apply
                self.redirect_message(apply(getattr(self,"action_progress",lambda _:None),getattr(self,"after_commit",None),getattr(self,"action_job_id",None),data.get("revision",[None])[0]));return
            if action.startswith('route_'):
                import router_routes
                if action=='route_apply':
                    from route_batch import apply as apply_route_batch
                    output=apply_route_batch(data,getattr(self,'action_progress',lambda _:None),getattr(self,'after_commit',None),getattr(self,'action_job_id',None))
                else:output=router_routes.change(action,data)
                self.redirect_message(output,tab='routes')
                return
            if action == 'component_change':
                import vpn_components
                self.redirect_message(vpn_components.change(data.get('component',[''])[0],data.get('operation',[''])[0],data.get('version_id',[''])[0]),tab='components')
                return
            if action == 'panel_update_install':
                import panel_updater
                message = panel_updater.install(data.get('version',[''])[0])
                after_commit = getattr(self, 'after_commit', None)
                if after_commit:
                    # The action queue passes a callback (list.append), not its callback list.
                    after_commit(panel_updater.schedule_restart)
                self.redirect_message(message,tab='components')
                return
            if action in ('subscription_add', 'subscription_refresh', 'subscription_info_refresh', 'subscription_delete', 'subscription_automation', 'subscription_edit'):
                import vpn_subscriptions
                try:
                    message = vpn_subscriptions.handle(action, data,
                                                       before_apply=getattr(self, "before_subscription_apply", None),
                                                       report=getattr(self, "action_progress", None))
                except ValueError as error:
                    message = "Ошибка подписки: " + str(error)
                except Exception:
                    message = "Ошибка подписки при применении конфигурации."
                self.redirect_message(message, tab='vpn', view='subscriptions')
                return
            if action == 'vpn_client':
                import vpn_clients
                self.redirect_message(vpn_clients.select(data.get('name',[''])[0],data.get('client',[''])[0],data.get('fingerprint',[None])[0]),tab='vpn')
                return
            if action == 'vpn_edit':
                import vpn_editor
                self.redirect_message(vpn_editor.update(data.get('name',[''])[0],data),tab='vpn')
                return
            if action == 'vpn_import':
                import proxy_manager
                names=proxy_manager.import_connections(data.get('source',[''])[0],data.get('vpn_format',['auto'])[0],data.get('vpn_name',['VPN'])[0],data.get('client',['mihomo'])[0])
                self.redirect_message('VPN-соединения добавлены: '+', '.join(names),tab='vpn')
                return
            if action == "proxy_import":
                import proxy_manager
                names = proxy_manager.import_source(data.get("source", [""])[0])
                self.redirect_message("Добавлены и применены: " + ", ".join(names), tab="proxies")
                return
            if action == "proxy_delete_selected":
                import proxy_manager
                count = proxy_manager.delete_many(data.get("selected", []),
                                                 destination=data.get("replacement_route", [""])[0])
                self.redirect_message("Удалено прокси: " + str(count), tab="proxies")
                return
            if action == "proxy_enable_selected":
                import proxy_manager
                count = proxy_manager.set_balance_many(data.get("selected", []), True)
                self.redirect_message("Включена балансировка у прокси: " + str(count), tab="proxies")
                return
            if action in ("proxy_balance", "proxy_delete"):
                import proxy_manager
                name = data.get("name", [""])[0]
                if action == "proxy_balance":
                    proxy_manager.set_balance(name, data.get("enabled", ["0"])[-1] == "1")
                else:
                    proxy_manager.delete(name, destination=data.get("replacement_route", [""])[0])
                self.redirect_message("Настройки прокси применены", tab="proxies")
                return
            if action == "routing_save":
                try:
                    output = handle_routing_action(data)
                    self.redirect_message(output)
                except Exception as e:
                    self.redirect_message("Ошибка маршрутизации: " + str(e))
                return
            if action.startswith("service_"):
               try:
                   output = handle_action(data, getattr(self, "action_progress", lambda _stage: None),
                                          getattr(self, "after_commit", None))
                   self.redirect_message(output, tab="services")
               except Exception as e:
                   self.redirect_message("Ошибка правила: " + str(e))
               return
            old_value = data.get("old", [""])[0]
            new_value = data.get("new", [""])[0]

            if action == "domain_dns":
                domain = valid_domain(old_value)
                if domain not in (read_local(ADDS) | read_source()) - read_local(DELETED):
                    raise ValueError("Локальный домен больше не найден.")
                output = set_local_domain_dns(domain, data.get("dns_mode", [""])[0])
                self.redirect_message(output)
                return
            if action == "dns_save":
                from dns_panel import save
                self.redirect_message(save(data))
                return
            if action == "filter_save":
                try:
                    import domain_filter
                    expression = data.get("filter_expr", [""])[0].strip()
                    domain_filter.parse_patterns(expression)
                    fd, temp_path = tempfile.mkstemp(prefix=".ru-blocked-filters-", dir=BASE)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as f:
                            f.write(expression + "\n")
                        durable_replace(temp_path, FILTER_FILE)
                    finally:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    self.redirect_message("Фильтр сохранён. Он применится при следующем обновлении из GitHub.")
                except Exception as e:
                    self.redirect_message("Ошибка фильтра: " + str(e))
                return

            if action == "clear_auto_domains":
                output = clear_auto_domains()
                self.redirect_message(output)
                return

            if action == "refresh":
                output = run_script(REFRESH)
                self.redirect_message("Источник обновлён:\n" + output)
            elif action in ("add", "enable", "disable", "delete"):
                output = change_domains(action, old_value, new_value)
                if action in ("enable", "disable", "delete"):
                    output += "\n" + set_local_domain_dns(valid_domain(old_value), None)
                labels = {
                    "add": "Домены добавлены и включены",
                    "enable": "Домен включён",
                    "disable": "Домен отключён",
                    "delete": "Домен удалён из панели"
                }
                self.redirect_message(labels[action] + ". YAML пересобран:\n" + output)
            else:
                self.redirect_message("Неизвестное действие")
        except Exception as e:
            self.redirect_message("Ошибка: " + str(e))


if __name__ == "__main__":
    import panel_updater
    panel_updater.recover()
    import dns_forwarder
    dns_forwarder.start()
    from boot_config import ready
    ready()
    import log_panel
    log_panel.start()
    import vpn_traffic
    vpn_traffic.start()
    import vpn_clients
    vpn_clients.start()
    from action_queue import ActionQueue
    from service_routes_panel import write_services
    write_services(read_services())
    from action_log import describe
    from action_recovery import Recovery
    QUEUE=ActionQueue(os.path.join(BASE,"configuration-jobs.sqlite3"),execute_queued_action,describe=describe,recovery=Recovery())
    from subscription_automation import watch
    threading.Thread(target=watch,args=(QUEUE,),name="subscription-automation",daemon=True).start()
    import router_routes
    if router_routes.auto_rest():
        threading.Thread(target=router_routes.watch_service_routes,daemon=True).start()
    print("RU-BLOCKED panel listening on 0.0.0.0:%d" % PORT, flush=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    panel_updater.complete_start()
    cached_domain_counts()
    httpd.serve_forever()


