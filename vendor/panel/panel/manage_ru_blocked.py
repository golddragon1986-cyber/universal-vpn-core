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
from urllib.parse import parse_qs, urlencode, quote
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
    return """
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Резервная копия</title><style></style></head><body>
<section class="panel backup-panel"><h2>Резервная копия</h2>
<p>Сохраняются полные настройки Mihomo: активная и стартовая конфигурации, шаблон, настройки DNS, маршрутов и прокси, базы доменов и правил, ручные изменения и фильтры загрузки.</p>
<p class="backup-note"><strong>Важно:</strong> файл содержит адреса серверов и данные доступа к прокси. Храните его в безопасном месте.</p>
<div class="backup-actions"><a class="backup-download" href="/?download=backup">Скачать резервную копию</a></div>
<hr><h3>Восстановить из файла</h3>
<p>Выберите ранее сохранённый JSON-файл. Текущие настройки Mihomo, базы доменов и правил будут заменены данными из файла.</p>
<div class="backup-actions"><input id="backup-file" type="file" accept=".json,application/json">
<button id="backup-restore" type="button" disabled>Восстановить из файла</button></div>
<div id="backup-result" role="status" aria-live="polite"></div></section>
<style>
.backup-panel{width:100%;max-width:none;box-sizing:border-box;padding:24px;margin:0 0 18px}.backup-panel p{line-height:1.55}
body .backup-panel .backup-note{padding:12px 14px;border-left:4px solid #315ee8;background:#eef3ff;color:#182033;border-radius:7px}body .backup-panel .backup-note strong{color:inherit}
.backup-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:14px 0}
body .backup-panel .backup-download,body .backup-panel #backup-restore{display:inline-flex;align-items:center;justify-content:center;min-height:40px;margin:0;padding:8px 14px;box-sizing:border-box;border:1px solid #315ee8;border-radius:7px;background:#315ee8;color:#fff;text-decoration:none;font:inherit;font-weight:700;line-height:1.4;cursor:pointer}body .backup-panel #backup-restore:disabled{opacity:.5;cursor:not-allowed}body .backup-panel .backup-download:hover,body .backup-panel #backup-restore:not(:disabled):hover{background:#244dcc;border-color:#244dcc}@media(prefers-color-scheme:dark){body .backup-panel .backup-note{background:#202a3b;color:#edf1fa;border-left-color:#8aa9ff}}
.backup-panel hr{border:0;border-top:1px solid #d8deea;margin:22px 0}
#backup-result{margin-top:12px;white-space:pre-wrap}#backup-result.error{color:#b42318}#backup-result.success{color:#087443}
</style>
<script>
const bf=document.getElementById("backup-file"),br=document.getElementById("backup-restore"),out=document.getElementById("backup-result");
bf.addEventListener("change",()=>{br.disabled=!bf.files.length;out.textContent="";out.className="";});
br.addEventListener("click",async()=>{const file=bf.files[0];if(!file)return;
 if(file.size>32*1024*1024){out.textContent="Файл превышает допустимый размер 32 МБ.";out.className="error";return;}
 if(!confirm("Настройки Mihomo и базы доменов и правил будут заменены. Продолжить восстановление?"))return;
 br.disabled=true;out.textContent="Проверка и восстановление…";out.className="";
 try{const r=await fetch("/api/backup/restore",{method:"POST",headers:{"Content-Type":"application/json"},body:file});
 const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||"Не удалось восстановить данные");
 out.textContent=j.message;out.className="success";setTimeout(()=>location.href="/?tab=backup&msg="+encodeURIComponent(j.message),700);
 }catch(e){out.textContent="Ошибка восстановления: "+e.message;out.className="error";br.disabled=false;}});
</script>
</body></html>
"""


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


def decorate_page(page, active_tab, targets=None, domain_counts=None):
    """Добавляет общую оболочку к существующей странице."""
    missing_providers = []
    try:
        domain_count, enabled_domains = domain_counts if domain_counts is not None else get_domain_counts()
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
    api_label = "API Mihomo доступен" if api_ok else "API Mihomo недоступен"
    if api_ok and missing_providers:
        api_label += " · конфигурация неполная"
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

    shell = f"""
<header class="unified-topbar">
  <div class="unified-brand">
    <div class="unified-logo" aria-hidden="true">UvpnC</div>
    <div>
      <div class="unified-brand-title">Universal VPN Core</div>
    </div>
  </div>
  <div class="unified-status">
    <div class="unified-health-group">{proxy_buttons}</div>
  </div>
</header>
{health_script}
<main class="unified-main">
  <section class="unified-metrics">
    <div class="unified-metric"><div>VPN</div><strong>{proxy_active_count}/{proxy_count}</strong><small>Активные / всего в конфигурации</small></div>
    <div class="unified-metric"><div>Правила</div><strong>{service_count}</strong><small>В пользовательском списке</small></div>
    <div class="unified-metric"><div>Домены</div><strong>{domain_count}</strong><small>В текущем списке</small></div>
    <div class="unified-metric"><div>Маршруты</div><strong>{ip_route_count}</strong><small>IP-маршруты через контейнер</small></div>
  </section>
  <!--CONFIG_QUEUE_SLOT-->
  {render_routing_panel()}
  <nav class="unified-tabs" aria-label="Разделы">
    <a class="{'active' if active_tab == 'proxies' else ''}" href="/?tab=vpn">VPN</a>
    <a class="{'active' if active_tab == 'services' else ''}" href="/?tab=services">Правила</a>
    <a class="{'active' if active_tab == 'geodata' else ''}" href="/?tab=geodata">GeoDAT</a>
    <a class="{'active' if active_tab == 'domains' else ''}" href="/">DNS</a>
    <a class="{'active' if active_tab == 'routes' else ''}" href="/?tab=routes">Маршруты</a>
    <a class="{'active' if active_tab == 'clients' else ''}" href="/?tab=clients">Клиенты</a>
    <a class="{'active' if active_tab == 'components' else ''}" href="/?tab=components">Компоненты</a>
    <a class="{'active' if active_tab == 'logs' else ''}" href="/?tab=logs">Логи</a>
    <a class="{'active' if active_tab == 'backup' else ''}" href="/?tab=backup">Резервная копия</a>
  </nav>
"""
    shell = shell.replace("<!--CONFIG_QUEUE_SLOT-->", Path(os.path.join(BASE,"action_queue_ui.html")).read_text(encoding="utf-8"), 1)
    # Общие стили макета поверх прежних стилей страниц.
    css = """
.unified-topbar{width:calc(100% - 32px);max-width:1100px;box-sizing:border-box;margin:0 auto;
background:#17243d;color:#f7f9ff;padding:18px clamp(16px,4vw,48px);
display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.unified-brand{display:flex;align-items:center;gap:12px}
.unified-logo{height:40px;padding:0 9px;border-radius:13px;display:grid;place-items:center;
background:#315ee8;color:white;font-weight:800;font-size:13px}
.unified-brand-title{font-size:18px;font-weight:800;letter-spacing:-.4px}
.unified-brand-sub{font-size:12px;color:#b9c5dd;margin-top:3px}
.unified-api{display:flex;align-items:center;gap:8px;font-size:12px;color:#dce5f8;
border:1px solid #3c4a64;border-radius:999px;padding:8px 12px}
.unified-api span{width:7px;height:7px;border-radius:50%;display:inline-block}
.unified-main{width:calc(100% - 32px);max-width:1100px;box-sizing:border-box;margin:0 auto;padding:0 clamp(14px,3vw,32px) 44px}
.unified-heading{margin-bottom:20px}
.unified-eyebrow{font-size:11px;font-weight:800;letter-spacing:1.3px;color:#315ee8}
.unified-title{font-size:28px;letter-spacing:-.8px;margin:7px 0}
.unified-lead{font-size:14px;line-height:1.5;color:#69758a;margin:0}
.unified-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}
.unified-metric{background:var(--surface,#fff);border:1px solid var(--border,#e0e5ef);
border-radius:14px;padding:15px;box-shadow:0 8px 28px #18203312;min-width:0}
.unified-metric div{font-size:12px;color:#69758a}
.unified-metric strong{display:block;font-size:25px;letter-spacing:-.8px;margin-top:6px}
.unified-metric small{display:block;font-size:11px;color:#69758a;margin-top:4px}
.routing-panel{
  color:#182033;background:#fff;border:1px solid #d5dbe5;
  border-radius:14px;padding:16px;margin:16px 0;
  box-shadow:0 8px 28px #1820330b;box-sizing:border-box;
}
.routing-panel .routing-heading{
  font-size:16px;font-weight:700;line-height:24px;margin:0 0 12px;
}
.routing-panel .routing-grid{
  display:grid;
  grid-template-columns:max-content max-content max-content;
  column-gap:20px;
  row-gap:12px;
  align-items:start;
  justify-content:start;
}
.routing-panel .routing-heading{
  font-size:16px;font-weight:400;line-height:24px;
  margin:0;color:inherit;white-space:nowrap;
}
.routing-panel form.routing-controls{
  display:contents;
}
.routing-panel select option.current-route{color:#16803c;font-weight:700}
.routing-panel select{
  display:block;width:220px;max-width:100%;height:40px;
  margin:0;padding:0 10px;box-sizing:border-box;line-height:20px;
}
.routing-panel button{
  display:block;background:#315ee8;color:#fff;border:1px solid #315ee8;
  border-radius:8px;padding:0 15px;height:40px;min-height:40px;
  margin:0;box-sizing:border-box;line-height:20px;white-space:nowrap;
}
.routing-panel button.service-toggle{
  min-width:130px;height:40px;padding:0 16px;
  color:#fff;border:0;border-radius:8px;font-weight:400;
}
.routing-panel button.service-on{background:#16803c;border-color:#16803c}
.routing-panel button.service-off{background:#c62828;border-color:#c62828}
@media(max-width:600px){
  .routing-panel .routing-grid{grid-template-columns:1fr;row-gap:10px}
  .routing-panel .routing-heading:nth-child(1){grid-column:1;grid-row:1}
  .routing-panel .routing-heading:nth-child(2){grid-column:1;grid-row:3}
  .routing-panel .routing-heading:nth-child(3){display:none}
  .routing-panel select{grid-column:1}
  .routing-panel button.service-toggle{grid-column:1}
  .routing-panel form.routing-controls > button[type="submit"]:last-child{grid-column:1}
}
.routing-panel .routing-error{color:#b42318}

.routing-panel button.service-toggle{
  min-width:130px;height:40px;padding:0 16px;
  color:#fff;border:0;border-radius:8px;font-weight:700;
}
.routing-panel button.service-on{background:#16803c;border-color:#16803c}
.routing-panel button.service-off{background:#c62828;border-color:#c62828}

@media(prefers-color-scheme:dark){
  .routing-panel{color:#edf1fa;background:#171d29;border-color:#343d4c}
  .routing-panel .routing-check{color:#edf1fa}
  .routing-panel button{color:#fff;background:#315ee8;border-color:#315ee8}
}
.unified-tabs{display:flex;gap:5px;border-bottom:1px solid #e0e5ef;margin:0 0 18px}
.unified-tabs a{padding:12px 17px;border-bottom:3px solid transparent;margin-bottom:-1px;
color:#69758a;text-decoration:none;font-weight:750}
.unified-tabs a.active{color:#315ee8;border-bottom-color:#315ee8}
body{width:100%;max-width:none;box-sizing:border-box;margin:0;padding:0;background:#f3f5fa;color:#182033;font-family:Inter,ui-sans-serif,system-ui,sans-serif}
body>h1,body>p,body>div.panel,body>form{margin-left:auto;margin-right:auto;max-width:1200px}
button,input,select,textarea{font:inherit}
input:not([type="hidden"]),select,textarea{
  color:#182033;background-color:#fff;border:1px solid #b8c2d3;
  border-radius:7px;padding:9px 10px;box-sizing:border-box;
}
input:not([type="hidden"])::placeholder,textarea::placeholder{
  color:#69758a;opacity:1;
}
input:not([type="hidden"]):focus,select:focus,textarea:focus{
  outline:2px solid #8aa9ff;outline-offset:1px;border-color:#315ee8;
}
input:disabled,select:disabled,textarea:disabled{
  color:#69758a;background-color:#edf0f5;opacity:1;
}
button{cursor:pointer;border-radius:8px}
.panel{background:var(--surface,#fff);border-color:var(--border,#e0e5ef);border-radius:14px;
box-shadow:0 8px 28px #1820330b}
table{border-collapse:collapse}
th{background:#f7f8fc}
a{color:#315ee8}

/* Контраст старой и новой разметки */
body{color:#182033}
body h1,body h2,body h3,body p,body b,body strong,
body label,body td,body th,body .panel,body .msg{
  color:#182033;
}
body .panel{
  color:#182033;background-color:#fff;border-color:#d5dbe5;
}
body .msg{
  color:#182033;background-color:#eef3ff;
}
body table{background-color:#fff}
body th{color:#182033;background-color:#e9eef6}
body td{color:#182033}
body .unified-lead,body .unified-metric div,
body .unified-metric small{
  color:#475569;
}
body .unified-tabs a{color:#475569}
body .unified-tabs a.active{color:#244dcc}
body button{
  color:#182033;background-color:#eef1f6;border-color:#aab4c4;
}
body button.danger{color:#8b1e1e;background-color:#fee2e2;border-color:#efb4b4}
body .on{color:#176b35}
body .off{color:#8a4b00}

@media(max-width:760px){
.unified-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}
.unified-title{font-size:24px}
.unified-main{padding-top:18px}
}
@media(prefers-color-scheme:dark){
body{background:#10141d;color:#edf1fa}
.unified-title{color:#edf1fa}
.unified-lead,.unified-metric div,.unified-metric small{color:#a0abc0}
.unified-metric{background:#171b24;border-color:#343d4c}
.unified-tabs{border-color:#343d4c}
th{background:#202633}
input:not([type="hidden"]),select,textarea{
  color:#edf1fa;background-color:#1b2230;border-color:#465168;
}
input:not([type="hidden"])::placeholder,textarea::placeholder{
  color:#a0abc0;
}
input:disabled,select:disabled,textarea:disabled{
  color:#a0abc0;background-color:#252d3b;
}
body{color:#edf1fa}
body h1,body h2,body h3,body p,body b,body strong,
body label,body td,body th,body .panel,body .msg{
  color:#edf1fa;
}
body .panel{
  color:#edf1fa;background-color:#171d29;border-color:#343d4c;
}
body .msg{color:#edf1fa;background-color:#202a3b}
body table{background-color:#171d29}
body th{color:#edf1fa;background-color:#202633}
body td{color:#edf1fa}
body .unified-lead,body .unified-metric div,
body .unified-metric small{color:#b3bfd3}
body .unified-tabs a{color:#b3bfd3}
body .unified-tabs a.active{color:#9bb4ff}
body button{
  color:#edf1fa;background-color:#252d3b;border-color:#465168;
}
body button.danger{
  color:#ffd1d1;background-color:#48272b;border-color:#754047;
}
body .on{color:#78d99b}
body .off{color:#ffc66d}

.unified-status{display:flex;align-items:center;justify-content:flex-end;
gap:10px;flex-wrap:wrap;margin-left:auto}
.unified-health-group{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
body button.proxy-health-btn{
  display:inline-flex;align-items:center;justify-content:center;gap:9px;
  min-height:36px;padding:8px 12px;border:1px solid #465168;border-radius:999px;
  color:#edf1fa;background:#252d3b;font-size:12px;font-weight:700;
  cursor:pointer;white-space:nowrap
}
body button.proxy-health-btn .proxy-health-result{
  display:inline-block;min-width:42px;text-align:center;font-variant-numeric:tabular-nums;
  color:#b3bfd3;font-weight:800
}
body button.proxy-health-btn.health-ok{border-color:#35c58a;color:#a6f0c9}
body button.proxy-health-btn.health-ok .proxy-health-result{color:#35c58a}
body button.proxy-health-btn.health-error{border-color:#ef626c;color:#ff858d}
body button.proxy-health-btn.health-error .proxy-health-result{color:#ff858d}
body button.proxy-health-btn.health-checking{opacity:.75;cursor:wait}
@media(max-width:620px){
  .unified-status{width:100%;justify-content:flex-start}
  .unified-health-group{width:100%}
}
}
"""
    if "</style>" in page:
        page = page.replace("</style>", css + "\n</style>", 1)

    # Страница правил в текущем renderer не содержит явных body-тегов.
    if "<body" not in page.lower():
        if "</style>" in page:
            page = page.replace("</style>", "</style><body>", 1)
        else:
            page = page.replace("</html>", "<body></body></html>", 1)

    import re
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
    from configuration_draft import LOCK
    with LOCK:return _execute_queued_action(payload)

def _execute_queued_action(payload):
    if "subscription_automation" in payload:
        import subscription_automation
        return subscription_automation.apply(payload["subscription_automation"])
    import io
    from types import MethodType
    handler=object.__new__(Handler)
    body=payload["body"].encode("utf-8")
    handler.path=payload["path"]
    handler.action_progress=payload.get("_progress", lambda _stage: None)
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
        from configuration_draft import status as draft_status
        seed=json.dumps(draft_status()).replace("<","\\u003c")
        script="<script id=configuration-state type=application/json>"+seed+"</script><script>"+Path(BASE,"configuration_draft_ui.js").read_text(encoding="utf-8")+"</script>"
        body=body.replace("</head>",script+"</head>",1) if "</head>" in body else script+body
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
            self.send_html(decorate_page(geodata_panel.render(params.get("msg", [""])[0]), "geodata"))
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
        if params.get('tab',[''])[0]=='components':
            try:
                import vpn_components
                self.send_html(decorate_page(vpn_components.render(),'components'))
            except Exception as error:
                self.send_html('<h1>Компоненты</h1><pre>'+esc(error)+'</pre>',503)
            return
        if self.path.split('?',1)[0] == '/api/logs':
            try:
                import log_panel
                self.send_json(log_panel.snapshot(max(0,int(params.get('after',['0'])[0]))))
            except (ValueError, TypeError):
                self.send_json({'message':'Некорректный курсор'},400)
            except Exception:
                self.send_json({'message':'Ядро временно недоступно'},503)
            return
        if params.get('tab',[''])[0] == 'logs':
            import log_panel
            self.send_html(decorate_page(log_panel.render(),'logs'))
            return

        if params.get("download", [""])[0]=="backup" and (QUEUE.status()["queued"]+QUEUE.status()["running"]):
            self.redirect_message("Дождитесь завершения очереди перед созданием резервной копии.",tab="backup")
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
            except Exception as e: self.send_html("<h1>Ошибка создания резервной копии</h1><pre>"+esc(e)+"</pre>",500)
            return
        if params.get("tab", [""])[0] == "backup":
            message=params.get("msg", [""])[0]; page=render_backup_page()
            if message: page='<div class="msg">'+esc(message)+'</div>'+page
            self.send_html(decorate_page(page,"backup")); return

        if self.path.split("?",1)[0]=="/api/actions/history":
            try:
                before=max(0,int(params.get("before",["0"])[0]))
                self.send_json(QUEUE.history(before=before))
            except (ValueError,TypeError):
                self.send_json({"message":"Некорректный номер действия"},400)
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
                message = params.get("msg", [""])[0]
                if message:
                    page = page.replace("<body>", "<body><p role=\"status\">" + esc(message) + "</p>", 1)
                self.send_html(decorate_page(page, "proxies"))
            except Exception as e:
                self.send_html("<h1>Ошибка раздела прокси</h1><pre>" + esc(e) + "</pre>", 500)
            return

        if params.get("tab", [""])[0] == "services":
            try:
                targets = route_targets()
                page = render_services(params, targets=targets)
                self.send_html(decorate_page(page, "services", targets=targets))
            except Exception as e:
                self.send_html("<h1>Ошибка раздела правил</h1><pre>" + esc(e) + "</pre>", 500)
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
        message = params.get("msg", [""])[0]

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
                self.send_html("<h1>Ошибка чтения данных</h1><pre>" + esc(e) + "</pre>", 500)
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
            elif fake_mode and ((owner is not None and target != "DIRECT") or (owner is None and legacy_fake and resolve_target() != "DIRECT")):
                dns_label = "FakeIP"
            if owner is None and domain in local_dns and settings.get("services_enabled", True):
                dns_label = local_dns[domain]
                if dns_label == "FakeIP" and not fake_mode:
                    dns_label = "RealIP"
            status_class = "off" if dns_label == "NODOMAIN" else "on" if dns_label == "FakeIP" else ""
            if owner is not None:
                origin = '<a href="' + esc(service_edit_url(owner)) + '">' + esc(owner["name"]) + '</a>'
                disabled = False
                actions = '<span>Управляется правилом</span>'
                status_control = f'<span class="{status_class}">{dns_label}</span>'
            elif domain in service_domains:
                origin = "Основной маршрут"
                status_control = f'<span class="{status_class}">{dns_label}</span>'
                actions = ""
            else:
                origin = esc(SOURCE_NAME if domain in source else "Локальный")
                disabled = domain in removes
                selected_mode = local_dns.get(domain, dns_label)
                dns_options = "".join(
                    f'<option value="{mode}"{" selected" if mode == selected_mode else ""}>{mode}</option>'
                    for mode in ("FakeIP", "RealIP", "NODOMAIN")
                )
                status_control = f"""<form method="post" action="/action" class="inline domain-toggle">
<input type="hidden" name="action" value="domain_dns">
<input type="hidden" name="old" value="{esc(domain)}">
<select name="dns_mode" aria-label="DNS домена {esc(domain)}" onchange="this.form.requestSubmit()">{dns_options}</select>
</form>"""
                actions = """<form method="post" action="/action" class="inline" onsubmit="return confirm('Удалить {domain} из панели?')">
<input type="hidden" name="action" value="delete">
<input type="hidden" name="old" value="{domain}">
<button class="danger" type="submit">Удалить</button>
</form>""".format(
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
            nav += page_link(page - 1, "← Назад") + " "
        nav += "Страница %d из %d" % (page, pages)
        if page < pages:
            nav += " " + page_link(page + 1, "Вперёд →")

        service_names = sorted({item["name"] for item in read_services() if item.get("name")}, key=str.casefold)
        service_filter_options = [
            '<option value="service" %s>S:Все правила</option>' % (
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

        body = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Universal VPN Core — DNS</title>
<style>
body{{font:16px system-ui,sans-serif;max-width:1250px;margin:24px auto;padding:0 14px;color:#222}}
input,button{{font:inherit;padding:8px}}input{{max-width:100%;box-sizing:border-box}}
button{{cursor:pointer;border:1px solid #999;border-radius:5px;background:#eee}}
button:disabled{{opacity:.4;cursor:default}}
.danger{{background:#fee}}
.panel{{border:1px solid #ccc;border-radius:8px;padding:14px;margin:14px 0}}
.panel-spoiler>summary{{cursor:pointer;font-size:1.25em;font-weight:700;list-style:none;display:flex;align-items:center;gap:9px}}
.panel-spoiler>summary::-webkit-details-marker{{display:none}}
.panel-spoiler>summary::before{{content:"";width:0;height:0;border-top:5px solid transparent;border-bottom:5px solid transparent;border-left:7px solid currentColor;flex:none}}
.panel-spoiler[open]>summary{{margin-bottom:14px}}
.panel-spoiler[open]>summary::before{{transform:rotate(90deg)}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;border-bottom:1px solid #ddd;padding:8px;overflow-wrap:anywhere}}
th{{background:#f4f4f4}}
.inline{{display:inline-block;margin:2px}}
.actions{{min-width:260px}}
.domain{{font-weight:500}}
.on{{color:#176b35;font-weight:600}}
.off{{color:#a45b00;font-weight:600}}
.msg{{white-space:pre-wrap;background:#f3f6ff;padding:12px;overflow-wrap:anywhere}}
nav{{margin:18px 0}}form.search{{display:flex;gap:8px;flex-wrap:wrap}}
.domain-filter-form{{width:100%;margin:0}}
.domain-filter-box{{width:100%;box-sizing:border-box;border:1px solid #b8c2d3;border-radius:8px;overflow:hidden}}
.domain-filter-box textarea{{display:block;width:100%;height:10em;min-height:10em;max-height:10em;box-sizing:border-box;resize:none;overflow:auto;white-space:pre;border:0!important;border-radius:0!important}}
.domain-filter-footer{{display:flex;justify-content:flex-end;padding:8px 10px;border-top:1px solid #b8c2d3}}
.domain-refresh-row{{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:12px}}
.domain-refresh-row p{{margin:0}}
.domain-refresh-row form{{flex:0 0 auto;margin:0}}
@media(max-width:760px){{.domain-refresh-row{{align-items:stretch;flex-direction:column}}.domain-refresh-row form button{{width:100%}}}}
@media(max-width:760px){{
 table{{font-size:14px}}
 th,td{{padding:5px}}
 .actions{{min-width:190px}}
}}
</style>
</head>
<body>
{message}
<div class="panel">
<details class="panel-spoiler"><summary>Добавить локальные домены</summary>
<form method="post" action="/action" class="domain-filter-form">
<input type="hidden" name="action" value="add">
<div class="domain-filter-box">
<textarea name="new" rows="8" wrap="off" placeholder="example.com; example.org&#10;example.net" required></textarea>
<div class="domain-filter-footer"><button type="submit">Добавить и включить домены</button></div>
</div>
</form>
<p>Перечислите домены через точку с запятой или каждый с новой строки. Для каждого домена сразу создаётся правило <code>DOMAIN-SUFFIX</code>, поэтому оно распространяется и на все его поддомены. Домены получают источник «Локальный».</p>
</details>
</div>
<div class="panel">
<details class="panel-spoiler" id="domain-list"{list_open}><summary>Список доменов</summary>
<div id="domain-list-content">
<form id="clear-auto-domains-form" method="post" action="/action"
onsubmit="return confirm('Очистить все автоматически загруженные домены? Локальные домены останутся.')">
<input type="hidden" name="action" value="clear_auto_domains">
</form>
<form class="search" method="get" action="/">
<input type="hidden" name="load" value="1">
<input name="q" value="{query}" placeholder="Поиск по домену">
<select name="source">
<option value="all" {source_all}>Все источники</option>
<option value="rkn" {source_rkn}>{source_name}</option>
<option value="local" {source_local}>Локальный</option>
{service_filter_options}
</select>
<select name="status">
<option value="all" {status_all}>Все статусы</option>
<option value="enabled" {status_enabled}>Включено</option>
<option value="disabled" {status_disabled}>Отключено</option>
</select>
<button type="submit">Найти</button>
<button type="button" onclick="window.location.href='/?load=1'">Сбросить поиск</button>
<button type="submit" form="clear-auto-domains-form" class="danger" style="font-weight:700">Очистить список доменов</button>
</form>
<p>Найдено: {match_count}</p>
<table>
<thead><tr><th>Домен</th><th>Источник</th><th>Статус</th><th>Действия</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<nav>{nav}</nav>
</div></details></div>
</body>
</html>""".format(
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
            rows="".join(rows) or '<tr><td colspan="4">Нет доменов по заданному запросу</td></tr>',
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
            body = body[:start] + '<p role="status">Раскройте список для загрузки.</p>' + body[end:]
        body = body.replace('</body>', """<script>
(()=> {
 const details=document.getElementById("domain-list"),content=document.getElementById("domain-list-content");
 let loaded=details.open,busy=false;
 async function load() {
  if(loaded||busy)return;
  busy=true;content.textContent="Загрузка доменов…";
  try {
   const url=new URL(location.href);url.searchParams.set("load","1");url.searchParams.set("fragment","domains");
   const response=await fetch(url,{cache:"no-store"});
   if(!response.ok)throw new Error("Не удалось загрузить список доменов.");
   content.innerHTML=await response.text();loaded=true;
  } catch(error) {
   content.replaceChildren(document.createTextNode(error.message+" "));
   const retry=document.createElement("button");retry.type="button";retry.textContent="Повторить";
   retry.addEventListener("click",load);content.append(retry);
  } finally {busy=false;}
 }
 details.addEventListener("toggle",()=>{if(details.open)load();});
})();
</script></body>""")
        from dns_panel import render as render_dns
        marker = '<div class="panel">\n<details class="panel-spoiler"><summary>Добавить локальные домены'
        body = body.replace(marker, render_dns() + marker, 1)
        self.send_html(decorate_page(body, "domains", domain_counts=domain_counts))

    def do_POST(self):
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
                if getattr(self, 'after_commit', None):
                    self.after_commit.append(panel_updater.schedule_restart)
                self.redirect_message(message,tab='components')
                return
            if action in ('subscription_add', 'subscription_refresh', 'subscription_delete', 'subscription_automation'):
                import vpn_subscriptions
                try:
                    message = vpn_subscriptions.handle(action, data)
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
                count = proxy_manager.delete_many(data.get("selected", []))
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
                    proxy_manager.delete(name)
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
    httpd.serve_forever()


