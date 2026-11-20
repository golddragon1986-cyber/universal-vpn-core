from durable_io import replace as durable_replace
#!/usr/bin/env python3
import copy
import uuid
import html
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import parse_qs, quote

BASE = "/etc/mihomo/rules"
DATA = os.path.join(BASE, "service-routes.json")
BUILDER = os.path.join(BASE, "build-service-routes.py")
DOMAIN_BUILDER = os.path.join(BASE, "update-ru-blocked.sh")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+"
)

def esc(value):
    return html.escape(str(value), quote=True)

def read_services():
    with open(DATA, encoding="utf-8") as f:
        items = json.load(f)
    if not isinstance(items, list):
        raise ValueError("\u041e\u0436\u0438\u0434\u0430\u043b\u0441\u044f \u0441\u043f\u0438\u0441\u043e\u043a \u0441\u0435\u0440\u0432\u0438\u0441\u043e\u0432")
    return items

SOURCE_REPO = "v2fly/domain-list-community"
CATALOG_CACHE = os.path.join(BASE, "domain-list-community-catalog.json")
CATALOG_TREE_URL = "https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1"
CATALOG_RAW_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"


def fetch_source_catalog(refresh=False):
    if not refresh:
        try:
            with open(CATALOG_CACHE, encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - float(cached.get("fetched_at", 0)) < 86400 and isinstance(cached.get("services"), list):
                return cached
        except (OSError, ValueError, TypeError):
            pass
    request = urllib.request.Request(
        CATALOG_TREE_URL,
        headers={"User-Agent": "Mihomo-Control/1.0", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read(8 * 1024 * 1024 + 1).decode("utf-8"))
    if payload.get("truncated"):
        raise RuntimeError("GitHub вернул неполный каталог сервисов")
    services = []
    for entry in payload.get("tree", []):
        path = entry.get("path", "")
        name = path[5:] if path.startswith("data/") else ""
        if entry.get("type") == "blob" and "/" not in name and re.fullmatch(r"[A-Za-z0-9._!-]{1,120}", name):
            services.append({"name": name, "sha": entry.get("sha", "")})
    services.sort(key=lambda item: item["name"].casefold())
    result = {"fetched_at": time.time(), "tree_sha": payload.get("sha", ""), "services": services}
    fd, tmp = tempfile.mkstemp(prefix="service-catalog-", dir=BASE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
            f.write("\n")
        durable_replace(tmp, CATALOG_CACHE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return result


def fetch_source_domains(slug, catalog, visited=None):
    visited = visited or set()
    if slug in visited:
        return set(), set(), set(), set()
    if len(visited) >= 100:
        raise ValueError("Слишком много связанных списков в источнике")
    if slug not in catalog or not re.fullmatch(r"[A-Za-z0-9._!-]{1,120}", slug):
        raise ValueError("Источник содержит ссылку на неизвестный список: " + slug)
    visited.add(slug)
    request = urllib.request.Request(
        CATALOG_RAW_URL + quote(slug, safe=""),
        headers={"User-Agent": "Mihomo-Control/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Файл списка превышает 2 МиБ: " + slug)
    suffix_domains, exact_domains, keyword_domains, regex_domains = set(), set(), set(), set()
    for line in raw.decode("utf-8-sig", "replace").splitlines():
        line = line.partition("#")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        if token.startswith("include:"):
            included = token.partition(":")[2]
            child_suffix, child_exact, child_keywords, child_regexes = fetch_source_domains(included, catalog, visited)
            suffix_domains.update(child_suffix)
            exact_domains.update(child_exact)
            keyword_domains.update(child_keywords)
            regex_domains.update(child_regexes)
            continue
        kind, sep, value = token.partition(":")
        if sep and kind in ("domain", "full"):
            exact = kind == "full"
            domain = value
            try:
                domain = domain.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError:
                continue
            if DOMAIN_RE.fullmatch(domain):
                (exact_domains if exact else suffix_domains).add(domain)
        elif sep and kind == "keyword":
            try:
                keyword = value.encode("idna").decode("ascii").lower()
            except UnicodeError:
                continue
            if re.fullmatch(r"[a-z0-9.-]{1,253}", keyword):
                keyword_domains.add(keyword)
        elif sep and kind == "regexp":
            if value and len(value) <= 1024 and "\n" not in value and "\r" not in value:
                regex_domains.add(value)
        elif sep:
            # Other source directives are not domain match rules.
            continue
        else:
            try:
                domain = token.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError:
                continue
            if DOMAIN_RE.fullmatch(domain):
                suffix_domains.add(domain)
        if len(suffix_domains) + len(exact_domains) + len(keyword_domains) + len(regex_domains) > 20000:
            raise ValueError("Список содержит больше 20 000 правил")
    return suffix_domains, exact_domains, keyword_domains, regex_domains

def source_display_name(slug):
    return " ".join(part.capitalize() for part in slug.replace("_", "-").split("-"))



def ensure_service_ids(items):
    for item in items:
        if not item.get("id"):
            item["id"]=uuid.uuid4().hex
    return items

def write_services(items):
    ensure_service_ids(items)
    fd, tmp = tempfile.mkstemp(prefix="service-routes-", dir=BASE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
            f.write("\n")
        durable_replace(tmp, DATA)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

ROUTE_LABELS = {
    "LOADBALANCE": "Балансировка (LOADBALANCE)",
    "DIRECT": "Напрямую (DIRECT)",
    "REJECT": "Блокировать (REJECT)",
    "PASS": "Разрешить (PASS)",
}

def route_targets():
    host = os.environ.get("EXTERNAL_CONTROLLER_ADDRESS", "127.0.0.1")
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    port = os.environ.get("UI_PORT", "9090")
    headers = {}
    secret = os.environ.get("UI_SECRET", "")
    if secret:
        headers["Authorization"] = "Bearer " + secret

    req = urllib.request.Request(
        f"http://{host}:{port}/proxies", headers=headers
    )
    with urllib.request.urlopen(req, timeout=4) as response:
        payload = json.load(response)

    groups = payload.get("proxies", {})
    balance = groups.get("LOADBALANCE", {})
    members = balance.get("all", [])

    if not isinstance(members, list) or not members:
        raise RuntimeError("Mihomo не вернул узлы группы LOADBALANCE")

    targets = sorted({
        str(name)[len("CHANNEL-"):] if str(name).startswith("CHANNEL-") else str(name)
        for name in members
        if isinstance(name, str) and name and name not in ROUTE_LABELS
    })
    for standard in ("LOADBALANCE", "DIRECT", "REJECT", "PASS"):
        if standard in groups:
            targets.append(standard)

    if "LOADBALANCE" not in targets:
        raise RuntimeError("В Mihomo отсутствует группа LOADBALANCE")
    return targets

def handle_action(data):
    action = data.get("action", [""])[0]
    items = read_services()
    original = copy.deepcopy(items)
    service_id=data.get("service_id",[""])[0]
    if service_id:
        matches=[i for i,item in enumerate(items) if item.get("id")==service_id or ("name:"+str(item.get("name","")))==service_id]
        if len(matches)!=1:
            raise ValueError("Сервис уже удалён или изменён. Обновите список.")
        data=dict(data)
        data["index"]=[str(matches[0])]

    extra_message = ""
    if action == "service_save":
        name = data.get("name", [""])[0].strip()
        target = data.get("target", [""])[0].strip()
        raw_domains = data.get("domains", [""])[0]
        from router_routes import validate_destination
        domains, exact_domains, keyword_domains, regex_domains, networks = [], [], [], [], []
        for raw_line in raw_domains.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            tokens = [raw_line] if raw_line.lower().startswith("regexp:") else re.split(r"[,;\s]+", raw_line)
            for raw_domain in tokens:
                raw_domain = raw_domain.strip()
                if not raw_domain:
                    continue
                if "/" in raw_domain and ":" not in raw_domain:
                    network = validate_destination(raw_domain)
                    if network not in networks:
                        networks.append(network)
                    continue
                kind, sep, value = raw_domain.partition(":")
                if sep and kind.lower() == "regexp":
                    if not value or len(value) > 1024 or "\n" in value or "\r" in value:
                        raise ValueError("Недопустимое регулярное выражение")
                    if value not in regex_domains:
                        regex_domains.append(value)
                    continue
                if sep and kind.lower() == "keyword":
                    keyword = value.lower().rstrip(".")
                    if not re.fullmatch(r"[a-z0-9.-]{1,253}", keyword):
                        raise ValueError("Недопустимое ключевое слово: " + value)
                    if keyword not in keyword_domains:
                        keyword_domains.append(keyword)
                    continue
                exact = bool(sep and kind.lower() == "full")
                if sep and kind.lower() not in ("full", "domain"):
                    raise ValueError("Неизвестный тип доменного правила: " + kind)
                domain = (value if sep else raw_domain).lower().rstrip(".")
                if not DOMAIN_RE.fullmatch(domain):
                    raise ValueError("Недопустимый домен: " + raw_domain)
                target_list = exact_domains if exact else domains
                if domain not in target_list:
                    target_list.append(domain)

        if not name or len(name) > 100:
            raise ValueError("Название сервиса обязательно, максимум 100 символов")
        if not (domains or exact_domains or keyword_domains or regex_domains or networks):
            raise ValueError("Укажите хотя бы один домен или IPv4-сеть")
        if target not in route_targets():
            raise ValueError("Недопустимая группа маршрутизации")

        index = int(data.get("index", ["-1"])[0])
        entry = {
            "name": name,
            "target": target,
            "domains": domains,
            "exact_domains": exact_domains,
            "keyword_domains": keyword_domains,
            "regex_domains": regex_domains,
            "networks": networks,
            "enabled": True
        }
        if index >= 0:
            if index >= len(items):
                raise ValueError("Неверный индекс сервиса")
            entry["enabled"] = bool(items[index].get("enabled", True))
            for key in ("id", "source_repo", "source_service", "source_sha"):
                if key in items[index]:
                    entry[key] = items[index][key]
            items[index] = entry
        else:
            items.append(entry)

    elif action == "service_catalog_import":
        selected = list(dict.fromkeys(data.get("catalog_service", [])))
        target = data.get("catalog_target", ["LOADBALANCE"])[0].strip()
        if not selected:
            raise ValueError("Выберите сервисы для загрузки")
        if len(selected) > 20:
            raise ValueError("За один раз можно загрузить не более 20 сервисов")
        if target not in route_targets():
            raise ValueError("Недопустимая группа маршрутизации")
        catalog_data = fetch_source_catalog()
        catalog = {item["name"]: item for item in catalog_data["services"]}
        existing = {item.get("source_service") for item in items if item.get("source_repo") == SOURCE_REPO}
        imported, skipped = [], []
        used_names = {str(item.get("name", "")).casefold() for item in items}
        for slug in selected:
            if slug not in catalog:
                raise ValueError("Список больше не найден в каталоге: " + slug)
            if slug in existing:
                skipped.append(slug)
                continue
            suffix_domains, exact_domains, keyword_domains, regex_domains = fetch_source_domains(slug, catalog)
            if not (suffix_domains or exact_domains or keyword_domains or regex_domains):
                raise ValueError("В списке нет поддерживаемых доменных правил: " + slug)
            display_name = source_display_name(slug)
            if display_name.casefold() in used_names:
                display_name = (display_name + " (v2fly)")[:100]
            items.append({
                "name": display_name,
                "target": target,
                "domains": sorted(suffix_domains),
                "exact_domains": sorted(exact_domains),
                "keyword_domains": sorted(keyword_domains),
                "regex_domains": sorted(regex_domains),
                "enabled": True,
                "source_repo": SOURCE_REPO,
                "source_service": slug,
                "source_sha": catalog[slug].get("sha", "")
            })
            existing.add(slug)
            used_names.add(display_name.casefold())
            imported.append(f"{slug} ({len(suffix_domains) + len(exact_domains) + len(keyword_domains) + len(regex_domains)} правил)")
        if not imported:
            raise ValueError("Выбранные сервисы уже добавлены; обновите их в таблице ниже")
        extra_message = "Добавлены и включены: " + ", ".join(imported)
        if skipped:
            extra_message += "; уже были добавлены: " + ", ".join(skipped)

    elif action == "service_update_source":
        index = int(data.get("index", ["-1"])[0])
        if index < 0 or index >= len(items):
            raise ValueError("Сервис не найден")
        entry = items[index]
        slug = entry.get("source_service", "")
        if entry.get("source_repo") != SOURCE_REPO or not slug:
            raise ValueError("Сервис не связан с каталогом GitHub")
        catalog_data = fetch_source_catalog(refresh=True)
        catalog = {item["name"]: item for item in catalog_data["services"]}
        if slug not in catalog:
            raise ValueError("Список удалён из каталога GitHub: " + slug)
        suffix_domains, exact_domains, keyword_domains, regex_domains = fetch_source_domains(slug, catalog)
        if not (suffix_domains or exact_domains or keyword_domains or regex_domains):
            raise ValueError("В списке нет поддерживаемых доменных правил: " + slug)
        entry["domains"] = sorted(suffix_domains)
        entry["exact_domains"] = sorted(exact_domains)
        entry["keyword_domains"] = sorted(keyword_domains)
        entry["regex_domains"] = sorted(regex_domains)
        entry["source_sha"] = catalog[slug].get("sha", "")
        extra_message = "Обновлён из GitHub: " + slug

    elif action in ("service_toggle", "service_delete"):
        index = int(data.get("index", ["-1"])[0])
        if index < 0 or index >= len(items):
            raise ValueError("\u0421\u0435\u0440\u0432\u0438\u0441 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d")
        if action == "service_delete":
            items.pop(index)
        else:
            items[index]["enabled"] = not bool(items[index].get("enabled", True))
    else:
        raise ValueError("Unknown action")

    write_services(items)
    result = subprocess.run(
        ["python3", BUILDER],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode:
        write_services(original)
        subprocess.run(
            ["python3", BUILDER],
            capture_output=True, text=True, timeout=15
        )
        raise RuntimeError(
            (result.stderr or result.stdout or "Builder failed").strip()
        )

    domain_result = subprocess.run(
        [DOMAIN_BUILDER], capture_output=True, text=True, timeout=240
    )
    if domain_result.returncode:
        write_services(original)
        subprocess.run(
            ["python3", BUILDER],
            capture_output=True, text=True, timeout=15
        )
        domain_rollback = subprocess.run(
            [DOMAIN_BUILDER], capture_output=True, text=True, timeout=240
        )
        message = (domain_result.stderr or domain_result.stdout or "Domain provider build failed").strip()
        if domain_rollback.returncode:
            message += "; domain provider rollback failed: " + (domain_rollback.stderr or domain_rollback.stdout or "unknown error").strip()
        raise RuntimeError(message)

    apply_result = subprocess.run(
        ["python3", os.path.join(BASE, "apply-service-routes.py")],
        capture_output=True, text=True, timeout=60
    )
    if apply_result.returncode:
        write_services(original)
        rollback = subprocess.run(
            ["python3", BUILDER],
            capture_output=True, text=True, timeout=15
        )
        domain_rollback = subprocess.run(
            [DOMAIN_BUILDER], capture_output=True, text=True, timeout=240
        )
        message = (
            apply_result.stderr or apply_result.stdout
            or "Live apply failed"
        ).strip()
        if rollback.returncode:
            message += "; template rollback failed: " + (
                rollback.stderr or rollback.stdout or "unknown error"
            ).strip()
        if domain_rollback.returncode:
            message += "; domain provider rollback failed: " + (
                domain_rollback.stderr or domain_rollback.stdout or "unknown error"
            ).strip()
        raise RuntimeError(message)

    messages = [
        (result.stdout or "").strip(),
        (domain_result.stdout or "").strip(),
        (apply_result.stdout or "").strip()
    ]
    if extra_message:
        messages.append(extra_message)
    return "\n".join(message for message in messages if message)

def render_services(params, targets=None):
    items = read_services()
    if targets is None:
        targets = route_targets()
    edit_index = -1
    try:
        edit_index = int(params.get("edit", ["-1"])[0])
    except (ValueError, TypeError):
        pass

    service_id=params.get("service_id",[""])[0]
    if service_id:
        matches=[i for i,item in enumerate(items) if item.get("id")==service_id or "name:"+str(item.get("name",""))==service_id]
        if len(matches)!=1:
            raise ValueError("Сервис уже удалён. Обновите список.")
        edit_index=matches[0]
    current = {}
    if 0 <= edit_index < len(items):
        current = items[edit_index]

    title = (
        "\u0420\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0441\u0435\u0440\u0432\u0438\u0441"
        if current else
        "\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u0441\u0435\u0440\u0432\u0438\u0441"
    )
    name_value = esc(current.get("name", ""))
    domains = current.get("domains", [])
    if isinstance(domains, str):
        domains = [domains]
    exact_domains = current.get("exact_domains", [])
    if isinstance(exact_domains, str):
        exact_domains = [exact_domains]
    keyword_domains = current.get("keyword_domains", [])
    regex_domains = current.get("regex_domains", [])
    if isinstance(keyword_domains, str):
        keyword_domains = [keyword_domains]
    if isinstance(regex_domains, str):
        regex_domains = [regex_domains]
    domains_value = esc("\n".join(list(domains) + list(current.get("networks", [])) + ["full:" + d for d in exact_domains] + ["keyword:" + d for d in keyword_domains] + ["regexp:" + d for d in regex_domains]))
    selected_target = current.get("target", "LOADBALANCE")
    if selected_target == "SELECTOR":
        selected_target = "LOADBALANCE"

    options = []
    for target in targets:
        selected = " selected" if target == selected_target else ""
        options.append(f'<option value="{esc(target)}"{selected}>{esc(ROUTE_LABELS.get(target, target))}</option>')

    rows = []
    for i, item in enumerate(items):
        domains = item.get("domains", [])
        if isinstance(domains, str):
            domains = [domains]
        enabled = bool(item.get("enabled", True))
        status_label = "Включено" if enabled else "Отключено"
        status_color = "#16803c" if enabled else "#c62828"
        status_button = f'''<form method="post"><input type="hidden" name="action" value="service_toggle"><input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}"><button type="submit" style="background:{status_color};color:white;font-weight:700;width:130px;min-width:130px;box-sizing:border-box;text-align:center;white-space:nowrap">{status_label}</button></form>'''
        source_update = ""
        if item.get("source_repo") == SOURCE_REPO and item.get("source_service"):
            source_update = f"""<form method=\"post\"><input type=\"hidden\" name=\"action\" value=\"service_update_source\"><input type=\"hidden\" name=\"index\" value=\"{i}\"><input type=\"hidden\" name=\"service_id\" value=\"{esc(item.get('id') or 'name:'+str(item.get('name','')))}\"><button type=\"submit\">Обновить</button></form>"""
        rows.append(f"""
<tr>
<td>{esc(item.get('name', ''))}</td>
<td>{esc(ROUTE_LABELS.get(item.get('target', ''), item.get('target', '')))}</td>
<td>{status_button}</td>
<td class="actions">
<a class="action-button" href="/?tab=services&amp;edit={i}&amp;service_id={quote(item.get('id') or 'name:'+str(item.get('name','')),safe='')}">\u0418\u0437\u043c\u0435\u043d\u0438\u0442\u044c</a>
{source_update}
<form method="post" onsubmit="return confirm('\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435?')">
<input type="hidden" name="action" value="service_delete">
<input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}">
<button type="submit" class="danger">\u0423\u0434\u0430\u043b\u0438\u0442\u044c</button></form>
</td></tr>""")

    table_rows = "\n".join(rows) or (
        '<tr><td colspan="4">\u041d\u0435\u0442 \u0441\u0435\u0440\u0432\u0438\u0441\u043e\u0432. \u0414\u043e\u0431\u0430\u0432\u044c\u0442\u0435 \u043f\u0435\u0440\u0432\u044b\u0439 \u0441\u0435\u0440\u0432\u0438\u0441.</td></tr>'
    )

    catalog_query = str(params.get("catalog_q", [""])[0]).strip()
    imported_source_services = {item.get("source_service") for item in items if item.get("source_repo") == SOURCE_REPO}
    catalog_panel = ""
    catalog_message = ""
    catalog_rows = []
    catalog_target_options = []
    for target in targets:
        selected = " selected" if target == "LOADBALANCE" else ""
        catalog_target_options.append(f'<option value="{esc(target)}"{selected}>{esc(ROUTE_LABELS.get(target, target))}</option>')
    if catalog_query:
        try:
            catalog_data = fetch_source_catalog()
            matches = [item for item in catalog_data["services"] if catalog_query.casefold() in item["name"].casefold()]
            for item in matches[:100]:
                slug = item["name"]
                already_added = slug in imported_source_services
                disabled = " disabled" if already_added else ""
                badge = " · уже добавлен" if already_added else ""
                catalog_rows.append(
                    f'<label class="catalog-service"><input type="checkbox" name="catalog_service" value="{esc(slug)}"{disabled}>'
                    f'<span><strong>{esc(source_display_name(slug))}{badge}</strong><small>{esc(slug)}</small></span></label>'
                )
            if matches:
                catalog_message = f'<p class="hint">Найдено: {len(matches)}. Показаны первые {min(100, len(matches))} результатов. Выберите до 20 списков.</p>'
                catalog_panel = f"""<form method="post" class="catalog-import-form">
<input type="hidden" name="action" value="service_catalog_import">
<div class="catalog-service-list">{''.join(catalog_rows)}</div>
<label>Маршрут для выбранных сервисов</label><select name="catalog_target">{''.join(catalog_target_options)}</select>
<button type="submit">Загрузить и включить выбранные</button></form>"""
            else:
                catalog_message = '<p class="hint">По этому запросу списки не найдены.</p>'
        except Exception as exc:
            catalog_message = f'<p class="catalog-error">Не удалось получить каталог GitHub: {esc(exc)}</p>'
    else:
        catalog_message = '<p class="hint">Введите часть названия и нажмите «Найти». Содержимое будет загружено только для выбранных сервисов.</p>'

    return f"""<!doctype html>
<html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mihomo Control — Сервисы</title>
<style>
body{{font:15px system-ui,sans-serif;max-width:1200px;margin:28px auto;padding:0 16px;background:#f5f7fa;color:#182230}}
h1,h2{{margin-top:0}} .panel{{background:white;border:1px solid #dce2ea;border-radius:12px;padding:18px;margin:16px 0}}
input,textarea,select,button{{font:inherit;padding:9px;border:1px solid #b9c4d2;border-radius:7px;box-sizing:border-box}}
input,textarea,select{{width:100%;margin:5px 0 14px}} textarea{{min-height:110px}}
button{{cursor:pointer;background:#e8eef7}} .danger{{color:#9b1c1c}}
.catalog-service-list{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:6px;margin:12px 0}}
.catalog-service{{display:flex;align-items:center;gap:9px;padding:8px;border:1px solid #e1e6ed;border-radius:7px;cursor:pointer}}
.catalog-service input{{width:auto;margin:0;flex:none}}.catalog-service span{{display:flex;flex-direction:column;min-width:0}}
.catalog-service small{{color:#657184;overflow-wrap:anywhere}}.catalog-import-form select{{max-width:420px}}
.catalog-error{{color:#a52222}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;border-bottom:1px solid #e1e6ed;text-align:left;vertical-align:middle}}
.reset-button,.action-button{{display:inline-block;font:inherit;padding:9px 12px;
border:1px solid #aab4c4;border-radius:8px;background:#eef1f6;color:#182033 !important;
text-decoration:none;line-height:1.2;vertical-align:middle}}
.reset-button:hover,.action-button:hover{{background:#e0e7f1}}
.actions{{vertical-align:middle}}
.actions form{{display:inline-block;vertical-align:middle;margin:4px}}
.actions a{{margin:4px}}
.actions form{{display:inline-block;margin:4px}} .hint{{color:#4d5a6b}} a{{color:#185abc}}

@media(prefers-color-scheme:dark){{
.reset-button,.action-button{{background:#252d3b;color:#edf1fa !important;border-color:#465168}}
.reset-button:hover,.action-button:hover{{background:#303b4d}}
}}
</style>
<div class="panel">
<details class="panel-spoiler"{" open" if current else ""}><summary>{title}</summary>
<form method="post">
<input type="hidden" name="action" value="service_save">
<input type="hidden" name="index" value="{edit_index if current else -1}"><input type="hidden" name="service_id" value="{esc(current.get('id') or ('name:'+str(current.get('name','')) if current else ''))}">
<label>\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u0430</label>
<input name="name" maxlength="100" required value="{name_value}" placeholder="\u0418\u043c\u044f, \u043d\u0430\u043f\u0440\u0438\u043c\u0435\u0440 YouTube">
<label>Домены и IPv4-сети. Разделяйте записи точкой с запятой или новой строкой.</label>
<textarea name="domains" required placeholder="youtube.com; googlevideo.com&#10;8.8.4.0/24">{domains_value}</textarea>
<label>\u0413\u0440\u0443\u043f\u043f\u0430 \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u0438</label>
<select name="target">{"".join(options)}</select>
<button type="submit">\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c</button>
<a class="reset-button" href="/?tab=services">\u0421\u0431\u0440\u043e\u0441\u0438\u0442\u044c</a>
</form></details></div>
<div class="panel"><details class="panel-spoiler"{" open" if catalog_query else ""}><summary>Каталог сервисов GitHub</summary>
<p class="hint">Поиск по спискам v2fly/domain-list-community. Выбранные списки загрузятся и включатся в правила маршрутизации.</p>
<form method="get"><input type="hidden" name="tab" value="services"><label>Поиск по названию списка</label><input name="catalog_q" value="{esc(catalog_query)}" placeholder="например, youtube, netflix, google"><button type="submit">Найти</button></form>
{catalog_message}{catalog_panel}</details></div>
<div class="panel"><h2>\u041d\u0430\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u044b\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044b</h2>
<table><thead><tr><th>\u0421\u0435\u0440\u0432\u0438\u0441</th><th>\u0413\u0440\u0443\u043f\u043f\u0430</th><th>\u0421\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435</th><th>\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044f</th></tr></thead>
<tbody>{table_rows}</tbody></table></div>
<p class="hint">\u0412\u0430\u0436\u043d\u043e: \u043f\u043e\u0441\u043b\u0435 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u043f\u043e\u043f\u0430\u0434\u0430\u044e\u0442 \u0432 \u0448\u0430\u0431\u043b\u043e\u043d, \u043d\u043e \u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0439 Mihomo \u043d\u0435 \u043f\u0435\u0440\u0435\u0437\u0430\u0433\u0440\u0443\u0436\u0430\u0435\u0442\u0441\u044f \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438.</p>
</html>"""
