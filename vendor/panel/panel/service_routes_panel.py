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
import threading
import time
import urllib.request
from contextlib import contextmanager
from urllib.parse import parse_qs, quote

BASE = "/etc/mihomo/rules"
DATA = os.path.join(BASE, "service-routes.json")
BUILDER = os.path.join(BASE, "build-service-routes.py")
DOMAIN_BUILDER = os.path.join(BASE, "update-ru-blocked.sh")
SERVICE_LOOKUP_LOCK = threading.Lock()
MRS_DOMAIN_CACHE_LOCK = threading.Lock()
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*"
)

def esc(value):
    return html.escape(str(value), quote=True)

def service_edit_url(item):
    service_id = item.get("id") or "name:" + item["name"]
    return "/?tab=services&service_id=" + quote(service_id, safe="") + "#service-editor"

def read_services():
    from configuration_draft import state_path
    with open(state_path(DATA), encoding="utf-8") as f:
        items = json.load(f)
    if not isinstance(items, list):
        raise ValueError("Ожидался список правил")
    for item in items:
        if not item.get("target"): item["target"] = "SELECTOR"
    return items


def service_rule_count(item):
    return item.get("geo_count", 0) + sum(
        1 if isinstance(value, str) else len(value)
        for key in ("domains", "exact_domains", "keyword_domains", "regex_domains", "networks")
        if (value := item.get(key))
    )


@contextmanager
def mrs_domains(path):
    from geodata_service_files import mrs_command

    cache = path.with_suffix(".domains")
    with MRS_DOMAIN_CACHE_LOCK:
        source_stat = path.stat()
        if not cache.exists() or cache.stat().st_ctime_ns < source_stat.st_ctime_ns:
            with tempfile.TemporaryDirectory(prefix=".domain-cache-", dir=path.parent) as temp:
                output = os.path.join(temp, "domains.txt")
                subprocess.run(
                    mrs_command(131072, "domain", "mrs", str(path), output),
                    env={**os.environ, "GOGC": "35", "GOMEMLIMIT": "80MiB"},
                    capture_output=True, check=True, timeout=15,
                )
                current = path.stat()
                if (current.st_ino, current.st_ctime_ns) != (source_stat.st_ino, source_stat.st_ctime_ns):
                    raise OSError("Набор доменов изменился во время чтения.")
                os.replace(output, cache)
        rules = cache.open(encoding="utf-8")
    with rules:
        yield rules


def service_domains_for_listing(item):
    from geodata_service_files import provider_file
    for key in ("domains", "exact_domains"):
        values = item.get(key, [])
        yield from ([values] if isinstance(values, str) else values)
    for provider in item.get("geo_sets", []):
        path, behavior, _ = provider_file(provider)
        if behavior == "domain":
            with mrs_domains(path) as rules:
                for line in rules:
                    yield line.strip().removeprefix("+.").removeprefix(".")


def matching_services(items, domain):
    from geodata_service_files import provider_file

    name = domain.strip().rstrip(".").encode("idna").decode().lower()
    if not DOMAIN_RE.fullmatch(name):
        raise ValueError("Введите домен без схемы и пути.")
    labels = name.split(".")
    suffixes = {".".join(labels[index:]) for index in range(len(labels))}

    def matches(kind, value):
        if name in value.lower():
            return True
        if kind == "DOMAIN-REGEX":
            try:
                return bool(re.search(value, name))
            except re.error:
                return False
        value = value.lower().rstrip(".")
        if kind == "DOMAIN-SUFFIX":
            return value in suffixes
        if kind == "DOMAIN-KEYWORD":
            return value in name
        return kind == "DOMAIN" and value == name

    def provider_matches(provider):
        path, behavior, fmt = provider_file(provider)
        if behavior == "ipcidr":
            return False
        if fmt == "text":
            with path.open(encoding="utf-8") as rules:
                return any(matches(*line.strip().split(",", 1)) for line in rules if "," in line)
        with mrs_domains(path) as rules:
            for line in rules:
                value = line.strip()
                if value.startswith("."):
                    if name in value.lower() or (value[1:] != name and value[1:] in suffixes):
                        return True
                    continue
                kind = "DOMAIN-SUFFIX" if value.startswith("+.") else "DOMAIN"
                if matches(kind, value.removeprefix("+.")):
                    return True
        return False

    fields = {"domains": "DOMAIN-SUFFIX", "exact_domains": "DOMAIN",
              "keyword_domains": "DOMAIN-KEYWORD", "regex_domains": "DOMAIN-REGEX"}
    result = []
    for item in items:
        for key, kind in fields.items():
            values = item.get(key, [])
            if any(matches(kind, value) for value in ([values] if isinstance(values, str) else values)):
                result.append(item)
                break
        else:
            if any(provider_matches(provider) for provider in item.get("geo_sets", [])):
                result.append(item)
    return result


def effective_domain_rules(items, domains):
    """Find the first enabled terminating domain rule for each displayed name."""
    from geodata_service_files import provider_file

    remaining = set(domains)
    owners = {}
    suffixes = {name: {name[index + 1:] for index, char in enumerate(name) if char == "."} | {name}
                for name in remaining}
    suffix_names = {}
    for name, values in suffixes.items():
        for value in values:
            suffix_names.setdefault(value, set()).add(name)

    def match(kind, value, name):
        if kind == "DOMAIN-REGEX":
            try:
                return re.search(value, name) is not None
            except re.error:
                return False
        value = value.lower().rstrip(".")
        if kind == "DOMAIN-SUFFIX":
            return value in suffixes[name]
        if kind == "DOMAIN-SUFFIX-ONLY":
            return name != value and value in suffixes[name]
        if kind == "DOMAIN-KEYWORD":
            return value in name
        return kind == "DOMAIN" and value == name

    for item in items:
        if not remaining:
            break
        if not item.get("enabled", True) or item.get("target", "").upper() == "PASS":
            continue
        def collect(kind, value):
            if kind in {"DOMAIN-SUFFIX", "DOMAIN-SUFFIX-ONLY"}:
                candidates = suffix_names.get(value.lower().rstrip("."), set()) & remaining
            elif kind == "DOMAIN":
                candidates = {value.lower().rstrip(".")} & remaining
            else:
                candidates = tuple(remaining)
            for name in candidates:
                if match(kind, value, name):
                    owners[name] = item
                    remaining.remove(name)
        for key, kind in (("domains", "DOMAIN-SUFFIX"), ("exact_domains", "DOMAIN"),
                          ("keyword_domains", "DOMAIN-KEYWORD"), ("regex_domains", "DOMAIN-REGEX")):
            values = item.get(key, [])
            for value in ([values] if isinstance(values, str) else values):
                collect(kind, value)
        for provider in item.get("geo_sets", []):
            if not remaining:
                break
            path, behavior, fmt = provider_file(provider)
            if behavior == "ipcidr":
                continue
            if fmt == "text":
                with path.open(encoding="utf-8") as rules:
                    for line in rules:
                        if "," in line:
                            collect(*line.strip().split(",", 1))
                        if not remaining:
                            break
            else:
                with mrs_domains(path) as rules:
                    for line in rules:
                        value = line.strip()
                        if value.startswith("+."):
                            collect("DOMAIN-SUFFIX", value[2:])
                        elif value.startswith("."):
                            collect("DOMAIN-SUFFIX-ONLY", value[1:])
                        else:
                            collect("DOMAIN", value)
                        if not remaining:
                            break
    return owners

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
        raise RuntimeError("GitHub вернул неполный каталог правил")
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
    "SELECTOR": "Основной маршрут",
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
    return ["SELECTOR", *targets]


def geo_service_rules(source, category, *, file_based=False, report):
    from geodata_service_files import compile_category

    report("Чтение категории GeoDAT")
    providers, count, records = compile_category(source, category, report=report,
                                                  inline_limit=0 if file_based else 20000)
    if providers:
        return {"geo_sets": providers, "geo_count": count}, providers
    rules = {}
    for key, value in records:
        if key != "ipv6":
            rules.setdefault(key, set()).add(value)
    if not rules:
        raise ValueError("В категории нет поддерживаемых доменных правил или IPv4-сетей.")
    inline = {key: sorted(values) for key, values in rules.items()}
    return {**inline, "geo_inline": inline}, []


GEO_INLINE_FIELDS = ("domains", "exact_domains", "keyword_domains", "regex_domains", "networks")


def geo_sources(item):
    if "geo_sources" in item:
        return item["geo_sources"]
    if source := item.get("geo_source"):
        return [{**source, "file_based": bool(item.get("geo_sets"))}]
    return []


def geo_inline_rules(item):
    if "geo_inline" in item:
        return item["geo_inline"]
    if item.get("geo_source") and not item.get("geo_sets"):
        return {key: item.get(key, []) for key in GEO_INLINE_FIELDS}
    return {}


def merge_geo_inline(entry, previous, incoming):
    for key in GEO_INLINE_FIELDS:
        current = set(entry.get(key, []))
        old = set(previous.get(key, []))
        new = set(incoming.get(key, []))
        entry[key] = sorted((new - (old - current)) | (current - old))
    entry["geo_inline"] = {key: sorted(values) for key, values in incoming.items()}

def handle_action(data, report=lambda _stage: None, after_commit=None):
    action = data.get("action", [""])[0]
    items = read_services()
    original = copy.deepcopy(items)
    service_id=data.get("service_id",[""])[0]
    if service_id:
        matches=[i for i,item in enumerate(items) if item.get("id")==service_id or ("name:"+str(item.get("name","")))==service_id]
        if len(matches)!=1:
            raise ValueError("Правило уже удалено или изменено. Обновите список.")
        data=dict(data)
        data["index"]=[str(matches[0])]

    extra_message = ""
    created_providers = []
    removed_providers = []
    if action == "service_save":
        name = data.get("name", [""])[0].strip()
        target = data.get("target", ["SELECTOR"])[0].strip() or "SELECTOR"
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
            raise ValueError("Название правила обязательно, максимум 100 символов")
        index = int(data.get("index", ["-1"])[0])
        if not (domains or exact_domains or keyword_domains or regex_domains or networks
                or (0 <= index < len(items) and items[index].get("geo_sets"))):
            raise ValueError("Укажите хотя бы один домен или IPv4-сеть")
        if target not in route_targets():
            raise ValueError("Недопустимая группа маршрутизации")

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
                raise ValueError("Неверный индекс правила")
            entry["enabled"] = bool(items[index].get("enabled", True))
            for key in ("id", "source_repo", "source_service", "source_sha", "geo_source", "geo_sources", "geo_sets", "geo_count", "geo_inline"):
                if key in items[index]:
                    entry[key] = items[index][key]
            items[index] = entry
        else:
            items.append(entry)

    elif action == "service_geodata_import":
        source = data.get("geo_id", [""])[0]
        category = data.get("geo_category", [""])[0]
        name = data.get("name", [""])[0].strip()
        target = data.get("target", ["SELECTOR"])[0] or "SELECTOR"
        if target not in route_targets():
            raise ValueError("Недопустимая группа маршрутизации")
        if not 1 <= len(name) <= 100:
            raise ValueError("Укажите название правила до 100 символов")
        entry = next((item for item in items if item["name"].casefold() == name.casefold()), None)
        existing = entry is not None
        if not existing:
            entry = {"name": name, "target": target, "enabled": True}
        sources = geo_sources(entry)
        if any(ref["id"] == source and ref["category"].casefold() == category.casefold() for ref in sources):
            raise ValueError("Эта категория уже добавлена в правило. Для повторной загрузки нажмите «Обновить».")
        rules, created_providers = geo_service_rules(source, category, report=report)
        previous = geo_inline_rules(entry)
        incoming = {key: set(previous.get(key, [])) | set(rules.get(key, [])) for key in GEO_INLINE_FIELDS}
        merge_geo_inline(entry, previous, incoming)
        entry["geo_sources"] = [*sources, {"id": source, "category": category, "file_based": bool(created_providers)}]
        if created_providers:
            entry["geo_sets"] = [*entry.get("geo_sets", []), *created_providers]
            entry["geo_count"] = entry.get("geo_count", 0) + rules["geo_count"]
        if not existing:
            items.append(entry)
        operation = "Дополнено" if existing else "Создано"
        extra_message = f'{operation} правило «{entry["name"]}». Записей — {service_rule_count(entry)}.'

    elif action == "service_refresh_geodata":
        import geodata_panel
        index = int(data.get("index", ["-1"])[0])
        if not 0 <= index < len(items):
            raise ValueError("Правило не найдено.")
        entry = items[index]
        from geodata_service_files import remove_providers
        sources = geo_sources(entry)
        if not sources:
            raise ValueError("У правила нет источников GeoDAT.")
        stage = ""
        def step(value):
            nonlocal stage
            stage = f"{category} · {value}"
            report(stage)
        refreshed = set()
        incoming = {key: set() for key in GEO_INLINE_FIELDS}
        total_file_rules = 0
        updated_sources = []
        try:
            for source in sources:
                sid, category = source["id"], source["category"]
                step("Проверка источника GeoDAT")
                database = geodata_panel.entries().get(sid)
                if not database or not database.get("url"):
                    raise ValueError("Источник GeoDAT больше не найден.")
                if database.get("file") and sid not in refreshed:
                    step("Обновление локальной базы GeoDAT")
                    geodata_panel.handle({"operation": "refresh", "id": sid, "token": geodata_panel.TOKEN})
                    refreshed.add(sid)
                rules, providers = geo_service_rules(sid, category, file_based=source.get("file_based", False), report=step)
                created_providers.extend(providers)
                total_file_rules += rules.get("geo_count", 0)
                updated_sources.append({**source, "file_based": bool(providers)})
                for key in GEO_INLINE_FIELDS:
                    incoming[key].update(rules.get(key, []))
        except Exception as error:
            remove_providers(created_providers)
            raise RuntimeError(f"Этап «{stage}». {error}") from error
        merge_geo_inline(entry, geo_inline_rules(entry), incoming)
        removed_providers = entry.pop("geo_sets", [])
        entry.pop("geo_count", None)
        entry["geo_sources"] = updated_sources
        if created_providers:
            entry.update(geo_sets=created_providers, geo_count=total_file_rules)
        extra_message = f'Правило «{entry["name"]}» обновлено. Записей — {service_rule_count(entry)}.'

    elif action == "service_catalog_import":
        selected = list(dict.fromkeys(data.get("catalog_service", [])))
        target = data.get("catalog_target", ["SELECTOR"])[0].strip()
        if not selected:
            raise ValueError("Выберите правила для загрузки")
        if len(selected) > 20:
            raise ValueError("За один раз можно загрузить не более 20 правил")
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
            raise ValueError("Выбранные правила уже добавлены; обновите их в таблице ниже")
        extra_message = "Добавлены и включены: " + ", ".join(imported)
        if skipped:
            extra_message += "; уже были добавлены: " + ", ".join(skipped)

    elif action == "service_update_source":
        index = int(data.get("index", ["-1"])[0])
        if index < 0 or index >= len(items):
            raise ValueError("Правило не найдено")
        entry = items[index]
        slug = entry.get("source_service", "")
        if entry.get("source_repo") != SOURCE_REPO or not slug:
            raise ValueError("Правило не связано с каталогом GitHub")
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

    elif action == "service_reorder":
        current = [item.get("id") or "name:" + item["name"] for item in items]
        try:
            baseline = json.loads(data.get("order_before", [""])[0])
            requested = json.loads(data.get("order", [""])[0])
        except (ValueError, TypeError):
            raise ValueError("Некорректный порядок правил") from None
        if baseline != current:
            raise ValueError("Список правил уже изменён. Обновите страницу и повторите перестановку.")
        if (not isinstance(requested, list) or not all(isinstance(key, str) for key in requested)
                or len(requested) != len(current) or set(requested) != set(current)):
            raise ValueError("Порядок должен содержать каждое правило ровно один раз")
        if requested == current:
            return "Порядок правил уже актуален."
        by_id = dict(zip(current, items))
        items = [by_id[key] for key in requested]
        extra_message = "Новый порядок правил применён."

    elif action in ("service_toggle", "service_delete", "service_set_target", "service_move"):
        index = int(data.get("index", ["-1"])[0])
        if index < 0 or index >= len(items):
            raise ValueError("Правило не найдено")
        if action == "service_move":
            direction = data.get("direction", [""])[0]
            if direction not in {"up", "down"}:
                raise ValueError("Недопустимое направление перемещения")
            destination = index + (-1 if direction == "up" else 1)
            if not 0 <= destination < len(items):
                return "Правило уже находится в крайней позиции."
            items.insert(destination, items.pop(index))
            extra_message = f"Правило перемещено на позицию {destination + 1}."
        elif action == "service_delete":
            removed_providers = items.pop(index).get("geo_sets", [])
        elif action == "service_set_target":
            target = data.get("target", ["SELECTOR"])[0] or "SELECTOR"
            if target not in route_targets():
                raise ValueError("Недопустимая группа маршрутизации")
            items[index]["target"] = target
        else:
            items[index]["enabled"] = not bool(items[index].get("enabled", True))
    else:
        raise ValueError("Unknown action")

    from geodata_service_files import remove_providers
    try:
        if action == "service_refresh_geodata":
            report("Применение правил Mihomo")
        message = apply_services(items, original, extra_message)
    except Exception as error:
        remove_providers(created_providers)
        if action == "service_refresh_geodata":
            raise RuntimeError(f"Этап «Применение правил Mihomo». {error}") from error
        raise
    if action == "service_refresh_geodata" and after_commit is not None:
        after_commit(lambda: remove_providers(removed_providers))
    else:
        remove_providers(removed_providers)
    return message


def apply_services(items, original, extra_message):
    write_services(items)
    from configuration_draft import staging
    if staging(): return "Правило сохранено в черновик. " + extra_message
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
        [DOMAIN_BUILDER, "--overlays"], capture_output=True, text=True, timeout=30
    )
    if domain_result.returncode:
        write_services(original)
        subprocess.run(
            ["python3", BUILDER],
            capture_output=True, text=True, timeout=15
        )
        domain_rollback = subprocess.run(
            [DOMAIN_BUILDER, "--overlays"], capture_output=True, text=True, timeout=30
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
            [DOMAIN_BUILDER, "--overlays"], capture_output=True, text=True, timeout=30
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
            raise ValueError("Правило уже удалено. Обновите список.")
        edit_index=matches[0]
    current = {}
    if 0 <= edit_index < len(items):
        current = items[edit_index]

    title = (
        "Редактировать правило"
        if current else
        "Добавить правило"
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
    geo_note = ""
    if current.get("geo_sets"):
        category = esc(", ".join(dict.fromkeys(ref["category"] for ref in geo_sources(current))) or current["name"])
        count = f'{current["geo_count"]:,}'.replace(",", "\u202f") if "geo_count" in current else "—"
        geo_note = (f'<p class="hint">Набор GeoDAT <strong>{category}</strong> хранится отдельным файлом. '
                    f'Записей в наборе — {count}. В поле ниже можно добавить отдельные правила.</p>')
    selected_target = current.get("target") or "SELECTOR"

    options = []
    for target in targets:
        selected = " selected" if target == selected_target else ""
        options.append(f'<option value="{esc(target)}"{selected}>{esc(ROUTE_LABELS.get(target, target))}</option>')

    lookup = params.get("service_domain", [""])[0].strip()
    lookup_error = ""
    visible_items = None
    if lookup:
        try:
            if not SERVICE_LOOKUP_LOCK.acquire(blocking=False):
                raise ValueError("Поиск уже выполняется.")
            try:
                visible_items = {id(item) for item in matching_services(items, lookup)}
            finally:
                SERVICE_LOOKUP_LOCK.release()
        except ValueError as error:
            lookup_error = f'<p role="alert">{esc(error)}</p>'
            visible_items = set()
        except (OSError, subprocess.SubprocessError):
            lookup_error = '<p role="alert">Не удалось выполнить поиск. Проверьте домен и доступность файлов наборов.</p>'
            visible_items = set()
    rows = []
    for i, item in enumerate(items):
        if visible_items is not None and id(item) not in visible_items:
            continue
        total = service_rule_count(item)
        move_buttons = "".join(
            f'<button type="button" data-rule-move="{direction}" aria-label="{label}">{arrow}</button>'
            for direction, label, arrow, disabled in (
                ("up", "Переместить выше", "↑", i == 0),
                ("down", "Переместить ниже", "↓", i == len(items)-1),
            )
        )
        target = item.get("target", "")
        selection = "".join(
            f'<option value="{esc(value)}"{" selected" if value == target else ""}>{esc(ROUTE_LABELS.get(value, value))}</option>'
            for value in dict.fromkeys([target, *targets])
        )
        target_form = f'''<form method="post" class="service-route-form"><input type="hidden" name="action" value="service_set_target">
<input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}">
<select name="target" aria-label="Группа правила {esc(item.get('name', ''))}" onchange="this.form.requestSubmit()">{selection}</select></form>'''
        count_label = "—" if item.get("geo_sets") and "geo_count" not in item else f"{total:,}".replace(",", "\u202f")
        enabled = bool(item.get("enabled", True))
        status_label = "Включено" if enabled else "Отключено"
        status_color = "#16803c" if enabled else "#c62828"
        status_button = f'''<form method="post"><input type="hidden" name="action" value="service_toggle"><input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}"><button type="submit" style="background:{status_color};color:white;font-weight:700;width:130px;min-width:130px;box-sizing:border-box;text-align:center;white-space:nowrap">{status_label}</button></form>'''
        source_update = ""
        if geo_sources(item):
            source_update = f'''<form method="post"><input type="hidden" name="action" value="service_refresh_geodata">
<input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}">
<button type="submit">Обновить</button></form>'''
        elif item.get("source_repo") == SOURCE_REPO and item.get("source_service"):
            source_update = f"""<form method=\"post\"><input type=\"hidden\" name=\"action\" value=\"service_update_source\"><input type=\"hidden\" name=\"index\" value=\"{i}\"><input type=\"hidden\" name=\"service_id\" value=\"{esc(item.get('id') or 'name:'+str(item.get('name','')))}\"><button type=\"submit\">Обновить</button></form>"""
        rows.append(f"""
<tr data-rule-id="{esc(item.get("id") or "name:"+item["name"])}">
<td><div class="rule-order"><span>{i+1}</span>{move_buttons}</div></td>
<td>{esc(item.get('name', ''))}</td>
<td>{count_label}</td>
<td>{target_form}</td>
<td>{status_button}</td>
<td class="actions"><div class="service-row-actions">
<a class="action-button" href="{esc(service_edit_url(item))}">Изменить</a>
{source_update}
<form method="post" onsubmit="return confirm('Подтвердить удаление?')">
<input type="hidden" name="action" value="service_delete">
<input type="hidden" name="index" value="{i}"><input type="hidden" name="service_id" value="{esc(item.get('id') or 'name:'+str(item.get('name','')))}">
<button type="submit" class="danger">Удалить</button></form>
</div></td></tr>""")

    table_rows = "\n".join(rows) or (
        '<tr><td colspan="6">Совпадений нет.</td></tr>' if lookup and not lookup_error else "" if lookup else
        '<tr><td colspan="6">Нет правил. Добавьте первое правило.</td></tr>'
    )

    return f"""<!doctype html>
<html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mihomo Control — Правила</title>
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
<details id="service-editor" class="panel-spoiler"{" open" if current else ""}><summary>{title}</summary>
<form method="post">
<input type="hidden" name="action" value="service_save">
<input type="hidden" name="index" value="{edit_index if current else -1}"><input type="hidden" name="service_id" value="{esc(current.get('id') or ('name:'+str(current.get('name','')) if current else ''))}">
<label>Название правила</label>
<input name="name" maxlength="100" required value="{name_value}" placeholder="Имя, например YouTube">
{geo_note}
<label>Домены и IPv4-сети. Разделяйте записи точкой с запятой или новой строкой.</label>
<textarea name="domains" {"required" if not current.get("geo_sets") else ""} placeholder="youtube.com; googlevideo.com&#10;8.8.4.0/24">{domains_value}</textarea>
<label>Группа маршрутизации</label>
<select name="target" aria-label="Маршрут правила">{"".join(options)}</select>
<button type="submit">Сохранить</button>
<a class="reset-button" href="/?tab=services">Сбросить</a>
</form></details></div>
<div class="panel"><details class="panel-spoiler"><summary>Поиск по источникам GeoDAT</summary>
<form class="geodata-search-form" method="get">
<input name="q" type="search" maxlength="253" aria-label="Категория, домен, IP или сеть" placeholder="Категория, домен, IP или сеть" required>
<button type="submit">Найти</button></form>
<p class="hint" id="geodata-search-status" role="status"></p>
<div id="geodata-search-results" style="overflow:auto"></div>
<template id="geodata-service-form">
<form method="post" action="/action" class="geodata-search-form">
<input type="hidden" name="action" value="service_geodata_import">
<input type="hidden" name="geo_id"><input type="hidden" name="geo_category">
<input name="name" placeholder="Название правила" aria-label="Название правила" maxlength="100" required>
<select name="target" aria-label="Маршрут">{"".join(options)}</select>
<button type="submit">Создать правило</button></form>
</template>
</details></div>
<style>.geodata-search-form{{display:flex;gap:10px;align-items:center;margin-top:12px}}
body .unified-main .geodata-search-form input{{width:min(100%,420px);min-width:0;margin:0}}
body .unified-main .geodata-search-form button{{margin:0}}
.geodata-category-preview{{white-space:pre-wrap;overflow-wrap:anywhere;max-height:260px;overflow:auto}}
body .unified-main #geodata-search-results form{{flex-wrap:wrap}}
body .unified-main #geodata-search-results select{{width:auto;max-width:100%;margin:0}}</style>
<script>
function geodataCategory(item){{
 const details=document.createElement("details"), title=document.createElement("summary");
 const preview=document.createElement("pre"), more=document.createElement("button");
 const form=document.getElementById("geodata-service-form").content.firstElementChild.cloneNode(true);
 title.textContent=item.name;details.append(title);
 preview.className="geodata-category-preview";preview.setAttribute("aria-live","polite");
 more.type="button";more.textContent="Показать ещё";more.hidden=true;
 form.elements.geo_id.value=item.source_id;form.elements.geo_category.value=item.name;
 form.elements.name.value=item.name.slice(0,100);
 details.append(preview,more,form);
 let next=0, loaded=false;
 async function load(){{
  if(more.disabled || next===null)return;
  more.disabled=true;
  if(!loaded)preview.textContent="Читаем категорию…";
  try{{
   const args=new URLSearchParams({{source:item.source_id,name:item.name,offset:next}});
   const response=await fetch("/api/geodata/category?"+args,{{cache:"no-store"}});
   const data=await response.json();
   if(!response.ok)throw new Error(data.message);
   if(!loaded)preview.textContent="";
   preview.textContent+=data.records.join(String.fromCharCode(10))+(data.records.length?String.fromCharCode(10):"");
   if(!preview.textContent)preview.textContent="Категория пуста.";
   loaded=true;next=data.next;more.hidden=next===null;
   more.textContent="Показать ещё";
  }}catch(error){{
   if(!loaded)preview.textContent=error.message;
   more.textContent="Повторить";more.hidden=false;
  }}finally{{more.disabled=false;}}
 }}
 details.addEventListener("toggle",()=>{{if(details.open&&!loaded)load();}});
 more.addEventListener("click",load);
 return details;
}}
const geoSearchForm=document.querySelector("form.geodata-search-form");
const geoSearchStatus=document.getElementById("geodata-search-status");
const geoSearchOutput=document.getElementById("geodata-search-results");
const geoSearchStorageKey="uvpnc-last-geodat-search";
function renderGeodataSearch(data){{
  const status=geoSearchStatus,out=geoSearchOutput;
  out.replaceChildren();
  status.textContent="Найдено категорий: "+data.results.length;
  for(const error of data.errors){{
   const line=document.createElement("p");
   line.className="catalog-error";line.textContent=error;out.append(line);
  }}
  if(!data.results.length)return;
  const table=document.createElement("table"), headings=table.createTHead().insertRow();
  for(const label of ["Категория","Источник","Записей","Совпадение"]){{
   const th=document.createElement("th");th.textContent=label;headings.append(th);
  }}
  const body=table.createTBody();
  for(const item of data.results){{
   const row=body.insertRow();
   row.insertCell().append(geodataCategory(item));
   row.insertCell().textContent=item.source+(item.kind==="ipcidr"?":IP":item.kind==="domain"?":domain":"");
   row.insertCell().textContent=Number(item.count).toLocaleString("ru-RU");
   row.insertCell().textContent=item.example||"Название категории";
  }}
  out.append(table);
}}
try{{
 const saved=JSON.parse(sessionStorage.getItem(geoSearchStorageKey));
 if(saved&&typeof saved.query==="string"&&Array.isArray(saved.data?.results)&&Array.isArray(saved.data?.errors)){{
  geoSearchForm.elements.q.value=saved.query;
  renderGeodataSearch(saved.data);
  geoSearchForm.closest("details").open=true;
 }}
}}catch(error){{}}
geoSearchForm.addEventListener("submit", async event=>{{
 event.preventDefault();
 const form=event.currentTarget,button=form.querySelector("button"),status=geoSearchStatus;
 if(button.disabled)return;
 button.disabled=true;
 status.textContent="Читаем источники GeoDAT…";
 try{{
  const query=new URLSearchParams(new FormData(form));
  const response=await fetch("/api/geodata/search?"+query,{{cache:"no-store"}});
  const data=await response.json();
  if(!response.ok)throw new Error(data.message);
  renderGeodataSearch(data);
  try{{sessionStorage.setItem(geoSearchStorageKey,JSON.stringify({{query:query.get("q"),data}}));}}catch(error){{}}
 }}catch(error){{status.textContent=error.message||"Не удалось завершить поиск.";}}
 finally{{button.disabled=false;}}
}});
</script>
<div class="panel"><div class="configured-services-header"><h2>Настроенные правила</h2>
<div class="rules-toolbar">
<form method="post" id="rule-order-form">
<input type="hidden" name="action" value="service_reorder">
<input type="hidden" name="order_before" value="{esc(json.dumps([item.get('id') or 'name:'+item['name'] for item in items]))}">
<input type="hidden" name="order">
<button type="submit" hidden id="rule-order-apply" disabled>Применить</button>
<button type="button" hidden id="rule-order-cancel" disabled>Отмена</button>
</form>
<form method="get" class="service-domain-search">
<input type="hidden" name="tab" value="services">
<input type="search" name="service_domain" maxlength="253" aria-label="Домен или часть домена в настроенных правилах" value="{esc(lookup)}" placeholder="Домен или часть домена" required>
<button type="submit">Найти правило</button>
{'<a class="reset-button" href="/?tab=services">Сбросить поиск</a>' if lookup else ''}
</form></div></div>
{lookup_error}
<p class="hint">Правила проверяются сверху вниз. Первое совпавшее включённое правило выбирает действие. PASS продолжает проверку. Новое правило добавляется в конец.</p>
<table class="configured-services"><thead><tr><th>Порядок</th><th>Правило</th><th>Записей</th><th>Группа</th><th>Состояние</th><th>Действия</th></tr></thead>
<tbody>{table_rows}</tbody></table></div>
<style>
body .unified-main .configured-services-header{{display:flex;align-items:center;flex-wrap:wrap;justify-content:space-between;gap:12px;margin-bottom:12px}}
body .unified-main .configured-services-header h2{{margin:0}}
body .unified-main .rules-toolbar{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
body .unified-main #rule-order-form{{display:flex;align-items:center;gap:8px;margin:0}}
body .unified-main #rule-order-apply{{background:var(--ui-primary);border-color:var(--ui-primary);color:white}}
body .unified-main .service-domain-search{{display:flex;align-items:center;gap:8px;max-width:100%;margin:0}}
body[data-page=services] .unified-main .panel form.service-domain-search > input[type=search]{{flex:1 1 270px;width:270px;min-width:0;height:40px;margin:0}}
body .unified-main .service-domain-search :is(button,.reset-button){{flex:none;min-width:max-content;height:40px;white-space:nowrap}}
body .unified-main .configured-services :is(th,td){{padding:10px 12px}}
body .unified-main .configured-services :is(th,td):nth-child(3){{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
body .unified-main .rule-order{{display:flex;align-items:center;gap:4px;font-variant-numeric:tabular-nums}}
body .unified-main .rule-order button{{padding:9px 6px;min-width:28px}}
body .unified-main .rule-order span{{min-width:16px}}
body .unified-main .configured-services form{{margin:0}}
body[data-page=services] .unified-main .panel .configured-services .service-route-form > select{{width:100%;min-width:210px;max-width:290px;height:40px;margin:0}}
body .unified-main .configured-services .service-row-actions{{display:flex;align-items:center;gap:8px;white-space:nowrap}}
body .unified-main .configured-services .service-row-actions :is(form,.action-button){{margin:0}}
body .unified-main .configured-services .service-row-actions :is(button,.action-button){{height:40px;white-space:nowrap}}
@media(max-width:520px){{body .unified-main .service-domain-search:has(.reset-button){{flex-wrap:wrap}}}}
</style>
<script>
(()=>{{
 const form=document.getElementById("rule-order-form");
 const body=document.querySelector(".configured-services tbody");
 const baseline=JSON.parse(form.elements.order_before.value);
 const originalRows=[...body.querySelectorAll("tr[data-rule-id]")];
 const visibleSlots=originalRows.map(row=>baseline.indexOf(row.dataset.ruleId));
 const cancel=document.getElementById("rule-order-cancel"),apply=document.getElementById("rule-order-apply");
 function update(){{
  const rows=[...body.querySelectorAll("tr[data-rule-id]")],order=[...baseline];
  rows.forEach((row,index)=>{{
   order[visibleSlots[index]]=row.dataset.ruleId;
   row.querySelector(".rule-order span").textContent=String(visibleSlots[index]+1);
   row.querySelector('[data-rule-move="up"]').disabled=index===0;
   row.querySelector('[data-rule-move="down"]').disabled=index===rows.length-1;
  }});
  form.elements.order.value=JSON.stringify(order);
  const changed=order.some((key,index)=>key!==baseline[index]);
  cancel.disabled=apply.disabled=!changed;
  if(changed)form.dataset.queueDirty="1";else delete form.dataset.queueDirty;
 }}
 body.addEventListener("click",event=>{{
  const button=event.target.closest("[data-rule-move]");
  if(!button)return;
  const row=button.closest("tr");
  if(button.dataset.ruleMove==="up"){{if(row.previousElementSibling)body.insertBefore(row,row.previousElementSibling);}}
  else if(row.nextElementSibling)body.insertBefore(row.nextElementSibling,row);
  update();
  window.configurationDraft?.set("order",new URLSearchParams(new FormData(form)));
 }});
 cancel.addEventListener("click",()=>{{originalRows.forEach(row=>body.append(row));update();}});
 update();
}})();
</script>
</html>"""
