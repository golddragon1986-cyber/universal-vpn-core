from durable_io import replace as durable_replace
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path("/etc/mihomo")
LOCK = threading.RLock()
FIXED = {"default_config.yaml", "default_config_candidate.yaml", "srv.yaml",
         "template/default_config.yaml", "rules/telegram-ip.yaml",
         "rules/ru-blocked-mihomo.yaml", "rules/user-proxies.yaml"}
DATA_FILES = ["rules/ru-blocked-source.txt", "rules/ru-blocked-local-add.txt",
              "rules/ru-blocked-local-remove.txt", "rules/ru-blocked-local-delete.txt",
              "rules/ru-blocked-filters.txt", "rules/service-routes.json",
              "rules/managed-proxies.json", "rules/routing-settings.json"]
LIMIT = 32 * 1024 * 1024

EXTRA = {"rules/panel-managed-template.yaml", "rules/ru-blocked-domain.txt", "rules/ru-blocked-mihomo.mrs", "rules/log-settings.json", "rules/resource-limits.json", "clients/sing-box.json", "clients/panel-xray.json", "rules/router-ip.yaml"}

EXTRA.add('rules/transparent-tcp.json')
EXTRA.add('rules/local-domain-dns.json')
EXTRA.add('rules/dns-settings.json')
EXTRA.add('rules/client-settings.json')
EXTRA.add('rules/vpn-traffic-totals.json')
EXTRA.add('rules/geodata/sources.json')
EXTRA.update(("rules/ru-blocked-local.txt", "rules/ru-blocked-excluded.txt"))

def allowed(name):
    return (name in FIXED or name in EXTRA or
            bool(re.fullmatch(r"rules/geodata/[0-9a-f]{32}-[0-9a-f]{16,64}\.(?:dat|mrs)",name)) or
            bool(re.fullmatch(r"rules/network-policy/(?:NET-[0-9a-f]{32}\.(?:text|mrs)|index\.json)", name)) or
            bool(re.fullmatch(r"rules/geodata-services/GEO-[0-9a-f]{32}-(?:(?:domain|ip)\.mrs|classical\.text)", name)) or
            bool(re.fullmatch(r"user_sh/[0-9][0-9]-[a-zA-Z0-9_-]+\.sh", name) and name != "user_sh/70-ru-blocked-panel.sh"))

def safe_restore_path(name):
    # The official image uses /etc/mihomo as an alias to its mounted home.
    # Trust that root alias, but still reject links anywhere below the root.
    path = ROOT.resolve() / name
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise ValueError("Недопустимый путь файла")
    return path

def paths():
    names = set(FIXED) | EXTRA
    index=ROOT/'rules/geodata/sources.json'
    if index.exists():
        for row in json.loads(index.read_bytes()).values():
            if not row.get('url') and row.get('file'):
                name='rules/geodata/'+row['file']
                if not allowed(name) or not safe_restore_path(name).is_file():raise ValueError('Не найден локальный файл GeoData: '+row['file'])
                names.add(name)
    names.update(str(p.relative_to(ROOT)) for p in (ROOT / "user_sh").glob("*.sh") if allowed(str(p.relative_to(ROOT))))
    names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/"rules/geodata-services").glob("GEO-*")
                 if allowed(p.relative_to(ROOT).as_posix()))
    names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/"rules/network-policy").glob("*") if allowed(p.relative_to(ROOT).as_posix()))
    return sorted(n for n in names if (ROOT / n).is_file() and not (ROOT / n).is_symlink())

def export(data):
    with LOCK:
        import vpn_traffic
        if vpn_traffic.STARTED:vpn_traffic.persist()
        result = dict(data)
        result["version"] = 2
        result["scope"] = "settings-and-databases"
        result["config_files"] = {}
        for name in paths():
            p = ROOT / name
            raw = p.read_bytes()
            if name=='rules/geodata/sources.json':
                sources=json.loads(raw)
                for row in sources.values():
                    if row.get('url'):
                        row.pop('file',None);row.pop('size',None)
                raw=json.dumps(sources,ensure_ascii=False).encode()
            result["config_files"][name] = {
                "base64": base64.b64encode(raw).decode("ascii"),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mode": stat.S_IMODE(p.stat().st_mode),
            }
        return result

def atomic(path, raw, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".config-restore-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        durable_replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def reload_config():
    req = Request("http://127.0.0.1:9090/configs?force=true",
        data=json.dumps({"path":str(ROOT / "default_config_candidate.yaml")}).encode(),
        headers={"Content-Type":"application/json"}, method="PUT")
    with urlopen(req, timeout=20):
        pass
    from log_panel import restore_level
    restore_level()
    import transparent_tcp
    transparent_tcp.apply()
    from vpn_components import reload_local_sing_box
    reload_local_sing_box()
    import vpn_clients
    with vpn_clients.LOCK:vpn_clients.ensure_runtime('xray')

def restore(payload, legacy_restore, make_backup):
    import vpn_traffic
    with LOCK, vpn_traffic.PERSIST_LOCK:
        from storage_space import require
        require(ROOT,len(json.dumps(payload,ensure_ascii=False).encode())*2,'Загрузка резервной копии')
        if not isinstance(payload, dict) or payload.get("version") != 2:
            return legacy_restore(payload)
        if payload.get("format") != "mihomo-control-backup" or payload.get("scope") != "settings-and-databases":
            raise ValueError("Неподдерживаемый формат резервной копии")
        entries = payload.get("config_files")
        if not isinstance(entries, dict) or not FIXED.issubset(entries):
            raise ValueError("В копии отсутствуют обязательные файлы конфигурации")
        decoded = {}
        total = 0
        for name, entry in entries.items():
            if not isinstance(name, str) or not allowed(name) or not isinstance(entry, dict):
                raise ValueError("Недопустимый файл в резервной копии")
            path = safe_restore_path(name)
            raw = base64.b64decode(entry.get("base64", ""), validate=True)
            if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
                raise ValueError("Нарушена целостность файла: " + name)
            total += len(raw)
            if total > LIMIT:
                raise ValueError("Конфигурация превышает допустимый размер")
            mode = 0o700 if name.startswith("user_sh/") else 0o600
            decoded[name] = (raw, mode)
        if 'rules/geodata/sources.json' in decoded:
            sources=json.loads(decoded['rules/geodata/sources.json'][0])
            if not isinstance(sources,dict):raise ValueError('Некорректный список источников GeoData')
            for row in sources.values():
                if not isinstance(row,dict):raise ValueError('Некорректный источник GeoData')
                if row.get('url'):
                    row.pop('file',None);row.pop('size',None)
                elif row.get('file') and 'rules/geodata/'+row['file'] not in decoded:
                    raise ValueError('В копии отсутствует локальная база GeoData')
            decoded['rules/geodata/sources.json']=(json.dumps(sources,ensure_ascii=False).encode(),0o600)
        if "rules/panel-managed-template.yaml" not in decoded:
            decoded["rules/panel-managed-template.yaml"] = (decoded["default_config_candidate.yaml"][0], 0o600)
        for generated in ("rules/ru-blocked-domain.txt", "rules/ru-blocked-mihomo.mrs",
                          "rules/ru-blocked-local.txt", "rules/ru-blocked-excluded.txt"):
            for name in ("default_config.yaml", "default_config_candidate.yaml", "rules/panel-managed-template.yaml"):
                if name in decoded and generated.encode() in decoded[name][0] and generated not in decoded:
                    raise ValueError("В копии отсутствует файл доменного набора: " + generated)
        old = {}
        for name in set(decoded) | set(DATA_FILES) | EXTRA:
            p = ROOT / name
            old[name] = (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) if p.exists() else None
        # Keep a persistent copy before replacing any settings.
        rollback_file = ROOT / "rules" / ("backup-before-restore-" + time.strftime("%Y%m%d-%H%M%S") + ".json")
        rollback_raw=json.dumps(make_backup(),ensure_ascii=False).encode()
        require(ROOT,len(rollback_raw)+sum(len(raw) for raw,mode in decoded.values()),'Восстановление настроек с резервной копией')
        atomic(rollback_file, rollback_raw, 0o600)
        try:
            for name, (raw, mode) in decoded.items():
                atomic(ROOT / name, raw, mode)
            if 'clients/sing-box.json' in decoded and Path('/usr/local/bin/sing-box').is_file():
                r=subprocess.run(['/usr/local/bin/sing-box','check','-c',str(ROOT/'clients/sing-box.json')],capture_output=True,text=True,timeout=30)
                if r.returncode:raise ValueError('Ошибка конфигурации sing-box в резервной копии')
            if 'clients/panel-xray.json' in decoded:
                import vpn_clients
                vpn_clients.validate('xray',json.loads((ROOT/'clients/panel-xray.json').read_text()))
            for name in ("default_config.yaml", "default_config_candidate.yaml"):
                r = subprocess.run(["mihomo", "-t", "-d", str(ROOT), "-f", str(ROOT / name)],
                                   capture_output=True, text=True, timeout=45)
                if r.returncode:
                    raise ValueError("Ошибка конфигурации Mihomo: " + (r.stderr or r.stdout)[-1200:])
            legacy = dict(payload)
            legacy["version"] = 1
            legacy_restore(legacy)
            from vpn_components import reload_local_sing_box
            reload_local_sing_box()
            if "rules/vpn-traffic-totals.json" in decoded:
                with vpn_traffic.LOCK:vpn_traffic.TOTALS.clear();vpn_traffic.PREVIOUS.clear();vpn_traffic.restore()
            return "Настройки Mihomo, базы доменов и правил восстановлены. Предыдущие настройки сохранены в " + rollback_file.name
        except Exception as error:
            for name, item in old.items():
                p = ROOT / name
                if item is None:
                    p.unlink(missing_ok=True)
                else:
                    atomic(p, *item)
            try:
                reload_config()
                from routing_panel import restore_routing_settings
                restore_routing_settings()
            except Exception as rollback_error:
                raise RuntimeError("Восстановление не выполнено. Файлы возвращены; ошибка применения прежнего конфига: " + str(rollback_error)) from error
            raise

EXTRA.add("rules/route-targets.json")
