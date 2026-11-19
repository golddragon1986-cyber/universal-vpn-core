"""Keep source, local domain additions and exclusions in separate providers."""
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen
import json
from durable_io import write, sync_dir

ROOT = Path("/etc/mihomo")


def split_config(text, fmt, base):
    text = provider_block(text, fmt, base / ("ru-blocked-mihomo.mrs" if fmt == "mrs" else "ru-blocked-domain.txt"))
    if "  RU-BLOCKED-LOCAL:\n" in text:
        return text
    anchors = ("  - RULE-SET,RU-BLOCKED,SELECTOR", "    - RULE-SET,RU-BLOCKED,fake-ip\n",
               "    # END SERVICE-FAKE-IP\n", "    'rule-set:RU-BLOCKED':\n")
    if any(text.count(anchor) != 1 for anchor in anchors):
        raise ValueError("The current configuration is missing managed domain rules")
    servers = re.search(r"(?m)^  nameserver:\n((?:^    - [^\n]+\n)+)", text)
    if servers is None:
        raise ValueError("Missing default DNS resolvers")
    for name, path in (("RU-BLOCKED-LOCAL", "ru-blocked-local.txt"),
                       ("RU-BLOCKED-EXCLUDED", "ru-blocked-excluded.txt")):
        block = f"  {name}:\n    type: file\n    behavior: domain\n    format: text\n    path: {base / path}\n"
        text = text.replace("rule-providers:\n", "rule-providers:\n" + block, 1)
    text = text.replace(
        "  - RULE-SET,RU-BLOCKED,SELECTOR",
        "  - AND,((NOT,((RULE-SET,RU-BLOCKED-EXCLUDED))),(OR,((RULE-SET,RU-BLOCKED-LOCAL),(RULE-SET,RU-BLOCKED)))),SELECTOR",
        1,
    )
    text = text.replace("    - RULE-SET,RU-BLOCKED,fake-ip\n", "", 1)
    text = text.replace(
        "    # END SERVICE-FAKE-IP\n",
        "    # END SERVICE-FAKE-IP\n"
        "    - RULE-SET,RU-BLOCKED-EXCLUDED,real-ip\n"
        "    - RULE-SET,RU-BLOCKED-LOCAL,fake-ip\n"
        "    - RULE-SET,RU-BLOCKED,fake-ip\n",
        1,
    )
    return text.replace(
        "    'rule-set:RU-BLOCKED':\n",
        "    'rule-set:RU-BLOCKED-EXCLUDED':\n"
        + "".join("  " + line for line in servers[1].splitlines(keepends=True)) +
        "    'rule-set:RU-BLOCKED-LOCAL,RU-BLOCKED':\n",
        1,
    )


def read_domains(path, prefix=""):
    result = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip().lower()
        if not raw or (not prefix and raw.startswith("#")):
            continue
        if not raw.startswith(prefix) or not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", raw[len(prefix):]):
            raise ValueError(f"Invalid domain in {path.name}")
        result.add(raw[len(prefix):])
    return result


def domain_payload(domains):
    return "".join("+." + domain + "\n" for domain in sorted(domains)).encode()


def update_split(root=ROOT, *, source=False, offline=False):
    from configuration_draft import staging
    if staging():return "Домены сохранены в черновик"
    base = root / "rules"
    configs = (base/"panel-managed-template.yaml", root/"default_config_candidate.yaml",
               root/"default_config.yaml", root/"template/default_config.yaml")
    separate = "  RU-BLOCKED-LOCAL:\n" in configs[0].read_text()
    added = read_domains(base/"ru-blocked-local-add.txt")
    excluded = read_domains(base/"ru-blocked-local-remove.txt") | read_domains(base/"ru-blocked-local-delete.txt")
    services = json.loads((base/"service-routes.json").read_bytes())
    excluded.update(domain for service in services for domain in service.get("domains", []))
    providers = {"RU-BLOCKED-LOCAL": (base/"ru-blocked-local.txt", domain_payload(added)),
                 "RU-BLOCKED-EXCLUDED": (base/"ru-blocked-excluded.txt", domain_payload(excluded))}
    changes = {path: raw for path, raw in providers.values() if not path.exists() or path.read_bytes() != raw}
    config_changed = False
    base_text = base/"ru-blocked-domain.txt"
    base_mrs = base/"ru-blocked-mihomo.mrs"
    if source or not separate or not base_text.exists():
        domains = read_domains(base/"ru-blocked-source.txt", "domain:")
        raw = domain_payload(domains)
        fmt = "mrs" if domains else "text"
        if not separate or not base_text.exists() or base_text.read_bytes() != raw or (domains and not base_mrs.exists()):
            changes[base_text] = raw
            if domains:
                with tempfile.TemporaryDirectory(prefix=".domain-source-", dir=base) as directory:
                    plain = Path(directory)/"source.txt"
                    packed = Path(directory)/"source.mrs"
                    plain.write_bytes(raw)
                    run(["mihomo", "convert-ruleset", "domain", "text", str(plain), str(packed)])
                    changes[base_mrs] = packed.read_bytes()
            path = base_mrs if domains else base_text
            providers["RU-BLOCKED"] = (path, changes[path])
        for path in configs:
            if path.exists():
                text = path.read_text()
                updated = split_config(text, fmt, base)
                if updated != text:
                    changes[path] = updated.encode()
                    config_changed = True
    if not changes:
        return "Списки доменов уже актуальны."
    last_good = root/"default_config_candidate.yaml.last-good"
    previous = {path: path.read_bytes() if path.exists() else None for path in changes}
    active = [name for name, (path, _) in providers.items() if path in changes]
    try:
        for path, raw in changes.items():
            write(path, raw)
        if not offline and config_changed:
            run(["mihomo", "-t", "-d", str(root), "-f", str(root/"default_config_candidate.yaml")])
            reload_config(root)
            write(last_good, (root/"default_config_candidate.yaml").read_bytes())
        elif not offline:
            for name in active:
                api("/providers/rules/" + name, "PUT", timeout=8)
    except Exception:
        for path, raw in previous.items():
            if raw is None:
                path.unlink(missing_ok=True)
                sync_dir(path.parent)
            else:
                write(path, raw)
        if not offline:
            if config_changed:
                reload_config(root)
            else:
                for name in active:
                    api("/providers/rules/" + name, "PUT")
        raise
    return "Обновлены списки: " + ", ".join(active)

def provider_block(text, fmt, path):
    section = re.search(r"(?m)^rule-providers:[ \t]*\n", text)
    if section is None:
        raise ValueError("Missing rule-providers")
    following = re.search(r"(?m)^[^\s#]", text[section.end():])
    end = section.end() + following.start() if following else len(text)
    body = text[section.end():end]
    pattern = r"(?ms)^  RU-BLOCKED:[ \t]*\n.*?(?=^  [^\s#][^\n]*:|\Z)"
    replacement = ("  RU-BLOCKED:\n    type: file\n    behavior: domain\n"
                   f"    format: {fmt}\n    path: {path}\n\n")
    body, count = re.subn(pattern, lambda _: replacement, body)
    if count != 1:
        raise ValueError("Expected one RU-BLOCKED provider")
    return text[:section.end()] + body + text[end:]

def run(args, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-3000:])
    return result.stdout

def api(path, method="GET", payload=None, timeout=20):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request("http://127.0.0.1:9090"+path, data=data, method=method,
                  headers={"Content-Type":"application/json"})
    with urlopen(req, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw) if raw else None

def reload_config(root):
    api("/configs?force=true", "PUT", {"path":str(root/"default_config_candidate.yaml")})
    from routing_panel import read_settings, set_global_proxy
    set_global_proxy(read_settings()["main_proxy"])

def verify_provider(count, fmt, timeout=20):
    deadline = time.monotonic() + timeout
    while True:
        info = api("/providers/rules")["providers"]["RU-BLOCKED"]
        if (info.get("ruleCount") == count and info.get("behavior", "").lower() == "domain"
                and info.get("format", "").lower().startswith(fmt)
                and not info.get("updatedAt", "0001").startswith("0001")):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Live RU-BLOCKED provider differs from generated data")
        time.sleep(.1)

if __name__ == "__main__":
    if sys.argv[1:] not in (["--source"], ["--overlays"]):
        raise SystemExit("Expected --source or --overlays")
    print(update_split(source=sys.argv[1] == "--source",
                       offline=os.environ.get("MIHOMO_BUILD_OFFLINE") == "1"))
