from durable_io import replace as durable_replace
#!/usr/bin/env python3
import json
import os
import re
import tempfile

BASE = "/etc/mihomo/rules"
DATA = os.path.join(BASE, "service-routes.json")
TEMPLATE = "/etc/mihomo/rules/panel-managed-template.yaml"
PROVIDER_FILE = "/etc/mihomo/srv.yaml"

RULE_BEGIN = "  # BEGIN SERVICE-ROUTES"
RULE_END = "  # END SERVICE-ROUTES"
FAKE_BEGIN = "    # BEGIN SERVICE-FAKE-IP"
FAKE_END = "    # END SERVICE-FAKE-IP"
GROUP_BEGIN = "  # BEGIN SERVICE-CHANNEL-GROUPS"
GROUP_END = "  # END SERVICE-CHANNEL-GROUPS"
SELECTOR_BEGIN = "      # BEGIN SELECTOR-CHANNELS"
SELECTOR_END = "      # END SELECTOR-CHANNELS"
BALANCE_BEGIN = "      # BEGIN BALANCE-CHANNELS"
BALANCE_END = "      # END BALANCE-CHANNELS"

domain_re = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+"
)
target_re = re.compile(r"[A-Za-z0-9 _.-]{1,80}")

def replace_marked_block(text, begin, end, content):
    pattern = re.compile(
        r"(?ms)^" + re.escape(begin) + r"\n.*?^" + re.escape(end) + r"\n?"
    )
    text, count = pattern.subn(lambda _: content + "\n", text)
    if count != 1:
        raise SystemExit(
            "ERROR: expected exactly one marked block: " + begin
        )
    return text

def read_proxy_names():
    names = []
    in_proxies = False
    with open(PROVIDER_FILE, encoding="utf-8") as f:
        for line in f:
            if re.match(r"^proxies:\s*(?:#.*)?$", line):
                in_proxies = True
                continue
            if in_proxies and line and not line[0].isspace() and not line.startswith("#"):
                break
            if in_proxies:
                match = re.match(r"^\s+-\s+name:\s*(.*?)\s*(?:#.*)?$", line)
                if match:
                    name = match.group(1).strip()
                    if len(name) >= 2 and name[0] == name[-1] and name[0] in ("'", '"'):
                        name = name[1:-1]
                    if not name or "," in name or "\n" in name:
                        raise SystemExit("ERROR: invalid proxy name in srv.yaml")
                    names.append(name)
    user_db = "/etc/mihomo/rules/managed-proxies.json"
    if os.path.isfile(user_db):
        with open(user_db, encoding="utf-8") as f:
            managed = json.load(f).get("nodes", [])
        names.extend(item["proxy"]["name"] for item in managed)
    if len(set(names)) != len(names):
        raise SystemExit("ERROR: duplicate proxy names")
    if len(set(names)) != len(names):
        raise SystemExit("ERROR: duplicate proxy names in " + PROVIDER_FILE)
    return names

def make_group_names(names):
    result = {}
    used = set()
    for name in names:
        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
        group = "CHANNEL-" + slug
        if not slug or group in used:
            raise SystemExit("ERROR: proxy names collide after group-name conversion: " + name)
        used.add(group)
        result[name] = group
    return result

with open(DATA, encoding="utf-8") as f:
    services = json.load(f)
if not isinstance(services, list):
    raise SystemExit("ERROR: service-routes.json must contain a JSON list")

proxy_names = read_proxy_names()
group_names = make_group_names(proxy_names)
standard_targets = {"LOADBALANCE", "DIRECT", "REJECT", "PASS"}
rules = []
fake_ip_rules = []
seen = set()
network_targets = {}

for service in services:
    if not isinstance(service, dict):
        raise SystemExit("ERROR: invalid service entry")
    if not service.get("enabled", True):
        continue

    name = str(service.get("name", "")).strip()
    target = str(service.get("target", "")).strip()
    domains = service.get("domains", [])

    if not name or not target_re.fullmatch(target) or "," in target:
        raise SystemExit("ERROR: invalid service name or route target")
    if target.upper() == "BLOCK":
        target = "REJECT"
    if target.startswith("CHANNEL-") and target[len("CHANNEL-"):] in group_names:
        target = target[len("CHANNEL-"):]
    if target not in group_names and target not in standard_targets:
        raise SystemExit("ERROR: unknown route target: " + target)
    exact_domains = service.get("exact_domains", [])
    keyword_domains = service.get("keyword_domains", [])
    regex_domains = service.get("regex_domains", [])
    networks = service.get("networks", [])
    if not all(isinstance(value, list) for value in (domains, exact_domains, keyword_domains, regex_domains, networks)):
        raise SystemExit("ERROR: service rule fields must be lists: " + name)
    if not (domains or exact_domains or keyword_domains or regex_domains or networks):
        raise SystemExit("ERROR: service has no valid rules: " + name)

    actual_target = group_names.get(target, target)
    if networks:
        from router_routes import validate_destination
        for value in networks:
            network = validate_destination(value)
            previous = network_targets.setdefault(network, actual_target)
            if previous != actual_target:
                raise ValueError("Для сети " + network + " заданы разные цели в сервисах")
    typed_rules = (
        [(value, "DOMAIN-SUFFIX") for value in domains]
        + [(value, "DOMAIN") for value in exact_domains]
        + [(value, "DOMAIN-KEYWORD") for value in keyword_domains]
        + [(value, "DOMAIN-REGEX") for value in regex_domains]
    )
    for raw_value, rule_type in typed_rules:
        value = str(raw_value).strip()
        if rule_type in {"DOMAIN-SUFFIX", "DOMAIN"}:
            value = value.lower().rstrip(".")
            if not domain_re.fullmatch(value):
                raise SystemExit("ERROR: invalid domain in service " + name)
        elif rule_type == "DOMAIN-KEYWORD":
            value = value.lower()
            if not re.fullmatch(r"[a-z0-9.-]{1,253}", value):
                raise SystemExit("ERROR: invalid domain keyword in service " + name)
        elif not value or len(value) > 1024 or "\n" in value or "\r" in value:
            raise SystemExit("ERROR: invalid domain regular expression in service " + name)

        key = (rule_type, value, actual_target)
        if key not in seen:
            seen.add(key)
            route_rule = f"{rule_type},{value},{actual_target}"
            rules.append("  - " + (json.dumps(route_rule, ensure_ascii=False) if rule_type in {"DOMAIN-KEYWORD", "DOMAIN-REGEX"} else route_rule))
        if actual_target not in {"DIRECT", "REJECT", "PASS"}:
            fake_rule = f"{rule_type},{value},fake-ip"
            fake_ip_rules.append("    - " + (json.dumps(fake_rule, ensure_ascii=False) if rule_type in {"DOMAIN-KEYWORD", "DOMAIN-REGEX"} else fake_rule))

ordered_networks = sorted(network_targets, key=lambda net: -int(net.rsplit("/", 1)[1]))
rules = [f"  - IP-CIDR,{net},{network_targets[net]},no-resolve" for net in ordered_networks] + rules
group_lines = []
for name, group in group_names.items():
    escaped = re.escape(name)
    group_lines.extend([
        f"  - name: {group}",
        "    type: select",
        "    use:",
        "      - SRV",
        "      - USER-MANAGED",
        f"    filter: '^{escaped}$'",
        ""
    ])
group_block = GROUP_BEGIN + "\n"
if group_lines:
    group_block += "\n".join(group_lines).rstrip() + "\n"
group_block += GROUP_END

selector_lines = [f"      - {group}" for group in group_names.values()]
selector_block = SELECTOR_BEGIN + "\n"
if selector_lines:
    selector_block += "\n".join(selector_lines) + "\n"
selector_block += SELECTOR_END
manager_db = json.load(open("/etc/mihomo/rules/managed-proxies.json", encoding="utf-8"))
managed_by_name = {n["proxy"]["name"]: n for n in manager_db.get("nodes", [])}
overrides = manager_db.get("balance_overrides", {})
balance_lines = [
    f"      - {group_names[name]}" for name in proxy_names
    if overrides.get(name, managed_by_name.get(name, {}).get("balance", True))
]
if not balance_lines:
    balance_lines = ["      - DIRECT"]
balance_block = BALANCE_BEGIN + "\n" + "\n".join(balance_lines) + "\n" + BALANCE_END


rule_block = RULE_BEGIN + "\n"
if rules:
    rule_block += "\n".join(rules) + "\n"
rule_block += RULE_END

with open(TEMPLATE, encoding="utf-8") as f:
    original = f.read()

fake_ip_block = FAKE_BEGIN + "\n"
if fake_ip_rules:
    fake_ip_block += "\n".join(dict.fromkeys(fake_ip_rules)) + "\n"
fake_ip_block += FAKE_END

updated = replace_marked_block(original, GROUP_BEGIN, GROUP_END, group_block)
updated = replace_marked_block(updated, RULE_BEGIN, RULE_END, rule_block)
updated = replace_marked_block(updated, FAKE_BEGIN, FAKE_END, fake_ip_block)
updated = replace_marked_block(updated, SELECTOR_BEGIN, SELECTOR_END, selector_block)
updated = replace_marked_block(updated, BALANCE_BEGIN, BALANCE_END, balance_block)
health = ('    url: https://www.gstatic.com/generate_204\n'
          '    interval: 120\n    timeout: 5000\n    lazy: false\n    expected-status: 204\n')
match = re.search(r'(?ms)^  - name: LOADBALANCE\n.*?(?=^  - name:|^  # BEGIN SERVICE-CHANNEL-GROUPS|^rules:|\Z)', updated)
if not match:raise SystemExit('Missing LOADBALANCE group')
block = re.sub(r'^    (url|interval|timeout|lazy|expected-status):.*\n', '', match.group(), flags=re.M)
block = block.replace('    strategy: round-robin\n', '    strategy: round-robin\n'+health, 1)
updated = updated[:match.start()] + block + updated[match.end():]

fd, temp = tempfile.mkstemp(prefix=".service-routes-", dir=os.path.dirname(TEMPLATE))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(updated)
    durable_replace(temp, TEMPLATE)
finally:
    if os.path.exists(temp):
        os.unlink(temp)

print("Service routes prepared:", len(rules), "domain and network rules")
print("Channel groups prepared:", len(group_names))
for name, group in group_names.items():
    print(" ", name, "->", group)
