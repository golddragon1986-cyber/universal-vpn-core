from durable_io import replace as durable_replace
#!/usr/bin/env python3
import json
import fcntl
import os
import re
import shutil
import tempfile
import time
from urllib.request import Request, urlopen

TEMPLATE = "/etc/mihomo/rules/panel-managed-template.yaml"
CANDIDATE = "/etc/mihomo/default_config_candidate.yaml"
LAST_GOOD = CANDIDATE + ".last-good"
API = "http://127.0.0.1:9090"
SETTINGS = "/etc/mihomo/rules/routing-settings.json"

RULE_BEGIN = "# BEGIN SERVICE-ROUTES"
RULE_END = "# END SERVICE-ROUTES"
GROUP_BEGIN = "# BEGIN SERVICE-CHANNEL-GROUPS"
GROUP_END = "# END SERVICE-CHANNEL-GROUPS"
FAKE_BEGIN = "# BEGIN SERVICE-FAKE-IP"
FAKE_END = "# END SERVICE-FAKE-IP"
SELECTOR_BEGIN = "# BEGIN SELECTOR-CHANNELS"
SELECTOR_END = "# END SELECTOR-CHANNELS"
BALANCE_BEGIN = "# BEGIN BALANCE-CHANNELS"
BALANCE_END = "# END BALANCE-CHANNELS"
DNS_MODE_RE = re.compile(r"(?m)^([ \t]*enhanced-mode:[ \t]*)([^#\s]+)(.*)$")

def get_block(text, begin, end):
    pattern = re.compile(
        r"(?m)^[ \t]*" + re.escape(begin) +
        r"[ \t]*\n.*?^[ \t]*" + re.escape(end) + r"[ \t]*$",
        re.S
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one marked block: " + begin)
    return matches[0].group(0)

def replace_block(base, new_block, begin, end):
    pattern = re.compile(
        r"(?m)^[ \t]*" + re.escape(begin) +
        r"[ \t]*\n.*?^[ \t]*" + re.escape(end) + r"[ \t]*$",
        re.S
    )
    result, count = pattern.subn(lambda _: new_block, base)
    if count != 1:
        raise RuntimeError("Could not replace exactly one marked block: " + begin)
    return result

def domains_in(block):
    return {
        m.group(1).strip().lower()
        for m in re.finditer(
            r"(?m)^[ \t]*-[ \t]*DOMAIN-SUFFIX,([^,\s]+),([^,\s]+)",
            block
        )
    }

def dns_mode(text):
    matches = list(DNS_MODE_RE.finditer(text))
    if len(matches) != 1:
        raise RuntimeError("Expected one DNS enhanced-mode setting")
    return matches[0].group(2)


def set_dns_mode(text, mode):
    matches = list(DNS_MODE_RE.finditer(text))
    if len(matches) != 1:
        raise RuntimeError("Expected one DNS enhanced-mode setting")
    match = matches[0]
    return text[:match.start()] + match.group(1) + mode + match.group(3) + text[match.end():]


def write_routing_settings(settings):
    directory = os.path.dirname(SETTINGS)
    fd, temp_path = tempfile.mkstemp(prefix=".routing-settings-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        durable_replace(temp_path, SETTINGS)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def api_json(path):
    with urlopen(API + path, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))

def put_config():
    body = json.dumps({"path": CANDIDATE}).encode("utf-8")
    req = Request(
        API + "/configs?force=true",
        data=body,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urlopen(req, timeout=15) as response:
        status=response.status
    from log_panel import restore_level
    restore_level()
    from client_policy import runtime as client_runtime
    client_runtime()
    return status

def verify(check_domains):
    rules = api_json("/rules").get("rules", [])
    actual = set()
    for rule in rules:
        typ = str(rule.get("type", "")).lower()
        payload = str(rule.get("payload", "")).lower()
        proxy = str(rule.get("proxy", ""))
        if typ in ("domainsuffix", "domain-suffix") and payload in check_domains:
            actual.add((payload, proxy))

    text = open(CANDIDATE, encoding="utf-8").read()
    block = get_block(text, RULE_BEGIN, RULE_END)
    expected = set()
    for line in block.splitlines():
        m = re.match(
            r"^\s*-\s*DOMAIN-SUFFIX,([^,\s]+),([^,\s]+)",
            line
        )
        if m and m.group(1).lower() in check_domains:
            expected.add((m.group(1).lower(), m.group(2)))

    if actual != expected:
        raise RuntimeError(
            "Active rules differ from candidate; "
            f"expected={sorted(expected)!r}, actual={sorted(actual)!r}"
        )
    return len(expected)


def save_last_good():
    directory = os.path.dirname(CANDIDATE)
    fd, temp_path = tempfile.mkstemp(prefix=".last-good-", dir=directory)
    try:
        with open(CANDIDATE, "rb") as source, os.fdopen(fd, "wb") as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        durable_replace(temp_path, LAST_GOOD)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    # Remove only dated automatic copies created by this apply script.
    pattern = re.compile(re.escape(os.path.basename(CANDIDATE)) + r"\.apply-backup-\d{8}-\d{6}$")
    for entry in os.scandir(directory):
        if pattern.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
            os.unlink(entry.path)

def main():
    from geodata_service_files import copy_providers, with_reject_dns
    with open(CANDIDATE, encoding="utf-8") as f:
        old_text = f.read()
    with open(TEMPLATE, encoding="utf-8") as f:
        template_text = f.read()
    from dns_panel import apply_settings as apply_dns_settings
    template_text = apply_dns_settings(template_text)

    old_rules = get_block(old_text, RULE_BEGIN, RULE_END)
    new_rules = get_block(template_text, RULE_BEGIN, RULE_END)

    routing_settings = {}
    if os.path.isfile(SETTINGS):
        with open(SETTINGS, encoding="utf-8") as f:
            routing_settings = json.load(f)
        if not isinstance(routing_settings, dict):
            raise RuntimeError("Invalid routing-settings.json")
    original_settings = dict(routing_settings)
    try:
        main_route = api_json("/proxies/SELECTOR").get("now")
    except Exception:
        main_route = None
    main_direct = str(main_route or routing_settings.get("main_proxy", "DIRECT")).strip().upper() == "DIRECT"
    if not bool(routing_settings.get("services_enabled", True)):
        new_rules = "  " + RULE_BEGIN + "\n  " + RULE_END
    new_groups = get_block(template_text, GROUP_BEGIN, GROUP_END)
    new_selector_channels = get_block(template_text, SELECTOR_BEGIN, SELECTOR_END)
    new_balance_channels = get_block(template_text, BALANCE_BEGIN, BALANCE_END)
    old_fake = get_block(old_text, FAKE_BEGIN, FAKE_END)
    new_fake = get_block(template_text, FAKE_BEGIN, FAKE_END)
    if not bool(routing_settings.get("services_enabled", True)):
        new_fake = "  " + FAKE_BEGIN + "\n  " + FAKE_END

    current_dns_mode = dns_mode(old_text)
    from dns_panel import tunnel_mode
    target_dns_mode = "redir-host" if tunnel_mode() else "fake-ip"
    routing_settings.pop("dns_enhanced_mode_before_direct", None)
    flush_dns_caches = old_rules != new_rules or old_fake != new_fake or target_dns_mode != current_dns_mode

    check_domains = (
        domains_in(old_rules) | domains_in(new_rules)
    )


    new_text = replace_block(
        old_text, new_groups, GROUP_BEGIN, GROUP_END
    )
    service_template = template_text if routing_settings.get("services_enabled", True) else ""
    new_text = copy_providers(new_text, service_template)
    new_text = with_reject_dns(new_text, template=service_template)
    new_text = apply_dns_settings(new_text)
    if new_text != old_text:
        flush_dns_caches = True
    new_text = replace_block(
        new_text, new_rules, RULE_BEGIN, RULE_END
    )
    new_text = replace_block(
        new_text, new_fake, FAKE_BEGIN, FAKE_END
    )
    new_text = replace_block(
        new_text, new_selector_channels, SELECTOR_BEGIN, SELECTOR_END
    )
    new_text = replace_block(
        new_text, new_balance_channels, BALANCE_BEGIN, BALANCE_END
    )
    if target_dns_mode != current_dns_mode:
        new_text = set_dns_mode(new_text, target_dns_mode)
    from router_routes import service_networks, sync_service_routes, with_service_tun_routes
    old_networks = service_networks(old_text)
    from network_priority import apply as apply_network_priority
    new_text = apply_network_priority(new_text)
    new_networks = service_networks(new_text)
    new_text = with_service_tun_routes(new_text, template_text)
    routes_synced = False

    directory = os.path.dirname(CANDIDATE)
    rollback_fd, backup = tempfile.mkstemp(prefix=".apply-rollback-", dir=directory)
    os.close(rollback_fd)
    shutil.copy2(CANDIDATE, backup)
    fd, temp_path = tempfile.mkstemp(
        prefix=".service-routes-", dir=directory
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
            f.flush()
            os.fsync(f.fileno())
        durable_replace(temp_path, CANDIDATE)

        # The controller parses the candidate before applying it.
        put_config()
        verified = verify(check_domains)
        if old_networks != new_networks:
            sync_service_routes(new_networks)
            routes_synced = True
        if routing_settings != original_settings:
            write_routing_settings(routing_settings)
        if flush_dns_caches:
            for cache_path in ("/cache/fakeip/flush", "/cache/dns/flush"):
                try:
                    request = Request(API + cache_path, data=b"", method="POST")
                    with urlopen(request, timeout=10):
                        pass
                except Exception as cache_error:
                    print("WARNING: could not flush " + cache_path + ": " + str(cache_error))
        try:
            save_last_good()
        except Exception as backup_error:
            print("WARNING: could not update last successful configuration:", backup_error)
        print(
            f"OK: applied {verified} service rules and channel groups; "
            f"main route={main_route}; DNS mode={target_dns_mode}; "
            f"backup: {LAST_GOOD}"
        )

    except Exception:
        shutil.copy2(backup, CANDIDATE)
        if routes_synced:
            try:
                sync_service_routes(old_networks)
            except Exception as rollback_error:
                print("WARNING: RouterOS route rollback failed:", rollback_error)
        try:
            put_config()
        except Exception as rollback_error:
            print("WARNING: runtime rollback failed:", rollback_error)
        raise
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        if os.path.exists(backup):
            os.unlink(backup)

if __name__ == "__main__":
    with open(CANDIDATE + ".apply.lock", "a") as apply_lock:
        fcntl.flock(apply_lock, fcntl.LOCK_EX)
        main()
