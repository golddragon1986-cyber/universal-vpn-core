from ui_i18n import text as _ui
"""DNS resolver configuration and wire-format diagnostics."""

import ast
import concurrent.futures
import html
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, urlencode

from durable_io import write


ROOT = Path("/etc/mihomo")
SETTINGS = ROOT / "rules/dns-settings.json"
PROBE_LOCK = threading.BoundedSemaphore(2)
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_section(text):
    match = re.search(r"(?ms)^dns:\n.*?(?=^[^\s#]|\Z)", text)
    if not match:
        raise ValueError("В конфигурации отсутствует раздел DNS.")
    return match


def list_values(text, key, indent=2):
    match = re.search(r"(?m)^" + " " * indent + re.escape(key) + r":[ ]*\n((?:[ ]+- [^\n]*\n)+)", text)
    if not match:
        return []
    values = []
    for line in match[1].splitlines():
        value = line.strip()[2:].strip()
        values.append(ast.literal_eval(value) if value.startswith(("'", '"')) else value)
    return values


def normalize(saved):
    if saved.get("version") == 2:
        return ensure_service_dns({**saved, "servers": [{**row, "route":row.get("route") or "SELECTOR"} for row in saved["servers"]]})
    bootstrap = saved.get("default-nameserver", [])
    routed = saved.get("routed-enabled", saved.get("mode") == "tunnel-real-ip")
    rows = []
    for key, route, enabled in (("nameserver", "DIRECT", not routed), ("routed-nameserver", "SELECTOR", routed)):
        for index, address in enumerate(saved.get(key, [])):
            rows.append({"id": key + str(index), "name": "DNS " + str(len(rows) + 1),
                         "address": address.split("#", 1)[0], "route": route, "enabled": enabled})
    for address in reversed(bootstrap):
        if not any(row["address"] == address and row["route"] == "DIRECT" for row in rows):
            rows.insert(0, {"id": "routeros-" + str(len(rows)), "name": "RouterOS DNS", "address": address, "route": "DIRECT", "enabled": True})
    return ensure_service_dns({"version": 2, "fake_ip": saved.get("mode", "fake-ip") != "tunnel-real-ip", "servers": rows})


def read_settings():
    from configuration_draft import state_path
    path = state_path(SETTINGS)
    if path.exists():
        saved = json.loads(path.read_text(encoding="utf-8"))
        if path != SETTINGS: return saved
        values = normalize(saved)
        return values
    section = dns_section((ROOT / "default_config.yaml").read_text(encoding="utf-8"))[0]
    return normalize({"default-nameserver": list_values(section, "default-nameserver"),
                      "nameserver": list_values(section, "nameserver")})


def tunnel_mode():
    from routing_panel import resolve_target
    return not read_settings()["fake_ip"] or resolve_target() == "TRANSIT"


def route_ports(values=None):
    import zlib
    values = values or read_settings()
    routes = {row["route"] for row in values["servers"] if row["route"] != "DIRECT"} | {"SELECTOR"}
    from client_policy import read as client_settings
    routes.update(row['route'] for row in client_settings() if row.get('enabled') and row.get('route','RULES') not in {'RULES','BYPASS'})
    return {route: 11080 if route == "SELECTOR" else 12000 + zlib.crc32(route.encode()) % 40000 for route in sorted(routes)}


def bootstrap_servers(values):
    result = []
    for row in values["servers"]:
        if not row["enabled"] or row["route"] != "DIRECT": continue
        parsed, _ = endpoint(row["address"])
        try: ipaddress.ip_address(parsed.hostname)
        except ValueError: continue
        result.append(row["address"])
    return list(dict.fromkeys(result))


def ensure_service_dns(values):
    if not bootstrap_servers(values):
        existing = {row['id'] for row in values['servers']}
        for index, address in enumerate(('1.1.1.1', '8.8.8.8')):
            ident = 'service-dns-' + str(index)
            while ident in existing: ident += '-new'
            existing.add(ident)
            values['servers'].append({'id': ident, 'name': 'Служебный', 'address': address,
                                     'route': 'DIRECT', 'enabled': True})
    return values


def route_choices():
    from routing_panel import global_info, available_main_routes
    choices = available_main_routes(global_info())
    return list(dict.fromkeys(["SELECTOR", "DIRECT"] + [route for route in choices if route != "SELECTOR"]))


def endpoint(value, *, bootstrap=False):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) <= 32 for c in value):
        raise ValueError("Некорректный адрес DNS.")
    try:
        ipaddress.ip_address(value)
        parsed = urlsplit("udp://[" + value + "]" if ":" in value else "udp://" + value)
    except ValueError:
        parsed = urlsplit(value if "://" in value else "udp://" + value)
    try:
        port = parsed.port or {"udp": 53, "tcp": 53, "tls": 853, "https": 443}[parsed.scheme]
        if not parsed.hostname or parsed.username or parsed.password or parsed.port == 0 or not 1 <= port <= 65535:
            raise ValueError
        if parsed.scheme != "https" and (parsed.path or parsed.query):
            raise ValueError
        if parsed.scheme == "https" and not parsed.path:
            raise ValueError
        if bootstrap:
            ipaddress.ip_address(parsed.hostname)
        if parsed.fragment and any(c in parsed.fragment for c in "'\"[]{}"):
            raise ValueError
    except (ValueError, KeyError):
        raise ValueError("Используйте IP[:порт], udp://, tcp://, tls:// или https://имя/dns-query.") from None
    return parsed, port


def parse_settings(form):
    # Installer compatibility. New panel submissions use the table schema.
    if "servers" not in form:
        legacy = {key: [v.strip() for v in re.split(r"[;\r\n]+", form.get(key, [""])[0]) if v.strip()]
                  for key in ("default-nameserver", "nameserver", "routed-nameserver")}
        result = normalize(legacy)
    else:
        result = {"version": 2, "fake_ip": form.get("fake_ip", ["0"])[-1] == "1", "servers": json.loads(form["servers"][0])}
    if not isinstance(result["servers"], list) or len(result["servers"]) > 32:
        raise ValueError("Допустимо до 32 DNS-серверов.")
    seen = set()
    choices = None
    for row in result["servers"]:
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("id", "name", "address", "route")):
            raise ValueError("Некорректная строка DNS.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", row["id"]) or row["id"] in seen:
            raise ValueError("Повторяющийся или некорректный идентификатор DNS.")
        seen.add(row["id"])
        row["name"] = row["name"].strip(); row["address"] = row["address"].strip()
        if not 1 <= len(row["name"]) <= 100 or type(row.get("enabled")) is not bool:
            raise ValueError("Укажите название и состояние DNS.")
        parsed, port = endpoint(row["address"])
        if parsed.fragment or (parsed.hostname in {"127.0.0.1", "localhost", "::1"} and port in {53, 1054}):
            raise ValueError("DNS не должен ссылаться обратно на DNS контейнера или содержать #маршрут.")
        row["route"] = row["route"] or "SELECTOR"
        if row["route"] not in {"SELECTOR", "DIRECT", "LOADBALANCE"}:
            if choices is None: choices = route_choices()
            if row["route"] not in choices:
                raise ValueError("Маршрут DNS недоступен: " + row["route"])
    ensure_service_dns(result)
    if not any(row["enabled"] for row in result["servers"]):
        raise ValueError("Оставьте хотя бы один включённый DNS.")
    ports = list(route_ports(result).values())
    if len(set(ports)) != len(ports): raise ValueError("Конфликт диагностических портов маршрутов DNS.")
    return result


def apply_settings(text):
    from transit_mode import with_group, with_sniffer
    text = with_sniffer(with_group(text))
    if not SETTINGS.exists():
        if tunnel_mode():
            text = re.sub(r"(?m)^(  enhanced-mode:)\s*[^\n]+", r"\1 redir-host", text)
        return with_probe_listener(text)
    values = read_settings()
    original = dns_section(text)
    section = original[0]
    for key, servers in {"default-nameserver": bootstrap_servers(values), "proxy-server-nameserver": bootstrap_servers(values),
                         "nameserver": ["tcp://127.0.0.1:1054"], "direct-nameserver": ["tcp://127.0.0.1:1054"]}.items():
        pattern = re.compile(r"(?m)^  " + re.escape(key) + r":[^\n]*\n(?:    - [^\n]*\n)*")
        block = "  " + key + ":\n" + "".join("    - " + json.dumps(value) + "\n" for value in servers)
        section = pattern.sub(lambda _: block, section, count=1) if pattern.search(section) else section.replace("dns:\n", "dns:\n" + block, 1)
    # All managed domain policies use the ordered table, except explicit NXDOMAIN.
    section = re.sub(r"(?m)^(    ['\"]rule-set:RU-BLOCKED[^\n]*['\"]:\n)(?:      - [^\n]*\n)+",
                     lambda m: m[1] + '      - "tcp://127.0.0.1:1054"\n', section)
    from routing_panel import resolve_target
    inherited_answer = "real-ip" if resolve_target() in {"DIRECT", "TRANSIT"} else "fake-ip"
    section = re.sub(r"(?m)^(    - RULE-SET,RU-BLOCKED(?:-LOCAL)?,)(?:fake-ip|real-ip)$",lambda m:m[1]+inherited_answer,section)
    text = text[:original.start()] + section + text[original.end():]
    text = re.sub(r"(?m)^(  enhanced-mode:)\s*[^\n]+", lambda m: m[1] + (" redir-host" if tunnel_mode() else " fake-ip"), text)
    # The new FakeIP control only changes DNS; restore the old mode's traffic fallback.
    text = re.sub(r"(?m)^  - MATCH,SELECTOR # DNS-TUNNEL-DEFAULT:([^\s]+)$", r"  - MATCH,\1", text)
    from local_dns_zones import configure
    return with_probe_listener(configure(text))


def with_probe_listener(text):
    entries = ''
    for route, port in route_ports().items():
        entries += ('  - name: dns-probe-' + str(port) + '\n    type: socks\n    listen: 127.0.0.1\n'
                    '    port: ' + str(port) + '\n    udp: true\n    proxy: ' + json.dumps(route) + '\n')
    block = '  # DNS PROBE LISTENER BEGIN\n' + entries + '  # DNS PROBE LISTENER END\n'
    text = re.sub(r'(?ms)^  # DNS PROBE LISTENER BEGIN\n.*?^  # DNS PROBE LISTENER END\n', '', text)
    text = re.sub(r'(?m)^listeners:[ \t]*\[\][ \t]*$', 'listeners:', text)
    if re.search(r'(?m)^listeners:[ \t]*$', text):
        return re.sub(r'(?m)^listeners:[ \t]*\n', lambda _: 'listeners:\n' + block, text, count=1)
    return text.rstrip() + '\nlisteners:\n' + block


def save(form):
    values = parse_settings(form)
    previous = SETTINGS.read_bytes() if SETTINGS.exists() else None
    write(SETTINGS, json.dumps(values, ensure_ascii=False).encode())
    try:
        from service_routes_panel import apply_services, read_services
        items = read_services()
        return apply_services(items, items, "Настройки DNS применены.")
    except Exception:
        if previous is None:
            SETTINGS.unlink(missing_ok=True)
        else:
            write(SETTINGS, previous)
        raise


def domain_name(value):
    name = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", name):
        raise ValueError("Введите доменное имя без схемы и пути.")
    if any(len(label) > 63 for label in name.split(".")):
        raise ValueError("Слишком длинная часть доменного имени.")
    return name


def read_name(data, offset):
    labels, seen, end = [], set(), None
    while True:
        if offset in seen or len(seen) > 128 or offset >= len(data):
            raise ValueError("Повреждённое имя в ответе DNS.")
        seen.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Обрезанный ответ DNS.")
            end = end or offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
            continue
        offset += 1
        if size == 0:
            return ".".join(labels), end or offset
        if size > 63 or offset + size > len(data):
            raise ValueError("Обрезанный ответ DNS.")
        labels.append(data[offset:offset + size].decode("ascii"))
        offset += size


def decode_response(data, transaction, name, qtype):
    if len(data) < 12:
        raise ValueError("Обрезанный ответ DNS.")
    ident, flags, questions, answers, _, _ = struct.unpack("!6H", data[:12])
    if ident != transaction or not flags & 0x8000 or questions != 1:
        raise ValueError("Ответ DNS не соответствует запросу.")
    question, offset = read_name(data, 12)
    if question.lower() != name or struct.unpack_from("!HH", data, offset) != (qtype, 1):
        raise ValueError("Ответ DNS содержит другой вопрос.")
    offset += 4
    records = []
    for _ in range(answers):
        record_name, offset = read_name(data, offset)
        typ, cls, ttl, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        end = offset + size
        if end > len(data):
            raise ValueError("Обрезанная запись DNS.")
        if cls == 1:
            if typ in (1, 28) and size == (4 if typ == 1 else 16):
                value = str(ipaddress.ip_address(data[offset:end]))
            elif typ == 5:
                value, _ = read_name(data, offset)
            else:
                value = None
            if value is not None:
                records.append({"type": {1: "A", 28: "AAAA", 5: "CNAME"}[typ], "value": value, "ttl": ttl})
        offset = end
    return {"status": RCODES.get(flags & 15, str(flags & 15)), "records": records, "truncated": bool(flags & 0x200)}


def receive(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise ValueError("DNS-сервер закрыл соединение.")
        result += part
    return result


def socks_address(address, port):
    ip = ipaddress.ip_address(address)
    return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack('!H', port)


def read_socks_address(sock):
    kind = receive(sock, 1)[0]
    if kind in {1, 4}:
        host = str(ipaddress.ip_address(receive(sock, 4 if kind == 1 else 16)))
    elif kind == 3:
        host = receive(sock, receive(sock, 1)[0]).decode('ascii')
    else:
        raise ValueError('Некорректный адрес SOCKS.')
    return host, struct.unpack('!H', receive(sock, 2))[0]


def route_socket(address, port, *, udp=False, route="SELECTOR", timeout=5):
    sock = socket.create_connection(('127.0.0.1', route_ports()[route]), timeout=timeout)
    try:
        sock.sendall(b'\x05\x01\x00')
        if receive(sock, 2) != b'\x05\x00':
            raise ValueError('Основной маршрут отклонил подключение SOCKS.')
        destination = socks_address('0.0.0.0', 0) if udp else socks_address(address, port)
        sock.sendall(b'\x05' + bytes([3 if udp else 1]) + b'\x00' + destination)
        reply = receive(sock, 3)
        if reply[0] != 5 or reply[1] != 0:
            raise ValueError('Основной маршрут вернул ошибку SOCKS ' + str(reply[1]))
        relay = read_socks_address(sock)
        return sock, relay
    except Exception:
        sock.close()
        raise


def exchange(server, name, qtype, *, bootstrap, routed=False, raw=False, request=None, timeout=4):
    parsed, port = endpoint(server)
    transaction = secrets.randbelow(65536)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet = struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)
    if request is not None:
        packet = request
        transaction = struct.unpack_from('!H', packet)[0]
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
        address = host
    except ValueError:
        address = None
        for initial in bootstrap:
            try:
                result = exchange(initial, domain_name(host), 1, bootstrap=[], timeout=timeout)
                address = next((r["value"] for r in result["records"] if r["type"] == "A"), None)
                if address:
                    break
            except (OSError, ValueError, http.client.HTTPException, struct.error):
                continue
        if not address:
            raise ValueError("Начальные DNS не разрешили адрес сервера.")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        try:
            connection.sock = route_socket(address, port, route="SELECTOR" if routed is True else routed, timeout=timeout)[0] if routed else socket.create_connection((address, port), timeout=timeout)
            connection.sock = context.wrap_socket(connection.sock, server_hostname=host)
            connection.request("POST", urlunsplit(("", "", parsed.path, parsed.query, "")), body=packet,
                               headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("DoH вернул HTTP " + str(response.status))
            data = response.read(65536)
            if len(data) > 65535:
                raise ValueError("Ответ DoH слишком большой.")
        finally:
            connection.close()
    elif parsed.scheme == "udp":
        control = None
        try:
            relay = None
            if routed:
                control, relay = route_socket(address, port, udp=True, route="SELECTOR" if routed is True else routed, timeout=timeout)
                if relay[0] in {'0.0.0.0', '::'}:
                    relay = ('127.0.0.1', relay[1])
            with socket.socket(socket.AF_INET6 if relay and ':' in relay[0] else socket.AF_INET if relay else family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect(relay or (address, port))
                sock.send(b'\0\0\0' + socks_address(address, port) + packet if routed else packet)
                data = sock.recv(65535)
                if routed:
                    import io
                    if data[:3] != b'\0\0\0':
                        raise ValueError('Некорректный ответ UDP через основной маршрут.')
                    class Reader:
                        def __init__(self, payload): self.buffer = io.BytesIO(payload)
                        def recv(self, size): return self.buffer.read(size)
                    reader = Reader(data[3:])
                    read_socks_address(reader)
                    data = reader.buffer.read()
        finally:
            if control:
                control.close()
        result = decode_response(data, transaction, name, qtype)
        if result["truncated"]:
            return exchange("tcp://[" + address + "]:" + str(port) if family == socket.AF_INET6
                            else "tcp://" + address + ":" + str(port), name, qtype, bootstrap=[], routed=routed, raw=raw, timeout=timeout)
        return data if raw else result
    else:
        with (route_socket(address, port, route="SELECTOR" if routed is True else routed, timeout=timeout)[0] if routed else socket.create_connection((address, port), timeout=timeout)) as stream:
            sock = ssl.create_default_context().wrap_socket(stream, server_hostname=host) if parsed.scheme == "tls" else stream
            try:
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                data = receive(sock, struct.unpack("!H", receive(sock, 2))[0])
            finally:
                if sock is not stream:
                    sock.close()
    result = decode_response(data, transaction, name, qtype)
    return data if raw else result


def fake_ip_origin(name, result):
    if result.get('status') != 'NOERROR':
        return {}
    ranges = [ipaddress.ip_network('198.18.0.0/16')]
    config_path = ROOT / 'default_config_candidate.yaml'
    if config_path.exists():
        config = config_path.read_text(encoding='utf-8')
        configured = re.findall(r'(?m)^  fake-ip-range(?:6)?:\s*[\"\']?([^\s\"\'#]+)', config)
        if configured:
            ranges = [ipaddress.ip_network(value, strict=False) for value in configured]
    addresses = [ipaddress.ip_address(record['value']) for record in result.get('records', [])
                 if record.get('type') in {'A', 'AAAA'}]
    if not any(address.version == network.version and address in network for address in addresses for network in ranges):
        return {}
    from service_routes_panel import read_services, effective_domain_rules, service_edit_url
    settings_path = ROOT / 'rules/routing-settings.json'
    settings = json.loads(settings_path.read_text(encoding='utf-8')) if settings_path.exists() else {}
    owner = effective_domain_rules(read_services(), [name]).get(name) if settings.get('services_enabled', True) else None
    if owner is not None:
        return {'status': 'FakeIP', 'via': owner['name'], 'via_url': service_edit_url(owner)}
    return {'status': 'FakeIP', 'via': 'Локальный домен',
            'via_url': '/?' + urlencode({'domains': '1', 'q': name})}


def probe(params):
    name = domain_name(params.get("domain", [""])[0])
    kind = "A"
    values = read_settings()
    servers = list(dict.fromkeys(part.strip() for part in re.split(r"[;\r\n]+", params.get("servers", [""])[0]) if part.strip()))
    if len(servers) > 12:
        raise ValueError("За один запрос проверяется до 12 внешних серверов.")
    for server in servers:
        endpoint(server)
    if not PROBE_LOCK.acquire(blocking=False):
        raise ValueError("Дождитесь завершения предыдущей проверки DNS.")
    def test(pair):
        label, server, routed = pair
        via = 'RouterOS · 172.31.41.1' if label == 'DNS RouterOS' else 'DNS контейнера' if server == '127.0.0.1' and label == 'DNS контейнера' else ('Основной маршрут' if routed in {True, 'SELECTOR'} else str(routed)) if routed else 'Напрямую'
        started = time.monotonic()
        try:
            result = {"server": label, "via": via, **exchange(server, name, 1 if kind == "A" else 28,
                                                bootstrap=bootstrap_servers(values), routed=routed),
                      "ms": round((time.monotonic() - started) * 1000, 1)}
            if label == 'DNS контейнера' and server == '127.0.0.1':
                result.update(fake_ip_origin(name, result))
            return result
        except (OSError, ValueError, http.client.HTTPException, struct.error) as error:
            return {"server": label, "via": via, "error": str(error), "ms": round((time.monotonic() - started) * 1000, 1)}
    try:
        targets = [("DNS контейнера", "127.0.0.1", False), ("DNS RouterOS", "172.31.41.1", False)]
        targets.extend((row['name'] + ' — ' + row['address'], row['address'], False if row['route'] == 'DIRECT' else row['route']) for row in values['servers'])
        targets.extend((server, server, False) for server in servers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return {"domain": name, "type": kind, "results": list(pool.map(test, targets))}
    finally:
        PROBE_LOCK.release()


def render():
    from dns_table_ui import render_settings
    from local_dns_zones import render as render_local_zones
    values = read_settings()
    try: choices = route_choices()
    except Exception: choices = ['DIRECT', 'LOADBALANCE']
    return (render_settings(values, choices) + render_local_zones() +
        _ui('<div class="panel"><details class="panel-spoiler"><summary>Проверка DNS</summary><form id="dns-probe-form"><input name="domain" aria-label="Домен для проверки DNS" placeholder="Домен, например example.com" required maxlength="253"><button type="submit">Проверить</button><p class="hint">Проверяются DNS контейнера, DNS RouterOS и каждый DNS из таблицы по заданному маршруту, включая отключённые строки. DNS контейнера и RouterOS учитывают свой кеш. Время включает соединение и получение ответа.</p></form><div id="dns-probe-result" role="status"></div></details></div><style>body .unified-main .dns-settings-form{display:grid;grid-template-columns:minmax(0,560px);gap:16px;justify-content:start}body .unified-main .dns-settings-form>p{grid-column:1/-1}body .unified-main .dns-settings-form>label{display:block;margin:0;width:100%}body .unified-main .dns-settings-form textarea{width:100%;box-sizing:border-box;resize:vertical;min-height:70px;margin:6px 0}body .unified-main .dns-routed-field>label:first-child{display:block;margin:0}body .unified-main .dns-routed-toggle{display:flex;align-items:center;gap:8px;margin:4px 0 8px}body .unified-main .dns-routed-toggle input{width:18px;height:18px;margin:0}body .unified-main #dns-probe-form textarea{min-height:70px;margin:6px 0}body .unified-main .dns-settings-form small{display:block;color:var(--ui-muted);font-weight:400}body .unified-main .dns-settings-form>button{justify-self:start}body .unified-main #dns-probe-form{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;margin-top:16px;align-items:center}body .unified-main #dns-probe-form>textarea,body .unified-main #dns-probe-form>p{grid-column:1/-1}body .unified-main #dns-probe-form>input,body .unified-main #dns-probe-form>select,body .unified-main #dns-probe-form>button{height:40px;box-sizing:border-box;margin:0;min-width:0}body .unified-main #dns-probe-form>button{white-space:nowrap}body .unified-main #dns-probe-result{overflow:auto}body .unified-main #dns-probe-result a,body .unified-main #dns-probe-result a:visited{color:#b8d5ff}@media(max-width:650px){body .unified-main .dns-settings-form{grid-template-columns:minmax(0,1fr);width:100%}}</style><script>(()=>{const form=document.getElementById("dns-probe-form"),out=document.getElementById("dns-probe-result");form.addEventListener("submit",async event=>{event.preventDefault();const button=form.querySelector("button");if(button.disabled)return;button.disabled=true;out.textContent="Проверяем DNS…";try{const response=await fetch("/api/dns/probe?"+new URLSearchParams(new FormData(form)),{cache:"no-store"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Ошибка проверки DNS");out.replaceChildren();const table=document.createElement("table"),head=table.createTHead().insertRow();for(const title of ["DNS","Путь","Время, мс","Ответ","Записи / TTL, сек."]){const th=document.createElement("th");th.textContent=title;head.append(th);}const body=table.createTBody();for(const item of data.results){const row=body.insertRow();let col=0;for(const value of [item.server,item.via,item.ms,item.error||item.status,(item.records||[]).map(r=>r.type+" "+r.value+" / "+r.ttl).join("\\n")||"—"]){const td=row.insertCell();if(col===1&&item.via_url){const link=document.createElement("a");link.href=item.via_url;link.textContent=value;td.append(link);}else td.textContent=value;col++;td.style.whiteSpace="pre-wrap";}}out.append(table);}catch(error){out.textContent=error.message;}finally{button.disabled=false;}});})();</script>')
    )
