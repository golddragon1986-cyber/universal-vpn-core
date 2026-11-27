from ui_i18n import text as _ui
"""Persistent VPN subscriptions and scoped node checks."""
import base64
import copy
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import proxy_manager as manager
import vpn_clients as clients
from durable_io import write
from vpn_import import parse, unique

HAPP_UA = "Happ/4.1.1/Windows/2608211947607"
PROFILES = {"standard": "Обычный", "happ": "Happ", "happ-hwid": "Happ + HWID"}
HWID = Path("/etc/mihomo/.subscription-hwid")
MAX_BYTES = 2 * 1024 * 1024


def installation_hwid():
    if not HWID.exists():
        write(HWID, (str(uuid.uuid4()) + "\n").encode("ascii"))
    return str(uuid.UUID(HWID.read_text(encoding="ascii").strip()))


def fetch(url, profile):
    headers = {"User-Agent": "Mihomo-Control/1.0" if profile == "standard" else HAPP_UA}
    if profile == "happ-hwid":
        headers["X-Hwid"] = installation_hwid()
    context = ssl.create_default_context()
    origin = None
    for _ in range(6):
        target, port, addresses = subscription_target(url)
        endpoint = (target.hostname, port)
        if origin is not None and endpoint != origin:
            headers.pop("X-Hwid", None)
        origin = endpoint
        status, location, body, userinfo = fetch_subscription_response(target, port, addresses, headers, context)
        if status == 200:
            if len(body) > MAX_BYTES:
                raise ValueError("Ответ подписки превышает 2 МиБ.")
            return body.decode("utf-8-sig", errors="replace").strip(), parse_userinfo(userinfo)
        if status not in (301, 302, 303, 307, 308) or not location:
            raise ValueError(f"Источник подписки вернул HTTP {status}.")
        url = urljoin(url, location)
    raise ValueError("Слишком много перенаправлений при загрузке подписки.")


def subscription_target(url):
    try:
        target = urlsplit(url)
        port = 443 if target.port is None else target.port
        if (target.scheme != "https" or not target.hostname or target.username is not None
                or not 1 <= port <= 65535 or target.fragment or len(url) > 4096
                or any(ord(char) <= 32 or ord(char) == 127 for char in url)):
            raise ValueError
        addresses = socket.getaddrinfo(target.hostname, port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError
    except (ValueError, OSError):
        raise ValueError("Нужен публичный HTTPS-адрес подписки с допустимым портом.") from None
    return target, port, addresses


def fetch_subscription_response(target, port, addresses, headers, context):
    class PinnedHTTPS(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(addresses[0][4][:2], self.timeout)
            try:
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            except Exception:
                raw.close()
                raise

    conn = PinnedHTTPS(target.hostname, port=port, timeout=15, context=context)
    try:
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        return (response.status, response.getheader("Location"),
                response.read(MAX_BYTES + 1) if response.status == 200 else b"",
                response.getheader("Subscription-Userinfo") if response.status == 200 else None)
    except (OSError, http.client.HTTPException, UnicodeError):
        raise ValueError("Ошибка HTTPS при загрузке подписки.") from None
    finally:
        conn.close()


def parse_userinfo(header):
    """Parse provider-reported bytes and Unix expiry; ignore malformed fields."""
    if not header or len(header) > 1024:
        return None
    result = {}
    for item in header.split(";"):
        key, sep, value = item.partition("=")
        key, value = key.strip().lower(), value.strip()
        if sep and key in ("upload", "download", "total", "expire") and re.fullmatch(r"[0-9]{1,19}", value):
            number = int(value)
            if number <= 2**63 - 1:
                result[key] = number
    return result or None


def format_bytes(value):
    amount = float(value)
    units = ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ")
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024
        index += 1
    return f"{amount:.1f}".rstrip("0").rstrip(".") + " " + units[index] if index else f"{value} Б"


def usage_html(usage):
    if not isinstance(usage, dict):
        return f'<span class="vpn-subscription-usage">{html.escape(_ui("Лимит и срок: провайдер не сообщил"))}</span>'
    parts = []
    upload, download, total, expiry = (usage.get(key) for key in ("upload", "download", "total", "expire"))
    if isinstance(upload, int) and isinstance(download, int):
        used = upload + download
        parts.append(f'{_ui("Использовано")} {format_bytes(used)}')
        if isinstance(total, int):
            parts[-1] += f' / {format_bytes(total)}' if total else f' · {_ui("без лимита")}'
            if total:
                parts.append(f'{_ui("Осталось")} {format_bytes(max(0, total - used))}')
        parts.append(f'↓ {format_bytes(download)} / ↑ {format_bytes(upload)}')
    elif isinstance(total, int):
        parts.append(f'{_ui("Лимит")} {format_bytes(total)}' if total else _ui("Без лимита трафика"))
    if isinstance(expiry, int):
        if expiry == 0:
            parts.append(_ui("Без срока действия"))
        else:
            try:
                date = datetime.fromtimestamp(expiry, timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
                parts.append(f'{_ui("Срок до")} {date}')
            except (OverflowError, OSError, ValueError):
                pass
    if not parts:
        parts.append(_ui("Лимит и срок: провайдер не сообщил"))
    return '<span class="vpn-subscription-usage">' + html.escape(" · ".join(parts)) + '</span>'


def xray_vless(outbound, name, engine):
    settings = outbound["settings"]
    server, = settings["vnext"]
    user, = server["users"]
    stream = outbound.get("streamSettings", {})
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    node = {"name": name, "type": "vless", "server": server["address"],
            "port": int(server["port"]), "uuid": user["id"], "udp": True}
    if engine == "xray":
        if set(outbound) - {"tag", "protocol", "settings", "streamSettings", "mux", "sendThrough"}:
            raise ValueError("Xray outbound содержит параметры, требующие отдельной поддержки.")
        if stream.get("sockopt", {}).get("dialerProxy") or outbound.get("proxySettings"):
            raise ValueError("Цепочки Xray outbound пока не поддерживаются.")
        node["xray_outbound"] = copy.deepcopy(outbound)
        return node
    if (network not in ("tcp", "raw") or security not in ("none", "reality", "tls")
            or user.get("encryption", "none") != "none"
            or set(user) - {"id", "encryption", "flow", "level", "email"}
            or set(outbound) - {"tag", "protocol", "settings", "streamSettings"}
            or set(settings) - {"vnext"} or set(server) - {"address", "port", "users"}
            or set(stream) - {"network", "security", "tcpSettings", "rawSettings", "realitySettings", "tlsSettings"}
            or stream.get("tcpSettings") or stream.get("rawSettings")):
        raise ValueError("Этот профиль Xray требует движок Xray.")
    node["network"] = "tcp"
    if user.get("flow"):
        node["flow"] = user["flow"]
    if security != "none":
        opts = stream.get(security + "Settings", {})
        allowed = {"serverName", "fingerprint", "publicKey", "password", "shortId"} if security == "reality" else {"serverName", "fingerprint", "allowInsecure"}
        if set(opts) - allowed:
            raise ValueError("Дополнительные параметры TLS/REALITY требуют Xray.")
        node["tls"] = True
        if opts.get("serverName"):
            node["servername"] = opts["serverName"]
        if opts.get("fingerprint"):
            node["client-fingerprint"] = opts["fingerprint"]
        if security == "reality":
            node["reality-opts"] = {"public-key": opts.get("password") or opts["publicKey"],
                                    "short-id": opts.get("shortId", "")}
            if os.environ.get("MIHOMO_REALITY_COMPAT") == "1":
                node["reality-opts"]["support-x25519mlkem768"] = True
            if engine == "mihomo" and (client_version := manager.reality_client_version()):
                node["reality-opts"]["client-version"] = client_version
        elif opts.get("allowInsecure"):
            node["skip-cert-verify"] = True
    return node


def parse_response(text, engine):
    if re.fullmatch(r"[A-Za-z0-9+/_=\s-]+", text):
        compact = "".join(text.split())
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                       altchars=b"-_", validate=True).decode("utf-8-sig")
            if decoded.lstrip().startswith(("{", "[")) or "://" in decoded:
                text = decoded
        except ValueError:
            pass
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    profiles = data if isinstance(data, list) else [data]
    nodes = []
    try:
        if any(isinstance(p, dict) and "outbounds" in p for p in profiles):
            for profile in profiles:
                for outbound in profile["outbounds"]:
                    protocol = outbound["protocol"]
                    if protocol in ("freedom", "blackhole", "dns"):
                        continue
                    if protocol != "vless":
                        raise ValueError("Из Xray JSON сейчас поддерживаются VLESS outbounds.")
                    name = profile.get("remarks") or outbound.get("tag") or "VLESS"
                    nodes.append(xray_vless(outbound, name, engine))
        else:
            nodes = parse(text, max_nodes=200)
    except (TypeError, KeyError, ValueError, AttributeError, OverflowError):
        raise ValueError("Ответ подписки не поддерживается выбранным движком или имеет неверный формат.") from None
    if not 1 <= len(nodes) <= 200:
        raise ValueError("Подписка должна содержать от 1 до 200 узлов.")
    for node in nodes:
        if (node.get("server") in ("0.0.0.0", "::")
                or node.get("uuid") == "00000000-0000-0000-0000-000000000000"):
            raise ValueError("Источник вернул заглушку вместо списка узлов.")
    return nodes


def normalized_server(value):
    server = str(value).strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(server.removeprefix("[").removesuffix("]")))
    except ValueError:
        return server


def identity(node):
    """Compare the imported connection independently of its display label."""
    profile = copy.deepcopy(node)
    profile.pop("name", None)
    profile["type"] = profile["type"].lower()
    profile["server"] = normalized_server(profile["server"])
    profile["port"] = int(profile["port"])
    # This local compatibility flag is absent from Xray subscriptions. Its
    # introduction must update an existing node instead of replacing it.
    if isinstance(profile.get("reality-opts"), dict):
        profile["reality-opts"].pop("support-x25519mlkem768", None)
        profile["reality-opts"].pop("client-version", None)
    if "uuid" in profile:
        try:
            profile["uuid"] = str(uuid.UUID(profile["uuid"]))
        except ValueError:
            pass
    if outbound := profile.get("xray_outbound"):
        # The managed client replaces the outbound tag with its own unique tag.
        outbound.pop("tag", None)
        for endpoint in outbound["settings"]["vnext"]:
            endpoint["address"] = normalized_server(endpoint["address"])
            endpoint["port"] = int(endpoint["port"])
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def refresh(subscription_id, name=None, url=None, engine=None, profile=None):
    with clients.LOCK:
        old = manager.read()
        new = copy.deepcopy(old)
        subscriptions = new.setdefault("subscriptions", {})
        if name is None:
            sub = subscriptions.get(subscription_id)
            if sub is None:
                raise ValueError("Подписка не найдена.")
        else:
            if not name.strip() or len(name) > 80 or profile not in PROFILES or engine not in clients.NAMES:
                raise ValueError("Проверьте имя, движок и профиль запроса.")
            if any(item["url"] == url for item in subscriptions.values()):
                raise ValueError("Этот URL уже добавлен. Используйте обновление подписки.")
            sub = {"name": name.strip(), "url": url, "engine": engine, "profile": profile}
        engine = sub["engine"]
        if not clients.binary(engine):
            raise ValueError("Выбранный движок не установлен.")
        source, usage = fetch(sub["url"], sub["profile"])
        incoming = parse_response(source, engine)
        previous_nodes = [n for n in new["nodes"] if n.get("subscription") == subscription_id]
        existing = {}
        for node in sorted(previous_nodes, key=lambda n: (bool(n.get("stale")), not n.get("balance", False))):
            existing.setdefault(identity(clients.canonical(node)), node)
        used = {n["proxy"]["name"] for n in new["nodes"]} | {
            "DIRECT", "REJECT", "GLOBAL", "SELECTOR", "LOADBALANCE", "TRANSIT", "PASS", "COMPATIBLE",
        }
        seen = set()
        retained = set()
        configs = {}
        for source in incoming:
            key = identity(source)
            if key in seen:
                continue
            seen.add(key)
            node = existing.get(key)
            if node is not None:
                retained.add(node["proxy"]["name"])
                node_engine = clients.current(node)
            else:
                normalized = unique({**source, "name": sub["name"] + "-" + source["name"]}, used)
                node = {"proxy": normalized, "balance": False, "subscription": subscription_id,
                        "source_key": key}
                new["nodes"].append(node)
                node_engine = engine
            canonical = {**source, "name": node["proxy"]["name"]}
            node.update(connection=canonical, client=node_engine, source_key=key)
            node.pop("stale", None)
            if node_engine == "mihomo":
                node["proxy"] = clients.convert(clients.effective_profile(node), node_engine)
            else:
                path, cfg, port = clients.build_external(node, node_engine, cfg=configs.get(node_engine, (None, None))[1])
                configs[node_engine] = (path, cfg)
                node.setdefault("client_ports", {})[node_engine] = port
                node["proxy"] = {"name": canonical["name"], "type": "socks5",
                                 "server": "127.0.0.1", "port": port, "udp": canonical.get("udp", True)}
        removed = {n["proxy"]["name"] for n in previous_nodes} - retained
        if removed:
            new["nodes"] = [n for n in new["nodes"] if n["proxy"]["name"] not in removed]
            for name in removed:
                new.get("balance_overrides", {}).pop(name, None)
            for node_engine, path in (("sing-box", clients.SB), ("xray", clients.XR)):
                if node_engine in configs:
                    _, cfg = configs[node_engine]
                elif path.exists():
                    cfg = json.loads(path.read_bytes())
                else:
                    continue
                cleaned = clients.without_bridges(node_engine, cfg, removed)
                if cleaned != cfg and cleaned.get("inbounds"):
                    configs[node_engine] = (path, cleaned)
        sub["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        sub["usage"] = usage
        subscriptions[subscription_id] = sub
        for node_engine, (_, cfg) in configs.items():
            clients.validate(node_engine, cfg)
        clients.validate("mihomo", {"proxies": [n["proxy"] for n in new["nodes"]], "rules": ["MATCH,DIRECT"]})
        applied = []
        try:
            for node_engine, (path, cfg) in configs.items():
                previous = path.read_bytes() if path.exists() else None
                if previous and json.loads(previous) == cfg:
                    continue
                applied.append((node_engine, path, previous))
                write(path, json.dumps(cfg).encode(), 0o600)
                if node_engine != "sing-box" or not clients.reload_sb():
                    clients.ensure_runtime(node_engine, force=True)
            manager.save(new)
            if old["nodes"] != new["nodes"]:
                manager.sync()
        except Exception:
            for _, path, previous in reversed(applied):
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    write(path, previous, 0o600)
            manager.save(old)
            for node_engine, _, _ in applied:
                if node_engine != "sing-box" or not clients.reload_sb():
                    clients.ensure_runtime(node_engine)
            manager.sync()
            raise ValueError("Не удалось применить обновление подписки.") from None
        return f"Подписка обновлена. Уникальных узлов: {len(seen)}. Удалено устаревших или повторных записей: {len(removed)}. Дублей в ответе пропущено: {len(incoming) - len(seen)}."


def handle(action, data):
    def field(name, default=""):
        return data.get(name, [default])[0].strip()
    if action == "subscription_add":
        return refresh(uuid.uuid4().hex, field("name"), field("url"), field("client"), field("profile"))
    if action == "subscription_refresh":
        return refresh(field("subscription"))
    if action == "subscription_automation":
        sid = field("subscription")
        limits = {"refresh": (5, 10080), "target": (1, 32), "grace": (1, 1440)}
        settings = {"enabled": field("enabled") == "1"}
        for key, (minimum, maximum) in limits.items():
            try:
                value = int(field(key))
            except ValueError:
                value = 0
            if not minimum <= value <= maximum:
                raise ValueError("Проверьте диапазоны настроек автобалансировки.")
            settings[key] = value
        with clients.LOCK:
            db = manager.read()
            sub = db.get("subscriptions", {}).get(sid)
            if sub is None:
                raise ValueError("Подписка не найдена.")
            sub["automation"] = settings
            manager.put(manager.DB, db)
        return "Настройки автобалансировки сохранены."
    if action == "subscription_delete":
        with clients.LOCK:
            count = manager.delete_many(subscription=field("subscription"))
        return f"Подписка удалена. Удалено соединений: {count}."
    raise ValueError("Неизвестное действие подписки.")


def navigation(subscriptions):
    return ('<nav class="unified-tabs vpn-subnav" aria-label="VPN">'
            f'<a href="/?tab=vpn" {"class=active aria-current=page" if not subscriptions else ""}>{_ui("Соединения")}</a>'
            f'<a href="/?tab=vpn&amp;view=subscriptions" {"class=active aria-current=page" if subscriptions else ""}>{_ui("Подписки")}</a>'
            '</nav><style>body .unified-main .unified-tabs.vpn-subnav{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}'
            '.vpn-subnav a{text-align:center}'
            '</style>')


def render():
    escape = html.escape
    db = manager.read()
    options = "".join(f'<option value="{key}" {"selected" if key == "xray" else ""}>{label}</option>' for key, label in clients.NAMES.items()
                      if clients.binary(key))
    profiles = "".join(f'<option value="{key}">{_ui(label)}</option>' for key, label in PROFILES.items())
    parts = [
             ''.join((_ui('<details class="vpn-subscription-add"><summary>Добавить подписку</summary><form class="vpn-subscription-form" method="post" action="/action"><input type="hidden" name="action" value="subscription_add"><label>Имя<input name="name" maxlength="80" required></label><label>HTTPS-адрес<input name="url" type="password" autocomplete="off" required></label><label>Движок<select name="client">'), f'{options}', _ui('</select></label><label>Профиль запроса<select name="profile">'), f'{profiles}', _ui('</select></label><button type="submit">Добавить подписку</button></form></details>')))]
    groups = {}
    for sid, sub in db.get("subscriptions", {}).items():
        auto = sub.get("automation", {})
        auto_enabled = bool(auto.get("enabled"))
        toggle_on = escape(_ui("Включено"), quote=True)
        toggle_off = escape(_ui("Отключено"), quote=True)
        controls = (
            ''.join(('<details class="vpn-auto" data-vpn-auto="', f'{escape(sid)}', _ui('"><summary>Автобалансировка</summary><form class="vpn-subscription-form" method="post" action="/action"><input type="hidden" name="action" value="subscription_automation"><input type="hidden" name="subscription" value="'), f'{escape(sid)}', '"><input type="hidden" name="enabled" value="', '1' if auto_enabled else '0', _ui('"><label>Обновлять каждые, мин<input type="number" name="refresh" min="5" max="10080" value="'), f"{escape(str(auto.get('refresh', 60)))}", _ui('" required></label><label>Серверов в балансе<input type="number" name="target" min="1" max="32" value="'), f"{escape(str(auto.get('target', 3)))}", _ui('" required></label><label>Исключать через, мин<input type="number" name="grace" min="1" max="1440" value="'), f"{escape(str(auto.get('grace', 5)))}", _ui('" required></label><button type="button" class="vpn-auto-toggle" data-toggle-on="'), '1' if auto_enabled else '0', '" data-label-on="', toggle_on, '" data-label-off="', toggle_off, '" aria-pressed="', 'true' if auto_enabled else 'false', '" onclick="const field=this.form.elements.enabled;field.value=field.value===\'1\'?\'0\':\'1\';this.dataset.toggleOn=field.value;this.setAttribute(\'aria-pressed\',String(field.value===\'1\'));this.textContent=field.value===\'1\'?this.dataset.labelOn:this.dataset.labelOff">', toggle_on if auto_enabled else toggle_off, _ui('</button><button type="submit">Сохранить</button></form></details>')))
        )
        groups[sid] = (sub["name"],
                     f'<small class="vpn-group-meta">{escape(clients.NAMES[sub["engine"]])} · {escape(_ui(PROFILES[sub["profile"]]))}'
                     f' · {escape(sub.get("updated", "—"))}</small>{usage_html(sub.get("usage"))}',
                     ''.join(('<form method="post" action="/action"><input type="hidden" name="action" value="subscription_refresh"><input type="hidden" name="subscription" value="', f'{escape(sid)}', _ui('"><button type="submit">Обновить подписку</button></form>'))),
                     ''.join((_ui('<form class="vpn-group-delete" method="post" action="/action" onsubmit="return confirm(\'Удалить подписку и все её соединения?\')"><input type="hidden" name="action" value="subscription_delete"><input type="hidden" name="subscription" value="'), f'{escape(sid)}', _ui('"><button type="submit">Удалить</button></form>'))), controls)
    return manager.render(navigation(True), subscription_controls="".join(parts), subscription_groups=groups)
