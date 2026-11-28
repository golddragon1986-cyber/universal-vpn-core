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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo

import proxy_manager as manager
import vpn_clients as clients
from durable_io import write
from vpn_import import parse, unique

HAPP_UA = "Happ/4.1.1/Windows/2608211947607"
PROFILES = {"standard": "Обычный", "happ": "Happ", "happ-hwid": "Happ + HWID"}
HWID = Path("/etc/mihomo/.subscription-hwid")
MAX_BYTES = 2 * 1024 * 1024
DEFAULT_USAGE_INTERVAL = 5
MAX_USAGE_INTERVAL = 10080


def usage_interval(sub):
    return sub.get("usage_interval", DEFAULT_USAGE_INTERVAL)


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
        return f'<span class="vpn-subscription-usage" data-vpn-usage>{html.escape(_ui("Лимит и срок: провайдер не сообщил"))}</span>'
    parts = []
    summary = []
    upload, download, total, expiry = (usage.get(key) for key in ("upload", "download", "total", "expire"))
    if isinstance(upload, int) and isinstance(download, int):
        used = upload + download
        parts.append(f'{_ui("Использовано")} {format_bytes(used)}')
        if isinstance(total, int):
            parts[-1] += f' / {format_bytes(total)}' if total else f' · {_ui("без лимита")}'
            if total:
                parts.append(f'{_ui("Осталось")} {format_bytes(max(0, total - used))}')
                summary.append(f'{_ui("Осталось")} {format_bytes(max(0, total - used))} / {format_bytes(total)}')
            else:
                summary.append(f'{format_bytes(used)} · {_ui("без лимита")}')
        else:
            summary.append(parts[-1])
        parts.append(f'↓ {format_bytes(download)} / ↑ {format_bytes(upload)}')
    elif isinstance(total, int):
        parts.append(f'{_ui("Лимит")} {format_bytes(total)}' if total else _ui("Без лимита трафика"))
        summary.append(parts[-1])
    if isinstance(expiry, int):
        if expiry == 0:
            parts.append(_ui("Без срока действия"))
            summary.append(_ui("Без срока действия"))
        else:
            try:
                date = datetime.fromtimestamp(expiry, ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M MSK")
                parts.append(f'{_ui("Срок до")} {date}')
                summary.append(f'{_ui("Срок до")} {date[:10]}')
            except (OverflowError, OSError, ValueError):
                pass
    if not parts:
        parts.append(_ui("Лимит и срок: провайдер не сообщил"))
    if not summary:
        summary = parts
    return ('<span class="vpn-subscription-usage" data-vpn-usage title="'
            + html.escape(" · ".join(parts), quote=True) + '">'
            + html.escape(" · ".join(summary)) + '</span>')


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


def source_label(name):
    return re.sub(r"(?i)[\s_-]+\d+(?:[.,]\d+)?\s*[KMGT]i?B[\s_-]+\d+\s*D$", "", name).strip() or name


def pinned_channels(names):
    import router_routes
    targets = {"CHANNEL-" + re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-"): name
               for name in names}
    targets.update({name: name for name in names})
    pinned = {name for _, name in manager.client_route_references(names)}

    def collect(value):
        if isinstance(value, str) and value in targets:
            pinned.add(targets[value])
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)

    for filename in ("routing-settings.json", "service-routes.json", "route-targets.json", "dns-settings.json"):
        path = router_routes.ROOT / "rules" / filename
        if path.is_file():
            collect(json.loads(path.read_bytes()))
    return pinned


def replacement_ready(node):
    try:
        delay = manager.delay(node["proxy"]["name"], expected=204)
        return type(delay) in (int, float) and delay > 0
    except (OSError, ValueError):
        return False


def refresh(subscription_id, name=None, url=None, engine=None, profile=None, *, _fetched=None):
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
        if _fetched is None:
            source, usage = fetch(sub["url"], sub["profile"])
            incoming = parse_response(source, engine)
        else:
            incoming, usage = _fetched
        previous_nodes = [n for n in new["nodes"] if n.get("subscription") == subscription_id]
        unique_sources = {}
        for source in incoming:
            unique_sources.setdefault(identity(source), source)
        incoming_keys = unique_sources.keys()
        labels = Counter(source_label(node["name"]).casefold() for node in unique_sources.values())
        previous_names = {node["proxy"]["name"] for node in previous_nodes}
        pinned = pinned_channels(previous_names)
        overrides = new.get("balance_overrides", {})
        protected = pinned | {node["proxy"]["name"] for node in previous_nodes
                              if overrides.get(node["proxy"]["name"], node.get("balance", False))}
        missing_by_label = {}
        existing = {}
        for node in sorted(previous_nodes, key=lambda n: (bool(n.get("stale")), not n.get("balance", False))):
            key = node.get("source_key") or identity(clients.canonical(node))
            existing.setdefault(key, node)
            if key not in incoming_keys and not node.get("replacement_for"):
                label = node.get("source_label") or source_label(
                    node["proxy"]["name"].removeprefix(sub.get("original_name", sub["name"]) + "-"))
                missing_by_label.setdefault(label.casefold(), []).append(node)
        used = {n["proxy"]["name"] for n in new["nodes"]} | {
            "DIRECT", "REJECT", "GLOBAL", "SELECTOR", "LOADBALANCE", "TRANSIT", "PASS", "COMPATIBLE",
        }
        retained = set()
        configs = {}
        staged_replacement = False
        for key, source in unique_sources.items():
            node = existing.get(key)
            label = source_label(source["name"])
            matches = missing_by_label.get(label.casefold(), [])
            predecessor = matches[0] if len(matches) == 1 and labels[label.casefold()] == 1 else None
            if labels[label.casefold()] == 1 and source.get("uuid"):
                base = sub.get("original_name", sub["name"]) + "-" + label
                same_endpoint = []
                for previous in previous_nodes:
                    previous_name = previous["proxy"]["name"]
                    if (previous.get("replacement_for")
                            or (previous.get("source_key") or identity(clients.canonical(previous))) in incoming_keys):
                        continue
                    if not re.fullmatch(re.escape(base) + r"(?:-\d+)?", previous_name, re.IGNORECASE):
                        continue
                    profile = clients.canonical(previous)
                    if (normalized_server(profile["server"]) == normalized_server(source["server"])
                            and int(profile["port"]) == int(source["port"])
                            and str(profile.get("uuid", "")).lower() == str(source["uuid"]).lower()):
                        same_endpoint.append(previous)
                if len(same_endpoint) == 1:
                    predecessor = same_endpoint[0]
            if node is not None and predecessor is None:
                node.pop("replacement_for", None)
            if predecessor is not None:
                previous_name = predecessor["proxy"]["name"]
                if (node is not None and node.get("replacement_for")
                        and node["proxy"]["name"] not in protected):
                    node["replacement_for"] = previous_name
                if node is None and previous_name not in protected:
                    node = predecessor
                elif (node is not None and node.get("replacement_for") == previous_name
                      and node["proxy"]["name"] not in protected
                      and clients.current(node) == clients.current(predecessor)
                      and node.get("tls_fingerprint") == predecessor.get("tls_fingerprint")
                      and identity(clients.canonical(node)) == key
                      and replacement_ready(node)):
                    node = predecessor
            if node is not None:
                retained.add(node["proxy"]["name"])
                node_engine = clients.current(node)
                if node.get("source_key") == key:
                    node["source_label"] = label
                    node.pop("stale", None)
                    continue
            else:
                normalized = unique({**source, "name": sub["name"] + "-" + label}, used)
                node = {"proxy": normalized, "balance": False, "subscription": subscription_id,
                        "source_key": key}
                if predecessor is not None:
                    node["replacement_for"] = predecessor["proxy"]["name"]
                    if fingerprint := predecessor.get("tls_fingerprint"):
                        node["tls_fingerprint"] = fingerprint
                    staged_replacement = True
                new["nodes"].append(node)
                node_engine = clients.current(predecessor) if predecessor is not None else engine
            canonical = {**source, "name": node["proxy"]["name"]}
            node.update(connection=canonical, client=node_engine, source_key=key, source_label=label)
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
        referenced = removed & protected
        for node in previous_nodes:
            if node["proxy"]["name"] in referenced:
                node["stale"] = True
        removed -= referenced
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
        sub["usage_updated"] = sub["updated"]
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
        if staged_replacement and _fetched is None:
            try:
                return refresh(subscription_id, _fetched=(incoming, usage))
            except (OSError, ValueError):
                pass  # The first pass has already saved the working channels and inactive candidates.
        pending = sum(bool(node.get("replacement_for")) for node in new["nodes"]
                      if node.get("subscription") == subscription_id)
        return (f"Подписка обновлена. Уникальных узлов: {len(unique_sources)}. "
                f"Удалено записей: {len(removed)}. Дублей в ответе пропущено: {len(incoming) - len(unique_sources)}. "
                f"Сохранено активных или привязанных каналов: {len(referenced)}. Кандидатов ожидают замены: {pending}.")


def refresh_info(subscription_id, *, automatic=False):
    """Update provider usage without touching nodes, routes, or VPN clients."""
    with clients.LOCK:
        sub = manager.read().get("subscriptions", {}).get(subscription_id)
        if sub is None:
            raise ValueError("Подписка не найдена.")
        if automatic and usage_interval(sub) == 0:
            return "Автообновление данных подписки отключено."
        url, profile = sub["url"], sub["profile"]
    _, usage = fetch(url, profile)
    with clients.LOCK:
        db = manager.read()
        sub = db.get("subscriptions", {}).get(subscription_id)
        if sub is None or (sub["url"], sub["profile"]) != (url, profile):
            raise ValueError("Подписка изменилась во время обновления данных.")
        sub["usage"] = usage
        sub["usage_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        manager.put(manager.DB, db)
    return "Данные подписки обновлены." if usage else "Провайдер не передал лимит и срок действия."


def edit_subscription(sid, name, url, profile, interval=None):
    name, url = name.strip(), url.strip()
    if not name or len(name) > 80 or any(ord(char) < 32 for char in name) or profile not in PROFILES:
        raise ValueError("Проверьте имя и профиль запроса.")
    if interval is not None and (not re.fullmatch(r"[0-9]{1,5}", interval)
                                 or int(interval) > MAX_USAGE_INTERVAL):
        raise ValueError("Интервал обновления данных должен быть от 0 до 10080 минут.")
    with clients.LOCK:
        db = manager.read()
        subscriptions = db.get("subscriptions", {})
        sub = subscriptions.get(sid)
        if sub is None:
            raise ValueError("Подписка не найдена.")
        if url and url != sub["url"]:
            if any(key != sid and item["url"] == url for key, item in subscriptions.items()):
                raise ValueError("Этот URL уже добавлен. Используйте обновление подписки.")
            subscription_target(url)
            sub["url"] = url
            sub.pop("usage", None)
            sub.pop("usage_updated", None)
        sub.setdefault("original_name", sub["name"])
        sub.update(name=name, profile=profile)
        if interval is not None:
            sub["usage_interval"] = int(interval)
        manager.save(db)
    return "Настройки подписки сохранены."


def handle(action, data):
    def field(name, default=""):
        return data.get(name, [default])[0].strip()
    if action == "subscription_add":
        return refresh(uuid.uuid4().hex, field("name"), field("url"), field("client"), field("profile"))
    if action == "subscription_refresh":
        return refresh(field("subscription"))
    if action == "subscription_edit":
        return edit_subscription(field("subscription"), field("name"), field("url"), field("profile"),
                                 field("usage_interval") if "usage_interval" in data else None)
    if action == "subscription_info_refresh":
        return refresh_info(field("subscription"), automatic=field("automatic") == "1")
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


def usage_snapshot():
    return {"subscriptions": {sid: usage_html(sub.get("usage"))
                              for sid, sub in manager.read().get("subscriptions", {}).items()}}


def automation_dialog(sid, sub):
    e = lambda value: html.escape(str(value), quote=True)
    auto = sub.get("automation", {})
    enabled = bool(auto.get("enabled"))
    fields = "".join(
        f'<label>{_ui(label)}<input type="number" name="{key}" min="{minimum}" max="{maximum}" value="{e(auto.get(key, default))}" required></label>'
        for key, label, minimum, maximum, default in (
            ("refresh", "Обновлять каждые, мин", 5, 10080, 60),
            ("target", "Серверов в балансе", 1, 32, 3),
            ("grace", "Исключать через, мин", 1, 1440, 5)))
    return (f'<dialog class="vpn-auto-dialog" id="vpn-auto-{e(sid)}">'
            f'<h2>{_ui("Автобалансировка")}: {e(sub["name"])}</h2>'
            f'<form method="post" action="/action"><input type="hidden" name="action" value="subscription_automation">'
            f'<input type="hidden" name="subscription" value="{e(sid)}">'
            f'<input type="hidden" name="enabled" value="{"1" if enabled else "0"}">'
            f'<div class="vpn-auto-fields">{fields}</div><div class="vpn-auto-actions">'
            f'<button type="button" class="vpn-auto-toggle" data-vpn-auto-toggle data-toggle-on="{"1" if enabled else "0"}" aria-pressed="{str(enabled).lower()}">'
            f'{_ui("Включено" if enabled else "Отключено")}</button>'
            f'<button type="submit">{_ui("Сохранить")}</button>'
            f'<button type="button" data-vpn-auto-close>{_ui("Отмена")}</button>'
            '</div></form></dialog>')


def edit_dialog(sid, sub):
    e = lambda value: html.escape(str(value), quote=True)
    options = "".join(
        f'<option value="{key}" {"selected" if key == sub["profile"] else ""}>{_ui(label)}</option>'
        for key, label in PROFILES.items())
    return (
        f'<dialog class="vpn-auto-dialog" id="vpn-edit-sub-{e(sid)}">'
        f'<h2>{_ui("Редактировать подписку")}</h2>'
        '<form method="post" action="/action"><input type="hidden" name="action" value="subscription_edit">'
        f'<input type="hidden" name="subscription" value="{e(sid)}">'
        f'<div class="vpn-auto-fields"><label>{_ui("Имя")}<input name="name" maxlength="80" value="{e(sub["name"])}" required></label>'
        f'<label>{_ui("Профиль запроса")}<select name="profile">{options}</select></label>'
        f'<label class="vpn-subscription-url">{_ui("HTTPS-адрес")}<input name="url" type="text"'
        f' autocomplete="off" spellcheck="false" maxlength="4096" value="{e(sub["url"])}" required></label>'
        f'<label class="vpn-subscription-url">{_ui("Обновлять трафик и срок, мин (0 — отключено)")}'
        f'<input name="usage_interval" type="number" min="0" max="{MAX_USAGE_INTERVAL}"'
        f' value="{e(usage_interval(sub))}" required></label></div>'
        f'<div class="vpn-auto-actions"><button type="submit">{_ui("Сохранить")}</button>'
        f'<button type="button" data-vpn-auto-close>{_ui("Отмена")}</button></div></form></dialog>')


def render():
    escape = html.escape
    db = manager.read()
    options = "".join(f'<option value="{key}" {"selected" if key == "xray" else ""}>{label}</option>' for key, label in clients.NAMES.items()
                      if clients.binary(key))
    profiles = "".join(f'<option value="{key}">{_ui(label)}</option>' for key, label in PROFILES.items())
    parts = [
             ''.join((_ui('<details class="vpn-subscription-add"><summary>Добавить подписку</summary><form class="vpn-subscription-form" method="post" action="/action"><input type="hidden" name="action" value="subscription_add"><label>Имя<input name="name" maxlength="80" required></label><label>HTTPS-адрес<input name="url" type="password" autocomplete="off" required></label><label>Движок<select name="client">'), f'{options}', _ui('</select></label><label>Профиль запроса<select name="profile">'), f'{profiles}', _ui('</select></label><button type="submit">Добавить подписку</button></form></details>')))]
    groups = {}
    dialogs = []
    for sid, sub in db.get("subscriptions", {}).items():
        dialogs.append(automation_dialog(sid, sub))
        dialogs.append(edit_dialog(sid, sub))
        groups[sid] = (sub["name"],
                     f'<small class="vpn-group-meta" title="{escape(sub.get("updated", "—"), quote=True)}">'
                     f'{escape(clients.NAMES[sub["engine"]])} · {escape(_ui(PROFILES[sub["profile"]]))}</small>'
                     f'{usage_html(sub.get("usage"))}',
                     f'<form method="post" action="/action"><input type="hidden" name="action" value="subscription_refresh">'
                     f'<input type="hidden" name="subscription" value="{escape(sid, quote=True)}">'
                     f'<button type="submit" title="{escape(_ui("Обновить подписку"), quote=True)}">{_ui("Обновить")}</button></form>'
                     f'<button type="button" data-vpn-sub-edit="{escape(sid, quote=True)}">{_ui("Изменить")}</button>'
                     f'<button type="button" data-vpn-auto-open="{escape(sid, quote=True)}" title="{escape(_ui("Автобалансировка"), quote=True)}">{_ui("Балансировка")}</button>',
                     ''.join((_ui('<form class="vpn-group-delete" method="post" action="/action" onsubmit="return confirm(\'Удалить подписку и все её соединения?\')"><input type="hidden" name="action" value="subscription_delete"><input type="hidden" name="subscription" value="'), f'{escape(sid)}', _ui('"><button type="submit">Удалить</button></form>'))), '')
    assets = _ui('''<style>
body .vpn-auto-dialog{width:min(560px,calc(100vw - 36px));max-height:calc(100vh - 40px);overflow:auto;box-sizing:border-box;padding:22px;background:var(--ui-surface,#171e2b);color:var(--ui-text,#f4f7ff);border:1px solid var(--ui-border,#344056);border-radius:12px}
body .vpn-auto-dialog::backdrop{background:rgba(0,0,0,.7)}
body .vpn-auto-dialog h2{margin:0 0 18px;font-size:20px}
body .vpn-auto-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
body .vpn-auto-fields label{display:grid;gap:6px;min-width:0;font-size:14px}
body .vpn-auto-fields :is(input,select){width:100%;height:40px;margin:0}
body .vpn-auto-fields .vpn-subscription-url{grid-column:1/-1}
body .vpn-auto-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:20px}
body .vpn-auto-actions button{min-height:40px;margin:0;padding:8px 12px;white-space:nowrap}
body .vpn-auto-toggle[data-toggle-on="1"]{background:#128038;border-color:#128038;color:#fff;font-weight:700}
body .vpn-auto-toggle[data-toggle-on="0"]{background:#c62828;border-color:#c62828;color:#fff;font-weight:700}
</style><script>
document.addEventListener('click',event=>{
 const edit=event.target.closest('[data-vpn-sub-edit]');
 if(edit){document.getElementById('vpn-edit-sub-'+edit.dataset.vpnSubEdit)?.showModal();return;}
 const open=event.target.closest('[data-vpn-auto-open]');
 if(open){document.getElementById('vpn-auto-'+open.dataset.vpnAutoOpen)?.showModal();return;}
 const close=event.target.closest('[data-vpn-auto-close]');
 if(close){close.closest('dialog')?.close();return;}
 const toggle=event.target.closest('[data-vpn-auto-toggle]');
 if(toggle){const field=toggle.form.elements.enabled;const on=field.value!=='1';field.value=on?'1':'0';toggle.dataset.toggleOn=field.value;toggle.setAttribute('aria-pressed',String(on));toggle.textContent=on?window.uiText('Включено'):window.uiText('Отключено');}
});
document.addEventListener('DOMContentLoaded',()=>{
 let pending=false;
 async function updateSubscriptionUsage(){if(pending)return;pending=true;try{
  const response=await fetch('/api/subscription-usage',{cache:'no-store'});
  if(!response.ok)return;const data=await response.json();
  for(const [sid,markup] of Object.entries(data.subscriptions||{})){
   const group=[...document.querySelectorAll('[data-vpn-group]')].find(item=>item.dataset.vpnGroup===sid);
   const current=group?.querySelector('[data-vpn-usage]');if(!current)continue;
   const template=document.createElement('template');template.innerHTML=markup;
   const next=template.content.firstElementChild;
   if(next?.matches('[data-vpn-usage]')&&next.outerHTML!==current.outerHTML)current.replaceWith(next);
  }
 }catch(error){}finally{pending=false;}}
 const timer=setInterval(updateSubscriptionUsage,30000);
 window.addEventListener('pagehide',()=>clearInterval(timer),{once:true});
});
</script>''')
    return manager.render(navigation(True), subscription_controls="".join(parts), subscription_groups=groups) + ''.join(dialogs) + assets
