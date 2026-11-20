from ui_i18n import text as _ui, message as _ui_message
from durable_io import replace as durable_replace
#!/usr/bin/env python3
import html
from ui_i18n import language_button
import json
import os
import proxy_manager
import subprocess
import tempfile
from urllib.request import Request, urlopen

BASE = "/etc/mihomo/rules"
SETTINGS = os.path.join(BASE, "routing-settings.json")
API = "http://127.0.0.1:9090"
APPLY = os.path.join(BASE, "apply-service-routes.py")


def api_json(path):
    with urlopen(API + path, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def global_info():
    return api_json("/proxies/SELECTOR")


def available_main_routes(info):
    choices = info.get("all", [])
    db = proxy_manager.read()
    managed = {
        item.get("proxy", {}).get("name"): item
        for item in db.get("nodes", [])
        if isinstance(item, dict) and isinstance(item.get("proxy"), dict)
    }
    overrides = db.get("balance_overrides", {})
    available = []
    for name in choices:
        if not isinstance(name, str) or name == "SELECTOR":
            continue
        if name.startswith("CHANNEL-"):
            proxy_name = name[len("CHANNEL-"):]
            enabled = overrides.get(
                proxy_name,
                managed.get(proxy_name, {}).get("balance", True),
            )
            if not bool(enabled):
                continue
        available.append(name)
    return available


def read_settings(current="DIRECT"):
    data = {}
    from configuration_draft import state_path
    path = state_path(SETTINGS)
    if path.is_file():
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise RuntimeError("routing-settings.json must contain an object")
    result = {
        "main_proxy": str(data.get("main_proxy", current)),
        "services_enabled": bool(data.get("services_enabled", True)),
    }
    if "dns_enhanced_mode_before_direct" in data:
        result["dns_enhanced_mode_before_direct"] = str(data["dns_enhanced_mode_before_direct"])
    return result


def resolve_target(target=None):
    """Resolve an inherited route for policies that need its concrete behavior."""
    if target and target != "SELECTOR": return target
    route = read_settings()["main_proxy"]
    if route == "SELECTOR": raise ValueError("Основной маршрут не может ссылаться на себя")
    return route


def write_settings(data):
    fd, temp_path = tempfile.mkstemp(prefix=".routing-settings-", dir=BASE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        durable_replace(temp_path, SETTINGS)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def set_global_proxy(name):
    info = global_info()
    choices = info.get("all", [])
    if name not in choices:
        raise RuntimeError("Unknown SELECTOR route: " + name)

    body = json.dumps({"name": name}).encode("utf-8")
    req = Request(
        API + "/proxies/SELECTOR",
        data=body,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urlopen(req, timeout=10) as response:
        response.read()


def apply_services():
    result = subprocess.run(
        ["python3", APPLY],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        message = (result.stderr or result.stdout or "apply failed").strip()
        raise RuntimeError(message[-1800:])
    return (result.stdout or "Service rules applied").strip()


def render_routing_panel():
    try:
        info = global_info()
        choices = available_main_routes(info)
        current = info.get("now", "DIRECT")
        settings = read_settings(current)

        selected = settings["main_proxy"] if settings["main_proxy"] in choices else "DIRECT"

        labels = {}
        options = []
        for name in choices:
            label = name[len("CHANNEL-"):] if name.startswith("CHANNEL-") else name
            mark = " selected" if name == selected else ""
            current_class = ' class="current-route"' if name == selected else ""
            options.append(
                '<option value="' + html.escape(name, quote=True) + '"' +
                current_class + mark + '>' + html.escape(label) + '</option>'
            )

        services_enabled = bool(settings["services_enabled"])
        error = ""
    except Exception as e:
        options = ['<option value="DIRECT">DIRECT</option>']
        selected = "DIRECT"
        services_enabled = False
        error = '<p class="routing-error">' + html.escape(_ui_message(e)) + '</p>'

    heading = _ui('Основной маршрут')
    button_text = _ui('Применить конфигурацию')
    services_title = _ui('Правила')
    selected_value = html.escape(selected, quote=True)

    if services_enabled:
        service_button = (
            _ui('<button type="submit" name="services_enabled" value="0" class="service-toggle service-on" title="Правила включены — нажмите, чтобы отключить" aria-label="Правила включены, нажмите чтобы отключить">Включено</button>')
        )
    else:
        service_button = (
            _ui('<button type="submit" name="services_enabled" value="1" class="service-toggle service-off" title="Правила отключены — нажмите, чтобы включить" aria-label="Правила отключены, нажмите чтобы включить">Отключено</button>')
        )

    return ''.join(('\n<section class="routing-panel">\n  <div class="routing-grid">\n    <div class="routing-heading">', f'{heading}', '</div>\n    <div class="routing-heading">', f'{services_title}', '</div>\n    <div class="routing-heading"></div>\n\n    <form method="post" action="/" class="routing-controls">\n      <input type="hidden" name="action" value="routing_save">\n      <input type="hidden" name="services_enabled" value="', f"{('1' if services_enabled else '0')}", '">\n      <select id="main_proxy" name="main_proxy">', f"{''.join(options)}", '</select>\n      ', f'{service_button}', '\n      <button type="button" id="configuration-apply" disabled>', f'{button_text}', _ui('</button>\n      <button type="button" id="configuration-cancel" disabled>Отмена</button>\n      <button type="submit" form="core-restart-form">Перезапустить ядро</button>\n      '), f'{language_button()}', '\n      <span id="configuration-message" role="status"></span>\n    </form>\n  </div>\n  <form method="post" class="runtime-action" id="core-restart-form"><input type="hidden" name="action" value="core_restart"></form>\n  ', f'{error}', '\n</section>\n'))

def handle_routing_action(data):
    info = global_info()
    current = info.get("now", "DIRECT")
    old_settings = read_settings(current)
    new_proxy = data.get("main_proxy", [current])[0]
    new_enabled = data.get("services_enabled", ["0"])[-1] == "1"

    choices = available_main_routes(info)
    if new_proxy not in choices:
        raise RuntimeError("Маршрут недоступен: прокси выключен в балансировке или отсутствует")

    new_settings = dict(old_settings)
    new_settings["main_proxy"] = new_proxy
    new_settings["services_enabled"] = new_enabled

    from configuration_draft import staging
    if staging():
        write_settings(new_settings)
        return "Основной маршрут и состояние правил сохранены в черновик"

    existed = os.path.exists(SETTINGS)
    old_file = None
    if existed:
        with open(SETTINGS, "rb") as f:
            old_file = f.read()

    try:
        write_settings(new_settings)
        if new_proxy != current:
            set_global_proxy(new_proxy)
        output = apply_services()
        return "Настройки сохранены. " + output
    except Exception as error:
        try:
            if existed and old_file is not None:
                fd, temp_path = tempfile.mkstemp(
                    prefix=".routing-rollback-", dir=BASE
                )
                with os.fdopen(fd, "wb") as f:
                    f.write(old_file)
                durable_replace(temp_path, SETTINGS)
            elif os.path.exists(SETTINGS):
                os.unlink(SETTINGS)

            now = global_info().get("now", "DIRECT")
            if now != old_settings["main_proxy"]:
                set_global_proxy(old_settings["main_proxy"])
            apply_services()
        except Exception as rollback_error:
            raise RuntimeError(
                str(error) + "; rollback warning: " + str(rollback_error)
            ) from error
        raise RuntimeError("Изменения отменены: " + str(error)) from error


def restore_routing_settings():
    if not os.path.isfile(SETTINGS):
        return
    settings = read_settings()
    set_global_proxy(settings["main_proxy"])
    print("Routing settings restored: " + settings["main_proxy"], flush=True)
    print(apply_services(), flush=True)
