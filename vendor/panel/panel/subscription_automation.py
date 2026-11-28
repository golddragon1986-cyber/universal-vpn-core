"""Periodically refresh subscriptions and maintain their LOADBALANCE membership."""

import concurrent.futures
import hashlib
import json
import time
from datetime import datetime, timezone
from urllib.request import urlopen
from urllib.parse import urlencode

import proxy_manager as manager
import vpn_clients as clients
import vpn_subscriptions as subscriptions


CHECK_INTERVAL = 30
INFO_INTERVAL = 300
CANDIDATE_BATCH = 8


def snapshot(db, sid):
    sub = db.get("subscriptions", {}).get(sid, {})
    settings = sub.get("automation", {})
    nodes = [node for node in db["nodes"] if node.get("subscription") == sid]
    return sub, settings, nodes


def signature(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def refresh_due(sub, settings):
    try:
        updated = datetime.strptime(sub["updated"], "%Y-%m-%d %H:%M UTC")
        age = time.time() - updated.replace(tzinfo=timezone.utc).timestamp()
        return age >= settings["refresh"] * 60
    except (KeyError, ValueError):
        return True


def info_due(sub):
    try:
        updated = datetime.strptime(sub["usage_updated"], "%Y-%m-%d %H:%M UTC")
        return time.time() - updated.replace(tzinfo=timezone.utc).timestamp() >= INFO_INTERVAL
    except (KeyError, ValueError):
        return True


def has_enabled_node(db, nodes):
    overrides = db.get("balance_overrides", {})
    return any(not node.get("stale") and overrides.get(node["proxy"]["name"], node.get("balance", True))
               for node in nodes)


def apply(task):
    sid = task["subscription"]
    with clients.LOCK:
        db = manager.read()
        sub, settings, nodes = snapshot(db, sid)
        if not settings.get("enabled") or settings != task["settings"]:
            return "Настройки изменились, автоматическое действие пропущено."
        if task["operation"] == "refresh":
            if refresh_due(sub, settings):
                return subscriptions.refresh(sid)
            return "Подписка уже обновлена."
        if time.time() - task["checked_at"] > 2 * CHECK_INTERVAL or signature(nodes) != task["signature"]:
            return "Состав подписки изменился или результаты проверки устарели."
        enabled, disabled = set(task["enable"]), set(task["disable"])
        changes = {
            node["proxy"]["name"]: name in enabled
            for node in nodes
            if (name := node["proxy"]["name"]) in enabled | disabled
        }
        old = json.loads(json.dumps(db))
        for node in nodes:
            name = node["proxy"]["name"]
            if name in changes:
                node["balance"] = changes[name]
                db.get("balance_overrides", {}).pop(name, None)
        try:
            manager.put(manager.DB, db)
            manager.sync()
        except Exception:
            manager.put(manager.DB, old)
            manager.sync()
            raise
        return f"В баланс добавлено: {len(enabled)}. Исключено: {len(disabled)}."


def probe(name):
    try:
        delay = manager.delay(name, expected=204)
        return delay if type(delay) in (float, int) and delay > 0 else None
    except (OSError, ValueError):
        return None


def core_ready():
    with urlopen(manager.API + "/version", timeout=3) as response:
        return response.status == 200


def check(pool, settings, nodes, state):
    if not nodes or not core_ready():
        return None
    failures = state.setdefault("failures", {})
    active = [node for node in nodes if node.get("balance")]
    active_keys = {signature(node) for node in active}
    state["failures"] = failures = {key: since for key, since in failures.items() if key in active_keys}
    names = [node["proxy"]["name"] for node in active]
    results = dict(zip(names, pool.map(probe, names)))
    if not core_ready():
        return None
    now = time.monotonic()
    expired = set()
    for node in active:
        key = signature(node)
        name = node["proxy"]["name"]
        if results[name] is not None:
            failures.pop(key, None)
        elif now - failures.setdefault(key, now) >= settings["grace"] * 60:
            expired.add(name)
    eligible = [name for name in names if name not in expired]
    eligible.sort(key=lambda name: results[name] is None)
    target = settings["target"]
    disable = expired | set(eligible[target:])
    slots = target - min(target, len(eligible))
    enable = []
    if slots:
        candidates = [node["proxy"]["name"] for node in nodes
                      if not node.get("balance") and not node.get("stale") and not node.get("replacement_for")]
        if candidates:
            start = state.get("cursor", 0) % len(candidates)
            batch = (candidates[start:] + candidates[:start])[:CANDIDATE_BATCH]
            state["cursor"] = start + len(batch)
            passing = [(delay, name) for name, delay in zip(batch, pool.map(probe, batch)) if delay is not None]
            enable = [name for _, name in sorted(passing)[:slots]]
    if enable or disable:
        return {"operation": "balance", "enable": enable, "disable": sorted(disable),
                "signature": signature(nodes), "checked_at": time.time()}
    return None


def watch(queue):
    states = {}
    info_states = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        while not queue.stop.is_set():
            try:
                db = manager.read()
                configured = db.get("subscriptions", {})
                states = {sid: state for sid, state in states.items()
                          if configured.get(sid, {}).get("automation", {}).get("enabled")}
                info_states = {sid: state for sid, state in info_states.items() if sid in configured}
                for sid in configured:
                    sub, settings, nodes = snapshot(db, sid)
                    if has_enabled_node(db, nodes):
                        info = info_states.setdefault(sid, {})
                        if job := info.get("job"):
                            with queue.db() as conn:
                                row = conn.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()
                            busy = bool(row and row["status"] in ("queued", "running"))
                            if not busy:
                                info.pop("job", None)
                        else:
                            busy = False
                        now = time.monotonic()
                        if not busy and now >= info.get("next_try", 0) and info_due(sub):
                            info["next_try"] = now + INFO_INTERVAL
                            info["job"] = queue.submit("Обновление данных подписки",
                                {"path": "/action", "body": urlencode({
                                    "action": "subscription_info_refresh", "subscription": sid})})
                    if not settings.get("enabled"):
                        continue
                    state = states.setdefault(sid, {})
                    if job := state.get("job"):
                        with queue.db() as conn:
                            row = conn.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()
                        if row and row["status"] in ("queued", "running"):
                            continue
                        state.pop("job", None)
                    now = time.monotonic()
                    refresh = now >= state.get("next_refresh", 0) and refresh_due(sub, settings)
                    if refresh:
                        state["next_refresh"] = now + min(300, settings["refresh"] * 60)
                        task = {"operation": "refresh"}
                    else:
                        try:
                            task = check(pool, settings, nodes, state)
                        except OSError:
                            state.pop("failures", None)
                            continue
                    if task:
                        task.update(subscription=sid, settings=settings)
                        label = ("Автообновление подписки" if refresh else "Автобалансировка подписки")
                        state["job"] = queue.submit(label, {"path": "/action", "body": "",
                                                            "subscription_automation": task})
            except Exception as error:
                print("Subscription automation:", type(error).__name__, flush=True)
            queue.stop.wait(CHECK_INTERVAL)
