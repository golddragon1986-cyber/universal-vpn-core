"""Bounded, volatile Mihomo log feed; no extra daemon or disk log files."""
import collections
import http.client
import json
import re
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen
from durable_io import write

API = 'http://127.0.0.1:9090'
SETTINGS = Path('/etc/mihomo/rules/log-settings.json')
LEVELS = ('silent', 'error', 'warning', 'info', 'debug')
ROWS = collections.deque(maxlen=512)
LOCK = threading.Lock()
NEXT_ID = 0
STATUS = 'Подключение к ядру'
PROXIES = {}
STARTED = False
RECORD_LEVEL = 'warning'


def api(path, data=None, method=None):
    request = Request(API + path, data=None if data is None else json.dumps(data).encode(),
                      headers={'Content-Type': 'application/json'}, method=method)
    with urlopen(request, timeout=5) as response:
        body = response.read()
        return json.loads(body) if body else {}


def saved_level():
    if SETTINGS.exists():
        level = json.loads(SETTINGS.read_text()).get('level')
        if level in LEVELS:
            return level
    return None


def restore_level():
    global RECORD_LEVEL
    level = saved_level()
    if level:
        api('/configs', {'log-level': level}, 'PATCH')
        RECORD_LEVEL = level


def set_level(level):
    global RECORD_LEVEL
    if level not in LEVELS:
        raise ValueError('Неизвестный уровень логов')
    old = api('/configs')['log-level']
    api('/configs', {'log-level': level}, 'PATCH')
    try:
        write(SETTINGS, (json.dumps({'level': level}) + '\n').encode())
        RECORD_LEVEL = level
    except Exception:
        api('/configs', {'log-level': old}, 'PATCH')
        raise


def classify(message, proxies):
    # Only attribute explicitly recorded outbound chains, not arbitrary text matches.
    match = re.search(r'\busing\s+(.+?)\s*$', message)
    if not match:
        match = re.search(r'\bdial\s+(\S+)\s+\(match\b', message)
    if not match:
        return [], []
    chain = re.split(r'[\[\]]', match.group(1))
    names = [name.strip() for name in chain if name.strip() in proxies]
    return names, sorted({str(proxies[name].get('type', 'Unknown')) for name in names})


def append(item):
    global NEXT_ID
    level = str(item.get('type', item.get('level', 'info'))).lower()
    # API subscribers can receive messages below the console threshold.
    if RECORD_LEVEL == 'silent' or level not in LEVELS or LEVELS.index(level) > LEVELS.index(RECORD_LEVEL):
        return
    message = str(item.get('payload', item.get('message', '')))[:2048]
    with LOCK:
        names, protocols = classify(message, PROXIES)
        NEXT_ID += 1
        ROWS.append({'id': NEXT_ID, 'time': time.strftime('%H:%M:%S'), 'level': level,
                     'message': message, 'vpns': names, 'protocols': protocols})


def collect():
    global STATUS, PROXIES
    while True:
        connection = None
        try:
            proxies = api('/proxies').get('proxies', {})
            with LOCK:
                PROXIES = proxies
            # HTTP NDJSON is supported by Mihomo; the core log-level remains authoritative.
            connection = http.client.HTTPConnection('127.0.0.1',9090,timeout=5)
            connection.request('GET','/logs?level=debug')
            # An idle stream is healthy. Do not reconnect and lose events during quiet periods.
            connection.sock.settimeout(None)
            with connection.getresponse() as stream:
                if stream.status != 200:
                    raise RuntimeError('Log stream unavailable')
                STATUS = 'Подключено'
                while True:
                    line = stream.readline(65536)
                    if not line:
                        break
                    if len(line) >= 65536:
                        raise ValueError('Слишком длинная запись')
                    append(json.loads(line))
        except Exception:
            STATUS = 'Переподключение к ядру'
            time.sleep(2)
        finally:
            if connection:
                connection.close()


def start():
    global STARTED
    if not STARTED:
        STARTED = True
        restore_level()
        threading.Thread(target=collect, name='core-logs', daemon=True).start()


def snapshot(after=0):
    # Refresh names when profiles are added without a core restart.
    global PROXIES, RECORD_LEVEL
    proxies = api('/proxies').get('proxies', {})
    level = api('/configs').get('log-level', 'warning')
    if level in LEVELS:
        RECORD_LEVEL = level
    with LOCK:
        PROXIES = proxies
        rows = [row for row in ROWS if row['id'] > after][:256]
        return {'rows': rows, 'cursor': rows[-1]['id'] if rows else NEXT_ID,
                'first': ROWS[0]['id'] if ROWS else NEXT_ID, 'status': STATUS,
                'level': level, 'vpns': sorted(proxies),
                'protocols': sorted({str(p.get('type', 'Unknown')) for p in proxies.values()})}


def render():
    fragment = Path(__file__).with_name('logs_ui.html').read_text(encoding='utf-8')
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Логи</title><style></style></head><body>' + fragment + '</body></html>')
