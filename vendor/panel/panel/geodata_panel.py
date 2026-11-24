from ui_i18n import text as _ui
"""Import and manage standalone Mihomo rule sets."""

import hashlib
import html
import json
import io
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from durable_io import sync_dir, write
from vpn_subscriptions import fetch_subscription_response, subscription_target
from storage_space import require


ROOT = Path("/etc/mihomo/rules/geodata")
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
MAX_FILE = 2 * 1024 * 1024
MAX_UPLOAD = 160 * 1024 * 1024
BEHAVIORS = {"domain": "Домены", "ipcidr": "IP-сети"}


def entries():
    index = ROOT / "sources.json"
    return json.loads(index.read_text(encoding="utf-8")) if index.exists() else {}


def save_entries(items):
    ROOT.mkdir(mode=0o700, exist_ok=True)
    write(ROOT / "sources.json", json.dumps(items, ensure_ascii=False).encode())


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def source_url(value):
    url = value.strip()
    try:
        target = urlsplit(url)
        if (target.scheme != "https" or not target.hostname or target.username is not None
                or target.port == 0 or target.fragment or len(url) > 4096
                or any(ord(char) <= 32 or ord(char) == 127 for char in url)):
            raise ValueError
    except ValueError:
        raise ValueError("Укажите корректную HTTPS-ссылку на источник GeoDAT.") from None
    return url


def download(url):
    context = ssl.create_default_context()
    for _ in range(6):
        try:
            target, port, addresses = subscription_target(url)
            status, location, data = fetch_subscription_response(
                target, port, addresses, {"User-Agent": "UvpnC/GeoDAT"}, context)
        except ValueError:
            raise ValueError("Не удалось загрузить файл по публичному HTTPS-адресу.") from None
        if status == 200:
            return data
        if status not in (301, 302, 303, 307, 308) or not location:
            raise ValueError(f"Источник вернул HTTP {status}.")
        url = urljoin(url, location)
    raise ValueError("Слишком много перенаправлений.")


def read_form(content_type, data):
    if content_type.startswith("application/x-www-form-urlencoded"):
        return {name: values[0] for name, values in parse_qs(data.decode("utf-8")).items()}
    if not content_type.startswith("multipart/form-data;"):
        raise ValueError("Неверный формат загрузки.")
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + content_type.encode("ascii") + b"\r\n\r\n" + data)
    if not message.is_multipart() or message.defects:
        raise ValueError("Файл не получен полностью.")
    result = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name not in {"operation", "token", "name", "file"} or name in result or part.is_multipart():
            raise ValueError("Неверные поля загрузки.")
        raw = part.get_payload(decode=True)
        result[name] = raw if name == "file" else raw.decode("utf-8")
    return result


def detect_behavior(data):
    from geodata_service_files import mrs_command

    if not data or len(data) > MAX_FILE:
        raise ValueError("Выберите непустой файл .mrs размером до 2 МиБ.")
    if data[:4] != b"\x28\xb5\x2f\xfd":
        raise ValueError("Файл имеет неверный формат .mrs.")
    require(ROOT,len(data),'Проверка MRS')
    with tempfile.TemporaryDirectory(prefix=".check-", dir=ROOT) as tmp:
        candidate = Path(tmp) / "source.mrs"
        candidate.write_bytes(data)
        for behavior in BEHAVIORS:
            try:
                result = subprocess.run(
                    mrs_command(98304, behavior, "mrs", str(candidate), "/dev/null"),
                    env={**os.environ, "GOGC": "35", "GOMEMLIMIT": "80MiB"},
                    capture_output=True, timeout=15)
            except subprocess.TimeoutExpired:
                raise ValueError("Mihomo не успел проверить файл.") from None
            if result.returncode == 0:
                return behavior
    raise ValueError("Mihomo не прочитал файл .mrs.")


@contextmanager
def read_request(content_type, stream, length):
    """Spool large DAT uploads to disk rather than keeping the database in RAM."""
    if not 0 < length <= MAX_UPLOAD + 16384:raise ValueError('Размер файла должен быть не больше 160 МиБ.')
    if content_type.startswith('application/x-www-form-urlencoded'):
        if length>16384:raise ValueError('Слишком большой запрос GeoDAT.')
        body=stream.read(length)
        if len(body)!=length:raise ValueError('Данные получены не полностью.')
        yield read_form(content_type,body);return
    header=BytesParser(policy=policy.default).parsebytes(b'Content-Type: '+content_type.encode('ascii')+b'\r\n\r\n')
    boundary=header.get_boundary()
    if header.get_content_type()!='multipart/form-data' or not boundary or len(boundary)>70 or any(ord(c)<32 or ord(c)>126 for c in boundary):
        raise ValueError('Неверный формат загрузки.')
    require(ROOT,length*2,'Загрузка файла и подготовка копии')
    marker=b'\r\n--'+boundary.encode('ascii');buffer=b'';remaining=length
    def fill():
        nonlocal buffer,remaining
        data=stream.read(min(65536,remaining)) if remaining else b''
        if not data:raise ValueError('Файл не получен полностью.')
        remaining-=len(data);buffer+=data
    def take(size):
        nonlocal buffer
        while len(buffer)<size:fill()
        result,buffer=buffer[:size],buffer[size:];return result
    def until(delimiter,sink,limit):
        nonlocal buffer
        total=0
        while True:
            index=buffer.find(delimiter)
            count=index if index>=0 else max(0,len(buffer)-len(delimiter)+1)
            total+=count
            if total>limit:raise ValueError('Превышен допустимый размер данных загрузки.')
            if not isinstance(sink,io.BytesIO):require(ROOT,count,'Загрузка файла')
            sink.write(buffer[:count]);buffer=buffer[count:]
            if index>=0:buffer=buffer[len(delimiter):];return
            fill()
    with ExitStack() as stack:
        if take(len(marker))!=marker[2:]+b'\r\n':raise ValueError('Неверная граница загрузки.')
        result={}
        while True:
            raw=io.BytesIO();until(b'\r\n\r\n',raw,8192)
            part=BytesParser(policy=policy.default).parsebytes(raw.getvalue()+b'\r\n\r\n')
            name=part.get_param('name',header='content-disposition')
            if name not in {'operation','token','name','file'} or name in result or part.is_multipart():raise ValueError('Неверные поля загрузки.')
            if name=='file':
                ROOT.mkdir(mode=0o700,exist_ok=True)
                sink=stack.enter_context(tempfile.TemporaryFile(dir=ROOT))
            else:sink=io.BytesIO()
            until(marker,sink,MAX_UPLOAD if name=='file' else 4096)
            if name=='file':sink.seek(0);result[name]=sink
            else:result[name]=sink.getvalue().decode('utf-8')
            ending=take(2)
            if ending==b'--':
                if len(buffer)+remaining>2:raise ValueError('Неверное завершение загрузки.')
                tail=buffer+(stream.read(remaining) if remaining else b'')
                if tail not in (b'',b'\r\n'):raise ValueError('Неверное завершение загрузки.')
                break
            if ending!=b'\r\n':raise ValueError('Неверная граница загрузки.')
        yield result


def upload_dat(items, sid, name, source):
    from geodata_search import LimitedStream, detect_database
    source.seek(0,2);size=source.tell();source.seek(0)
    if not 0<size<=MAX_UPLOAD:raise ValueError('Выберите непустой файл .dat размером до 160 МиБ.')
    require(ROOT,size,'Сохранение GeoDAT')
    behavior=detect_database(LimitedStream(source,MAX_UPLOAD+1,time.monotonic()+180))
    source.seek(0);digest=hashlib.sha256()
    fd,temporary=tempfile.mkstemp(prefix='.upload-',dir=ROOT)
    try:
        with os.fdopen(fd,'wb') as out:
            while chunk:=source.read(65536):
                require(ROOT,len(chunk),'Сохранение GeoDAT');digest.update(chunk);out.write(chunk)
            out.flush();os.fsync(out.fileno())
        filename=f'{sid}-{digest.hexdigest()}.dat'
        os.replace(temporary,ROOT/filename);sync_dir(ROOT)
        items[sid]={'name':name,'kind':'geodat','behavior':behavior,'url':'','file':filename,'size':size,'updated':timestamp()}
        try:save_entries(items)
        except OSError:
            if entries().get(sid,{}).get('file')!=filename:(ROOT/filename).unlink(missing_ok=True)
            raise
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return 'Локальная база GeoDAT добавлена.'


def handle(form, progress=None, *, expected_behavior=None):
    if not secrets.compare_digest(form.get("token", ""), TOKEN):
        raise ValueError("Обновите вкладку GeoDAT и повторите действие.")
    operation = form.get("operation")
    with LOCK:
        items = entries()
        sid = form.get("id")
        old = items.get(sid)
        if operation == "remove":
            if old is None:
                raise ValueError("Источник уже удалён.")
            del items[sid]
            save_entries(items)
            if old.get("file"):
                (ROOT / old["file"]).unlink(missing_ok=True)
                sync_dir(ROOT)
            return "Источник удалён."
        if operation == "register":
            name = form.get("name", "").strip()
            if not 1 <= len(name) <= 100:
                raise ValueError("Укажите название источника.")
            url = source_url(form.get("url", ""))
            items[secrets.token_hex(16)] = {"name": name, "kind": "geodat", "url": url,
                                           "updated": timestamp()}
            save_entries(items)
            return "Ссылка на источник GeoDAT сохранена."
        if old and old.get("kind") == "geodat" and operation in ("refresh", "delete_file"):
            previous = old.get("file")
            if operation == "delete_file":
                old.pop("file", None)
                old.pop("size", None)
                save_entries(items)
                if previous:
                    (ROOT / previous).unlink(missing_ok=True)
                    sync_dir(ROOT)
                return "Локальный файл удалён. Ссылка сохранена."
            from geodata_search import save_database
            filename = sid + "-" + secrets.token_hex(8) + ".dat"
            def report_download(received):
                if progress is not None:
                    progress("Загружено " + format(received / 1048576, ".1f") + " МиБ")
            kind, size = save_database(old["url"], ROOT / filename, progress=report_download)
            if expected_behavior is not None and kind != expected_behavior:
                (ROOT / filename).unlink()
                raise ValueError("Источник должен содержать доменную базу GeoSite.")
            old.update(file=filename, size=size, behavior=kind, updated=timestamp())
            try:
                save_entries(items)
            except OSError:
                if entries().get(sid, {}).get("file") != filename:
                    (ROOT / filename).unlink(missing_ok=True)
                raise
            if previous:
                (ROOT / previous).unlink(missing_ok=True)
                sync_dir(ROOT)
            return "Локальная база GeoDAT обновлена." if previous else "Локальная база GeoDAT скачана."
        if operation == "refresh":
            if not old or not old.get("file") or not old.get("url"):
                raise ValueError("У источника нет адреса для обновления.")
            name, url = old["name"], old["url"]
        elif operation == "upload":
            name = form.get("name", "").strip()
            url = ""
            if not 1 <= len(name) <= 100:
                raise ValueError("Укажите название набора.")
            sid = secrets.token_hex(16)
        else:
            raise ValueError("Неизвестное действие GeoDAT.")
        if url:require(ROOT,MAX_FILE,'Обновление MRS')
        data = download(url) if url else form.get("file", b"")
        ROOT.mkdir(mode=0o700, exist_ok=True)
        if operation=='upload':
            source=io.BytesIO(data) if isinstance(data,bytes) else data
            magic=source.read(4);source.seek(0)
            if magic!=b'\x28\xb5\x2f\xfd':return upload_dat(items,sid,name,source)
            data=source.read(MAX_FILE+1)
        digest = hashlib.sha256(data).hexdigest()
        filename = f"{sid}-{digest}.mrs"
        if old and old["file"] == filename and (ROOT / filename).is_file():
            return "Источник уже актуален."
        behavior = detect_behavior(data)
        if old and old["behavior"] != behavior:
            raise ValueError("Источник вернул набор другого типа. Добавьте его как новый источник.")
        require(ROOT,len(data),'Сохранение MRS')
        write(ROOT / filename, data)
        items[sid] = {"name": name, "behavior": behavior, "url": url, "file": filename,
                      "size": len(data), "updated": timestamp()}
        try:
            save_entries(items)
        except OSError:
            if entries().get(sid, {}).get("file") != filename:
                (ROOT / filename).unlink(missing_ok=True)
            raise
        if old and old["file"] != filename:
            (ROOT / old["file"]).unlink(missing_ok=True)
            sync_dir(ROOT)
        return "Источник обновлён." if old else "Источник добавлен."


def render(message=""):
    escape = html.escape
    token = f'<input type="hidden" name="token" value="{TOKEN}">'
    fields = _ui('<input name="name" aria-label="Название" placeholder="Название" maxlength="100" required>')
    file_field = (_ui('<span class="geodata-file"><input type="file" name="file" aria-label="Выберите файл .mrs или .dat" accept=".mrs,.dat" required><span class="geodata-file-button" aria-hidden="true">Выберите .mrs / .dat</span><span class="geodata-file-name" aria-live="polite"></span></span>'))
    forms = []
    for op, title, submit, field, encoding in (
        ("upload", _ui('Загрузить файл'), _ui('Загрузить файл'), file_field, ' enctype="multipart/form-data"'),
        ("register", _ui('Источник GeoDAT'), _ui('Добавить источник'), _ui('<input type="url" name="url" aria-label="Ссылка" placeholder="Ссылка" maxlength="4096" required>'), ""),
    ):
        forms.append(f'<details class="panel-spoiler"><summary>{title}</summary>'
                     f'<form class="geodata-form" method="post" action="/api/geodata"{encoding}>{token}'
                     f'<input type="hidden" name="operation" value="{op}">{fields}{field}'
                     f'<button type="submit">{submit}</button></form></details>')
    rows = []
    for sid, item in entries().items():
        geodat = item.get("kind") == "geodat"
        source = item["url"] or _ui('Локальный файл')
        behavior = item.get("behavior")
        suffix = {"domain": ":domain", "ipcidr": ":ip"}.get(behavior, "")
        kind = "GeoDAT" + suffix if geodat else BEHAVIORS[behavior] + suffix
        size = ''.join((f"{item['size'] / 1024:.1f}", _ui(' КиБ'))) if item.get("file") else "—"
        def button(operation, label, attrs=""):
            queued = operation == "refresh" and geodat
            action = "/action" if queued else "/api/geodata"
            queue_field = '<input type="hidden" name="action" value="geodata_source_download">' if queued else ""
            return (f'<form method="post" action="{action}" {attrs}>{token}{queue_field}'
                    f'<input type="hidden" name="id" value="{escape(sid)}">'
                    f'<input type="hidden" name="operation" value="{operation}">'
                    f'<button type="submit">{label}</button></form>')
        refresh_label = _ui('Скачать') if geodat and not item.get("file") else _ui('Обновить')
        actions = button("refresh", refresh_label) if item["url"] else ""
        if geodat and item.get("file") and item.get('url'):
            actions += button("delete_file", _ui('Удалить файл'), _ui('onsubmit="return confirm(\'Удалить локальную копию базы?\')" '))
        actions += button("remove", _ui('Удалить'), _ui('onsubmit="return confirm(\'Удалить этот источник?\')" '))
        rows.append(f'<tr><td title="{escape(source)}"><strong>{escape(item["name"])}</strong></td>'
                    f'<td>{kind}</td><td>{size}</td>'
                    f'<td>{escape(item["updated"])}</td><td class="geodata-actions">{actions}</td></tr>')
    status = f'<p class="msg" role="status">{escape(message)}</p>' if message else ""
    listing = (_ui('<div style="overflow:auto"><table><thead><tr><th>Название</th><th>Тип</th><th>Размер</th><th>Добавлен / обновлён</th><th>Управление</th></tr></thead><tbody>') + "".join(rows) + '</tbody></table></div>') if rows else _ui('<p>Источники ещё не добавлены.</p>')
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>GeoDAT</title></head><body>'
            + status + "".join('<div class="panel">' + form + '</div>' for form in forms)
            + _ui('<div class="panel"><h2>Источники GeoDAT</h2>') + listing + '</div>'
            '<style>.geodata-form{display:grid;grid-template-columns:minmax(0,220px) minmax(0,360px) max-content;'
            'gap:10px;align-items:center;margin-top:12px}'
            'body .unified-main .geodata-form>input:not([type=hidden]){width:100%;min-width:0;margin:0;height:40px}'
            'body .unified-main .geodata-form>button{margin:0;height:40px;justify-self:start}'
            '.geodata-form>input:focus::placeholder{color:transparent}'
            '.geodata-file{position:relative;display:flex;align-items:center;gap:10px;min-width:0;height:40px}'
            'body .unified-main .geodata-file>input{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer}'
            '.geodata-file-button{display:inline-flex;align-items:center;flex:none;height:40px;box-sizing:border-box;'
            'padding:0 12px;border:1px solid var(--ui-border);border-radius:8px;background:var(--ui-button);font-size:14px;font-weight:600}'
            '.geodata-file:hover .geodata-file-button{background:var(--ui-button-hover)}'
            '.geodata-file:focus-within .geodata-file-button{outline:2px solid var(--ui-primary);outline-offset:2px}'
            '.geodata-file-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ui-muted)}'
            '.geodata-actions form{display:inline-block;margin:2px}'
            '@media(max-width:700px){.geodata-form{grid-template-columns:minmax(0,1fr)}}</style>'
            '<script>document.querySelectorAll(".geodata-file").forEach(field=>{'
            'const input=field.querySelector("input"),name=field.querySelector(".geodata-file-name");'
            'const update=()=>{name.textContent=input.files[0]?.name||"";name.title=name.textContent;};'
            'input.addEventListener("change",update);update();});</script>'
            '</body></html>')
