"""Verify and install signed-by-HTTPS panel bundles published as GitHub releases."""
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from durable_io import write
from storage_space import require_many

BASE = Path('/etc/mihomo/rules')
REPOSITORY = 'golddragon1986-cyber/universal-vpn-core'
MANIFEST_URL = 'https://raw.githubusercontent.com/' + REPOSITORY + '/main/updates/panel/stable.json'
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_FILES = 256
VERSION_FILE = BASE / 'panel-version.json'
BACKUP_ROOT = BASE / '.panel-update-backup'
TRANSACTION = BASE / '.panel-update-transaction.json'
MODULE_LOADED_AT = time.time()
EXTENSIONS = {'.py', '.js', '.html', '.css', '.sh', '.json'}
PROTECTED = {'routing-settings.json', 'dns-settings.json', 'service-routes.json',
             'route-targets.json', 'client-settings.json', 'local-domain-dns.json',
             'routeros-local-dns.json', 'managed-proxies.json', 'container-clients-observed.json',
             'router-routes-observed.json', 'panel-version.json'}


def _opener(proxy):
    handlers = [urllib.request.ProxyHandler({'https': 'http://127.0.0.1:1080'} if proxy else {})]
    return urllib.request.build_opener(*handlers)


def _get(url, limit, github=False):
    error = None
    for proxy in (False, True):
        try:
            headers = {'User-Agent': 'Universal-VPN-Core-Panel-Updater',
                       'Accept': 'application/vnd.github+json' if github else 'application/json'}
            with _opener(proxy).open(urllib.request.Request(url, headers=headers), timeout=20) as response:
                raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('Ответ GitHub превышает допустимый размер')
            return raw
        except Exception as exc:
            error = exc
    raise RuntimeError('GitHub недоступен: ' + str(error))


def _version(value):
    value = str(value)
    if not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise ValueError('В манифесте указана некорректная версия панели')
    return tuple(int(part) for part in value.split('.'))


def current_version():
    try:
        data = json.loads(VERSION_FILE.read_bytes())
        value = data.get('version', '')
        if re.fullmatch(r'\d+\.\d+\.\d+', str(value)):
            return str(value)
    except (OSError, ValueError, TypeError):
        pass
    return 'сборка из образа'


def read_manifest():
    try:
        raw = _get(MANIFEST_URL, 64 * 1024)
    except RuntimeError as error:
        if '404' in str(error):
            raise RuntimeError('В GitHub ещё не опубликован выпуск с обновлением панели.') from error
        raise
    data = json.loads(raw)
    version = str(data.get('version', ''))
    _version(version)
    tag = str(data.get('tag', ''))
    if tag != 'panel-v' + version and not re.fullmatch(r'v\d+\.\d+[a-z]?\.\d{6}\.\d{4}', tag):
        raise ValueError('Некорректный тег выпуска панели или контейнера')
    url = str(data.get('url', ''))
    expected = 'https://github.com/' + REPOSITORY + '/releases/download/' + tag + '/panel.tar.gz'
    if url != expected:
        raise ValueError('Недопустимая ссылка на архив панели')
    digest = str(data.get('sha256', ''))
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('В манифесте отсутствует SHA-256 архива')
    size = data.get('size')
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ARCHIVE:
        raise ValueError('Недопустимый размер архива панели')
    return {'version': version, 'tag': tag, 'url': url, 'sha256': digest, 'size': size}


def check():
    release = read_manifest()
    installed = current_version()
    available = installed == 'сборка из образа' or _version(release['version']) > _version(installed)
    return {'ok': True, 'repository': REPOSITORY, 'installed': installed,
            'available': release['version'], 'update_available': available,
            'tag': release['tag'], 'size': release['size']}


def _download(release, path):
    digest = hashlib.sha256()
    size = 0
    error = None
    for proxy in (False, True):
        try:
            digest = hashlib.sha256()
            size = 0
            with _opener(proxy).open(urllib.request.Request(release['url'], headers={
                    'User-Agent': 'Universal-VPN-Core-Panel-Updater'}), timeout=25) as response, path.open('wb') as output:
                while True:
                    block = response.read(65536)
                    if not block:
                        break
                    size += len(block)
                    if size > release['size'] or size > MAX_ARCHIVE:
                        raise ValueError('Архив превышает размер из GitHub-манифеста')
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if size != release['size'] or digest.hexdigest() != release['sha256']:
                raise ValueError('Размер или SHA-256 архива не совпадает с манифестом')
            return
        except Exception as exc:
            error = exc
    raise RuntimeError('Не удалось загрузить архив панели: ' + str(error))


def _safe_name(name):
    path = Path(name)
    if (path.is_absolute() or len(path.parts) != 2 or path.parts[0] != 'panel'
            or path.parts[1] in ('', '.', '..') or path.name != path.parts[1]):
        raise ValueError('В архиве обнаружен недопустимый путь')
    filename = path.name
    if filename == 'panel-release.json':
        return filename
    if Path(filename).suffix.lower() not in EXTENSIONS or filename in PROTECTED:
        raise ValueError('В архиве обнаружен файл, который нельзя обновлять: ' + filename)
    return filename


def _extract(archive, stage, version):
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        if not 1 <= len(members) <= MAX_FILES + 1:
            raise ValueError('Недопустимое количество файлов в архиве')
        names = set()
        total = 0
        for member in members:
            name = _safe_name(member.name)
            if name in names or not member.isfile() or member.size < 0:
                raise ValueError('В архиве есть повторяющийся или специальный файл')
            names.add(name)
            total += member.size
            if total > MAX_UNPACKED:
                raise ValueError('Распакованный архив слишком велик')
        manifest_member = next((m for m in members if m.name == 'panel/panel-release.json'), None)
        if manifest_member is None:
            raise ValueError('В архиве нет списка файлов panel-release.json')
        internal = json.load(source.extractfile(manifest_member))
        if internal.get('version') != version or not isinstance(internal.get('files'), list):
            raise ValueError('Версия или список файлов в архиве некорректны')
        expected = {}
        for item in internal['files']:
            name = _safe_name('panel/' + str(item.get('name', '')))
            size = item.get('size')
            digest = item.get('sha256', '')
            mode = item.get('mode', 0o644)
            if (name == 'panel-release.json' or name in expected or not isinstance(size, int)
                    or isinstance(size, bool) or size < 0 or mode not in (0o644, 0o755)
                    or not re.fullmatch(r'[0-9a-f]{64}', str(digest))):
                raise ValueError('Некорректная запись в списке файлов панели')
            expected[name] = (size, digest, mode)
        archive_files = {m.name.removeprefix('panel/') for m in members if m.name != 'panel/panel-release.json'}
        if not expected or archive_files != set(expected):
            raise ValueError('Содержимое архива не совпадает со списком файлов')
        by_name = {m.name.removeprefix('panel/'): m for m in members if m.name != 'panel/panel-release.json'}
        for name, (size, digest, mode) in expected.items():
            member = by_name[name]
            if member.size != size:
                raise ValueError('Размер файла не совпадает: ' + name)
            raw = source.extractfile(member).read(size + 1)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Контрольная сумма файла не совпадает: ' + name)
            if name.endswith('.py'):
                compile(raw.decode('utf-8'), name, 'exec')
            staged = stage / name
            staged.write_bytes(raw)
            staged.chmod(mode)
        return expected


def _restore(backup, names):
    for name in names:
        saved = backup / name
        target = BASE / name
        if saved.is_file():
            write(target, saved.read_bytes(), mode=saved.stat().st_mode & 0o777)
        elif target.exists():
            target.unlink()


def schedule_restart():
    """Restart only after the action queue has durably recorded success."""
    def restart():
        try:
            os.execv(sys.executable, [sys.executable, '-u', '/etc/mihomo/rules/manage_ru_blocked.py'])
        except Exception:
            try:
                transaction = json.loads(TRANSACTION.read_bytes())
                backup = Path(transaction['backup'])
                if backup.parent == BACKUP_ROOT:
                    _restore(backup, transaction.get('files', []))
                TRANSACTION.unlink(missing_ok=True)
            except Exception as error:
                print('Panel update rollback after restart error failed:', error, flush=True)
            raise
    threading.Timer(2.0, restart).start()


def install(expected_version):
    release = read_manifest()
    if release['version'] != expected_version:
        raise ValueError('На GitHub опубликована другая версия. Проверьте обновления ещё раз.')
    if not check()['update_available']:
        return 'Установлена актуальная версия панели ' + release['version']
    from storage_space import require_many
    require_many([(BASE, release['size'] + 2 * MAX_UNPACKED + 8 * 1024 * 1024)], 'Обновление панели')
    temp = Path(tempfile.mkdtemp(prefix='.panel-update-', dir=BASE))
    stage = temp / 'files'
    stage.mkdir()
    backup = BACKUP_ROOT / (str(int(time.time())) + '-' + release['version'])
    changed = []
    try:
        archive = temp / 'panel.tar.gz'
        _download(release, archive)
        expected = _extract(archive, stage, release['version'])
        VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        old_files = list(expected) + ['panel-version.json']
        backup.mkdir(parents=True, exist_ok=False)
        for name in old_files:
            source = BASE / name
            if source.is_file():
                saved = backup / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, saved)
        transaction = {'version': release['version'], 'backup': str(backup), 'files': old_files,
                       'phase': 'installing', 'started': time.time()}
        write(TRANSACTION, json.dumps(transaction).encode())
        try:
            for name in expected:
                destination = BASE / name
                old_mode = destination.stat().st_mode & 0o777 if destination.exists() else (stage / name).stat().st_mode & 0o777
                write(destination, (stage / name).read_bytes(), mode=old_mode)
                changed.append(name)
            write(VERSION_FILE, json.dumps({'version': release['version'], 'tag': release['tag']}).encode())
            transaction.update(phase='await_start', pid=os.getpid(), restart_after=time.time() + 3.0)
            write(TRANSACTION, json.dumps(transaction).encode())
        except Exception:
            _restore(backup, old_files)
            TRANSACTION.unlink(missing_ok=True)
            raise
        return 'Панель обновлена до ' + release['version'] + '. Перезапускается веб-панель; VPN-конфигурация не менялась.'
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def recover():
    """Roll back interrupted writes or a failed panel re-exec at the next startup."""
    try:
        transaction = json.loads(TRANSACTION.read_bytes())
    except FileNotFoundError:
        return
    backup = Path(transaction.get('backup', ''))
    if backup.parent != BACKUP_ROOT or not backup.is_dir():
        raise RuntimeError('Не удалось найти резервную копию файлов панели после прерванного обновления')
    if (transaction.get('phase') == 'await_start' and transaction.get('pid') == os.getpid()
            and MODULE_LOADED_AT >= float(transaction.get('restart_after', 0))):
        return
    _restore(backup, transaction.get('files', []))
    TRANSACTION.unlink(missing_ok=True)


def complete_start():
    try:
        transaction = json.loads(TRANSACTION.read_bytes())
    except FileNotFoundError:
        return
    if transaction.get('phase') == 'await_start' and transaction.get('pid') == os.getpid():
        TRANSACTION.unlink(missing_ok=True)
