"""Install an administrator-prepared compatible release; never substitute apk."""
import hashlib,json,os,re,shutil,signal,subprocess,tempfile,time
from pathlib import Path
from durable_io import replace
from storage_space import require

BINARY=Path('/usr/local/bin/sing-box')
CONFIG=Path('/etc/mihomo/clients/sing-box.json')
UPDATES=Path('/etc/mihomo/updates/sing-box')
STATE=Path('/tmp/sing-box-supervisor.json')

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def command(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if p.returncode:raise ValueError('Совместимая сборка не прошла проверку версии или конфигурации')
    return p.stdout.strip()

def supervisor():
    data=json.loads(STATE.read_text());pid=data.get('pid')
    if not isinstance(pid,int) or pid<=1:raise ValueError('Некорректное состояние процесса sing-box')
    args=Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')
    if b'/etc/mihomo/rules/sing_box_supervisor.py' not in args or str(BINARY).encode() not in args:
        raise ValueError('Не найден управляемый процесс sing-box')
    return data

def wait_ready(previous,version):
    end=time.monotonic()+60
    while time.monotonic()<end:
        try:
            data=supervisor()
            if data['generation']>previous['generation'] and data.get('failed'):raise RuntimeError('Новая сборка не прошла стартовую проверку')
            if data['generation']>previous['generation'] and data.get('ready') and data.get('healthy')==data.get('total') and data.get('version')==version:return
        except (OSError,ValueError,KeyError):pass
        time.sleep(.5)
    raise RuntimeError('Новая сборка не подтвердила работоспособность VPN')

def update(force=False):
    current=command([str(BINARY),'version']).splitlines()[0]
    manifest=UPDATES/'release.json'
    if not manifest.is_file():return 'Новых подготовленных совместимых обновлений sing-box нет. Установлено: '+current
    if manifest.is_symlink() or manifest.stat().st_size>4096:raise ValueError('Некорректный манифест обновления')
    release=json.loads(manifest.read_text())
    expected=release.get('sha256','');version=release.get('version','')
    if not re.fullmatch('[0-9a-f]{64}',expected) or not re.fullmatch(r'[A-Za-z0-9.+_-]{1,100}',version):raise ValueError('Некорректные сведения о сборке')
    if not force and digest(BINARY)==expected:return 'Подготовленная совместимая сборка sing-box уже установлена: '+version
    candidate=UPDATES/'sing-box'
    return install(candidate,version,expected,force)

def install(candidate,version,expected,force=False):
    current=command([str(BINARY),'version']).splitlines()[0]
    if not force and digest(BINARY)==expected:return 'Совместимая сборка уже установлена: '+version
    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size>150_000_000 or digest(candidate)!=expected:raise ValueError('Файл обновления отсутствует или SHA256 не совпадает')
    reported=command([str(candidate),'version']).splitlines()[0]
    if reported!='sing-box version '+version:raise ValueError('Версия файла не совпадает с манифестом')
    command([str(candidate),'check','-c',str(CONFIG)])
    try:previous=supervisor()
    except (OSError,ValueError):raise ValueError('Для управляемого обновления требуется однократный перезапуск контейнера')
    if not previous.get('ready'):raise ValueError('Дождитесь завершения запуска sing-box')
    require(BINARY.parent,candidate.stat().st_size+BINARY.stat().st_size,'Обновление sing-box с резервной копией')
    with tempfile.TemporaryDirectory(prefix='.sing-box-update-',dir=BINARY.parent) as directory:
        old=Path(directory)/'old';new=Path(directory)/'new'
        shutil.copy2(BINARY,old);shutil.copy2(candidate,new);new.chmod(0o755)
        if digest(new)!=expected:raise ValueError('SHA256 изменился во время подготовки обновления')
        old_version=current.removeprefix('sing-box version ')
        try:
            replace(new,BINARY);os.kill(previous['pid'],signal.SIGHUP);wait_ready(previous,version)
        except Exception:
            replace(old,BINARY)
            active=supervisor();os.kill(active['pid'],signal.SIGHUP)
            try:wait_ready(active,old_version)
            except Exception:raise RuntimeError('Старый файл восстановлен; проверьте доступность VPN в панели')
            raise RuntimeError('Обновление не прошло проверку. Предыдущая сборка восстановлена')
    return ('Sing-box переустановлен на версию ' if force else 'Sing-box обновлён до ')+version+'. Настройки сохранены, работоспособность VPN проверена'
