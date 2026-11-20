"""Validate, atomically replace and recover native component binaries."""
import json,os,shutil,signal,subprocess,tempfile,time
from pathlib import Path
from urllib.request import urlopen
from durable_io import replace

ROOT=Path('/etc/mihomo')
def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=40)
    if p.returncode:raise ValueError('Выбранная версия не совместима с архитектурой или текущей конфигурацией')
    return p.stdout.strip()

def core_state():
    s=json.loads(Path('/tmp/mihomo-supervisor.json').read_text());pid=s.get('pid')
    if not isinstance(pid,int) or pid<=1:raise ValueError('Нет управляющего процесса Mihomo')
    args=Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')
    if b'/etc/mihomo/rules/core-supervisor.sh' not in args or b'mihomo' not in args:raise ValueError('Некорректный управляющий процесс Mihomo')
    return s

def core_ready(old,version):
    end=time.monotonic()+60
    while time.monotonic()<end:
        try:
            s=core_state()
            with urlopen('http://127.0.0.1:9090/version',timeout=2) as response:v=json.load(response)['version']
            if s['generation']>old['generation'] and v==version:
                from boot_config import ready
                os.environ['MIHOMO_BOOT_PREPARED']='1';ready();return
        except (OSError,ValueError,KeyError):pass
        time.sleep(.5)
    raise RuntimeError('Ядро не подтвердило запуск выбранной версии')


def restart(component):
    if component == 'mihomo':
        previous = core_state()
        version = run(['/mihomo','-v']).split()[2]
        os.kill(previous['pid'], signal.SIGHUP)
        core_ready(previous, version)
        return 'Mihomo перезапущен, API и маршруты восстановлены'
    if component not in ('sing-box','xray'):
        raise ValueError('Этот компонент не запускается отдельным процессом')
    import vpn_clients
    with vpn_clients.LOCK:
        if not vpn_clients.binary(component):
            raise ValueError('Компонент не установлен')
        if not vpn_clients.users(component):
            return 'Клиент не используется ни одним соединением'
        if component == 'sing-box' and vpn_clients.reload_sb():
            return 'sing-box перезапущен'
        vpn_clients.ensure_runtime(component, restart=True)
        return vpn_clients.NAMES[component] + ' перезапущен'

def install_binary(component,candidate,version):
    from sing_box_update import digest
    if component=='sing-box':
        from sing_box_update import install,BINARY,CONFIG
        running=subprocess.run(['pidof','sing-box'],capture_output=True).returncode==0
        if BINARY.exists() and CONFIG.exists() and running:return install(candidate,version.removeprefix('v'),digest(candidate),force=True)
        if running:raise ValueError('Сначала остановите неуправляемый sing-box')
        actual=run([str(candidate),'version']).splitlines()[0]
        if actual!='sing-box version '+version.removeprefix('v'):raise ValueError('Версия sing-box не совпадает с выбранной')
        if CONFIG.exists():run([str(candidate),'check','-c',str(CONFIG)])
        BINARY.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=BINARY.parent,delete=False) as f:temp=Path(f.name)
        try:shutil.copy2(candidate,temp);temp.chmod(0o755);replace(temp,BINARY)
        finally:
            if temp.exists():temp.unlink()
        return 'sing-box установлен: '+version+'. Сохранённые настройки не изменены'
    if component not in ('mihomo','xray'):raise ValueError('Неизвестный native-компонент')
    destination=Path('/mihomo') if component=='mihomo' else Path('/usr/local/bin/xray')
    if component=='mihomo':
        actual=run([str(candidate),'-v']).splitlines()[0].split()[2]
        if actual!=version:raise ValueError('Версия ядра не совпадает с выбранной')
        run([str(candidate),'-t','-d',str(ROOT),'-f',str(ROOT/'default_config.yaml')])
        old_state=core_state();old_version=run([str(destination),'-v']).splitlines()[0].split()[2]
    else:
        actual=run([str(candidate),'version']).splitlines()[0]
        if version.removeprefix('v') not in actual:raise ValueError('Версия Xray не совпадает с выбранной')
        cfg=ROOT/'clients/xray.json'
        if cfg.exists():run([str(candidate),'run','-test','-config',str(cfg)])
        if subprocess.run(['pidof','xray'],capture_output=True).returncode==0:raise ValueError('Сначала остановите используемый Xray перед переустановкой')
    if shutil.disk_usage(destination.parent).free<2*candidate.stat().st_size:raise ValueError('Недостаточно места для безопасной переустановки')
    with tempfile.TemporaryDirectory(prefix='.component-update-',dir=destination.parent) as temp:
        old=Path(temp)/'old';new=Path(temp)/'new';existed=destination.exists()
        if existed:shutil.copy2(destination,old)
        shutil.copy2(candidate,new);new.chmod(0o755)
        try:
            replace(new,destination)
            if component=='mihomo':os.kill(old_state['pid'],signal.SIGHUP);core_ready(old_state,version)
        except Exception:
            if existed:replace(old,destination)
            elif destination.exists():destination.unlink()
            if component=='mihomo':
                active=core_state();os.kill(active['pid'],signal.SIGHUP);core_ready(active,old_version)
            raise RuntimeError('Установка не прошла проверку; предыдущая версия восстановлена')
    return component+' переустановлен на версию '+version+'. Конфигурация сохранена'
