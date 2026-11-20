"""Version catalogs are read-only metadata; only explicit install changes binaries."""
import codecs,gzip,hashlib,json,os,platform,re,shutil,subprocess,tarfile,tempfile,threading,time,zipfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request,urlopen,build_opener,ProxyHandler
from durable_io import write

CACHE=Path('/etc/mihomo/rules/component-versions.json')
LOCK=threading.Lock()
REPOS={'mihomo':'MetaCubeX/mihomo','sing-box':'SagerNet/sing-box','xray':'XTLS/Xray-core'}
PACKAGES={'openvpn':'openvpn','wireguard-tools':'wireguard-tools-wg'}
MAX_BINARY=150_000_000

def arch():
    value=platform.machine().lower()
    result={'armv7l':'armv7','armv7':'armv7','aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64','i386':'386','i686':'386'}.get(value)
    if not result:raise ValueError('Архитектура не поддерживается каталогом версий: '+value)
    return result

def request(url):
    return build_opener(ProxyHandler({'https':'http://127.0.0.1:1080'})).open(Request(url,headers={'User-Agent':'VPN-Control-Panel','Accept':'application/vnd.github+json'}),timeout=25)

def asset_name(component,version,architecture):
    if component=='mihomo':
        target={'amd64':'amd64-compatible','386':'386','arm64':'arm64','armv7':'armv7'}[architecture]
        return 'mihomo-linux-'+target+'-'+version+'.gz'
    if component=='sing-box':return 'sing-box-'+version.removeprefix('v')+'-linux-'+architecture+'.tar.gz'
    return 'Xray-linux-'+{'armv7':'arm32-v7a','arm64':'arm64-v8a','amd64':'64','386':'32'}[architecture]+'.zip'

def releases(response):
    decoder=json.JSONDecoder();utf8=codecs.getincrementaldecoder('utf-8')();buffer='';started=False;total=0
    while True:
        buffer=buffer.lstrip()
        if not started and buffer:
            if not buffer.startswith('['):raise ValueError('Некорректный каталог релизов')
            buffer=buffer[1:];started=True
        buffer=buffer.lstrip(' \r\n\t,')
        if started and buffer.startswith(']'):return
        if started and buffer:
            try:item,end=decoder.raw_decode(buffer)
            except ValueError:pass
            else:
                buffer=buffer[end:];yield item;continue
        chunk=response.read(65536)
        if not chunk:raise ValueError('Каталог релизов загрузился не полностью')
        total+=len(chunk)
        if total>60_000_000 or len(buffer)>2_000_000:raise ValueError('Каталог релизов слишком большой')
        buffer+=utf8.decode(chunk)

def github_versions(component):
    architecture=arch();repo=REPOS[component];result=[]
    with request('https://api.github.com/repos/'+repo+'/releases?per_page=100') as response:
      for release in releases(response):
        version=release.get('tag_name','')
        if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'v?\d+\.\d+(?:\.\d+)?',version):continue
        name=asset_name(component,version,architecture)
        asset=next((x for x in release.get('assets',[]) if x.get('name')==name),None)
        if not asset or asset.get('size',MAX_BINARY)>MAX_BINARY:continue
        url=asset.get('browser_download_url','')
        if not url.startswith('https://github.com/'+repo+'/releases/download/'):continue
        digest=asset.get('digest') or ''
        verified=bool(re.fullmatch(r'sha256:[0-9a-f]{64}',digest))
        result.append({'id':'github:'+version,'version':version,'source':'GitHub · '+repo,'installable':verified,'note':'' if verified else 'Нет опубликованного SHA256','url':url,'sha256':digest.removeprefix('sha256:'),'asset':name})
    return result

def apk_versions(component):
    from vpn_components import SYSTEM_PACKAGES
    package=SYSTEM_PACKAGES[component][1] if component in SYSTEM_PACKAGES else PACKAGES[component]
    p=subprocess.run(['apk','list','--all-matches','--available',package],capture_output=True,text=True,timeout=30)
    if p.returncode:raise ValueError('Не удалось прочитать версии Alpine')
    versions=[]
    for line in p.stdout.splitlines():
        name=line.split()[0] if line.split() else ''
        if name.startswith(package+'-'):
            v=name[len(package)+1:]
            if re.fullmatch(r'[0-9][A-Za-z0-9._+~-]{0,99}',v) and v not in versions:versions.append(v)
    return [{'id':'apk:'+v,'version':v,'source':'Alpine · подключённые репозитории','installable':True,'note':''} for v in versions]

def local_versions(component):
    import vpn_components as c
    if component=='sing-box' and c.LOCAL_SING_BOX.is_file():
        version=c.run([str(c.LOCAL_SING_BOX),'version']).splitlines()[0].removeprefix('sing-box version ')
        result=[{'id':'installed:'+version,'version':version,'source':'Установленная совместимая сборка','installable':True,'note':'ML-KEM'}]
        path=Path('/etc/mihomo/updates/sing-box/release.json')
        if path.is_file():
            prepared=json.loads(path.read_text())
            result.insert(0,{'id':'prepared:'+prepared['version'],'version':prepared['version'],'source':'Подготовленная совместимая сборка','installable':True,'note':'ML-KEM'})
        return result
    if component=='mihomo':
        version=c.run(['/mihomo','-v']).splitlines()[0].split()[2]
        return [{'id':'installed:'+version,'version':version,'source':'Установленная сборка','installable':True,'note':''}]
    return []

def catalog(refresh=False):
    with LOCK:
        if not refresh and CACHE.is_file():
            data=json.loads(CACHE.read_text())
            if data.get('architecture')==arch():
                for key in data['items']:data['items'][key]=local_versions(key)+[x for x in data['items'][key] if not x['id'].startswith(('installed:','prepared:'))]
                return data
        if not refresh:return {'architecture':arch(),'checked_at':None,'items':{},'errors':{},'unchecked':True}
        data={'architecture':arch(),'checked_at':time.strftime('%Y-%m-%d %H:%M:%S'),'items':{},'errors':{}}
        try:
            p=subprocess.run(['apk','update'],capture_output=True,text=True,timeout=90)
            if p.returncode:data['errors']['alpine']='Не удалось обновить индексы Alpine'
        except subprocess.TimeoutExpired:
            data['errors']['alpine']='Репозиторий Alpine не ответил за 90 секунд'
        from vpn_components import SYSTEM_PACKAGES, installed
        system = [key for key, (_, package, _) in SYSTEM_PACKAGES.items() if installed(package)]
        for component in ('mihomo','openvpn','wireguard-tools','sing-box','xray',*system):
            versions=local_versions(component)
            try:
                if component in PACKAGES or component in SYSTEM_PACKAGES:
                    if 'alpine' not in data['errors']:
                        versions+=apk_versions(component)
                else:
                    versions+=github_versions(component)
            except Exception as e:data['errors'][component]=str(e)[:200]
            data['items'][component]=versions
        write(CACHE,json.dumps(data).encode())
        return data

def public_catalog(refresh=False):
    import vpn_components as components
    data=catalog(refresh)
    if data.get('unchecked'):
        return data
    installed = {item['id']: item['version'] for item in components.status()['items'] if item['installed']}
    items = {}
    for key, values in data['items'].items():
        current = installed.get(key)
        items[key] = []
        for value in values:
            item = {k:v for k,v in value.items() if k not in ('url','sha256','asset')}
            item['newer'] = bool(current and item.get('installable') and newer_version(item, current))
            items[key].append(item)
    return {**{k:v for k,v in data.items() if k != 'routeros'}, 'items':items}


def newer_version(item, current):
    candidate = item['version']
    if item['id'].startswith('apk:'):
        result = subprocess.run(['apk','version','-t',candidate,current], capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() == '>'
    # Stable binary releases use numeric versions. A local rebuild of the
    # same release is treated as a reinstall, regardless of its build suffix.
    def numbers(version):
        match = re.match(r'v?(\d+(?:\.\d+){0,3})', version)
        return tuple(map(int, match[1].split('.'))) if match else ()
    left, right = numbers(candidate), numbers(current)
    return bool(left and right and left + (0,) * (4-len(left)) > right + (0,) * (4-len(right)))

def download(component,item,directory):
    expected=item['sha256']
    if not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('Нет проверенной контрольной суммы сборки')
    repo=REPOS[component]
    if not item['url'].startswith('https://github.com/'+repo+'/releases/download/'):raise ValueError('Недопустимый источник сборки')
    archive=directory/'release';h=hashlib.sha256();size=0
    with request(item['url']) as source,archive.open('wb') as target:
        while True:
            chunk=source.read(1024*1024)
            if not chunk:break
            size+=len(chunk)
            if size>MAX_BINARY:raise ValueError('Слишком большой файл обновления')
            if shutil.disk_usage(directory).free<len(chunk)+5_000_000:raise ValueError('Недостаточно места для загрузки сборки')
            target.write(chunk);h.update(chunk)
    if h.hexdigest()!=expected:raise ValueError('SHA256 загруженного файла не совпадает')
    binary=directory/'binary'
    if component=='mihomo':stream=gzip.open(archive,'rb')
    elif component=='sing-box':
        tar=tarfile.open(archive,'r:gz');members=[x for x in tar.getmembers() if x.isfile() and Path(x.name).name=='sing-box']
        if len(members)!=1 or members[0].size>MAX_BINARY:tar.close();raise ValueError('Некорректный архив sing-box')
        stream=tar.extractfile(members[0])
    else:
        zip=zipfile.ZipFile(archive);members=[x for x in zip.infolist() if not x.is_dir() and Path(x.filename).name=='xray']
        if len(members)!=1 or members[0].file_size>MAX_BINARY:zip.close();raise ValueError('Некорректный архив Xray')
        stream=zip.open(members[0])
    try:
        total=0
        with stream,binary.open('wb') as target:
            while True:
                chunk=stream.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>MAX_BINARY:raise ValueError('Распакованный файл слишком большой')
                if shutil.disk_usage(directory).free<len(chunk)+5_000_000:raise ValueError('Недостаточно места для распаковки сборки')
                target.write(chunk)
    finally:
        if component=='sing-box':tar.close()
        elif component=='xray':zip.close()
    binary.chmod(0o755)
    return binary

def install(component,selected):
    import vpn_components as c
    if component not in set(REPOS)|set(PACKAGES):raise ValueError('Неизвестный компонент')
    data=catalog();entry=next((x for x in data['items'].get(component,[]) if x['id']==selected),None)
    if not entry or not entry['installable']:raise ValueError('Выберите доступную версию после проверки каталога')
    if component in PACKAGES:
        package=PACKAGES[component];spec=package+'='+entry['version']
        if c.disk_limit() and c.used_bytes()+c.CATALOG[component][2]>c.disk_limit():raise ValueError('Недостаточно места в лимите диска')
        c.run(['apk','add','--no-cache','--upgrade',spec])
        c.run(['apk','fix','--no-cache','--reinstall',package])
        return 'Установлена версия '+entry['version']+' компонента '+c.CATALOG[component][0]+'. Конфигурация сохранена'
    if selected.startswith('prepared:'):
        from sing_box_update import update
        return update(force=True)
    if selected.startswith('installed:'):
        binary=Path('/mihomo') if component=='mihomo' else c.LOCAL_SING_BOX
        from component_binary import install_binary
        return install_binary(component,binary,entry['version'])
    with tempfile.TemporaryDirectory(prefix='component-release-') as temp:
        binary=download(component,entry,Path(temp))
        from component_binary import install_binary
        return install_binary(component,binary,entry['version'])
