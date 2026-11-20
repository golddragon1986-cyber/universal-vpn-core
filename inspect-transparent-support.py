import gzip,json,shutil,subprocess
from pathlib import Path
for directory in ('/sbin','/usr/sbin'):
    print(directory,sorted(str(x) for x in Path(directory).glob('*tables*')))
for name in ('/proc/net/ip_tables_names','/proc/net/ip6_tables_names'):
    path=Path(name)
    try:print(name,path.read_text() if path.exists() else 'absent')
    except OSError as error:print(name,type(error).__name__,str(error))
path=Path('/proc/config.gz')
if path.exists():
    text=gzip.decompress(path.read_bytes()).decode()
    print('\n'.join(x for x in text.splitlines() if any(k in x for k in ('CONFIG_NF_TABLES','CONFIG_IP_NF','CONFIG_NETFILTER','CONFIG_NF_NAT','CONFIG_NETFILTER_XT_TARGET_REDIRECT'))))
for command in (['apk','info','-e','iptables-legacy'],['iptables-legacy','-t','nat','-S']):
    if not shutil.which(command[0]):continue
    p=subprocess.run(command,capture_output=True,text=True,timeout=15)
    print(json.dumps({'command':command,'returncode':p.returncode,'output':(p.stdout+p.stderr)[-1500:]}))
