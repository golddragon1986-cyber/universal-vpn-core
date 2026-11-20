import sys
from pathlib import Path
sys.path.insert(0,'/etc/mihomo/rules')
from durable_io import write
source=Path('/etc/mihomo/fix-check/vpn_clients.py').read_bytes()
compile(source,'vpn_clients.py','exec')
for path in (Path('/etc/mihomo/rules/vpn_clients.py'),Path('/usr/local/lib/mihomo-panel/panel/vpn_clients.py')):
    if not path.exists():continue
    backup=Path(str(path)+'.before-xray-mlkem-fix')
    if not backup.exists():write(backup,path.read_bytes())
    write(path,source)
    print(str(path)+': Xray converter updated')
