from pathlib import Path
import sys
sys.path.insert(0,'/etc/mihomo/rules')
from durable_io import write
source=Path('/etc/mihomo/fix-check/sing_box_supervisor.py').read_text()
compile(source,'sing_box_supervisor.py','exec')
for path in (Path('/etc/mihomo/rules/sing_box_supervisor.py'),Path('/usr/local/lib/mihomo-panel/panel/sing_box_supervisor.py')):
    if not path.exists():continue
    backup=Path(str(path)+'.before-listener-readiness')
    if not backup.exists():write(backup,path.read_bytes())
    write(path,source.encode())
    print(str(path)+': readiness fix installed')
