"""Read-only accounting of the live merged rootfs, persistent state and backups."""
import json
import os
import re
import stat
import time
from pathlib import Path

SKIP={'/proc','/sys','/dev'}
backup_pattern=re.compile(r'(^|/)(backups?|backup-[^/]*|\.pending-action[^/]*)(/|$)|\.bak(?:[-.]|$)|\.backup(?:[-.]|$)|\.last-good(?:[-.]|$)',re.I)
seen=set();totals={key:{'allocated':0,'logical':0,'files':0} for key in ['rootfs','data','backups']}
excluded=[];errors=[]

for directory,dirs,files in os.walk('/',topdown=True,followlinks=False):
    dirs[:]=[name for name in dirs if os.path.join(directory,name) not in SKIP]
    try:
        info=os.lstat(directory)
        identity=(info.st_dev,info.st_ino)
        if identity not in seen:
            seen.add(identity)
            category='backups' if backup_pattern.search(directory) else 'data' if directory=='/etc/mihomo' or directory.startswith('/etc/mihomo/') else 'rootfs'
            totals[category]['allocated']+=info.st_blocks*512
            totals[category]['logical']+=info.st_size
    except OSError as error:errors.append({'path':directory,'error':type(error).__name__})
    for name in [*files,*[d for d in dirs if Path(directory,d).is_symlink()]]:
        path=os.path.join(directory,name)
        try:
            info=os.lstat(path)
        except OSError as error:
            errors.append({'path':path,'error':type(error).__name__});continue
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):continue
        identity=(info.st_dev,info.st_ino)
        if identity in seen:continue
        seen.add(identity)
        category='backups' if backup_pattern.search(path) else 'data' if path.startswith('/etc/mihomo/') else 'rootfs'
        totals[category]['allocated']+=info.st_blocks*512
        totals[category]['logical']+=info.st_size
        totals[category]['files']+=1
        if category=='backups':excluded.append(path)

samples=[]
for _ in range(5):
    samples.append(int(Path('/sys/fs/cgroup/memory.current').read_text()))
    time.sleep(1)
memory_stat=dict(line.split() for line in Path('/sys/fs/cgroup/memory.stat').read_text().splitlines())
events=dict(line.split() for line in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())
processes=[]
for directory in Path('/proc').iterdir():
    if not directory.name.isdigit() or int(directory.name)==os.getpid():continue
    try:
        args=(directory/'cmdline').read_bytes().split(b'\0')
        executable=Path(args[0].decode()).name if args[0] else ''
        if executable not in ('mihomo','sing-box','python3'):continue
        status=dict(line.split(':',1) for line in (directory/'status').read_text().splitlines() if ':' in line)
        processes.append({'name':executable,'pid':int(directory.name),'rss_kib':int(status.get('VmRSS','0 kB').split()[0])})
    except (OSError,ValueError,UnicodeError):continue

result={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'disk':totals,
        'without_backups_allocated':totals['rootfs']['allocated']+totals['data']['allocated'],
        'without_backups_logical':totals['rootfs']['logical']+totals['data']['logical'],
        'excluded_backup_files':excluded,'read_errors':errors,
        'memory_samples':samples,'memory_limit':int(Path('/sys/fs/cgroup/memory.max').read_text()),
        'memory_stat':{key:int(memory_stat.get(key,0)) for key in ['anon','file','kernel','slab','sock']},
        'memory_events':{key:int(value) for key,value in events.items()},'processes':processes}
print(json.dumps(result,ensure_ascii=False,indent=2))
