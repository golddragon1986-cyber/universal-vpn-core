"""Check peak additional disk usage on each filesystem, preserving a reserve."""
import shutil
from pathlib import Path

RESERVE=4*1024*1024

def existing(path):
    path=Path(path)
    while not path.exists():
        parent=path.parent
        if parent==path:raise ValueError('Не удалось определить носитель для '+str(path))
        path=parent
    return path

def require_many(requests,operation='Операция',reserve=RESERVE):
    groups={}
    for path,size in requests:
        if not isinstance(size,int) or size<0:raise ValueError('Некорректная оценка размера файла')
        path=existing(path);device=path.stat().st_dev
        group=groups.setdefault(device,{'path':path,'size':0});group['size']+=size
    for group in groups.values():
        required=group['size']+reserve;free=shutil.disk_usage(group['path']).free
        if free<required:
            mib=1024*1024
            raise ValueError(f'{operation}: недостаточно свободного места на {group["path"]}. '
                             f'Нужно {required/mib:.1f} МиБ с резервом, доступно {free/mib:.1f} МиБ.')

def require(path,size,operation='Загрузка файла'):
    require_many([(path,size)],operation)

def binary_destination(component):
    return Path('/mihomo') if component=='mihomo' else Path('/usr/local/bin')/component

def binary_budget(component,directory,archive_size,unpacked_size):
    destination=binary_destination(component)
    old=destination.stat().st_size if destination.exists() else 0
    require_many([(directory,archive_size+unpacked_size),(destination.parent,old+unpacked_size)],
                 'Обновление '+component)
