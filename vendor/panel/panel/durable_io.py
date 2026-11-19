import os
import tempfile
from pathlib import Path

def sync_dir(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def replace(source,target):
    from configuration_draft import capture_write
    if capture_write(target,Path(source).read_bytes()):
        os.unlink(source);return
    fd=os.open(source,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    os.replace(source,target)
    sync_dir(Path(target).parent)

def write(path,data,mode=0o600):
    from configuration_draft import capture_write
    if capture_write(path,data):return
    path=Path(path)
    fd,tmp=tempfile.mkstemp(prefix=".durable-",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
