import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path
from urllib.parse import parse_qs
from durable_io import sync_dir,replace,write

class Recovery:
    def __init__(self,root="/etc/mihomo"):
        self.root=Path(root);self.base=self.root/"rules";self.pending=self.base/".pending-action"
        self.db=self.base/"configuration-jobs.sqlite3"
    def names(self,payload=None):
        import config_backup
        names=set(config_backup.FIXED)|set(config_backup.DATA_FILES)|set(config_backup.EXTRA)|{"rules/panel-managed-template.yaml","default_config_candidate.yaml.last-good"}
        names.update(config_backup.paths())
        if not payload or payload.get('path')!='/api/backup/restore':names.discard('rules/vpn-traffic-totals.json')
        if payload and payload.get("path")=="/action":
            action=parse_qs(payload.get("body","")).get("action",[""])[0]
            template=self.base/"panel-managed-template.yaml"
            if template.exists() and "  RU-BLOCKED-LOCAL:\n" in template.read_text():
                if action in ("add","enable","disable","delete") and not (self.base/"local-domain-dns.json").exists():
                    names={"rules/"+name for name in (
                        "ru-blocked-local-add.txt","ru-blocked-local-remove.txt","ru-blocked-local-delete.txt",
                        "ru-blocked-local.txt","ru-blocked-excluded.txt")}
                elif action.startswith(("service_","route_")):
                    names.difference_update("rules/"+name for name in (
                        "ru-blocked-source.txt","ru-blocked-domain.txt","ru-blocked-mihomo.mrs","ru-blocked-mihomo.yaml"))
        if payload and payload.get("path")=="/api/backup/restore":
            uploaded=json.loads(payload["body"])
            names.update(uploaded.get("config_files",{}))
        for name in names:
            if name not in config_backup.DATA_FILES and name!="default_config_candidate.yaml.last-good" and not config_backup.allowed(name):
                raise ValueError("Invalid transaction path")
        return sorted(names)
    def path(self,name):
        p=self.root/name
        if not p.resolve().is_relative_to(self.root.resolve()) or p.is_symlink():
            raise ValueError("Unsafe transaction path")
        return p
    def discard(self,path):
        if path.parent!=self.base or path.is_symlink() or not (path.name==".pending-action" or path.name.startswith(".pending-action-build-")):
            raise ValueError("Unsafe journal directory")
        shutil.rmtree(path);sync_dir(self.base)
    def recover(self):
        recovered=None
        if self.pending.exists():
            manifest=json.loads((self.pending/"manifest.json").read_text())
            state=None
            if self.db.exists():
                with sqlite3.connect(self.db) as db:
                    row=db.execute("SELECT status FROM jobs WHERE id=?",(manifest["job_id"],)).fetchone()
                    state=row[0] if row else None
            if state not in ("done","failed"):
                for item in manifest["files"]:
                    target=self.path(item["path"])
                    if not item["exists"]:
                        if target.exists():target.unlink();sync_dir(target.parent)
                        continue
                    source=self.pending/str(item["file"])
                    if source.parent!=self.pending or hashlib.sha256(source.read_bytes()).hexdigest()!=item["sha256"]:
                        raise ValueError("Incomplete operation journal")
                    target.parent.mkdir(parents=True,exist_ok=True)
                    fd,tmp=tempfile.mkstemp(prefix=".recover-",dir=target.parent)
                    try:
                        with os.fdopen(fd,"wb") as out,source.open("rb") as inp:
                            shutil.copyfileobj(inp,out);out.flush();os.fsync(out.fileno())
                        os.chmod(tmp,item["mode"]);replace(tmp,target)
                    finally:
                        if os.path.exists(tmp):os.unlink(tmp)
                recovered=manifest["job_id"]
            self.discard(self.pending)
        for path in self.base.glob(".pending-action-build-*"):
            if path.is_dir() and not path.is_symlink():self.discard(path)
        return recovered
    def begin(self,job_id,payload):
        self.recover()
        from storage_space import require
        names=self.names(payload)
        sizes=[self.path(name).stat().st_size for name in names if self.path(name).is_file()]
        require(self.base,sum(sizes)+max(sizes,default=0),'Подготовка резервной копии перед изменением')
        directory=Path(tempfile.mkdtemp(prefix=".pending-action-build-",dir=self.base))
        os.chmod(directory,0o700)
        try:
            items=[]
            for index,name in enumerate(names):
                source=self.path(name);item={"path":name,"exists":source.exists()}
                if source.exists():
                    if not source.is_file():raise ValueError("Expected a regular settings file")
                    dest=directory/str(index);digest=hashlib.sha256()
                    with source.open("rb") as inp,dest.open("wb") as out:
                        os.chmod(dest,0o600)
                        while True:
                            block=inp.read(65536)
                            if not block:break
                            out.write(block);digest.update(block)
                        out.flush();os.fsync(out.fileno())
                    item.update(file=index,sha256=digest.hexdigest(),mode=stat.S_IMODE(source.stat().st_mode))
                items.append(item)
            write(directory/"manifest.json",json.dumps({"job_id":job_id,"files":items}).encode())
            sync_dir(directory);os.replace(directory,self.pending);sync_dir(self.base)
        finally:
            if directory.exists():self.discard(directory)
    def flush(self,job_id):
        manifest=json.loads((self.pending/"manifest.json").read_text())
        if manifest["job_id"]!=job_id:raise ValueError("Operation journal mismatch")
        directories=set()
        for item in manifest["files"]:
            p=self.path(item["path"])
            if p.exists():
                with p.open("rb") as f:os.fsync(f.fileno())
            if p.parent.exists():directories.add(p.parent)
        for directory in directories:sync_dir(directory)
    def finish(self,job_id,state):
        if self.pending.exists():
            manifest=json.loads((self.pending/"manifest.json").read_text())
            if manifest["job_id"]!=job_id:raise ValueError("Operation journal mismatch")
            self.discard(self.pending)

    def abort(self,job_id):
        recovered=self.recover()
        if recovered is not None:
            from urllib.request import Request,urlopen
            request=Request("http://127.0.0.1:9090/configs?force=true",
                data=json.dumps({"path":str(self.root/"default_config_candidate.yaml")}).encode(),
                headers={"Content-Type":"application/json"},method="PUT")
            with urlopen(request,timeout=20):pass
            from routing_panel import read_settings,set_global_proxy
            set_global_proxy(read_settings()["main_proxy"])
