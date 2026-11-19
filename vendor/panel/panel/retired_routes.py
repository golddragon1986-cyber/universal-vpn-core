"""Retain unavailable channel bindings while disabling their consumers."""
import json
from pathlib import Path
from durable_io import write
import router_routes as rr

def disable_missing(groups,names=()):
    available=set(groups)|set(names)|{'SELECTOR','DIRECT','LOADBALANCE','REJECT','PASS','BLOCK'}
    targets=rr.read_targets();changed=False
    for value in targets.values():
        if value.get('target','SELECTOR') not in available:
            if value.get('enabled',True) or not value.get('unavailable'):
                value.update(enabled=False,unavailable=True);changed=True
    if changed:write(rr.TARGETS,json.dumps(targets,ensure_ascii=False).encode())
    path=rr.ROOT/'rules/service-routes.json'
    if path.exists():
        rows=json.loads(path.read_bytes());changed=False
        for row in rows:
            if row.get('target') and row['target'] not in available and row.get('enabled',True):
                row.update(enabled=False,unavailable=True);changed=True
        if changed:write(path,json.dumps(rows,ensure_ascii=False).encode())
