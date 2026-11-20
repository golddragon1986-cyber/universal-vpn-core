"""Export installed software and panel source, never the mounted runtime state."""
import hashlib
import json
from pathlib import Path
import tarfile

out = Path('/etc/mihomo/hap-ac3-clean-base.tgz')
roots = ['mihomo', 'bin', 'sbin', 'lib', 'usr', 'etc/apk', 'etc/ssl',
         'etc/alpine-release', 'etc/passwd', 'etc/group', 'etc/protocols',
         'etc/services', 'etc/nsswitch.conf', 'var/lib/apk']
code = Path('/etc/mihomo/rules')
files = []

def clean(info):
    if '__pycache__' in info.name or info.name.endswith('.pyc'):
        return None
    if info.isfile():
        files.append(info.name)
    return info

with tarfile.open(out, 'w:gz', dereference=False) as archive:
    for name in roots:
        path = Path('/') / name
        if path.exists() or path.is_symlink():
            archive.add(path, arcname=name, filter=clean)
    # The running panel keeps updated program files on its data mount.
    # Only program extensions are eligible; no JSON/YAML/SQLite/profiles.
    for path in sorted(code.iterdir()):
        if path.is_file() and path.suffix in {'.py', '.sh', '.html', '.css', '.js'}:
            archive.add(path, arcname='usr/local/lib/mihomo-panel/panel/' + path.name,
                        filter=clean)
print(json.dumps({'archive': out.name, 'bytes': out.stat().st_size,
                  'sha256': hashlib.file_digest(out.open('rb'), 'sha256').hexdigest(),
                  'runtime_state_included': False, 'files': len(files)}))
