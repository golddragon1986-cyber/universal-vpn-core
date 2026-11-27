"""Archive only panel code files from the running AX3 container."""

import hashlib
import json
from pathlib import Path
import tarfile

source = Path('/etc/mihomo/rules')
output = source / 'live-panel-0.42b.tgz'
extensions = {'.py', '.js', '.html', '.css', '.sh'}
files = sorted(path for path in source.iterdir()
               if path.is_file() and not path.is_symlink()
               and path.suffix in extensions
               and path.name != 'snapshot-live-panel.py')
if not files or any(path.stat().st_size > 2_000_000 for path in files):
    raise RuntimeError('unexpected panel file set')
with tarfile.open(output, 'w:gz') as archive:
    for path in files:
        archive.add(path, arcname='panel/' + path.name, recursive=False)
print(json.dumps({'files': len(files), 'bytes': output.stat().st_size,
                  'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                  'names': [path.name for path in files]}))
