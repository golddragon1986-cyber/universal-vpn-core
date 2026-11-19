import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vendor' / 'panel' / 'panel'
EXTENSIONS = {'.py', '.js', '.html', '.css', '.sh'}


def main():
    if len(sys.argv) != 3 or not re.fullmatch(r'\d+\.\d+\.\d+', sys.argv[1]):
        raise SystemExit('Usage: build-panel-release.py VERSION OUTPUT.tar.gz')
    version, output = sys.argv[1], Path(sys.argv[2])
    files = []
    for path in sorted(SOURCE.iterdir()):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        raw = path.read_bytes()
        files.append((path.name, raw))
    if not files:
        raise SystemExit('Panel source files were not found')
    release = {'version': version, 'files': [
        {'name': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
         'mode': 0o755 if Path(name).suffix.lower() == '.sh' else 0o644}
        for name, raw in files
    ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
        manifest = json.dumps(release, sort_keys=True, separators=(',', ':')).encode()
        info = tarfile.TarInfo('panel/panel-release.json')
        info.size = len(manifest)
        info.mode = 0o644
        import io
        archive.addfile(info, io.BytesIO(manifest))
        for name, raw in files:
            info = tarfile.TarInfo('panel/' + name)
            info.size = len(raw)
            info.mode = 0o755 if Path(name).suffix == '.sh' else 0o644
            archive.addfile(info, io.BytesIO(raw))
    print(json.dumps({'version': version, 'archive': str(output), 'size': output.stat().st_size,
                      'sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'files': len(files)}))


if __name__ == '__main__':
    main()
