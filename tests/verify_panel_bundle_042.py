"""Validate the 0.42b archive with the updater installed on AX3, without installing it."""

from pathlib import Path
import sys
import tempfile

sys.path.insert(0, '/etc/mihomo/rules')
from panel_updater import _extract

archive = Path('/etc/mihomo/rules/panel-042b-verify.tar.gz')
with tempfile.TemporaryDirectory(prefix='.panel-042b-verify-', dir='/etc/mihomo/rules') as folder:
    expected = _extract(archive, Path(folder), '0.4.2')
    if len(expected) != 71:
        raise AssertionError(f'expected 71 files, got {len(expected)}')
    print(f'panel updater accepted {len(expected)} files')
