"""Apply the user's no-dashboard choice to this development instance only."""
import re
import shutil
from pathlib import Path

root=Path('/etc/mihomo')
package=Path('/usr/local/lib/mihomo-panel')
for name, source in [('initialize.py','initialize-no-dashboard.py'),('default-config.yaml','default-no-dashboard.yaml')]:
    (package/name).write_bytes((root/source).read_bytes())
(package/'ui-backend.js').unlink(missing_ok=True)
for name in ['default_config.yaml','default_config_candidate.yaml','template/default_config.yaml',
             'rules/panel-managed-template.yaml','default_config_candidate.yaml.last-good']:
    target=root/name
    if target.is_file():
        text=target.read_text()
        text=re.sub(r'^external-ui(?:-url|-name)?:.*\n?', '', text, flags=re.M)
        target.write_text(text)
ui=root/'ui'
if ui.is_symlink():
    raise RuntimeError('Refusing dashboard symlink')
if ui.exists():
    if ui.resolve()!=Path('/etc/mihomo/ui'):
        raise RuntimeError('Unexpected dashboard path')
    shutil.rmtree(ui)
print('MetaCubeXD removed; external-ui disabled')
