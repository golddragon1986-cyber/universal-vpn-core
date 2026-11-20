import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read = path => fs.readFile(path, 'utf8').then(text => text.replace(/\r\n/g, '\n'));
const commonOnly = process.argv.includes('--common-only');
const arm64Only = process.argv.includes('--arm64-only');
const common = 'ready-to-copy/universal/universal-vpn';
const releases = [['armv7','usb-release','container-7.25.1-arm.npk'],['arm64','usb-release-arm64','container-7.25.1-arm64.npk']];
const selectedReleases = commonOnly ? [] : releases.filter(([arch])=>!arm64Only || arch==='arm64');
const releaseDirectory = arch => 'ready-to-copy/'+arch+'/0.2b/universal-vpn';
const src = 'usb-release/internal-install';
const installBase = (await read(src+'/01-install.rsc')).replaceAll('uvpn-int','uvpn-main');
const restPreflight = (await read('vendor/routeros/rest-preflight.rsc')).trimEnd();
const dnsSeed = (await read('vendor/routeros/dns-seed.rsc')).trimEnd();
const restInstall = (await read('vendor/routeros/rest-install.rsc')).trimEnd();
const restRemove = (await read('vendor/routeros/rest-remove.rsc')).trimEnd();
const locations = `:local internal "universal-vpn"
:if ([:len [/file find where name="flash"]] > 0) do={ :set internal "flash/universal-vpn" }
:local disks [/disk find where mount-filesystem=yes]
`;
const markerName = 'universal-vpn.install-marker';
const installHead = `# Set lan only if your trusted interface list has another name.
:local lan "LAN"
:local clients "uvpn-main-lan"
:local tag "uvpn-main: base"
:local arch [/system resource get architecture-name]
:local tarName "universal-vpn-core-armv7.tar"
:local minimum 209715200
:if ($arch = "arm64") do={ :set tarName "universal-vpn-core-arm64.tar"; :set minimum 268435456 } else={
    :if ($arch != "arm") do={ :error "ARM or ARM64 RouterOS required" }
}
:if ([/system device-mode get container] != true) do={ :error "Enable container device-mode first" }
${locations}:local image ""
:local sourceBase ""
:local sourceDisk ""
:local hits 0
:local found ""
:local fallback ""
:local fallbackCount 0
:if ([:len [/file find where name=($internal . "/" . $tarName)]] = 1) do={
    :set sourceBase $internal
    :set hits 1
    :set found ($internal . "/" . $tarName)
}
:foreach disk in=$disks do={
    :local mount [/disk get $disk mount-point]
    :if ([:len $mount] > 0 && $mount != "flash") do={
        :local candidate ($mount . "/universal-vpn")
        :if ([:len [/file find where name=($candidate . "/" . $tarName)]] = 1) do={
            :set sourceBase $candidate
            :set sourceDisk $disk
            :set hits ($hits + 1)
            :set found ($found . " " . $candidate . "/" . $tarName)
        }
        :if ([/disk get $disk fs] = "ext4" && [/disk get $disk mount-read-only] = false && [/disk get $disk free] >= $minimum) do={
            :set fallback $candidate
            :set fallbackCount ($fallbackCount + 1)
        }
    }
}
:if ($hits = 0) do={ :error ("Image not found for RouterOS architecture " . $arch . ": " . $tarName) }
:if ($hits > 1) do={ :error ("Keep exactly one copy of " . $tarName . ". Found:" . $found) }
:set image ($sourceBase . "/" . $tarName)
:local base $sourceBase
:if ([:typeof $sourceDisk] != "id") do={
    :if ([/system resource get free-hdd-space] < $minimum) do={
        :if ($fallbackCount != 1) do={ :error "Internal storage is low; connect exactly one writable ext4 disk with sufficient free space" }
        :set base $fallback
    }
} else={
    :if ([/disk get $sourceDisk fs] != "ext4" || [/disk get $sourceDisk mount-read-only] = true || [/disk get $sourceDisk free] < $minimum) do={
        :error "Image disk must be writable ext4 with sufficient free space"
    }
}
:local root ($base . "/rootfs")
:local data ($base . "/data")
:local marker ($base . "/${markerName}")
:if ([:len [/file find where name=$marker]] > 0) do={ :error "Installation marker already exists; use 04-uninstall first" }
`;
let install = installHead + installBase.slice(installBase.indexOf(':if ([:len [/interface list'));
install = install.replace(/# Read independent upstream DNS before creating the container\.\n[\s\S]*?(?=:local firstFilter )/, dnsSeed + '\n');
if (!install.includes('UVPNC_PRIMARY_DNS')) {
  install = install.replace(':local firstFilter ', dnsSeed + '\n:local firstFilter ')
    .replace('    /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN value=1',
      '    /container envs add list=uvpn-main key=UVPNC_PRIMARY_DNS value=$routerDnsPrimary\n' +
      '    /container envs add list=uvpn-main key=UVPNC_MAIN_DNS value=$routerDnsMain\n' +
      '    /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN value=1')
    .replace('dns=1.1.1.1 ', 'dns=$routerDnsPrimary ');
}
install = install.replace('Existing internal installer','Existing installer')
  .replace(':onerror installError in={',`${restPreflight}
:if ([:len [/file find where name=$base]] = 0) do={ /file add name=$base type=directory }
/file add name=$marker type=file
:onerror installError in={`)
  .replace('    /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN_AUTO_REDIRECT value=0',
    '    :if ($arch = "arm") do={ /container envs add list=uvpn-main key=MIHOMO_PANEL_TUN_AUTO_REDIRECT value=0 }')
  .replace('    /container add name=',restInstall.split('\n').map(line=>'    '+line).join('\n')+'\n    /container add name=')
  .replace('        /container mounts remove',restRemove.split('\n').map(line=>'        '+line).join('\n')+'\n        /container mounts remove')
  .replace('        /interface veth remove [find where name="uvpn-main-veth"]',`        /interface veth remove [find where name="uvpn-main-veth"]
        :if ([:len [/file find where name=$root or name=$data]] = 0) do={
            :foreach id in=[/file find where name=$marker] do={ /file remove $id }
        }`)
  .replace('internal installation failed','installation failed')
  .replace(':put "Wait for extraction (status stopped), then start the container."',
    `:put ("Image: " . $image . ". Storage: " . $base . ". Waiting for container extraction...")
:local deadline ([/system resource get uptime] + 15m)
:local instance [/container find where name="universal-vpn-core" and interface="uvpn-main-veth"]
:if ([:len $instance] != 1) do={ :error "Installed container entry not found" }
:while ([:len [/container find where name="universal-vpn-core" and interface="uvpn-main-veth" and stopped=yes]] != 1) do={
    :if ([:len [/container find where name="universal-vpn-core" and interface="uvpn-main-veth"]] != 1) do={
        :error "Container entry disappeared during extraction"
    }
    :if ([/system resource get uptime] >= $deadline) do={
        :error "Container did not reach S (stopped) within 15 minutes; check /container print detail and the container log"
    }
    :delay 2s
}
:put "Container is ready to start (S - stopped)."`);
install = install.replace(/^        (\/(?:container|ip|interface)[^\n]+) remove \[find where ([^\n]+)\]$/gm,
  '        :foreach id in=[$1 find where $2] do={ $1 remove $id }');

const removeServiceRoutes = `:if ([:len [/routing table find where name="uvpn-main-direct"]] = 1) do={
    :foreach id in=[/ip route find where gateway="172.31.41.2" and comment="universal-vpn: service"] do={ /ip route remove $id }
    :foreach id in=[/routing rule find where table="uvpn-main-direct" and comment="universal-vpn: service return path"] do={ /routing rule remove $id }
}`;
const uninstall = (await read('vendor/routeros/uninstall.rsc'))
  .replace(':foreach base,present in=$bases do={\n    :local root (',removeServiceRoutes+'\n'+restRemove+'\n:foreach base,present in=$bases do={\n    :local root (');
const routing=(await read(src+'/02-enable-routing.rsc')).replaceAll('uvpn-int','uvpn-main').replace('Internal container not installed','Unified container not installed')
  .replace(' dst-address=198.18.0.0/16 out-interface=uvpn-main-br action=accept',' out-interface=uvpn-main-br action=accept')
  .replace(' src-address=198.18.0.0/16 dst-address-list=',' dst-address-list=');
const rollback=(await read(src+'/03-disable-routing.rsc')).replaceAll('uvpn-int','uvpn-main')
  .replace(':put "Routing rules removed.',removeServiceRoutes+'\n:put "Routing rules removed.');
await fs.mkdir(common,{recursive:true});
const checksums = [];
for (const [arch, release, npk] of releases){
  const imageName = 'universal-vpn-core-'+arch+'.tar';
  const imageBytes = await fs.readFile(release+'/'+imageName);
  await fs.writeFile(common+'/'+imageName,imageBytes);
  checksums.push(createHash('sha256').update(imageBytes).digest('hex')+'  '+imageName);
  if (!selectedReleases.some(([selected])=>selected===arch)) continue;
  const dst=releaseDirectory(arch);
  await fs.mkdir(dst,{recursive:true});
  for (const name of ['universal-vpn-core-'+arch+'.tar',npk,'BUILD-INFO.json','SHA256SUMS']){
    await fs.copyFile(release+'/'+name,dst+'/'+name);
  }
}
await fs.writeFile(common+'/SHA256SUMS',checksums.join('\n')+'\n');
for (const dst of [common,...selectedReleases.map(([arch])=>releaseDirectory(arch))]){
  for (const [name, contents] of Object.entries({'01-install.rsc':install,'02-enable-routing.rsc':routing,'03-disable-routing.rsc':rollback,'04-uninstall.rsc':uninstall})){
    // Verbose import parses each top-level statement in its own scope.
    await fs.writeFile(dst+'/'+name,'{\n'+contents.trimEnd()+'\n}\n');
  }
}

function importBlock(file, dryRun) {
  return `{
    :local scriptName "${file}"
    :local scriptPath ("universal-vpn/" . $scriptName)
    :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
    :local hits [:len [/file find where name=$scriptPath]]
    :foreach disk in=[/disk find where mount-filesystem=yes] do={
        :local mount [/disk get $disk mount-point]
        :if ([:len $mount] > 0 && $mount != "flash") do={
            :local candidate ($mount . "/universal-vpn/" . $scriptName)
            :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
        }
    }
    :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
    /import file-name=$scriptPath${dryRun ? ' verbose=yes dry-run' : ''}
}`;
}
for (const [arch, release, npk] of [...selectedReleases,['universal',...releases[1].slice(1)]]){
  const universal=arch==='universal';
  const name=(universal?'ARMv7 и ARM64':arch==='armv7'?'ARMv7':'ARM64')+' · 0.2b';
  const source=(await read(release+'/internal-install/README.md')).replaceAll('uvpn-int','uvpn-main');
  const sections=source.slice(source.indexOf('## 2. Установка'))
    .replace('На первом запуске ARM64 дождитесь регистрации пакетов Alpine. ', '')
    .replace(/^> :if \(\[:len \[\/file find where name="flash"\]\] > 0\) do=\{ \/import file-name=flash\/universal-vpn\/([^ ]+) (verbose=yes dry-run )?\} else=\{ [^\n]+$/gm,
      (_, file, dry) => importBlock(file, Boolean(dry)).split('\n').map(line=>'> '+line).join('\n'))
    .replace('Архив и установочные скрипты остаются во внутреннем хранилище.', 'Архив и установочные скрипты остаются на исходном носителе.')
    .replace(/В образ (?:включён сервис Telegram[^.]*|(?:ARM64|ARMv7) 0\.2b включены домены и сервис Telegram[^.]*)\. VPN-профили добавляются после установки\./,
      (universal ? 'Образ ARMv7 0.2b содержит домены и сервисы с RB4011, образ ARM64 0.2b — с hAP ax³.' :
        'В образ включены домены и сервисы из выгрузки '+(arch==='armv7'?'RB4011':'hAP ax³')+'.')+' VPN-профили добавляются после установки.')
    .replace('Дождитесь перехода из `E` (распаковка) в `S` (остановлен). Запустите контейнер:',
      'Установщик ждёт окончания распаковки и сообщает об успехе, когда контейнер переходит в `S` (остановлен). Если за 15 минут контейнер не перешёл в `S`, проверьте его статус и журнал контейнера. После успешного завершения запустите контейнер:')
    .replace('> /file print where name="flash/universal-vpn/rootfs" or name="universal-vpn/rootfs"\n> /file print where name="flash/universal-vpn/data" or name="universal-vpn/data"',
      '> /file print where name~"universal-vpn.install-marker"')
    .replace('Списки должны быть пустыми или содержать только заголовки.', 'Списки должны быть пустыми или содержать только заголовки. На носителе, указанном установщиком в строке Storage, проверьте, что каталоги `rootfs` и `data` исчезли.');
  if (sections.includes('/import file-name=flash/universal-vpn/')) throw new Error('An import still uses a fixed path');
  let prep=source.slice(source.indexOf('## 1. Подготовка'),source.indexOf('В **WinBox → Files** создайте каталог'))
    .replaceAll('../'+npk,npk)
    .replace('> /file print where name="flash"', '> /file print where name="flash"\n> /disk print');
  if (universal) prep=prep.replace(/^Ожидаемая архитектура RouterOS[^\n]*/m,
    'Если пакет `container` отсутствует, скачайте пакет для установленной версии RouterOS и архитектуры, указанной в `architecture-name` (`arm` или `arm64`). Загрузите NPK в корень списка **WinBox → Files** и перезагрузите роутер. [Загрузки MikroTik](https://mikrotik.com/download).');
  const heading=`# Установка Universal VPN Core · ${name}

Один комплект для внешнего диска и внутреннего хранилища MikroTik. ${universal ? 'Установщик читает `architecture-name` и выбирает `universal-vpn-core-armv7.tar` для `arm` или `universal-vpn-core-arm64.tar` для `arm64`. Оба образа можно держать в одной папке `universal-vpn`. Чтобы сэкономить место, достаточно скопировать четыре скрипта и TAR для вашего роутера. Если подходящего TAR нет или найдено несколько его копий, скрипт остановится до изменения настроек.' : 'Скопируйте папку `universal-vpn` целиком. Оставьте на роутере только одну копию комплекта данной архитектуры.'} Если на роутере осталась прежняя установка из USB-, внутреннего или универсального комплекта, выполните полное удаление из раздела 5. Полное удаление стирает рабочие данные.

`;
  const storage=`Скопируйте папку \`universal-vpn\` в корень внешнего диска ext4 или во внутреннее хранилище. ${universal ? 'На роутере должна быть одна копия каждого установочного скрипта. ' : ''}Для внутренней памяти используйте каталог \`flash\`, если он есть в WinBox → Files. Иначе используйте корень Files. [Документация MikroTik по хранилищу](https://manual.mikrotik.com/docs/system-information-and-utilities/files/#storage-details).

Установщик задаёт мягкий порог памяти контейнера **160 МиБ** и жёсткий лимит **200 МиБ**. Требуется версия RouterOS с поддержкой параметра \`memory-max\`.

Если архив находится во внутренней памяти и после копирования свободно меньше **200 МиБ**, установщик размещает \`rootfs\` и \`data\` на подходящем внешнем диске ext4. Для ARM64 действует запас **256 МиБ**, поэтому при меньшем остатке установщик также ищет внешний диск. Архив и скрипты остаются в исходной папке. Если архив сразу скопирован на внешний диск, используется этот диск. При недостатке места, нескольких подходящих внешних дисках для автоматического переноса или нескольких копиях образа скрипт остановится до изменения сетевых настроек.

Установщик настраивает HTTPS REST на порту 8443 для панели и ограничивает доступ адресом контейнера. Для установки служба www-ssl должна быть отключена и иметь штатные настройки порта, сертификата и доступных адресов. Маршруты из сервисов появятся после включения маршрутизации скриптом 02-enable-routing.rsc и синхронизации панели.

Используется список интерфейсов \`LAN\` и диапазоны \`10.0.0.0/8\`, \`172.16.0.0/12\` и \`192.168.0.0/16\`. Если список доверенных интерфейсов называется иначе, задайте одинаковое значение \`lan\` в обоих скриптах. Список \`WAN\` должен включать выходы в интернет. Подсети \`172.31.41.0/24\` и \`198.18.0.0/16\` должны быть свободны.

`;
  await fs.writeFile((universal ? common : releaseDirectory(arch))+'/README.md',heading+prep+storage+sections);
}
