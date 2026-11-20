# Установка Universal VPN Core · ARMv7 и ARM64 · 0.2b

Один комплект для внешнего диска и внутреннего хранилища MikroTik. Установщик читает `architecture-name` и выбирает `universal-vpn-core-armv7.tar` для `arm` или `universal-vpn-core-arm64.tar` для `arm64`. Оба образа можно держать в одной папке `universal-vpn`. Чтобы сэкономить место, достаточно скопировать четыре скрипта и TAR для вашего роутера. Если подходящего TAR нет или найдено несколько его копий, скрипт остановится до изменения настроек. Если на роутере осталась прежняя установка из USB-, внутреннего или универсального комплекта, выполните полное удаление из раздела 5. Полное удаление стирает рабочие данные.

## 1. Подготовка

Сохраните резервную копию RouterOS. Выполните в терминале MikroTik:

> ```routeros
> /system resource print
> /system package print
> /system device-mode print
> /file print where name="flash"
> /disk print
> /interface list member print
> ```

Если пакет `container` отсутствует, скачайте пакет для установленной версии RouterOS и архитектуры, указанной в `architecture-name` (`arm` или `arm64`). Загрузите NPK в корень списка **WinBox → Files** и перезагрузите роутер. [Загрузки MikroTik](https://mikrotik.com/download).

Если в Device Mode указано `container: no`, выполните в терминале MikroTik и подтвердите изменение по подсказке роутера:

> ```routeros
> /system device-mode update container=yes
> ```

Скопируйте папку `universal-vpn` в корень внешнего диска ext4 или во внутреннее хранилище. На роутере должна быть одна копия каждого установочного скрипта. Для внутренней памяти используйте каталог `flash`, если он есть в WinBox → Files. Иначе используйте корень Files. [Документация MikroTik по хранилищу](https://manual.mikrotik.com/docs/system-information-and-utilities/files/#storage-details).

Установщик задаёт мягкий порог памяти контейнера **160 МиБ** и жёсткий лимит **200 МиБ**. Требуется версия RouterOS с поддержкой параметра `memory-max`.

Если архив находится во внутренней памяти и после копирования свободно меньше **200 МиБ**, установщик размещает `rootfs` и `data` на подходящем внешнем диске ext4. Для ARM64 действует запас **256 МиБ**, поэтому при меньшем остатке установщик также ищет внешний диск. Архив и скрипты остаются в исходной папке. Если архив сразу скопирован на внешний диск, используется этот диск. При недостатке места, нескольких подходящих внешних дисках для автоматического переноса или нескольких копиях образа скрипт остановится до изменения сетевых настроек.

Установщик настраивает HTTPS REST на порту 8443 для панели и ограничивает доступ адресом контейнера. Для установки служба www-ssl должна быть отключена и иметь штатные настройки порта, сертификата и доступных адресов. Маршруты из сервисов появятся после включения маршрутизации скриптом 02-enable-routing.rsc и синхронизации панели.

Используется список интерфейсов `LAN` и диапазоны `10.0.0.0/8`, `172.16.0.0/12` и `192.168.0.0/16`. Если список доверенных интерфейсов называется иначе, задайте одинаковое значение `lan` в обоих скриптах. Список `WAN` должен включать выходы в интернет. Подсети `172.31.41.0/24` и `198.18.0.0/16` должны быть свободны.

## 2. Установка

Проверьте скрипт в терминале MikroTik:

> ```routeros
> {
>     :local scriptName "01-install.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath verbose=yes dry-run
> }
> ```

Если проверка прошла без ошибок, выполните:

> ```routeros
> {
>     :local scriptName "01-install.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath
> }
> /container print detail where name="universal-vpn-core"
> ```

Установщик ждёт окончания распаковки и сообщает об успехе, когда контейнер переходит в `S` (остановлен). Если за 15 минут контейнер не перешёл в `S`, проверьте его статус и журнал контейнера. После успешного завершения запустите контейнер:

> ```routeros
> /container start [find where name="universal-vpn-core" and interface="uvpn-main-veth"]
> /log print follow where topics~"container"
> ```

Дождитесь `STARTUP READY`, нажмите Ctrl+C и откройте [панель](http://172.31.41.2:9091/) с ПК из разрешённой сети. Проверьте DNS на клиентском ПК:

> ```powershell
> nslookup example.com 172.31.41.2
> ```

Домены вне списков маршрутизации должны получать реальный адрес вне `198.18.0.0/16`. Образ ARMv7 0.2b содержит домены и сервисы с RB4011, образ ARM64 0.2b — с hAP ax³. VPN-профили добавляются после установки.

## 3. Подключение клиентов

Когда контейнер запущен и DNS отвечает, проверьте скрипт в терминале MikroTik:

> ```routeros
> {
>     :local scriptName "02-enable-routing.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath verbose=yes dry-run
> }
> ```

После успешной проверки выполните:

> ```routeros
> {
>     :local scriptName "02-enable-routing.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath
> }
> /ip route print detail where comment="uvpn-main: routing"
> /ip firewall nat print stats where comment="uvpn-main: routing"
> ```

Ожидается маршрут `198.18.0.0/16` через `172.31.41.2`. Обычные IPv4 DNS-запросы клиентов по TCP/UDP 53 перенаправляются в контейнер. Настройки DHCP и DNS самого роутера сохраняются. Скрипт также включает автозапуск контейнера.

## 4. Откат маршрутизации

Выполните в терминале MikroTik:

> ```routeros
> {
>     :local scriptName "03-disable-routing.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath
> }
> ```

Контейнер и его данные сохраняются. Удаляются маршрут Fake-IP и правила перенаправления DNS.

## 5. Полное удаление

Скрипт удаляет контейнер, его настройки и каталоги `rootfs` и `data`, включая профили. Архив и установочные скрипты остаются на исходном носителе.

Проверьте скрипт в терминале MikroTik:

> ```routeros
> {
>     :local scriptName "04-uninstall.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath verbose=yes dry-run
> }
> ```

После успешной проверки выполните:

> ```routeros
> {
>     :local scriptName "04-uninstall.rsc"
>     :local scriptPath ("universal-vpn/" . $scriptName)
>     :if ([:len [/file find where name="flash"]] > 0) do={ :set scriptPath ("flash/" . $scriptPath) }
>     :local hits [:len [/file find where name=$scriptPath]]
>     :foreach disk in=[/disk find where mount-filesystem=yes] do={
>         :local mount [/disk get $disk mount-point]
>         :if ([:len $mount] > 0 && $mount != "flash") do={
>             :local candidate ($mount . "/universal-vpn/" . $scriptName)
>             :if ([:len [/file find where name=$candidate]] = 1) do={ :set scriptPath $candidate; :set hits ($hits + 1) }
>         }
>     }
>     :if ($hits != 1) do={ :error "Expected exactly one copy of the script in universal-vpn" }
>     /import file-name=$scriptPath
> }
> ```

После сообщения об успешном удалении проверьте состояние:

> ```routeros
> /container print where interface="uvpn-main-veth"
> /interface print where name~"^uvpn-main-"
> /ip address print where comment="uvpn-main: base"
> /ip route print where comment="uvpn-main: routing"
> /ip firewall nat print where comment~"^uvpn-main:"
> /ip firewall filter print where comment~"^uvpn-main:"
> /container mounts print where list="uvpn-main"
> /container envs print where list="uvpn-main"
> /ip firewall address-list print where list="uvpn-main-lan"
> /file print where name~"universal-vpn.install-marker"
> ```

Списки должны быть пустыми или содержать только заголовки. На носителе, указанном установщиком в строке Storage, проверьте, что каталоги `rootfs` и `data` исчезли. На клиентском ПК проверьте обычный DNS:

> ```powershell
> nslookup example.com
> ```
