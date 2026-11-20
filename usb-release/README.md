# Установка Universal VPN с USB

Комплект рассчитан минимально на MikroTik hAP ac³ (RouterOS 7+). Носитель остаётся в роутере. На нём лежат архив образа, распакованный контейнер `rootfs` и его рабочие данные `data`. Для первой установки нужен пустой каталог `universal-vpn` на разделе ext4 с запасом от 512 МиБ. Если Windows не открывает ext4, скопируйте файлы через WinBox → Files после подключения носителя к роутеру.

Образ ARMv7 0.2b содержит Mihomo, веб-панель, домены и сервис Telegram с девятью IPv4-сетями из выгрузки RB4011. VPN-профили добавляются после установки. Начальный режим панели — DIRECT. Маршрут Fake-IP на роутере и перехват DNS создаются отдельным скриптом.

## 1. Подготовка

Сохраните резервную копию RouterOS. Выполните в терминале MikroTik:

> ```routeros
> /system resource print
> /system package print
> /system device-mode print
> /disk print
> /interface list member print
> ```

Если на RouterOS отсутствует пакет `container`, загрузите пакет `container` в корень **внутреннего хранилища** через WinBox → Files и перезагрузите роутер.

Если указано `container: no`, выполните в терминале MikroTik:

> ```routeros
> /system device-mode update container=yes
> ```

Подтвердите изменение физически по подсказке RouterOS.

Скопируйте содержимое этой папки в каталог `universal-vpn` на флешке. В `01-install.rsc` задайте имя раздела, если оно отличается от `usb1-part1`. Если список доверенных интерфейсов называется иначе, задайте одинаковый `lan` в `01-install.rsc` и `02-enable-routing.rsc`. К панели, прокси и DNS допускаются клиенты из `10.0.0.0/8`, `172.16.0.0/12` и `192.168.0.0/16`, если трафик приходит через интерфейс из списка `LAN`.
Проверьте, что список `WAN` включает выходы в интернет и не пересекается с выбранным LAN. Подсети `172.31.41.0/24` и `198.18.0.0/16` должны быть свободны. Для роутера с существующим контейнером или policy routing сначала проверьте пересечения с его маршрутами, правилами mangle и RAW. Скрипты рассчитаны на маршрутизацию клиентов через таблицу `main`.

## 2. Установка и проверка

В командах замените `usb1-part1` на имя раздела из Files.

Проверьте скрипт в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/01-install.rsc verbose=yes dry-run
> ```

Если проверка прошла без ошибок, выполните в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/01-install.rsc
> /container print detail where name="universal-vpn-core"
> ```

Дождитесь, пока флаг `E` сменится на `S`, и запустите контейнер.

> ```routeros
> /container start [find where name="universal-vpn-core" and interface="uvpn-usb-veth"]
> /log print where message~"STARTUP READY"
> ```

С клиента из разрешённой сети проверьте доступность панели по адресу `http://172.31.41.2:9091/`. Для проверки DNS выполните на клиентском ПК:

> ```powershell
> nslookup example.com 172.31.41.2
> ```

Для доменов вне списков маршрутизации ожидается реальный IP вне `198.18.0.0/16`. Если нужен VPN, импортируйте свой профиль в панели и выберите его для нужного трафика. Пока панель в DIRECT, можно проверить установку и DNS.

## 3. Подключение клиентов

Проверьте состояние контейнера в терминале MikroTik:

> ```routeros
> /container print detail where name="universal-vpn-core"
> ```

Переходите к импорту, когда контейнер отмечен флагом `R`, а проверка DNS с клиента прошла.

Проверьте скрипт в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/02-enable-routing.rsc verbose=yes dry-run
> ```

Если проверка прошла без ошибок, выполните в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/02-enable-routing.rsc
> /ip route print detail where comment="uvpn-usb: routing"
> /ip firewall nat print stats where comment="uvpn-usb: routing"
> ```

Скрипт включает автозапуск контейнера, маршрут Fake-IP через него и перенаправление DNS TCP/UDP 53 для клиентов из разрешённых сетей через LAN. Настройки DHCP и DNS самого роутера остаются прежними. Клиентские запросы к локальным зонам роутера тоже попадут в Mihomo. Для проверки используйте клиент с обычным DNS IPv4 без DoH, DoT или IPv6 DNS.

## 4. Откат переключения

Выполните в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/03-disable-routing.rsc
> ```

Скрипт удаляет свои DNS-правила и маршрут Fake-IP. Обновите DNS-кэш и соединения клиентов. Панель, данные и автозапуск остаются доступны. При сбое распаковки до переключения клиентов проверьте лог и запись контейнера. Перед повторным чистым импортом удалите только созданные установщиком записи с меткой `uvpn-usb: base`, bridge `uvpn-usb-br`, veth `uvpn-usb-veth`, списки mount/env `uvpn-usb` и перенесите частично созданные `rootfs` и `data` из каталога релиза.

## 5. Полное удаление установки

`04-uninstall.rsc` отключает маршрутизацию через контейнер, удаляет контейнер, его сетевые настройки и рабочие каталоги `rootfs` и `data`. VPN-профили и другие данные в `data` будут удалены. Установочные файлы на флешке сохраняются.

Проверьте скрипт в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/04-uninstall.rsc verbose=yes dry-run
> ```

Если проверка прошла без ошибок, выполните в терминале MikroTik:

> ```routeros
> /import file-name=usb1-part1/universal-vpn/04-uninstall.rsc
> ```

При успешном удалении скрипт выводит `Universal VPN removed. USB release files retained.`

### Проверка после удаления

Выполните в терминале MikroTik:

> ```routeros
> /container print where name="universal-vpn-core"
> /interface print where name~"^uvpn-usb-"
> /ip address print where comment="uvpn-usb: base"
> /ip route print where comment="uvpn-usb: routing"
> /ip route print where dst-address="172.31.41.0/24"
> /ip route print where dst-address="198.18.0.0/16"
> /ip firewall nat print where comment~"^uvpn-usb:"
> /ip firewall filter print where comment~"^uvpn-usb:"
> /container mounts print where list="uvpn-usb"
> /container envs print where list="uvpn-usb"
> /ip firewall address-list print where list="uvpn-usb-lan"
> /file print where name="usb1-part1/universal-vpn/rootfs"
> /file print where name="usb1-part1/universal-vpn/data"
> /file print where name="usb1-part1/universal-vpn/universal-vpn-core-armv7.tar"
> ```

Проверки контейнера, его настроек и рабочих каталогов должны показать пустой список или только заголовки. Если есть маршрут с тем же префиксом от другой установки, проверьте его шлюз и назначение отдельно. Последняя команда должна показать архив образа.

Правила перенаправления DNS удалены, если проверка NAT не показывает записей с меткой `uvpn-usb:`. Настройки `/ip dns` и DHCP установщик не меняет. Выполните на клиентском ПК:

> ```powershell
> nslookup example.com
> ```

Запрос должен вернуть адрес через обычный DNS клиента. Если в выводе указан `172.31.41.2`, проверьте настройки DNS самого клиента и DHCP.
