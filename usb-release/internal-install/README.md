# Установка Universal VPN во внутреннее хранилище

Комплект для MikroTik **ARMv7** с поддержкой контейнеров. TAR, распакованный контейнер `rootfs` и рабочие данные `data` хранятся во внутренней памяти роутера. После загрузки TAR установщик требует не менее **150 МиБ** свободного места для распаковки и работы. На моделях с меньшим объёмом используйте USB-комплект. MikroTik рекомендует внешний диск для контейнеров, чтобы снизить нагрузку на встроенный накопитель. [Рекомендации MikroTik](https://manual.mikrotik.com/docs/containers/).

## 1. Подготовка

Сохраните резервную копию RouterOS. Выполните в терминале MikroTik:

> ```routeros
> /system resource print
> /system package print
> /system device-mode print
> /file print where name="flash"
> /interface list member print
> ```

Ожидаемая архитектура RouterOS — `arm`. Если пакет `container` отсутствует, загрузите NPK соответствующей архитектуры и версии RouterOS в корень списка **WinBox → Files** и перезагрузите роутер. Для RouterOS 7.25.1 в комплекте есть [пакет ARMv7](../container-7.25.1-arm.npk).

Если в Device Mode указано `container: no`, выполните в терминале MikroTik и подтвердите изменение по подсказке роутера:

> ```routeros
> /system device-mode update container=yes
> ```

В **WinBox → Files** создайте каталог `universal-vpn` внутри `flash`, если `flash` есть в списке. Иначе создайте `universal-vpn` в корне Files. Если `flash` есть, файлы вне него хранятся в RAM и пропадают при перезагрузке. [Документация MikroTik по Files](https://manual.mikrotik.com/docs/system-information-and-utilities/files/#storage-details).

Загрузите в этот каталог [образ ARMv7](../universal-vpn-core-armv7.tar) и четыре файла `.rsc` из папки этой инструкции. Команды ниже сами выбирают путь с `flash` или без него. Если список доверенных интерфейсов называется иначе, задайте одинаковый `lan` в `01-install.rsc` и `02-enable-routing.rsc`. К панели, прокси и DNS допускаются клиенты из `10.0.0.0/8`, `172.16.0.0/12` и `192.168.0.0/16`, если трафик приходит через интерфейс из списка `LAN`.

Список `WAN` должен включать интерфейсы выхода в интернет. Подсети `172.31.41.0/24` и `198.18.0.0/16` должны быть свободны. Если на роутере уже установлена USB-версия Universal VPN, сначала удалите её скриптом из USB-комплекта. Полное удаление стирает рабочие данные старой установки.

## 2. Установка

Проверьте скрипт в терминале MikroTik:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/01-install.rsc verbose=yes dry-run } else={ /import file-name=universal-vpn/01-install.rsc verbose=yes dry-run }
> ```

Если проверка прошла без ошибок, выполните:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/01-install.rsc } else={ /import file-name=universal-vpn/01-install.rsc }
> /container print detail where name="universal-vpn-core"
> ```

Дождитесь перехода из `E` (распаковка) в `S` (остановлен). Запустите контейнер:

> ```routeros
> /container start [find where name="universal-vpn-core" and interface="uvpn-int-veth"]
> /log print follow where topics~"container"
> ```

Дождитесь `STARTUP READY`, нажмите Ctrl+C и откройте [панель](http://172.31.41.2:9091/) с ПК из разрешённой сети. Проверьте DNS на клиентском ПК:

> ```powershell
> nslookup example.com 172.31.41.2
> ```

Домены вне списков маршрутизации должны получать реальный адрес вне `198.18.0.0/16`. В образ ARMv7 0.2b включены домены и сервис Telegram с девятью IPv4-сетями из выгрузки RB4011. VPN-профили добавляются после установки.

## 3. Подключение клиентов

Когда контейнер запущен и DNS отвечает, проверьте скрипт в терминале MikroTik:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/02-enable-routing.rsc verbose=yes dry-run } else={ /import file-name=universal-vpn/02-enable-routing.rsc verbose=yes dry-run }
> ```

После успешной проверки выполните:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/02-enable-routing.rsc } else={ /import file-name=universal-vpn/02-enable-routing.rsc }
> /ip route print detail where comment="uvpn-int: routing"
> /ip firewall nat print stats where comment="uvpn-int: routing"
> ```

Ожидается маршрут `198.18.0.0/16` через `172.31.41.2`. Обычные IPv4 DNS-запросы клиентов по TCP/UDP 53 перенаправляются в контейнер. Настройки DHCP и DNS самого роутера сохраняются. Скрипт также включает автозапуск контейнера.

## 4. Откат маршрутизации

Выполните в терминале MikroTik:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/03-disable-routing.rsc } else={ /import file-name=universal-vpn/03-disable-routing.rsc }
> ```

Контейнер и его данные сохраняются. Удаляются маршрут Fake-IP и правила перенаправления DNS.

## 5. Полное удаление

Скрипт удаляет контейнер, его настройки и каталоги `rootfs` и `data`, включая профили. Архив и установочные скрипты остаются во внутреннем хранилище.

Проверьте скрипт в терминале MikroTik:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/04-uninstall.rsc verbose=yes dry-run } else={ /import file-name=universal-vpn/04-uninstall.rsc verbose=yes dry-run }
> ```

После успешной проверки выполните:

> ```routeros
> :if ([:len [/file find where name="flash"]] > 0) do={ /import file-name=flash/universal-vpn/04-uninstall.rsc } else={ /import file-name=universal-vpn/04-uninstall.rsc }
> ```

После сообщения об успешном удалении проверьте состояние:

> ```routeros
> /container print where interface="uvpn-int-veth"
> /interface print where name~"^uvpn-int-"
> /ip address print where comment="uvpn-int: base"
> /ip route print where comment="uvpn-int: routing"
> /ip firewall nat print where comment~"^uvpn-int:"
> /ip firewall filter print where comment~"^uvpn-int:"
> /container mounts print where list="uvpn-int"
> /container envs print where list="uvpn-int"
> /ip firewall address-list print where list="uvpn-int-lan"
> /file print where name="flash/universal-vpn/rootfs" or name="universal-vpn/rootfs"
> /file print where name="flash/universal-vpn/data" or name="universal-vpn/data"
> ```

Списки должны быть пустыми или содержать только заголовки. На клиентском ПК проверьте обычный DNS:

> ```powershell
> nslookup example.com
> ```
