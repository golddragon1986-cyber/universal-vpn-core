# Universal VPN Core

Контейнер VPN для MikroTik RouterOS на ARMv7 и ARM64.

Через панель можно добавлять VPN-профили и подписки, выбирать каналы для клиентов, управлять маршрутами, DNS и правилами GeoDAT. Она показывает состояние подключений, журналы и счётчики трафика, позволяет сохранять настройки в резервную копию и обновлять компоненты и саму панель.

## Установка последнего релиза из GitHub

Перед установкой сохраните резервную копию конфигурации RouterOS на компьютер. Для контейнера нужны архитектура ARMv7 (`arm`) или ARM64 (`arm64`), пакет `container` и разрешения `container` и `fetch` в device mode. Проверить архитектуру и установленные пакеты можно в терминале роутера:

```routeros
/system/resource/print
/system/package/print
```

Если пакета `container` ещё нет, установите его **непосредственно с сервера MikroTik** (RouterOS 7.18 и новее). Выполните проверку обновлений, дождитесь её завершения и убедитесь, что `container` появился в списке доступных пакетов:

```routeros
/system/package/update/check-for-updates
/system/package/print where name=container
```

Затем запланируйте установку и примените её. Роутер скачает пакет и перезагрузится:

```routeros
/system/package/enable [find where name=container]
/system/package/apply-changes
```

После возвращения роутера проверьте, что `container` установлен и включён:

```routeros
/system/package/print where name=container
```

Если пакет уже был установлен и включён, пропустите его установку. Теперь проверьте device mode. Если `container` или `fetch` выключен, включите оба разрешения:

```routeros
/system/device-mode/print
/system/device-mode/update container=yes fetch=yes
```

**В течение 5 минут подтвердите изменение физически:** коротко нажмите кнопку Reset или Mode либо выключите и снова включите питание роутера. Не удерживайте Reset до сброса настроек. Обычная команда `/system/reboot` отменит ожидающее изменение. После подтверждения роутер перезагрузится; проверьте `/system/device-mode/print` — должны быть `container: yes` и `fetch: yes`. Если оба разрешения уже включены, команду `update` и физическое подтверждение пропустите. [Инструкция MikroTik по пакетам](https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Packages) и [device mode](https://manual.mikrotik.com/docs/system-information-and-utilities/device-mode/).

Теперь скачайте установщик текущего релиза в терминале роутера:

```routeros
/tool fetch url="https://raw.githubusercontent.com/golddragon1986-cyber/universal-vpn-core/main/scripts/install-latest.rsc" dst-path="install-latest.rsc" check-certificate=yes
/import file-name="install-latest.rsc"
```

Скрипт скачает образ для архитектуры роутера и четыре установочных скрипта из текущего выпуска. Он выведет путь к файлам и команды для проверки и запуска `01-install.rsc`. Прочитайте [полную инструкцию текущего релиза](version/0.31b.191126.1600/universal-vpn/README.md) до запуска установки.

Установщик рассчитан на новый экземпляр и останавливается при конфликте с существующим контейнером.

## Обновление панели

Панель проверяет [манифест обновлений](https://raw.githubusercontent.com/golddragon1986-cyber/universal-vpn-core/main/updates/panel/stable.json), скачивает `panel.tar.gz`, сверяет размер и SHA-256, сохраняет предыдущий код и может откатить неудачное обновление. Рабочие настройки и VPN-профили в этот архив не входят.

Начиная со следующего выпуска, архив панели будет прикрепляться к тому же релизу, что и контейнер. Для совместимости с уже выпущенным образом 0.31b служебный архив панели 0.3.1 остаётся доступным по прежней ссылке.

## Состав репозитория

- `vendor/panel/panel` — исходники панели.
- `scripts` — сборка и установка.
- `updates/panel` — версия и манифест обновления панели.
- `version/0.31b.191126.1600/universal-vpn` — документы и установочные скрипты текущего выпуска.

Образы ARMv7 и ARM64 скачиваются из [GitHub Releases](https://github.com/golddragon1986-cyber/universal-vpn-core/releases/latest). Испытание загрузки образа ARM64 на реальном устройстве в документации 0.31b не заявлено.
