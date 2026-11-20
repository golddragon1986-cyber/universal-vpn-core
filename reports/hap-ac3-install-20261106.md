# hAP ac3: чистая установка с RB4011, 6 ноября 2026

- RouterOS, wireless, container: 7.25.1, ARMv7.
- SSH: dragon@192.168.99.1 через IPsec к RB5009.
- WAN: ether1, 5.23.108.48, distance=1; LTE резерв distance=2.
- USB usb1-part1 отформатирован в ext4 с разрешения владельца.
- Swap: /usb1-part1/swapfile, 512 МиБ, активен.
- Контейнер universal-vpn-core: running, start-on-boot=yes.
- Root: /usb1-part1/containers/universal-vpn-rb4011-clean.
- Данные: /usb1-part1/universal-vpn-clean-data -> /etc/mihomo.
- memory-high=120M, memory-max=160M, swap-max=256M.
- Панель: http://192.168.99.1:19091/.
- API: http://192.168.99.1:19090/version.
- Тестовый HTTP/SOCKS: 192.168.99.1:11080.
- Доступ к контейнеру: только 192.168.99.0/24 и 192.168.8.0/23.
- Клиентские маршруты в VPN не переключались, профили не перенесены.

## Источник

Чистый экспорт системного ПО работающего universal-vpn-core с RB4011
10.0.0.3 и актуальных программных файлов из /etc/mihomo/rules.
Из rules перенесены только .py/.sh/.html/.css/.js. JSON, YAML, SQLite,
профили, сертификаты управления и секреты из тома данных не копировались.
Заводские шаблоны приложения остаются в образе для создания пустого состояния.

Экспортер: export-clean-4011.py. Сборка:

```powershell
$env:BUILD_OUTPUT='build/hap-ac3-clean'
$env:USE_LIVE_PANEL='1'
node build.mjs
```

Исходная локальная сборка сохранена. Ее импортированный экземпляр
universal-vpn-local-unused оставлен остановленным после отказа автоматической
проверки на удаление. Его том и root-dir не используются новым экземпляром.

## Проверки

- Панель HTTP 200, API v1.19.33, запрос example.com через прокси HTTP 200.
- Mihomo и основной файл панели совпадают с RB4011 по SHA256:
  - /mihomo: e9eaf8ad3467ca980af75abab56969ed7167b4d7a0dd63cd4a112004e4a39fcc
  - manage_ru_blocked.py: 39c1cff13d7f5437f720eaf92e4f41696290f720b2a32d90af94ae35adb2a632
- managed-proxies: nodes=[], service-routes=[]. Каталог clients отсутствует.
- memory.events: max=0, oom=0, oom_kill=0.
- Разовый замер: memory-current=77.2 МиБ, свободно на хосте 63.8 МиБ,
  swap-current контейнера 72 КиБ, container-size=87.6 МиБ.
- Это проверка пустого экземпляра, не нагрузочное испытание VPN.

SHA256 образа: eddc54b525cb5f6b0ebe6c00966455e5324dca5f08a746508786f15b316c3292.
Сборка и BUILD-INFO.json: build/hap-ac3-clean/.
