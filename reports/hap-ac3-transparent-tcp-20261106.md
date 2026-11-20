# hAP ac3: прозрачный TCP, TUN для UDP

6 ноября 2026. Владелец явно разрешил постоянное включение для доверенных
локальных сетей и автозапуск. После просьбы проверять только работоспособность
дальнейшие проверки выполнялись короткими запросами, без измерения скорости.

## Схема

- RouterOS по прежним маршрутам направляет Fake IP и выбранные реальные сети
  в 172.31.41.2. Маршруты, DNS и VPN-профили не перестраивались.
- В контейнере legacy iptables PREROUTING перехватывает новые TCP с
  veth-universal от 192.168.99.0/24 и 192.168.8.0/23.
- Собственная цепочка UVPN_TCP делает RETURN для dst=172.31.41.2/32:
  DNS, панель и API на адресе контейнера не перехватываются.
- Остальные подходящие TCP получают REDIRECT на Mihomo redir-port 7893.
  SO_ORIGINAL_DST сохраняет адрес и порт назначения; Fake IP сопоставляет
  с доменом тот же Mihomo, который обслуживает DNS.
- UDP правилами NAT не затрагивается и продолжает идти через mixed TUN.
- Существующий mixed TUN оставлен также резервным путём, если opt-in
  transparent TCP при старте не настроится. Ошибка настройки не завершает
  entrypoint и не отключает само ядро.

## Совместимость ядра

nftables backend вернул Invalid argument. Установлен iptables-legacy 1.8.13
из Alpine вместе с libip4tc/libip6tc. Legacy NAT и REDIRECT в данном
контейнере работоспособны. Privileged mode не включался; имеющихся
capabilities достаточно. NAT RouterOS не заменялся контейнерным NAT.

Прямой dst-nat на RouterOS вместо внутреннего REDIRECT не использовался:
исходное назначение нужно восстановить в namespace контейнера.

## Постоянство

- redir-port: 7893 записан в runtime, candidate и оба шаблона.
- rules/transparent-tcp.json включает режим и содержит доверенные сети.
- transparent_tcp.py установлен в rules и package/panel.
- entrypoint применяет правила после boot_config.py; при ошибке пишет
  сообщение и сохраняет TUN fallback.
- config_backup.py включает marker JSON в export/restore и применяет
  соответствующие правила после восстановления конфигурации.
- Скрипт идемпотентен и меняет только собственную цепочку UVPN_TCP.
- Резерв до включения: /etc/mihomo/tcp-redirect-20261106/before-install/.

## Проверено после реального перезапуска контейнера

- Панель HTTP 200.
- Legacy UVPN_TCP и jump PREROUTING восстановились автоматически.
- HTTPS telegram.org с src-address=192.168.99.1: HTTP 200, сертификат проверен.
- DNS для STUN выдал Fake IP.
- Небольшой UDP STUN к stun.cloudflare.com:3478 получил корректный
  Binding Success Response с совпадающим transaction ID; inbound=Tun.
- В API наблюдались Redir/tcp=9, Tun/udp=2, Inner/tcp=1.
  TCP через Tun в этом снимке отсутствовал.
- Исключение собственного адреса и REDIRECT имеют сработавшие счётчики.
- Sing-box ready=true, healthy=2, total=2; оба VPN остаются на sing-box.

Google STUN при первоначальной проверке не ответил; это не использовалось
как свидетельство поломки UDP. Cloudflare STUN подтвердил путь до и после
перезапуска.

## Файлы

- vendor/panel/panel/transparent_tcp.py
- vendor/panel/entrypoint.sh
- vendor/panel/panel/config_backup.py
- install-hap-transparent-tcp.py
- hap-transparent-stage.py — первоначальный ограниченный тест/откат
- verify-hap-transparent.py
- build/hap-ac3-clean/transparent-functional-verification.json

Для повторной установки на другом образе предварительно требуется
`apk add --no-cache iptables-legacy`. Без opt-in JSON новый startup hook
не меняет сетевую конфигурацию других установок.
