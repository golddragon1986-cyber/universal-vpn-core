# hAP ac3: Fake IP, DNS и Telegram

6 ноября 2026, настройки применены к hAP 192.168.99.1.

- 198.18.0.0/16 направлен через 172.31.41.2.
- TUN включён постоянно в шаблоне панели; gvisor, auto-route=yes,
  auto-redirect=no. route-address синхронизирован с десятью маршрутами RouterOS.
- DNS RouterOS: 172.31.41.2; DNS DHCP LAN: 192.168.99.1.
- Клиентский UDP/TCP DNS на 53/5353/1253 направляется в контейнер, только
  для universal-vpn-access. Старые глобальные redirect отключены.
- Upstream DNS контейнера исключён из перехвата. DHCP WAN и LTE не добавляют
  DNS провайдеров. Входящий публичный DNS заблокирован с исключением IPsec.
- LAN-трафик в контейнер и обратные established/related соединения обходят
  FastTrack. Основной WAN и IPsec не переключались.
- Telegram: сервис в панели, LOADBALANCE, 21 доменное правило из
  https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram.
- Девять IPv4-сетей Telegram из https://core.telegram.org/resources/cidr.txt
  направлены через контейнер. В IPv6 маршруты не добавлялись: IPv6 в ядре выключен.
- Для исходящего трафика контейнера к этим сетям настроены правила возврата
  в uvpn-direct (WAN приоритет 1, LTE 2), чтобы исключить маршрутную петлю.
- Существующие профили SV-inbound и FL сохранены. Выбран LOADBALANCE;
  сервисные маршруты включены.

После явного разрешения владельца создана отдельная учётная запись панели
для RouterOS REST. HTTPS 8443 ограничен src=172.31.41.2, интерфейсом
container-universal, TLS 1.2 и сертификатом локального CA. Файл учётных данных
в контейнере имеет 0600; временный bootstrap с паролем на роутере удалён.
Приватная локальная копия установки: backups/hap-ac3-2026-11-06/private-rest.
Не публиковать эту папку.

## Проверено

- Telegram DNS: 198.18.0.42 через 192.168.99.1.
- HTTPS telegram.org с src-address=192.168.99.1 на роутере: HTTP 200.
- HTTPS Telegram через тестовый прокси: HTTP 200.
- Прямой адрес 149.154.167.99 с LAN-источником направляется в Meta TUN.
- Панель routes и services: HTTP 200.
- Панель получает live snapshot RouterOS, 10 маршрутов через контейнер.
- memory.events max/oom/oom_kill = 0; IPsec established.

Область настройки: LAN hAP 192.168.99.0/24. DNS по 192.168.99.1 также
доступен из доверенной сети RB5009 через IPsec, но глобальная маршрутизация
Fake IP за RB5009 не менялась.

Перед изменениями сохранён /flash/before-fakeip-20261106.rsc на роутере.
Сценарии: hap-fakeip-routing.rsc, prepare-hap-telegram.mjs,
configure-hap-fakeip.py, configure-hap-telegram.py, verify-hap-rest.py.
