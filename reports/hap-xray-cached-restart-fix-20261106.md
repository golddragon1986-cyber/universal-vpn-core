# ac³: HTTP 503 при повторном выборе Xray

Диагностика: SV-inbound работал на Mihomo, в managed-proxies.json сохранены client_proxies.xray и client_ports.xray=18401. Xray установлен, panel-xray.json существует, но 127.0.0.1:18401 не слушал. В vpn_clients.select ветка сохранённого client_proxies возвращала локальный SOCKS-профиль без вызова ensure_runtime. Фоновый supervisor запускал клиента только по текущему managed client; до сохранения там Mihomo. Проверка соединения могла приходить раньше фонового запуска и получать HTTP 503.

Исправление: исключена отдельная ветка обхода build_external/validate/ensure_runtime при наличии кэшированного профиля. Любой выбор внешнего движка повторно собирает его конфигурацию из canonical connection, сохраняет существующий порт и обеспечивает запуск процесса до manager.save/sync/delay. Откат при ошибке сохранён.

Регрессионный тест test_cached_xray_is_rebuilt_and_started_before_healthcheck проверяет, что кэшированный Xray проходит сборку и валидацию, запускается до sync и healthcheck, и сохраняется как текущий движок. 14 тестов test_vpn_clients.py прошли на ac³ с изолированными временными файлами и mock runtime.

Установлены runtime /etc/mihomo/rules/vpn_clients.py и пакетный /usr/local/lib/mihomo-panel/panel/vpn_clients.py. Локальный исходник vendor/panel/panel/vpn_clients.py также исправлен. Резервная копия кода/managed DB/Xray/default config: /etc/mihomo/before-client-restart-fix-20261106 (содержит секреты, не публиковать).

После перезапуска контейнера выполнено реальное действие панели vpn_client SV-inbound xray: job 43, status done, 25,27 с. Соединение проверено, Xray использует firefox для REALITY/ML-KEM. SV-inbound оставлен на Xray; FL не переключался. Swap не включался, OOM 0. Панель HTTP 200. На RB4011 код этим действием не устанавливался.
