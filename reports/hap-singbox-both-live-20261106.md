# hAP ac3: оба подключения на sing-box

6 ноября 2026. Владелец явно разрешил сетевые тесты, перевод FL и SV-inbound
на sing-box и включение обоих в балансировку.

В изолированном sing-box оба исходных профиля прошли по 3/3 HTTPS-проверки
https://www.gstatic.com/generate_204 с первого запуска, без REALITY-ошибок.
Это показало, что текущие конвертированные настройки и ML-KEM binary совместимы
с серверами. Прежний отказ панели сопровождался REALITY verification failed;
также наблюдалось объявление готовности 0/1 до успешного открытия listener.
Установленное ранее исправление ждёт доступности локальных портов до пробы.

Применение выполнено через штатную очередь панели:

- №19: FL -> sing-box, done, 15.54 секунды.
- №20: SV-inbound -> sing-box, done, 22.18 секунды.
- №21: включение обоих в балансировку, done, 16.60 секунды.

## Итоговые проверки рабочего экземпляра

- FL: 8/8 HTTPS HTTP 204 напрямую через его sing-box mixed-port.
- SV-inbound: 8/8 HTTPS HTTP 204 через его sing-box mixed-port.
- Через Mihomo provider healthcheck: SV 551/550/629 мс, FL 1028/997/1025 мс.
- Оба node.client=sing-box, node.balance=true.
- LOADBALANCE: CHANNEL-SV-inbound, CHANNEL-FL. SELECTOR=LOADBALANCE.
- Супервизор sing-box: ready=true, healthy=2, total=2.
- Версия: 1.14.4-local.mlkem1.
- memory.events high/max/oom/oom_kill = 0.

На проверенном интервале ошибок нет; это не гарантия отсутствия будущих
сетевых сбоев или несовместимых randomized TLS seed.

Сценарии: test-hap-singbox-isolated.py, verify-hap-singbox-live.py.
Результат: build/hap-ac3-clean/singbox-live-verified.json.
