# ac³: Xray, RETN Stockholm, лимит 16

Повтор той же методики: speedtest-go 1.8.3 на Windows → HTTP proxy 192.168.99.1:11080 → SV-inbound/Xray → Speedtest.net RETN Stockholm №32926. --thread=16, ping-mode=http, protocol=http. Для upload количество соединений адаптивное. API подтвердил HTTPS-цепочку SV-inbound / CHANNEL-SV-inbound. Xray выбран после исправления повторного запуска клиента; REALITY fingerprint firefox.

Download 3 958 317,660 байт/с = 31,67 Мбит/с. Upload 2 312 590,136 байт/с = 18,50 Мбит/с. Latency 163,84 мс, jitter 69,29 мс. Общая CPU в коротких снимках 7/12/54/96/95/95/38/60/85/63%; пик 96%, максимум ядра 100%. Это не непрерывный профиль; короткие последовательные тесты не доказывают устойчивое преимущество одного движка, хотя в этом запуске Xray медленнее.

Предыдущие значения на том же сервере с лимитом 16: Mihomo 56,14/84,70 Мбит/с download/upload, пик CPU 92%; sing-box 48,26/59,12 Мбит/с, пик CPU 97%. Swap во всех этих запусках отключён. Временное правило после проверки снято, Xray оставлен выбранным, панель доступна.

Артефакт: build/hap-ac3-clean/stockholm-retn-16-xray-speedtest.json.
