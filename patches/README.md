# sing-box 1.14.4: локальная совместимость REALITY / ML-KEM

База: официальный `SagerNet/sing-box`, tag `v1.14.4`, commit
`c005f35300ce76427dc285481ec5695f5b179cd2`.

`sing-box-1.14.4-reality-mlkem.patch` добавляет **локальную**, неофициальную
опцию `tls.reality.enable_mlkem`. Она отключена по умолчанию.
При `true` клиент сохраняет гибридную долю `X25519MLKEM768` в ClientHello;
если отдельного ECDHE-ключа нет, для REALITY-аутентификации используется
ECDHE-часть гибридной доли. Проверка серверного сертификата REALITY не менялась.
Без опции сохраняется поведение upstream; флаг переносится при Clone().

Это не параметр штатного sing-box: конфигурация с ним требует этой сборки.
Для текущей конфигурации используется `utls.fingerprint: "randomized"` и
`reality.enable_mlkem: true`. Первоначальный `chrome` повторил исторические
отказы под клиентской нагрузкой. Сравнение и восстановление описаны в
`reports/sing-box-randomized-recovery-20261104.md`. Поля UUID, SNI, public_key, short_id и flow
сохранены из исходных профилей.

## Воспроизведение

Нужен Go 1.25.5+ и исходники ровно указанного тега. Из корня проекта:

```sh
git clone --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git build/sing-box-source
cd build/sing-box-source
git apply ../../patches/sing-box-1.14.4-reality-mlkem.patch
cp ../../patches/reality_mlkem_test.go common/tls/
go test -tags with_utls ./common/tls -run TestRealityMLKEMClientHello -v
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -p 2 -trimpath -tags with_utls -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4-local.mlkem1' -o ../sing-box-1.14.4-mlkem-armv7 ./cmd/sing-box
```

Для Windows задайте эти переменные через `$env:...`. В данной проверке
использован Go 1.25.14. Загрузка зависимостей проверялась штатными go.sum;
зеркало `goproxy.cn` использовалось из-за зависания прямой загрузки.

Сборка минимальная, с `with_utls`, предназначена для проверенного
VLESS/REALITY. Это **не полный набор опциональных протоколов** официального
универсального бинарника sing-box.

## Проверки

`reality_mlkem_test.go` читает реальный ClientHello через net.Pipe:
в legacy-режиме нет ML-KEM, в hybrid-режиме он есть и расположен перед
отдельным X25519, если последний присутствует. Проверяется клонированная
конфигурация. Незавершённое рукопожатие не может считаться успешным.

На реальных серверах с намеренно неверными public_key оба соединения
отклонены. Основные сетевые результаты и ограничения описаны в
`reports/sing-box-mlkem-20261104.md`.

SHA256 собранного ARMv7 binary:
`c38fa0d889a53e014017f3ecffe3d92410deb3c4d9041cc9edc7f25242560715`.
Размер: 33 816 760 байт. Метаданные: `build/sing-box-mlkem-build.json`.

Штатное обновление через apk для локального binary блокируется, чтобы
не потерять исправление. Обновление требует новой сборки и повторной
проверки совместимости с серверами.
