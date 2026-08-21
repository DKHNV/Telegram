# Telegram

Репозиторий содержит материалы, связанные с сетевой обработкой трафика сервиса Telegram.
Здесь собраны данные и файлы, которые могут использоваться при построении правил маршрутизации, фильтрации, сегментации и сетевой политики.

## Готовые файлы

- [Telegram_RouterOS.rsc](Telegram_RouterOS.rsc) — файл с командами для роутеров MikroTik, позволяющий обновлять `address list` сервиса
- [Telegram_CIDR.txt](Telegram_CIDR.txt) — список IP-адресов и CIDR-диапазонов сервиса
- [Telegram_DNS](Telegram_DNS) — список доменных имён сервиса

## DNS maintenance

Обслуживание `Telegram_DNS` выполняется централизованно через [DKHNV/DNS-Maintenance](https://github.com/DKHNV/DNS-Maintenance).

Автоматика:

- ищет новые DNS-имена Telegram по открытым источникам;
- проверяет DNS через несколько независимых резолверов;
- допускает в DNS lifecycle только hostname с публичным unicast IPv4;
- ведёт состояния `pending`, `suspect`, `quarantine` и `expired`;
- отдельно наблюдает HTTPS/TLS, не используя его как основание для удаления DNS.

## Структура автоматизации

- `dns-maintenance-v1.json` — конфигурация Telegram для центрального движка;
- `dns/telegram/` — lifecycle state, discovery state, HTTPS/TLS state и отчёт;
- `.github/workflows/dns-maintenance.yml` — единственный production workflow DNS-Maintenance.

Локального исполняемого DNS-движка в этом репозитории больше нет: код обслуживания находится только в центральном `DNS-Maintenance`.

При этом `Telegram-CIDR.txt` и `Telegram_RouterOS.rsc` являются самостоятельными файлами проекта и не относятся к внутреннему DNS-движку.
