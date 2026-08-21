# Telegram

Репозиторий содержит готовые сетевые списки Telegram и автоматизированно поддерживаемый список DNS-имён.

## Готовые файлы

- [Telegram-CIDR.txt](Telegram-CIDR.txt) — IPv4/CIDR-сети Telegram.
- [Telegram_RouterOS.rsc](Telegram_RouterOS.rsc) — готовый address-list для RouterOS.
- [Telegram_DNS](Telegram_DNS) — актуальный список DNS-имён Telegram.

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
