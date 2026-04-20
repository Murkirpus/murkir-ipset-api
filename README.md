# murkir-ipset-api

Минималистичный PHP API + веб-интерфейс для блокировки IP через `ipset` с авто-разбаном по таймауту. Часть экосистемы **MurKir Security**.

Блокирует IPv4 и IPv6 на уровне INPUT-цепочки ядра Linux. Один файл, одна зависимость (`ipset`), никаких крон-задач для очистки — ядро само снимает баны по истечении таймаута.

---

## Почему ipset, а не iptables напрямую

При работе с тысячами заблокированных IP обычные правила `iptables -I INPUT -s X -j DROP` быстро деградируют — каждый пакет линейно проверяется против списка. `ipset` использует хэш-таблицу в ядре: проверка O(1) независимо от размера списка.

**Плюс авто-разбан:** у каждой записи свой `timeout`, ядро удаляет просроченные элементы само. Никакого `cron`, никакого `at`, никакого `cleanup.php`.

## Возможности

- 🔥 Блокировка IPv4/IPv6 через единый API
- ⏱️ Таймаут бана задаётся индивидуально при блокировке (по умолчанию 1 час)
- 🧹 Авто-разбан выполняет ядро — без внешних скриптов
- 🌐 Веб-интерфейс с тремя вкладками: блокировка, список, статистика
- 📊 Отображение оставшегося времени бана для каждого IP
- 🛡️ Защита от injection (`filter_var` + `escapeshellarg`)
- 🔐 Timing-safe сравнение API-ключа (`hash_equals`)
- 📦 Один PHP-файл, без composer, совместим с PHP 5.6–8.3
- ⚡ Ленивая инициализация: сеты и правила создаются при первом запросе
- 🔄 Переживает перезагрузку — при старте PHP пересоздаёт сеты автоматически

## Требования

- Linux с поддержкой `xt_set` (все современные дистрибутивы)
- `ipset` — `apt install ipset` / `yum install ipset`
- `iptables` и `ip6tables` (как правило уже есть)
- PHP 5.6+ (CLI или через веб-сервер)
- Права на выполнение `sudo ipset/iptables/ip6tables` от имени пользователя веб-сервера

## Установка

```bash
# 1. Зависимости
sudo apt install -y ipset

# 2. Клонирование
cd /var/www/your-site/
git clone https://github.com/Murkirpus/murkir-ipset.git dos
cd dos

# 3. API-ключ
openssl rand -hex 24
# Скопируй результат в settings.php → API_BLOCK_KEY

# 4. sudoers — пользователь веб-сервера должен выполнять ipset без пароля
sudo tee /etc/sudoers.d/iptables-api > /dev/null <<'EOF'
Cmnd_Alias IPSET_CMDS = /usr/sbin/ipset, /sbin/ipset, /bin/ipset
Cmnd_Alias IPT4_CMDS  = /sbin/iptables, /usr/sbin/iptables
Cmnd_Alias IPT6_CMDS  = /sbin/ip6tables, /usr/sbin/ip6tables
www-data ALL=(root) NOPASSWD: IPSET_CMDS, IPT4_CMDS, IPT6_CMDS
EOF
sudo chmod 440 /etc/sudoers.d/iptables-api
sudo visudo -cf /etc/sudoers.d/iptables-api  # проверка синтаксиса
```

Замени `www-data` на пользователя, под которым работает PHP-FPM (`nginx`, `apache`, и т.д.).

## Использование

### Веб-интерфейс

Открой в браузере:
```
https://your-site.com/dos/iptables.php?api_key=ВАШ_КЛЮЧ
```

Три вкладки: **Блокировка** (ручной ввод IP и таймаута), **Список IP** (заблокированные с оставшимся временем), **Статистика** (счётчики).

### API

Все эндпоинты принимают GET и POST. Добавь `&api=1` к URL, чтобы получить JSON вместо HTML.

**Заблокировать IP на 1 час (дефолт):**
```bash
curl "https://your-site.com/dos/iptables.php?action=block&ip=1.2.3.4&api=1&api_key=КЛЮЧ"
```

**Заблокировать на произвольный таймаут (секунды):**
```bash
curl "https://your-site.com/dos/iptables.php?action=block&ip=1.2.3.4&timeout=7200&api=1&api_key=КЛЮЧ"
```

**Разблокировать:**
```bash
curl "https://your-site.com/dos/iptables.php?action=unblock&ip=1.2.3.4&api=1&api_key=КЛЮЧ"
```

**Список заблокированных:**
```bash
curl "https://your-site.com/dos/iptables.php?action=list&api=1&api_key=КЛЮЧ"   # IPv4
curl "https://your-site.com/dos/iptables.php?action=list6&api=1&api_key=КЛЮЧ"  # IPv6
```

**Очистить все баны:**
```bash
curl "https://your-site.com/dos/iptables.php?action=clear&api=1&api_key=КЛЮЧ"
```

**Отладка (правила + сеты):**
```bash
curl "https://your-site.com/dos/iptables.php?action=debug&api=1&api_key=КЛЮЧ"
```

### Пример на PHP

```php
function banIp(string $ip, int $seconds = 3600): array {
    $url = 'https://your-site.com/dos/iptables.php';
    $data = http_build_query([
        'action'  => 'block',
        'ip'      => $ip,
        'timeout' => $seconds,
        'api'     => 1,
        'api_key' => 'ВАШ_КЛЮЧ',
    ]);
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => 'Content-Type: application/x-www-form-urlencoded',
        'content' => $data,
        'timeout' => 3,
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    return json_decode($body, true) ?: ['status' => 'error'];
}

// Прогрессивный бан: первый раз 10 минут, повторно — час, потом сутки
banIp('1.2.3.4', 600);
banIp('1.2.3.4', 3600);
banIp('1.2.3.4', 86400);
```

## Структура JSON-ответов

**block:**
```json
{
  "status": "success",
  "message": "IP 1.2.3.4 заблокирован на 1 ч",
  "details": "Set: banlist4, timeout: 3600 сек"
}
```

**list / list6:**
```json
{
  "status": "success",
  "version": "IPv4",
  "set": "banlist4",
  "count": 2,
  "blocked_ips": ["1.2.3.4", "5.6.7.8"],
  "blocked_details": [
    {
      "ip": "1.2.3.4",
      "ports": ["all"],
      "remaining": 3412,
      "remaining_human": "56 мин 52 сек"
    }
  ]
}
```

Поле `status` бывает `success`, `warning`, `error`. Проверяй именно его — текст `message` может меняться.

## Конфигурация

`settings.php`:

```php
<?php
// Обязательно
define('API_BLOCK_KEY', 'your-strong-key-here');

// Опционально (дефолты в iptables.php)
// define('BAN_TIMEOUT', 3600);           // таймаут по умолчанию, сек
// define('IPSET_V4', 'banlist4');        // имена сетов
// define('IPSET_V6', 'banlist6');
// define('IPSET_MAXELEM', 1000000);      // предел записей в сете
```

## Безопасность

- **API-ключ обязателен** — без него 403 на любой запрос, включая веб-интерфейс
- **`hash_equals`** защищает от timing-атак при сравнении ключа
- **`filter_var(FILTER_VALIDATE_IP)`** отсекает всё, что не является валидным IP, до передачи в shell
- **`escapeshellarg`** экранирует параметр для команды
- Для публичного доступа к интерфейсу настрой доп. защиту (Basic Auth в nginx, VPN, IP-allowlist)

## Как это работает

При первом запросе к API скрипт проверяет и при необходимости создаёт:
1. `ipset create banlist4 hash:ip timeout 3600 maxelem 1000000`
2. `ipset create banlist6 hash:ip family inet6 timeout 3600 maxelem 1000000`
3. `iptables -I INPUT -m set --match-set banlist4 src -j DROP`
4. `ip6tables -I INPUT -m set --match-set banlist6 src -j DROP`

Блокировка IP:
- `ipset add banlist4 1.2.3.4 timeout 3600 -exist`

Ядро хранит запись ровно указанное время, после чего удаляет. Никакой дополнительной работы на уровне приложения не требуется.

После перезагрузки сервера сеты пропадают (живут в памяти ядра) — при первом запросе к API они создаются заново с пустым содержимым. Если хочешь сохранять баны между ребутами — добавь `ipset save` в systemd unit.

## FAQ

**Почему файл называется `iptables.php`, а не `ipset.php`?**
Совместимость со старыми интеграциями. С точки зрения API-клиента это всё ещё «блокировщик через iptables» — деталь реализации (ipset) для клиента неважна.

**Что будет при перезагрузке сервера?**
Сеты и правила пропадут вместе с памятью ядра. Скрипт создаст их заново при первом запросе — с пустым списком IP. Это задумано: обычно после ребута перебаниваешь актуальных нарушителей через несколько минут трафика.

**Как продлить бан?**
Просто вызови `block` с тем же IP ещё раз — старый таймаут перезапишется на новый. Флаг `-exist` делает операцию идемпотентной.

**Сколько IP можно держать в сете?**
До 1 000 000 по умолчанию (параметр `maxelem`). Каждая запись ~40 байт — миллион IP займут около 40 МБ в ядре. Проверка пакета O(1) при любом размере.

**Можно ли сделать постоянный бан?**
Да, создай параллельный сет без timeout: `ipset create banlist4_perm hash:ip`. В этом случае добавь второе правило в INPUT. В текущей версии эта функциональность не встроена — форкни и добавь.

## Тесты

В репозитории 72 теста покрывают:
- Безопасность (API-ключ, timing-атаки, injection)
- Валидацию IP (IPv4/IPv6, битые форматы, shell-метасимволы)
- Все эндпоинты (block/unblock/list/clear/debug)
- Парсинг вывода `ipset list`
- HTML-интерфейс (рендер, Content-Type)
- GET vs POST

Запуск тестов с моками:
```bash
cd tests/
./run.sh
```

## Требования

Минимальный набор для работы `iptables.php`. Все проверки автоматизированы на вкладке **🔍 Диагностика** — при первом открытии UI она покажет что не так и как исправить.

### Операционная система

- **Linux** с ядром 3.13+ (Ubuntu 14.04+, Debian 8+, CentOS 7+, RHEL 7+, Alpine 3.x)
- Поддержка netfilter в ядре — есть по умолчанию во всех дистрибутивах
- Модуль ядра `xt_set` — загружается автоматически при первом использовании `ipset`, или вручную: `sudo modprobe xt_set`

Не подходит: shared-хостинги без доступа к `sudo` и iptables, контейнеры без `CAP_NET_ADMIN`, Windows.

### Пакеты

```bash
# Ubuntu / Debian
sudo apt install ipset iptables sudo

# CentOS / RHEL / AlmaLinux / Rocky
sudo yum install ipset iptables sudo

# Alpine
apk add ipset iptables sudo
```

`iptables` и `ip6tables` обычно уже установлены в системе.

### PHP

- **Версия: 5.6 или новее** (протестировано на 5.6, 7.0–7.4, 8.0–8.3)
- **Расширения** — все стандартные, отдельно ставить ничего не нужно:
  - `ext/filter` (проверка IP через `filter_var`)
  - `ext/hash` (timing-safe сравнение ключа через `hash_equals`)
  - `ext/json` (кодирование ответов API)
  - `ext/posix` — опционально, для определения реального пользователя PHP в диагностике

### Функции PHP, которые должны быть доступны

Проверь `php.ini` → директиву `disable_functions`. Эти функции **не должны** быть в списке:

| Функция | Зачем нужна | Критично? |
|---|---|---|
| `exec` | Выполнение команд `ipset`/`iptables` | ❌ без неё скрипт не работает |
| `escapeshellarg` | Экранирование IP в shell-команде | ❌ защита от injection |
| `filter_var` | Валидация IPv4/IPv6 | ❌ |
| `hash_equals` | Защита API-ключа от timing-атак | ⚠️ желательно |
| `posix_geteuid` | Определение пользователя PHP в диагностике | ⚠️ опционально |

**Что можно отключать без проблем** (наоборот, рекомендуется отключать для безопасности): `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, `eval`. Скрипт их не использует.

### Права пользователя PHP

Пользователь, под которым работает PHP-FPM (обычно `www-data`, `nginx`, `apache` или `php`), должен уметь запускать три команды через `sudo` без пароля:

```bash
# Создай файл /etc/sudoers.d/iptables-api:
Cmnd_Alias IPSET_CMDS = /usr/sbin/ipset, /sbin/ipset, /bin/ipset
Cmnd_Alias IPT4_CMDS  = /sbin/iptables, /usr/sbin/iptables
Cmnd_Alias IPT6_CMDS  = /sbin/ip6tables, /usr/sbin/ip6tables

www-data ALL=(root) NOPASSWD: IPSET_CMDS, IPT4_CMDS, IPT6_CMDS
```

Замени `www-data` на реального пользователя PHP. Узнать его можно:

```bash
ps aux | grep php-fpm | grep -v root | head -1 | awk '{print $1}'
```

Или через саму диагностику — она покажет поле **«Пользователь PHP»**.

Применить:

```bash
sudo chmod 440 /etc/sudoers.d/iptables-api
sudo visudo -cf /etc/sudoers.d/iptables-api  # проверка синтаксиса
```

### Веб-сервер

Любой, умеющий запускать PHP:

- **nginx + PHP-FPM** — рекомендуемая связка
- **Apache + mod_php / PHP-FPM**
- **LiteSpeed / OpenLiteSpeed**
- **Caddy + PHP-FPM**

Специальной конфигурации не требуется. Никаких WebSocket-ов, long-polling, chunked-ответов — обычный `POST/GET → JSON`.

### Доступ к файловой системе

- Скрипт **не создаёт файлов** на диске (кроме временных от PHP error_log если включено)
- Достаточно прав `read` на `iptables.php` и `settings.php` для пользователя PHP
- Запись в `/tmp` желательна (для логов PHP, если они включены) — но не критична

### Сеть

- Порт веб-сервера (обычно 80/443) — открыт для клиентов API
- **Никаких исходящих соединений скрипт не делает** — всё работает локально через `sudo ipset`
- Никакого Redis, никакой БД, никакого composer/npm

### Ядро и контейнеры

| Окружение | Работает? |
|---|---|
| Железный сервер / VDS / VPS | ✅ Да |
| KVM / Xen / VMware | ✅ Да |
| OpenVZ (старые версии) | ⚠️ Только если хостер разрешил `ipset` и загрузку `xt_set` |
| LXC-контейнер с `CAP_NET_ADMIN` | ✅ Да |
| Docker с `--cap-add=NET_ADMIN --cap-add=NET_RAW` | ✅ Да |
| Docker обычный | ❌ Нет прав на изменение правил ядра |
| Shared-хостинг | ❌ Обычно нет `sudo` и iptables |

### Что делает скрипт при первом запуске

Если окружение настроено корректно, при первой блокировке IP:

1. Создаёт ipset-сет `banlist4` (hash:ip, timeout 3600s, maxelem 1M)
2. Создаёт ipset-сет `banlist6` (family inet6)
3. Вставляет правило в `INPUT`: `iptables -I INPUT -m set --match-set banlist4 src -j DROP`
4. То же для `ip6tables`

После этого любой IP, добавленный в сет, блокируется мгновенно. Ядро само удаляет записи по истечении таймаута.

### Что произойдёт после перезагрузки сервера

Сеты живут в памяти ядра, после ребута пропадают вместе с правилами. При первом HTTP-запросе скрипт создаст их заново с пустым содержимым. Если нужно сохранить баны между ребутами — добавь в `crontab -e` пользователя root:

```
# Сохранять каждые 5 минут
*/5 * * * * ipset save banlist4 banlist6 > /etc/ipset.conf

# Восстанавливать при старте (через systemd-unit или /etc/rc.local)
@reboot ipset restore < /etc/ipset.conf 2>/dev/null
```

Но обычно это не нужно — после ребута достаточно нескольких минут трафика чтобы перебанить активных нарушителей.

### Проверка что всё работает

Открой в браузере:

```
https://your-domain.com/path/to/iptables.php?api_key=ВАШ_КЛЮЧ
```

Нажми на вкладку **🔍 Диагностика**. Если все пункты ✅ — скрипт готов к работе. Если есть ❌ — читай подсказки, там точные команды для исправления.

Быстрый тест через API:

```bash
# Должен вернуть JSON с количеством заблокированных IP = 0
curl "https://your-domain.com/path/to/iptables.php?action=list&api=1&api_key=ВАШ_КЛЮЧ"
```

Если получил HTTP 200 и валидный JSON — всё работает.

## Лицензия

MIT

## Связанные проекты

- **[MurKir Security](https://github.com/Murkirpus/Redis-Bot-Protection)** — комплексная Redis-защита от ботов, которая использует этот API для блокировок на уровне ядра
- **[PrompTessor AI]([https://murkir.com/temp/promptessor.html](https://chromewebstore.google.com/detail/promptessor-ai/ipiephgmgodielnamhgeiijekldmcomg)** — фреймворк анализа и оптимизации промптов

---

Баги, предложения, PR — в Issues. Вопросы — в Discussions.


# murkir-ipset-api

**PHP API и веб-интерфейс для блокировки IPv4/IPv6 через `ipset`** с авто-разбаном на уровне ядра Linux. Один файл, без cron, без cleanup-скриптов, без composer. Часть экосистемы [MurKir Security](#связанные-проекты).

---

## 📋 Содержание

- [Почему ipset](#почему-ipset)
- [Возможности](#возможности)
- [Требования](#требования)
- [Установка](#установка)
- [Использование](#использование)
- [API](#api)
- [Структура JSON-ответов](#структура-json-ответов)
- [Веб-интерфейс](#веб-интерфейс)
- [Диагностика](#диагностика)
- [Конфигурация](#конфигурация)
- [Безопасность](#безопасность)
- [Как это работает](#как-это-работает)
- [FAQ](#faq)
- [Тесты](#тесты)
- [Лицензия](#лицензия)

---

## Почему ipset

Типичная схема банов через `iptables -I INPUT -s X -j DROP` быстро деградирует при тысячах правил — ядро линейно проверяет каждый пакет против всего списка.

`ipset` использует хэш-таблицу в ядре: проверка **O(1)** независимо от количества записей. Миллион забаненных IP — такая же скорость, как десять.

**Плюс авто-разбан:** у каждой записи свой `timeout`, ядро удаляет просроченные элементы само. Никакого `cron`, никакого `at`, никакого `cleanup.php`. Заблокировал IP на час — через час он разблокируется сам, без твоего участия.

---

## Возможности

- 🔥 Блокировка **IPv4 и IPv6** через единый API
- ⏱️ **Индивидуальный таймаут** для каждого бана (по умолчанию 1 час)
- 🧹 **Авто-разбан выполняет ядро** — без внешних скриптов
- 🌐 **Веб-интерфейс** с четырьмя вкладками: блокировка, список, статистика, диагностика
- 📊 Отображение **оставшегося времени** для каждого забаненного IP
- 🔍 **Встроенная диагностика системы** с подсказками что именно не так и как исправить
- ⚡ **Кнопка «Инициализировать»** для ручного создания сетов и правил
- 🛡️ Защита от shell-injection (`filter_var` + `escapeshellarg`)
- 🔐 **Timing-safe** сравнение API-ключа (`hash_equals`)
- 📦 **Один PHP-файл**, совместим с PHP 5.6–8.3
- 🔄 **Переживает reboot** — при старте PHP пересоздаёт сеты и правила автоматически
- 🚀 **Работает с отключенным `shell_exec`** (критичные функции — только `exec`)

---

## Требования

Минимальный набор для работы. Все проверки автоматизированы на вкладке **🔍 Диагностика** — при первом открытии UI она покажет что не настроено и как это исправить.

### Операционная система

- **Linux** с ядром 3.13+ (Ubuntu 14.04+, Debian 8+, CentOS 7+, RHEL 7+, Alpine 3.x)
- Поддержка netfilter в ядре — есть по умолчанию во всех дистрибутивах
- Модуль ядра `xt_set` — загружается автоматически при первом использовании `ipset`, или вручную: `sudo modprobe xt_set`

**Не подходит:** shared-хостинги без доступа к `sudo` и iptables, контейнеры без `CAP_NET_ADMIN`, Windows.

### Пакеты

```bash
# Ubuntu / Debian
sudo apt install ipset iptables sudo

# CentOS / RHEL / AlmaLinux / Rocky
sudo yum install ipset iptables sudo

# Alpine
apk add ipset iptables sudo
```

`iptables` и `ip6tables` обычно уже установлены.

### PHP

- **Версия: 5.6 или новее** (протестировано на 5.6, 7.0–7.4, 8.0–8.3)
- **Расширения** — все стандартные:
  - `ext/filter` (проверка IP через `filter_var`)
  - `ext/hash` (timing-safe сравнение ключа через `hash_equals`)
  - `ext/json` (кодирование ответов API)
  - `ext/posix` — опционально, для определения реального пользователя PHP в диагностике

### Функции PHP, которые должны быть доступны

Проверь `php.ini` → директиву `disable_functions`. Эти функции **не должны** быть в списке:

| Функция | Зачем нужна | Критично |
|---|---|---|
| `exec` | Выполнение команд `ipset`/`iptables` | ❌ без неё скрипт не работает |
| `escapeshellarg` | Экранирование IP в shell-команде | ❌ защита от injection |
| `filter_var` | Валидация IPv4/IPv6 | ❌ |
| `hash_equals` | Защита API-ключа от timing-атак | ⚠️ желательно |
| `posix_geteuid` | Определение пользователя PHP в диагностике | ⚠️ опционально |

**Что можно отключать без проблем** (наоборот, рекомендуется для безопасности): `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, `eval`. Скрипт их не использует.

### Веб-сервер

Любой, умеющий запускать PHP:

- **nginx + PHP-FPM** — рекомендуемая связка
- **Apache + mod_php / PHP-FPM**
- **LiteSpeed / OpenLiteSpeed**
- **Caddy + PHP-FPM**

Специальной конфигурации не требуется.

### Сеть и файловая система

- Скрипт **не создаёт файлов** на диске
- Достаточно прав `read` на `iptables.php` и `settings.php` для пользователя PHP
- Никаких исходящих соединений — всё локально через `sudo ipset`
- Никакого Redis, БД, composer/npm

### Совместимость с окружениями

| Окружение | Работает |
|---|---|
| Железный сервер / VDS / VPS | ✅ Да |
| KVM / Xen / VMware | ✅ Да |
| OpenVZ (старые версии) | ⚠️ Только если хостер разрешил `ipset` и загрузку `xt_set` |
| LXC-контейнер с `CAP_NET_ADMIN` | ✅ Да |
| Docker с `--cap-add=NET_ADMIN --cap-add=NET_RAW` | ✅ Да |
| Docker обычный | ❌ Нет прав на изменение правил ядра |
| Shared-хостинг | ❌ Обычно нет `sudo` и iptables |

---

## Установка

### 1. Клонирование

```bash
cd /var/www/your-site/
git clone https://github.com/Murkirpus/murkir-ipset-api.git dos
cd dos
```

Или просто скачай `iptables.php` и `settings.php` в нужную папку.

### 2. Зависимости

```bash
sudo apt install -y ipset  # Ubuntu/Debian
# или
sudo yum install -y ipset  # RHEL/CentOS
```

### 3. API-ключ

Сгенерируй сильный ключ:

```bash
openssl rand -hex 24
```

Открой `settings.php` и вставь результат:

```php
define('API_BLOCK_KEY', 'твой-сгенерированный-ключ');
```

### 4. sudoers

Пользователь, под которым работает PHP-FPM (обычно `www-data`, `nginx`, `apache` или `php`), должен запускать три команды через `sudo` без пароля. Узнать пользователя:

```bash
ps aux | grep php-fpm | grep -v root | head -1 | awk '{print $1}'
```

Или открой диагностику в UI — она покажет поле **«Пользователь PHP»**.

Создай файл `/etc/sudoers.d/iptables-api`:

```
Cmnd_Alias IPSET_CMDS = /usr/sbin/ipset, /sbin/ipset, /bin/ipset
Cmnd_Alias IPT4_CMDS  = /sbin/iptables, /usr/sbin/iptables
Cmnd_Alias IPT6_CMDS  = /sbin/ip6tables, /usr/sbin/ip6tables

www-data ALL=(root) NOPASSWD: IPSET_CMDS, IPT4_CMDS, IPT6_CMDS
```

Замени `www-data` на имя своего пользователя. Затем:

```bash
sudo chmod 440 /etc/sudoers.d/iptables-api
sudo visudo -cf /etc/sudoers.d/iptables-api  # проверка синтаксиса
```

### 5. Проверка

Открой в браузере:

```
https://your-domain.com/dos/iptables.php?api_key=ТВОЙ_КЛЮЧ
```

Если есть критичные ошибки — скрипт автоматически откроет вкладку **🔍 Диагностика** с подробными подсказками.

Если всё зелёное — нажми **⚡ Инициализировать сеты и правила**, и система готова к работе.

---

## Использование

### Быстрый старт через API

```bash
# Заблокировать IP на 1 час (дефолт)
curl "https://your-site/dos/iptables.php?action=block&ip=1.2.3.4&api=1&api_key=КЛЮЧ"

# Заблокировать на 2 часа
curl "https://your-site/dos/iptables.php?action=block&ip=1.2.3.4&timeout=7200&api=1&api_key=КЛЮЧ"

# Список заблокированных
curl "https://your-site/dos/iptables.php?action=list&api=1&api_key=КЛЮЧ"
```

### Пример интеграции на PHP

```php
function banIp(string $ip, int $seconds = 3600): array {
    $url = 'https://your-site/dos/iptables.php';
    $data = http_build_query([
        'action'  => 'block',
        'ip'      => $ip,
        'timeout' => $seconds,
        'api'     => 1,
        'api_key' => 'ТВОЙ_КЛЮЧ',
    ]);
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => 'Content-Type: application/x-www-form-urlencoded',
        'content' => $data,
        'timeout' => 3,
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    return json_decode($body, true) ?: ['status' => 'error'];
}

// Прогрессивный бан
banIp('1.2.3.4', 600);     // первое нарушение — 10 минут
banIp('1.2.3.4', 3600);    // повторное — час
banIp('1.2.3.4', 86400);   // третье — сутки
```

---

## API

Все эндпоинты принимают **GET и POST**. Для JSON-ответа добавь `&api=1`.

| Action | Параметры | Описание |
|---|---|---|
| `block` | `ip`, `timeout` (опционально) | Заблокировать IP с таймаутом |
| `unblock` | `ip` | Снять бан досрочно |
| `list` | — | Список заблокированных IPv4 |
| `list6` | — | Список заблокированных IPv6 |
| `clear` | — | Снять все баны |
| `debug` | — | Полная информация о правилах и сетах |
| `diag` | — | Диагностика окружения |
| `init` | — | Принудительная инициализация сетов и правил |

### Шпаргалка по таймаутам

| Длительность | Секунд |
|---|---|
| 1 минута | `60` |
| 5 минут | `300` |
| 10 минут | `600` |
| 30 минут | `1800` |
| 1 час | `3600` |
| 6 часов | `21600` |
| 12 часов | `43200` |
| 1 сутки | `86400` |
| 1 неделя | `604800` |
| 30 суток | `2592000` |
| 1 год | `31536000` (максимум) |

### Продление бана

Вызови `block` с тем же IP ещё раз — timeout перезапишется. Не нужно сначала `unblock`.

```bash
# IP забанен на 10 минут, через 3 минуты делаем это:
curl "...?action=block&ip=1.2.3.4&timeout=3600&api=1&api_key=KEY"
# Теперь ему сидеть час от этого момента, а не 7 минут
```

---

## Структура JSON-ответов

### block

```json
{
  "status": "success",
  "message": "IP 1.2.3.4 заблокирован на 1 ч",
  "details": "Set: banlist4, timeout: 3600 сек"
}
```

### unblock

```json
{
  "status": "success",
  "message": "IP 1.2.3.4 успешно разблокирован",
  "details": "Удалён из banlist4"
}
```

Если IP не был в списке — `status: "warning"`.

### list / list6

```json
{
  "status": "success",
  "version": "IPv4",
  "set": "banlist4",
  "count": 2,
  "blocked_ips": ["1.2.3.4", "5.6.7.8"],
  "blocked_details": [
    {
      "ip": "1.2.3.4",
      "ports": ["all"],
      "remaining": 3412,
      "remaining_human": "56 мин 52 сек"
    }
  ]
}
```

### diag

```json
{
  "status": "warn",
  "can_init": true,
  "summary": "Есть предупреждения. Нажми «Инициализировать» чтобы создать сеты и правила.",
  "checks": [
    {
      "name": "Бинарник ipset",
      "status": "ok",
      "value": "/usr/sbin/ipset",
      "hint": ""
    },
    {
      "name": "ipset: banlist4",
      "status": "warn",
      "value": "не создан",
      "hint": "Будет создан автоматически при первой блокировке IPv4"
    }
  ]
}
```

Поле `status` бывает `success`, `warning`, `error` (для операций) или `ok`, `warn`, `fail` (для диагностики). В коде клиента проверяй именно `status`, текст `message` может меняться.

---

## Веб-интерфейс

Открой в браузере:

```
https://your-site/dos/iptables.php?api_key=ТВОЙ_КЛЮЧ
```

Четыре вкладки:

**🔒 Блокировка** — ручной ввод IP и таймаута. Кнопки: Заблокировать / Разблокировать. Быстрые действия: «Заблокировать мой IP» и «Снять все баны».

**📋 Список IP** — все заблокированные адреса с оставшимся временем для каждого. AJAX-обновление. У каждой записи кнопка «Разблокировать».

**📊 Статистика** — счётчики IPv4 / IPv6 / всего.

**🔍 Диагностика** — 17+ проверок окружения с подсказками. Подробнее ниже.

---

## Диагностика

Автоматически проверяется при открытии UI. Если хоть одна проверка критична (❌) — UI сразу открывает эту вкладку.

### Что проверяется

| Категория | Что именно |
|---|---|
| **PHP** | Версия, `exec()`, `escapeshellarg()`, `filter_var()`, `hash_equals()` |
| **Бинарники** | `sudo`, `ipset`, `iptables`, `ip6tables` — с путями где найдены |
| **Ядро** | Модуль `xt_set` загружен |
| **sudoers** | `sudo -n ipset/iptables/ip6tables` работает без пароля |
| **Пользователь** | Реальный пользователь PHP (для подставления в хинты) |
| **ipset** | Существуют ли сеты `banlist4` / `banlist6` |
| **iptables** | Установлены ли DROP-правила в INPUT |
| **Файловая система** | Запись в `/tmp` для логов PHP |

### Типы статусов

- ✅ **ok** — всё в порядке
- ⚠️ **warn** — предупреждение, но работать будет (например, сет ещё не создан — создастся при первой блокировке)
- ❌ **fail** — критично, нужно исправить перед использованием

### Подсказки

Для каждой проблемы диагностика выдаёт конкретную команду:

- Нет `ipset`? → `sudo apt install ipset`
- sudoers не настроен? → готовый блок для `/etc/sudoers.d/iptables-api` **с твоим именем пользователя уже подставленным**
- Сет не создан? → кнопка «⚡ Инициализировать сеты и правила»

---

## Конфигурация

Файл `settings.php`:

```php
<?php
// Обязательно
define('API_BLOCK_KEY', 'your-strong-key-here');

// Опционально (раскомментируй если нужно переопределить дефолты)
// define('BAN_TIMEOUT', 3600);           // таймаут по умолчанию, сек
// define('IPSET_V4', 'banlist4');        // имена сетов
// define('IPSET_V6', 'banlist6');
// define('IPSET_MAXELEM', 1000000);      // предел записей в сете
```

Никаких других настроек для базовой работы не требуется.

---

## Безопасность

- **API-ключ обязателен** — без него 403 на любой запрос, включая веб-интерфейс
- **`hash_equals`** защищает от timing-атак при сравнении ключа
- **`filter_var(FILTER_VALIDATE_IP)`** отсекает всё, что не является валидным IP, до передачи в shell
- **`escapeshellarg`** экранирует параметр для команды
- **Control chars фильтруются** в выводе sudo, чтобы JSON-ответ не ломался
- **Никакого пользовательского ввода в shell** кроме провалидированного IP

### Рекомендации для production

- Генерируй сильные ключи: `openssl rand -hex 24`
- Меняй ключ если что-то подозрительное в логах
- Закрой доступ к веб-интерфейсу дополнительно: Basic Auth в nginx, IP-allowlist или VPN
- Настрой `fail2ban` на логи nginx, чтобы сам iptables.php не стал целью брутфорса ключа
- Используй HTTPS — API-ключ передаётся в URL

Пример защиты в nginx:

```nginx
location = /dos/iptables.php {
    # Только с доверенных IP (твой управляющий сервер)
    allow 192.0.2.10;
    deny all;

    include fastcgi_params;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
}
```

---

## Как это работает

### Ленивая инициализация

При первом запросе к API (или по кнопке `action=init`) скрипт проверяет и создаёт:

1. `ipset create banlist4 hash:ip timeout 3600 maxelem 1000000`
2. `ipset create banlist6 hash:ip family inet6 timeout 3600 maxelem 1000000`
3. `iptables -I INPUT -m set --match-set banlist4 src -j DROP`
4. `ip6tables -I INPUT -m set --match-set banlist6 src -j DROP`

Проверяет через `ipset list <name> -name` и `iptables -C` — всё идемпотентно.

### Блокировка

```
sudo ipset add banlist4 1.2.3.4 timeout 3600 -exist
```

Флаг `-exist` делает операцию идемпотентной. Повторный вызов перезапишет таймаут.

### Разблокировка

```
sudo ipset del banlist4 1.2.3.4
```

Без `-exist` — чтобы различать «удалил» (`success`) и «не было в списке» (`warning`).

### Список с остатком времени

Парсится вывод `ipset list banlist4` — строки вида `1.2.3.4 timeout 3412` преобразуются в массив с `remaining` и `remaining_human`.

### Авто-разбан

Ядро само удаляет записи по таймауту. PHP в этом не участвует. Никакого cron.

### Перезагрузка сервера

Сеты живут в памяти ядра, после ребута пропадают вместе с правилами. При первом HTTP-запросе скрипт создаёт их заново с пустым содержимым.

Если нужно **сохранять баны между ребутами** — добавь в `crontab -e` пользователя root:

```
*/5 * * * * ipset save banlist4 banlist6 > /etc/ipset.conf
@reboot ipset restore < /etc/ipset.conf 2>/dev/null
```

Обычно это не нужно — после ребута достаточно нескольких минут трафика чтобы перебанить активных нарушителей.

---

## FAQ

**Почему файл называется `iptables.php`, а не `ipset.php`?**
Совместимость со старыми интеграциями. С точки зрения API-клиента это «блокировщик на уровне iptables» — деталь реализации (ipset) для клиента неважна. Плюс технически `iptables` тоже задействован: правило `-m set --match-set` висит именно в INPUT-цепочке iptables.

**Работает ли с отключенным `shell_exec`?**
Да. Используется только `exec()`. Если хостер отключил `shell_exec` — это нормально и даже рекомендуется для безопасности.

**Сколько IP можно держать в сете?**
До 1 000 000 по умолчанию (параметр `maxelem`). Каждая запись ~40 байт — миллион IP займут около 40 МБ в памяти ядра. Проверка пакета O(1) при любом размере.

**Как быстро применяется бан?**
Мгновенно. После `ipset add` следующий же пакет от этого IP дропается ядром.

**Можно ли забанить подсеть?**
Текущая версия поддерживает только одиночные IP (`hash:ip`). Для подсетей нужен сет типа `hash:net` — добавь вручную или форкни.

**Можно ли сделать постоянный бан?**
Создай параллельный сет без timeout: `ipset create banlist4_perm hash:ip`. Добавь второе правило в INPUT. В текущей версии эта функциональность не встроена.

**Что если забанить свой IP?**
Получишь немедленную блокировку. Снять можно только с другого IP или локально через SSH: `sudo ipset del banlist4 ТВОЙ_IP`. В UI есть кнопка «Заблокировать мой IP» с подтверждением — это защита от случайного нажатия.

**Переживает ли reboot?**
Сами правила — нет. Скрипт создаст их заново при первом запросе. Забаненные IP — тоже нет, но можно настроить `ipset save/restore` (см. [Как это работает](#как-это-работает)).

**Чем это лучше fail2ban?**
fail2ban — это сборщик-анализатор логов, он решает *кого* банить. `murkir-ipset-api` — это *инструмент блокировки*. Их можно использовать вместе: fail2ban анализирует логи, а через свой action вызывает этот API.

**А чем это лучше чем просто `iptables -I INPUT -s X -j DROP`?**
- **Производительность**: O(1) вместо O(N) при проверке пакета
- **Авто-разбан** без cron
- **Один вызов API** вместо пары `add-rule` + `schedule-cron-to-remove`
- **Удобный мониторинг** через UI

---

## Тесты

В репозитории 72 теста (плюс отдельные для диагностики), покрывают:

- Безопасность (API-ключ, timing-атаки, injection)
- Валидацию IP (IPv4/IPv6, битые форматы, shell-метасимволы)
- Все endpoints: `block`, `unblock`, `list`, `list6`, `clear`, `debug`, `diag`, `init`
- Парсинг вывода `ipset list`
- HTML-интерфейс (рендер, Content-Type)
- GET vs POST
- Работу с отключенным `shell_exec`

Запуск:

```bash
cd tests/
./run.sh
```

Тесты используют моки ipset/iptables через подменённый `PATH`, так что реальные правила ядра не трогаются.

---

## Структура репозитория

```
murkir-ipset-api/
├── iptables.php              # Основной файл (API + UI + диагностика)
├── settings.php              # Конфигурация (только API-ключ обязателен)
├── iptables-api.sudoers      # Готовый шаблон для /etc/sudoers.d/
├── README.md                 # Этот файл
├── LICENSE                   # MIT
└── tests/
    ├── test_runner.php       # Тестовый раннер
    ├── fake-sudo             # Мок sudo/ipset/iptables
    └── run.sh                # Скрипт запуска тестов
```

---

## Лицензия

MIT

---

## Связанные проекты

- **MurKir Security** — комплексная Redis-защита от ботов, которая использует этот API для блокировок на уровне ядра
- **PrompTessor AI** — фреймворк анализа и оптимизации промптов

---

## Поддержка

Баги, предложения — в [Issues](https://github.com/Murkirpus/murkir-ipset-api/issues).
Вопросы — в [Discussions](https://github.com/Murkirpus/murkir-ipset-api/discussions).
Pull Request-ы приветствуются.
