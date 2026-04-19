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
git clone https://github.com/USER/murkir-ipset.git dos
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

## Лицензия

MIT

## Связанные проекты

- **[MurKir Security](https://github.com/Murkirpus/Redis-Bot-Protection)** — комплексная Redis-защита от ботов, которая использует этот API для блокировок на уровне ядра
- **[PrompTessor AI]([https://murkir.com/temp/promptessor.html](https://chromewebstore.google.com/detail/promptessor-ai/ipiephgmgodielnamhgeiijekldmcomg)** — фреймворк анализа и оптимизации промптов

---

Баги, предложения, PR — в Issues. Вопросы — в Discussions.
