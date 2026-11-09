<?php
/**
 * Живой просмотр access-логов nginx / Apache (PHP 8.3, один файл).
 */
declare(strict_types=1);

// ───────────── Настройки ─────────────
// Где искать логи (шаблоны glob). Файлы *error*, *.gz и старые (.1, .2…) пропускаются.
const LOG_GLOBS = [
    '/var/log/nginx/*.log',
    '/var/log/nginx/*/*.log',
    '/var/log/apache2/*access*.log',
    '/var/log/httpd/*access*',
    '/var/www/*/data/logs/*.log',      // ISPmanager / FastPanel
    '/var/www/*/logs/*.log',
    '/var/www/httpd-logs/*.log',
    '/home/*/logs/*.log',
    '/home/*/*/logs/*.log',
    '/var/log/virtualmin/*access_log',
    '/usr/local/nginx/logs/*.log',
    '/opt/*/logs/*access*.log',
];
const EXTRA_LOG_FILES = [];          // свои пути, например ['/srv/murkir.com/logs/access.log']
const INITIAL_LINES   = 1000;        // сколько последних строк каждого лога показать при открытии
const MAX_CHUNK_BYTES = 2_000_000;   // максимум байт за один опрос
const ALLOW_PUBLIC_IPS = true;       // true — доступ из интернета; false — только с localhost и локальной сети
const AUTH_USER = 'admin';           // логин/пароль для входа НЕ с локального компьютера
const AUTH_PASS = 'adminc6';// смените на свой; пустой AUTH_USER = вход без пароля для всех
const ALLOW_IPS = [];                // доп. разрешённые IP, например ['203.0.113.7']

// ── Блокировка IP через ваш API (iptables). Ключ хранится только здесь, в браузер не передаётся.
const BLOCK_API_URL     = 'https://mydomain.com/murkirsecurity_v4/API/iptables.php';
const BLOCK_API_KEY     = ''; // пустая строка — блокировка через API выключена
const BLOCK_API_METHOD  = 'POST';    // POST — ключ не попадает в access-лог; можно 'GET'
const BLOCK_API_UNBLOCK = 'unblock'; // как называется действие разблокировки в вашем API ('' — кнопки «Разблокировать» не будет)
const BLOCK_TIMEOUTS    = [1800 => '30 минут', 3600 => '1 час', 21600 => '6 часов', 86400 => '24 часа', 604800 => '7 дней', 2592000 => '30 дней'];
const BLOCK_DEFAULT     = 1800;
const BLOCK_PROTECT_IPS = [];        // эти IP никогда не блокировать (свои, офис, мониторинг)
const HIDE_SELF         = true;      // не показывать в логах запросы к самому logs.php (его автообновление)

// ── 🤖 Автозащита: сама находит заразу и блокирует через API.
//    Работает из cron раз в минуту (строка для crontab — на вкладке «Автозащита») и пока открыта страница.
const AUTOBAN_MODE   = 'watch';      // 'off' — выключена, 'watch' — только записывает, кого заблокировала бы, 'ban' — блокирует.
                                     // Режим можно переключить и на странице — это настройка по умолчанию.
const AUTOBAN_WINDOW = 600;          // окно анализа, секунд
const AUTOBAN_RULES  = [
    'scan'   => ['on' => true, 'hits' => 2,    'timeout' => 86400,  'title' => 'Сканер уязвимостей',     'desc' => 'запросы к /.env, /wp-login.php, /phpmyadmin… — от {hits} за 10 мин (опасные вроде /.env и /.git — сразу)'],
    'flood'  => ['on' => true, 'per_min' => 120, 'timeout' => 3600, 'title' => 'Флуд',                   'desc' => 'больше {per_min} запросов страниц в минуту с одного IP (картинки и стили не считаются)'],
    'fake'   => ['on' => true,                 'timeout' => 86400,  'title' => 'Поддельный поисковик',   'desc' => 'представляется Googlebot / YandexBot…, но обратный DNS указывает на чужой домен'],
    'e404'   => ['on' => true, 'hits' => 60, 'share' => 0.8, 'timeout' => 21600, 'title' => 'Перебор адресов', 'desc' => 'от {hits} ответов 404 за 10 мин, и это больше {share_pct}% его запросов'],
    'badbot' => ['on' => true, 'bots' => ['Сканер уязвимостей'], 'timeout' => 86400, 'title' => 'Вредный бот', 'desc' => 'User-Agent из списка: {bots}'],
];
const AUTOBAN_MAX_PER_HOUR = 60;     // предохранитель: не больше стольких банов в час
const AUTOBAN_REPEAT_X2    = true;   // повторный нарушитель (за 7 дней) — срок ×2 за каждый прошлый бан, до 30 дней
const API_USER_AGENT       = 'MurkirLogViewer/1.0 (+logs.php; autoban)';   // так наши запросы к API видны в логах
const AUTOBAN_SKIP_BOTS    = ['Панель логов (мы)', 'Сервер (сам к себе)', 'UptimeRobot', 'Мониторинг', 'Telegram', 'WhatsApp', 'VK', 'Facebook', 'Twitter/X', 'Discord', 'Slack', 'LinkedIn', 'Skype', 'Pinterest'];
const AUTOBAN_VIA_WEB      = true;   // проверять и при открытой странице (раз в минуту), даже без cron

// Папка для данных (журнал, списки, состояние). Должна быть доступна на запись пользователю PHP и cron.
// Файлы в ней защищены от чтения через браузер. Если папку создать не удастся — используется временная папка.
const DATA_DIR = __DIR__ . '/logviewer-data';

// ───────────── Доступ ─────────────
function isLocalIp(string $ip): bool
{
    if (preg_match('~^::ffff:(\d+\.\d+\.\d+\.\d+)$~i', $ip, $m)) {
        $ip = $m[1];                                   // IPv4, записанный как IPv6 (::ffff:127.0.0.1)
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return true;                                   // 127.x, 10.x, 172.16-31.x, 192.168.x, ::1, fe80::, fc00::
    }
    $long = ip2long($ip);
    return $long !== false && ($long & 0xFFC00000) === (100 << 24 | 64 << 16); // 100.64.0.0/10 (CGNAT, Tailscale)
}
$remote = (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
if (!ALLOW_PUBLIC_IPS && !isLocalIp($remote) && !in_array($remote, ALLOW_IPS, true)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit("Доступ только с локального компьютера.\nВаш IP: {$remote}\n"
       . "Если это ваш компьютер — добавьте этот IP в ALLOW_IPS в начале logs.php.");
}
[$authUser, $authPass] = [(string)($_SERVER['PHP_AUTH_USER'] ?? ''), (string)($_SERVER['PHP_AUTH_PW'] ?? '')];
if ($authUser === '' && preg_match('~^Basic\s+(\S+)~i', (string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''), $am)) {
    [$authUser, $authPass] = array_pad(explode(':', (string)base64_decode($am[1]), 2), 2, '');
}
$needAuth = AUTH_USER !== '' && !isLocalIp($remote);
if ($needAuth && (!hash_equals(AUTH_USER, $authUser) || !hash_equals(AUTH_PASS, $authPass))) {
    header('WWW-Authenticate: Basic realm="Logs"');
    http_response_code(401);
    exit('Нужна авторизация');
}

// ───────────── Классификация User-Agent ─────────────
const SEARCH_BOTS = [
    'Googlebot'      => '~Googlebot|Google-InspectionTool|Storebot-Google|AdsBot-Google|Mediapartners-Google|GoogleOther|Google-Extended|APIs-Google~i',
    'YandexBot'      => '~Yandex(Bot|Images|Mobile|Metrika|Accessibility|Video|Media|News|Direct|Webmaster|Favicons|Renderer|Market|Additional|Blogs|PagesChecker|ImageResizer|Calendar|Turbo|RCA|Tracker|Forms|Verticals|SearchShop|Sprav|Adnet)?[A-Za-z]*Bot|YandexMetrika|YandexImages~i',
    'Bingbot'        => '~bingbot|BingPreview|msnbot|adidxbot~i',
    'Baiduspider'    => '~Baiduspider~i',
    'DuckDuckBot'    => '~DuckDuckBot|DuckAssistBot~i',
    'Applebot'       => '~Applebot~i',
    'Yahoo Slurp'    => '~Yahoo! Slurp~i',
    'Mail.Ru'        => '~Mail\.RU_Bot~i',
    'PetalBot'       => '~PetalBot|AspiegelBot~i',
    'SeznamBot'      => '~SeznamBot~i',
    'Sogou'          => '~Sogou~i',
    'Qwant'          => '~Qwantbot|Qwantify~i',
    'Naver'          => '~Yeti/|NaverBot~i',
    'Brave Search'   => '~Bravebot~i',
];
const AI_BOTS = [
    'GPTBot' => '~GPTBot~i', 'ChatGPT-User' => '~ChatGPT-User~i', 'OAI-SearchBot' => '~OAI-SearchBot~i',
    'ClaudeBot' => '~ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai~i', 'PerplexityBot' => '~Perplexity~i',
    'CCBot' => '~CCBot~i', 'Bytespider' => '~Bytespider~i', 'Amazonbot' => '~Amazonbot~i',
    'Meta AI' => '~meta-externalagent|meta-externalfetcher|FacebookBot~i', 'Cohere' => '~cohere-ai~i',
    'Diffbot' => '~Diffbot~i', 'YouBot' => '~YouBot~i', 'MistralAI' => '~MistralAI~i', 'DeepSeek' => '~DeepSeek~i',
    'ExaBot' => '~ExaSearchBot|Exabot-AI|crawler\.exa\.ai~i', 'Timpibot' => '~Timpibot~i', 'ImagesiftBot' => '~ImagesiftBot~i',
];
const OTHER_BOTS = [
    'Панель логов (мы)' => '~MurkirLogViewer|^LogViewer/~',
    'AhrefsBot' => '~AhrefsBot|AhrefsSiteAudit~i', 'SemrushBot' => '~Semrush~i', 'MJ12bot' => '~MJ12bot~i',
    'DotBot' => '~DotBot~i', 'BLEXBot' => '~BLEXBot~i', 'DataForSeoBot' => '~DataForSeoBot~i', 'SeekportBot' => '~Seekport~i',
    'Screaming Frog' => '~Screaming Frog~i', 'Facebook' => '~facebookexternalhit|facebookcatalog~i',
    'Twitter/X' => '~Twitterbot~i', 'Telegram' => '~TelegramBot~i', 'WhatsApp' => '~WhatsApp~i',
    'Discord' => '~Discordbot~i', 'Slack' => '~Slackbot|Slack-ImgProxy~i', 'LinkedIn' => '~LinkedInBot~i',
    'VK' => '~vkShare|VKRobot~i', 'Skype' => '~SkypeUriPreview~i', 'Pinterest' => '~Pinterest~i',
    'curl' => '~^curl/~i', 'Wget' => '~^Wget~i', 'Python' => '~python-requests|python-urllib|aiohttp|httpx|Python/~i',
    'Go' => '~Go-http-client~i', 'Java' => '~^Java/|Apache-HttpClient|okhttp~i', 'PHP' => '~GuzzleHttp|^PHP/|WordPress/~i',
    'Node.js' => '~node-fetch|axios|undici|^node~i', 'Scrapy' => '~Scrapy~i', 'Headless Chrome' => '~HeadlessChrome|PhantomJS|Puppeteer|Playwright~i',
    'Postman' => '~PostmanRuntime~i', 'UptimeRobot' => '~UptimeRobot~i', 'Мониторинг' => '~Pingdom|StatusCake|Uptime-Kuma|Site24x7|Better Uptime|monitor~i',
    'Сканер уязвимостей' => '~zgrab|masscan|Nmap|Nuclei|sqlmap|Nikto|WPScan|CensysInspect|Expanse|InternetMeasurement|Palo Alto|l9explore|ALittle~i',
];

/** Суффиксы rDNS для проверки подлинности поисковиков */
const VERIFY_DOMAINS = [
    'Googlebot'   => ['.googlebot.com', '.google.com', '.googleusercontent.com'],
    'YandexBot'   => ['.yandex.ru', '.yandex.net', '.yandex.com'],
    'Bingbot'     => ['.search.msn.com'],
    'Baiduspider' => ['.baidu.com', '.baidu.jp'],
    'Applebot'    => ['.applebot.apple.com'],
    'Yahoo Slurp' => ['.crawl.yahoo.net'],
    'Mail.Ru'     => ['.mail.ru'],
    'PetalBot'    => ['.petalsearch.com', '.aspiegel.com'],
    'SeznamBot'   => ['.seznam.cz'],
];

function classify(string $ua): array
{
    if ($ua === '' || $ua === '-') {
        return ['k' => 'bot', 'n' => 'Без User-Agent', 'os' => '—', 'd' => '—'];
    }
    foreach ([['search', SEARCH_BOTS], ['ai', AI_BOTS], ['bot', OTHER_BOTS]] as [$kind, $list]) {
        foreach ($list as $name => $re) {
            if (preg_match($re, $ua)) {
                return ['k' => $kind, 'n' => $name, 'os' => '—', 'd' => 'робот'];
            }
        }
    }
    if (preg_match('~bot\b|bot/|crawl|spider|slurp|scrap|fetch|preview|checker|scanner|http-?client|^Mozilla/5\.0$|^-?$~i', $ua)) {
        return ['k' => 'bot', 'n' => 'Неизвестный бот', 'os' => '—', 'd' => 'робот'];
    }

    $browser = match (true) {
        (bool)preg_match('~YaBrowser|YaSearchBrowser~', $ua)     => 'Яндекс Браузер',
        (bool)preg_match('~Edg(e|A|iOS)?/~', $ua)                => 'Edge',
        (bool)preg_match('~OPR/|Opera|OPiOS~', $ua)              => 'Opera',
        (bool)preg_match('~SamsungBrowser~', $ua)                => 'Samsung Internet',
        (bool)preg_match('~Vivaldi~', $ua)                       => 'Vivaldi',
        (bool)preg_match('~Firefox/|FxiOS~', $ua)                => 'Firefox',
        (bool)preg_match('~CriOS|Chrome/|Chromium~', $ua)        => 'Chrome',
        (bool)preg_match('~Safari/~', $ua) && str_contains($ua, 'Version/') => 'Safari',
        (bool)preg_match('~MSIE |Trident/~', $ua)                => 'Internet Explorer',
        default => null,
    };
    if ($browser === null) {
        return ['k' => 'bot', 'n' => 'Неизвестный клиент', 'os' => '—', 'd' => '—'];
    }
    $os = match (true) {
        str_contains($ua, 'Windows')                       => 'Windows',
        str_contains($ua, 'Android')                       => 'Android',
        (bool)preg_match('~iPhone|iPad|iPod~', $ua)        => 'iOS',
        str_contains($ua, 'Mac OS X')                      => 'macOS',
        str_contains($ua, 'CrOS')                          => 'ChromeOS',
        str_contains($ua, 'Linux')                         => 'Linux',
        default                                            => 'Другая',
    };
    $device = match (true) {
        (bool)preg_match('~iPad|Tablet~', $ua) || (str_contains($ua, 'Android') && !str_contains($ua, 'Mobile')) => 'планшет',
        (bool)preg_match('~Mobi|iPhone|iPod~', $ua)        => 'телефон',
        default                                            => 'компьютер',
    };
    return ['k' => 'browser', 'n' => $browser, 'os' => $os, 'd' => $device];
}

// ───────────── Парсинг строки лога ─────────────
// combined / main, опционально с хостом в начале и X-Forwarded-For в конце
const Q = '"((?:[^"\\\\]|\\\\.)*)"';
// Между [время] и "запросом" могут быть доп. поля (Accept, язык, сжатие…) — пропускаем их.
// После User-Agent: "X-Forwarded-For" "хост" и любые key=value (rt=0.016 …)
const LINE_RE = '~^(?:(\S+) )?(\S+) \S+ (\S+) \[([^\]]+)\] (?:.*? )?' . Q . ' (\d{3}) (\S+)(?: ' . Q . ' ' . Q . ')?(?: ' . Q . ')?(?: ' . Q . ')?~';

/** %C8%E3… (Windows-1251) и %D0%BC… (UTF-8) → читаемый текст */
function decodePath(string $p): string
{
    if (!str_contains($p, '%')) return $p;
    $d = rawurldecode(str_replace('+', '%20', $p));
    if (!mb_check_encoding($d, 'UTF-8')) {
        $d = (string)@mb_convert_encoding($d, 'UTF-8', 'Windows-1251');
    }
    return preg_replace('~[\x00-\x1F\x7F]~u', '?', $d) ?? $p;
}

/** Реальный IP посетителя, если сервер за прокси/Cloudflare и XFF записан в лог */
function realIp(string $ip, string $xff): string
{
    if ($xff === '' || $xff === '-') return $ip;
    $first = trim(explode(',', $xff)[0]);
    return filter_var($first, FILTER_VALIDATE_IP) ? $first : $ip;
}

/** Прячем секреты в адресах: ?api_key=…, token=…, password=… */
function redact(string $p): string
{
    return str_contains($p, '=') ? (string)preg_replace('~\b(api_?key|apikey|key|token|access_token|secret|pass(word)?|pwd|auth|sig(nature)?)=[^&\s]+~i', '$1=***', $p) : $p;
}

function makeEntry(int $t, string $vhost, string $ip, string $user, string $request, int $status, int $bytes, string $ref, string $ua): array
{
    $req = explode(' ', $request, 3);
    return [
        't'  => $t, 'v' => $vhost, 'ip' => $ip, 'u' => $user === '-' ? '' : $user,
        'm'  => count($req) >= 2 ? $req[0] : '',
        'p'  => count($req) >= 2 ? redact(decodePath($req[1])) : redact($request),
        'raw'=> count($req) >= 2 && str_contains($req[1], '%') ? $req[1] : '',
        's'  => $status, 'b' => $bytes,
        'r'  => $ref === '-' ? '' : $ref, 'ua' => $ua === '-' ? '' : $ua,
    ] + classify($ua === '-' ? '' : $ua);
}

function parseTime(string $s): int
{
    $dt = DateTimeImmutable::createFromFormat('d/M/Y:H:i:s O', $s);
    if (!$dt) { try { $dt = new DateTimeImmutable($s); } catch (Exception) { return time(); } }
    return $dt->getTimestamp();
}

function parseLine(string $line): ?array
{
    $line = rtrim($line, "\r");
    if (str_starts_with($line, '{')) {                    // log_format ... escape=json
        $j = json_decode($line, true);
        if (!is_array($j)) return null;
        $g = fn(string ...$keys) => (string)array_reduce($keys, fn($c, $k) => $c ?? ($j[$k] ?? null), null);
        $req = $g('request') ?: trim($g('request_method', 'method') . ' ' . $g('request_uri', 'uri', 'path') . ' ' . $g('server_protocol', 'protocol'));
        return makeEntry(parseTime($g('time_local', 'time_iso8601', 'time', '@timestamp', 'timestamp')), $g('host', 'server_name', 'vhost'),
            realIp($g('remote_addr', 'ip', 'client_ip'), $g('http_x_forwarded_for', 'x_forwarded_for')), $g('remote_user'),
            $req, (int)$g('status'), (int)$g('body_bytes_sent', 'bytes_sent', 'bytes'), $g('http_referer', 'referer', 'referrer'), $g('http_user_agent', 'user_agent', 'ua'));
    }
    if (!preg_match(LINE_RE, $line, $m)) {
        return null;
    }
    $host = ($m[11] ?? '') !== '-' ? ($m[11] ?? '') : '';
    $e = makeEntry(parseTime($m[4]), ($m[1] ?? '') ?: $host, realIp($m[2], stripcslashes($m[10] ?? '')), $m[3], stripcslashes($m[5]),
        (int)$m[6], $m[7] === '-' ? 0 : (int)$m[7], stripcslashes($m[8] ?? ''), stripcslashes($m[9] ?? ''));
    if (preg_match('~\brt=([\d.]+)~', $line, $rt)) $e['rt'] = (float)$rt[1];   // время ответа, сек
    return $e;
}

// ───────────── Поиск логов ─────────────
function discoverLogs(): array
{
    $paths = EXTRA_LOG_FILES;
    foreach (LOG_GLOBS as $g) {
        foreach (@glob($g, GLOB_NOSORT) ?: [] as $p) $paths[] = $p;
    }
    $out = [];
    foreach (array_unique($paths) as $p) {
        $b = basename($p);
        if (!in_array($p, EXTRA_LOG_FILES, true) && (stripos($b, 'error') !== false || preg_match('~\.(gz|bz2|zip|\d+)$~', $b))) continue;
        if (!@is_file($p)) continue;
        $label = (string)preg_replace('~[._-]?(access|ssl_access)?[._-]?log$|_log$~i', '', $b);
        if (in_array($label, ['', 'access', 'ssl'], true)) {
            $dir = basename(dirname($p));
            $label = in_array($dir, ['nginx', 'apache2', 'httpd', 'logs'], true) ? 'основной' . ($label === 'ssl' ? ' (ssl)' : '') : $dir;
        }
        $out[substr(sha1($p), 0, 10)] = ['path' => $p, 'label' => $label, 'readable' => @is_readable($p), 'size' => (int)@filesize($p), 'mtime' => (int)@filemtime($p)];
    }
    uasort($out, fn($a, $b) => [$b['readable'], $b['mtime']] <=> [$a['readable'], $a['mtime']]);
    return $out;
}

function diagnostics(array $logs): array
{
    $user = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : (get_current_user() ?: '?');
    $dirs = [];
    foreach (['/var/log/nginx', '/var/log/apache2', '/var/www'] as $d) {
        $dirs[$d] = !@file_exists($d) ? 'нет / не видно' : (@is_readable($d) ? 'доступна' : 'НЕТ ПРАВ на чтение');
    }
    return ['user' => $user, 'open_basedir' => (string)ini_get('open_basedir'), 'dirs' => $dirs, 'script' => __FILE__,
            'found' => array_values(array_map(fn($l) => ['path' => $l['path'], 'readable' => $l['readable'], 'size' => $l['size']], $logs))];
}

// ───────────── Чтение файла ─────────────
function json(array $data): never
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

/** До $lines полных строк, заканчивающихся на смещении $end (граница строки). Возвращает [строки, смещение начала] */
function readBefore(string $file, int $end, int $lines): array
{
    if ($end <= 0 || $lines <= 0) return [[], 0];
    $fh = fopen($file, 'rb');
    $pos = $end; $buf = ''; $nl = 0;
    while ($pos > 0 && $nl <= $lines && strlen($buf) < MAX_CHUNK_BYTES * 8) {
        $read = min(262144, $pos);
        $pos -= $read;
        fseek($fh, $pos);
        $chunk = (string)fread($fh, $read);
        $nl += substr_count($chunk, "\n");
        $buf = $chunk . $buf;
    }
    fclose($fh);
    if (str_ends_with($buf, "\n")) $buf = substr($buf, 0, -1);
    $arr = explode("\n", $buf);
    $start = $pos;
    if ($pos > 0) {                                   // первая строка обрезана
        if (count($arr) === 1) return [[], $end];
        $start += strlen(array_shift($arr)) + 1;
    }
    $drop = count($arr) - $lines;
    if ($drop > 0) {
        foreach (array_slice($arr, 0, $drop) as $l) $start += strlen($l) + 1;
        $arr = array_slice($arr, $drop);
    }
    return [$arr, $start];
}

/** Последние $lines строк: [строки, начало, конец последней полной строки] */
function readTail(string $file, int $lines): array
{
    $size = (int)filesize($file);
    if ($size === 0) return [[], 0, 0];
    $fh = fopen($file, 'rb');
    $len = min(65536, $size);
    fseek($fh, $size - $len);
    $last = (string)fread($fh, $len);
    fclose($fh);
    $nl = strrpos($last, "\n");
    if ($nl === false) return [[], 0, 0];
    $end = $size - $len + $nl + 1;
    [$arr, $start] = readBefore($file, $end, $lines);
    return [$arr, $start, $end];
}

/** Разбор пачки строк одного лога */
function parseLines(array $lines, string $label, int &$bad, array &$badSample): array
{
    $out = [];
    foreach ($lines as $line) {
        if (trim($line) === '') continue;
        $e = parseLine($line);
        if ($e === null) { $bad++; if (count($badSample) < 3) $badSample[] = mb_substr($line, 0, 300); continue; }
        if (HIDE_SELF && SELF_PATH !== '' && str_starts_with($e['p'], SELF_PATH)) continue;
        $e['f'] = $label;
        if ($e['ua'] === '') {
            $e['line'] = mb_substr(redact($line), 0, 500);              // для проверки: писал ли nginx User-Agent
            if (in_array(normIp($e['ip']), serverIps(), true)) $e['n'] = 'Сервер (сам к себе)';
        }
        if ($e['v'] === '') $e['v'] = $label;
        $out[] = $e;
    }
    return $out;
}

/** Шаблоны User-Agent ботов в формате регулярных выражений nginx */
function nginxPatterns(): array
{
    $o = [];
    foreach ([SEARCH_BOTS, AI_BOTS, OTHER_BOTS] as $list) {
        foreach ($list as $name => $re) $o[$name] = substr($re, 1, -2);
    }
    return $o;
}

function readFrom(string $file, int $offset): array
{
    $size = filesize($file);
    $skipFirst = false;
    if ($size - $offset > MAX_CHUNK_BYTES) {
        $offset = $size - MAX_CHUNK_BYTES;
        $skipFirst = true;
    }
    if ($size <= $offset) {
        return [[], $offset];
    }
    $fh = fopen($file, 'rb');
    fseek($fh, $offset);
    $data = fread($fh, $size - $offset);
    fclose($fh);
    $lastNl = strrpos($data, "\n");
    if ($lastNl === false) {
        return [[], $offset];
    }
    $arr = explode("\n", substr($data, 0, $lastNl));
    if ($skipFirst) {
        array_shift($arr);
    }
    return [$arr, $offset + $lastNl + 1];
}

function permissionHint(string $file): string
{
    $user = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'nginx') : 'nginx';
    return "Нет доступа к файлу {$file} (PHP работает от пользователя {$user}).\n"
        . "Выполните на сервере (по SSH):\n"
        . "sudo usermod -aG adm {$user}\n"
        . "sudo chgrp adm /var/log/nginx /var/log/nginx/*.log && sudo chmod 750 /var/log/nginx && sudo chmod 640 /var/log/nginx/*.log\n"
        . "sudo service php8.3-fpm restart";
}

// ───────────── API ─────────────
define('SELF_PATH', (string)($_SERVER['SCRIPT_NAME'] ?? ''));

// ───────────── Блокировка через API ─────────────
function blockEnabled(): bool { return BLOCK_API_URL !== '' && BLOCK_API_KEY !== ''; }
function csrfToken(): string { return hash_hmac('sha256', 'logviewer-block|' . __FILE__, BLOCK_API_KEY . '|' . AUTH_PASS); }
// ───────────── Хранилище данных ─────────────
const DATA_GUARD = "<?php http_response_code(404); exit; ?>\n";   // файл данных нельзя прочитать через браузер
function dataDir(): string
{
    static $dir = null;
    if ($dir !== null) return $dir;
    $d = rtrim(DATA_DIR, '/');
    if ($d !== '' && !is_dir($d)) @mkdir($d, 0770, true);
    if ($d !== '' && is_dir($d) && is_writable($d)) return $dir = $d;
    $d = sys_get_temp_dir() . '/logviewer-' . substr(md5(__FILE__), 0, 8);
    if (!is_dir($d)) @mkdir($d, 0700, true);
    return $dir = $d;
}
function dataPath(string $name): string { return dataDir() . '/' . $name . '.php'; }
function storeDecode(string $s, array $def): array
{
    if (str_starts_with($s, DATA_GUARD)) $s = substr($s, strlen(DATA_GUARD));
    $j = json_decode($s, true);
    return is_array($j) ? $j : $def;
}
function storeRead(string $name, array $def = []): array
{
    $s = @file_get_contents(dataPath($name));
    return $s === false ? $def : storeDecode($s, $def);
}
function storeUpdate(string $name, callable $fn, array $def = []): array
{
    $fh = @fopen(dataPath($name), 'c+');
    if (!$fh) return $def;
    flock($fh, LOCK_EX);
    $d = $fn(storeDecode((string)stream_get_contents($fh), $def));
    ftruncate($fh, 0); rewind($fh);
    fwrite($fh, DATA_GUARD . json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
    fflush($fh); flock($fh, LOCK_UN); fclose($fh);
    return $d;
}
function storeWrite(string $name, array $data): void { storeUpdate($name, fn() => $data); }

function blockStore(?callable $change = null): array
{
    $prune = function (array $d): array {                             // истёкшие храним сутки для истории
        foreach ($d as $ip => $b) if (($b['until'] ?? 0) && $b['until'] < time() - 86400) unset($d[$ip]);
        return $d;
    };
    return $change ? storeUpdate('blocks', fn($d) => $change($prune($d))) : $prune(storeRead('blocks'));
}

/** Проверка подлинности поискового робота по rDNS (с кешем на сутки) */
function verifyBot(string $bot, string $ip, bool $allowLookup = true): array
{
    if (!filter_var($ip, FILTER_VALIDATE_IP) || !isset(VERIFY_DOMAINS[$bot])) return ['res' => 'unknown', 'host' => ''];
    $ck = $bot . '|' . $ip;
    $cache = storeRead('rdns');
    if (isset($cache[$ck]) && $cache[$ck]['t'] > time() - 86400) return $cache[$ck];
    if (!$allowLookup) return ['res' => 'pending', 'host' => ''];
    $host = @gethostbyaddr($ip);
    $res = 'unknown';                       // нет PTR-записи или DNS недоступен — не утверждаем, что подделка
    if ($host && $host !== $ip) {
        $res = 'fake';
        foreach (VERIFY_DOMAINS[$bot] as $suffix) {
            if (!str_ends_with(strtolower($host), $suffix)) continue;
            $fwd = str_contains($ip, ':') ? array_column(@dns_get_record($host, DNS_AAAA) ?: [], 'ipv6') : (@gethostbynamel($host) ?: []);
            $fwd = array_map(fn($a) => inet_ntop(inet_pton($a)), $fwd);
            $res = in_array(inet_ntop(inet_pton($ip)), $fwd, true) ? 'ok' : 'fake';
            break;
        }
    }
    $rec = ['res' => $res, 'host' => $host ?: '', 't' => time()];
    storeUpdate('rdns', function ($c) use ($ck, $rec) {
        $c[$ck] = $rec;
        if (count($c) > 5000) { uasort($c, fn($a, $b) => $b['t'] <=> $a['t']); $c = array_slice($c, 0, 4000, true); }
        return $c;
    });
    return $rec;
}
function normIp(string $ip): string
{
    if (preg_match('~^::ffff:(\d+\.\d+\.\d+\.\d+)$~i', $ip, $m)) $ip = $m[1];
    $bin = @inet_pton($ip);
    return $bin === false ? '' : (string)inet_ntop($bin);
}
/** IP или подсеть CIDR в нормальном виде ('' если неверно) */
function normTarget(string $s): string
{
    $s = trim($s);
    if (!str_contains($s, '/')) return normIp($s);
    [$a, $p] = explode('/', $s, 2);
    $a = normIp($a);
    if ($a === '' || !ctype_digit($p)) return '';
    $max = str_contains($a, ':') ? 128 : 32;
    return (int)$p <= $max ? $a . '/' . (int)$p : '';
}
function ipInCidr(string $ip, string $cidr): bool
{
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    $ipb = @inet_pton($ip); $netb = @inet_pton((string)$net);
    if ($ipb === false || $netb === false || strlen($ipb) !== strlen($netb)) return false;
    $bits = $bits === null ? strlen($ipb) * 8 : (int)$bits;
    $bytes = intdiv($bits, 8); $rest = $bits % 8;
    if (strncmp($ipb, $netb, $bytes) !== 0) return false;
    if ($rest === 0) return true;
    $mask = chr((0xFF << (8 - $rest)) & 0xFF);
    return (($ipb[$bytes] & $mask) === ($netb[$bytes] & $mask));
}
/** Почему эту подсеть нельзя блокировать */
function protectCidr(string $cidr, string $viewer): string
{
    [$net, $bits] = explode('/', $cidr);
    $min = str_contains($net, ':') ? 32 : 16;
    if ((int)$bits < $min) return "слишком большая подсеть (минимум /{$min})";
    if (isLocalIp($net)) return 'локальная / внутренняя сеть';
    foreach (array_merge([$viewer], serverIps(), BLOCK_PROTECT_IPS, ALLOW_IPS) as $p) {
        $p = normIp((string)$p);
        if ($p !== '' && ipInCidr($p, $cidr)) return $p === normIp($viewer) ? 'в подсети ваш собственный IP' : "в подсети защищённый IP {$p}";
    }
    return '';
}
/** Разбор ответа action=list: JSON любой формы или текст */
function parseFwList(string $text): array
{
    $out = [];
    $add = function (string $raw, array $extra = []) use (&$out) {
        $t = normTarget($raw);
        if ($t === '' || isset($out[$t])) return;
        $out[$t] = ['ip' => $t] + $extra;
    };
    $j = json_decode($text, true);
    if (is_array($j)) {
        $walk = function ($node) use (&$walk, $add) {
            if (is_string($node)) { $add($node); return; }
            if (!is_array($node)) return;
            $ipKey = null;
            foreach (['ip', 'address', 'addr', 'cidr', 'network', 'net', 'source', 'src', 'subnet', 'value', 'host'] as $k) {
                if (isset($node[$k]) && is_string($node[$k]) && normTarget($node[$k]) !== '') { $ipKey = $k; break; }
            }
            if ($ipKey !== null) {
                $extra = [];
                foreach (['expires', 'expire', 'until', 'expires_at', 'expire_at', 'unblock_at', 'end'] as $k) {
                    if (empty($node[$k])) continue;
                    $v = $node[$k];
                    $ts = is_numeric($v) ? (int)$v : (int)strtotime((string)$v);
                    if ($ts > 1e9) { $extra['until'] = $ts; break; }
                }
                if (!isset($extra['until'])) foreach (['ttl', 'left', 'remaining', 'timeout'] as $k) {
                    if (isset($node[$k]) && is_numeric($node[$k]) && (int)$node[$k] > 0 && (int)$node[$k] < 1e8) { $extra['until'] = time() + (int)$node[$k]; break; }
                }
                foreach (['comment', 'reason', 'note', 'description', 'desc'] as $k) if (!empty($node[$k]) && is_string($node[$k])) { $extra['comment'] = mb_substr($node[$k], 0, 200); break; }
                foreach (['added', 'created', 'created_at', 'date', 'time', 'blocked_at'] as $k) {
                    if (empty($node[$k])) continue;
                    $ts = is_numeric($node[$k]) ? (int)$node[$k] : (int)strtotime((string)$node[$k]);
                    if ($ts > 1e9) { $extra['at'] = $ts; break; }
                }
                $add($node[$ipKey], $extra);
                return;
            }
            foreach ($node as $k => $v) {
                if (is_string($k) && normTarget($k) !== '' && !is_array($v)) { $add($k, is_numeric($v) && $v > 1e9 ? ['until' => (int)$v] : []); continue; }
                $walk($v);
            }
        };
        $walk($j);
    }
    if (!$out) {                                            // текстовый ответ: вытаскиваем все IP/подсети
        preg_match_all('~(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?)(?![\w:.])~i', $text, $m);
        foreach ($m[1] as $ip) $add($ip);
    }
    return array_values($out);
}

/** Все IP этого сервера: SERVER_ADDR, адреса имени хоста и домена API (A и AAAA). Кеш на 6 часов. */
function serverIps(): array
{
    static $mem = null;
    if ($mem !== null) return $mem;
    $c = storeRead('server_ips');
    if (!empty($c['t']) && $c['t'] > time() - 21600 && !empty($c['ips'])) return $mem = $c['ips'];
    $ips = [];
    foreach (['SERVER_ADDR', 'LOCAL_ADDR'] as $k) if (!empty($_SERVER[$k])) $ips[] = (string)$_SERVER[$k];
    $hosts = array_filter([gethostname() ?: '', (string)parse_url(BLOCK_API_URL, PHP_URL_HOST), (string)($_SERVER['SERVER_NAME'] ?? '')]);
    foreach (array_unique($hosts) as $h) {
        foreach (@gethostbynamel($h) ?: [] as $a) $ips[] = $a;
        foreach (@dns_get_record($h, DNS_AAAA) ?: [] as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    }
    $ips = array_values(array_unique(array_filter(array_map('normIp', $ips))));
    // накапливаем: однажды увиденный адрес сервера остаётся в списке
    $ips = array_values(array_unique(array_merge($c['ips'] ?? [], $ips)));
    storeWrite('server_ips', ['t' => time(), 'ips' => $ips]);
    return $mem = $ips;
}

/** Почему этот IP нельзя блокировать (или '' если можно) */
function protectReason(string $ip, string $viewer): string
{
    if (isLocalIp($ip)) return 'локальный / внутренний адрес';
    if ($ip === normIp($viewer)) return 'это ваш собственный IP';
    if (in_array($ip, serverIps(), true)) return 'это IP самого сервера';
    foreach (array_merge(BLOCK_PROTECT_IPS, ALLOW_IPS) as $p) if (normIp((string)$p) === $ip) return 'IP в списке защищённых (BLOCK_PROTECT_IPS)';
    foreach (storeRead('rdns') as $k => $v) {
        if (($v['res'] ?? '') === 'ok' && str_ends_with($k, '|' . $ip)) return 'подтверждённый поисковый робот ' . explode('|', $k)[0] . ' (' . $v['host'] . ')';
    }
    return '';
}
function blockApiCall(string $action, string $ip, int $timeout = 0): array
{
    $params = ['action' => $action, 'api_key' => BLOCK_API_KEY, 'api' => 1];
    if ($ip !== '') $params['ip'] = $ip;
    if ($timeout > 0) $params['timeout'] = $timeout;
    $body = http_build_query($params);
    $url = BLOCK_API_URL;
    $post = strtoupper(BLOCK_API_METHOD) !== 'GET';
    if (!$post) $url .= (str_contains($url, '?') ? '&' : '?') . $body;
    $resp = false; $code = 0; $err = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => API_USER_AGENT, CURLOPT_HTTPHEADER => ['Accept: application/json']]);
        if ($post) { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $body); }
        $resp = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => ['method' => $post ? 'POST' : 'GET', 'timeout' => 20, 'ignore_errors' => true,
            'header' => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nUser-Agent: " . API_USER_AGENT, 'content' => $post ? $body : '']]);
        $resp = @file_get_contents($url, false, $ctx);
        if (isset($http_response_header[0]) && preg_match('~\s(\d{3})\s~', $http_response_header[0], $m)) $code = (int)$m[1];
        if ($resp === false) $err = error_get_last()['message'] ?? 'ошибка запроса';
    }
    $text = trim(str_replace(BLOCK_API_KEY, '***', (string)$resp));
    $ok = $resp !== false && $code >= 200 && $code < 300;
    $j = json_decode($text, true);
    if (is_array($j)) {
        if (!empty($j['error']) || (isset($j['errors']) && $j['errors'])) $ok = false;
        foreach (['success', 'ok', 'status', 'result'] as $k) {
            if (!array_key_exists($k, $j)) continue;
            $v = $j[$k];
            $ok = $ok && ($v === true || $v === 1 || in_array(strtolower((string)$v), ['1', 'true', 'ok', 'success', 'blocked', 'unblocked', 'done', 'already_blocked'], true));
            break;
        }
    } elseif ($ok && preg_match('~error|ошибк|denied|invalid|forbidden|fail~iu', $text)) {
        $ok = false;
    }
    return ['ok' => $ok, 'code' => $code, 'resp' => mb_substr($text, 0, 600), 'err' => $err] + ($action === 'list' ? ['raw' => $text] : []);
}
/** Список из iptables через API action=list (кеш 20 с) */
function fwList(bool $force = false): array
{
    $c = storeRead('fwcache');
    if (!$force && !empty($c['at']) && $c['at'] > time() - 20) return $c;
    $r = blockApiCall('list', '');
    $list = $r['resp'] === '' ? [] : parseFwList($r['raw'] ?? $r['resp']);
    $res = ['ok' => $r['ok'] || $list, 'list' => $list, 'count' => count($list), 'code' => $r['code'], 'err' => $r['err'],
            'sample' => mb_substr($r['resp'], 0, 600), 'at' => time()];
    storeWrite('fwcache', $res);
    return $res;
}
function requireCsrf(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !hash_equals(csrfToken(), (string)($_SERVER['HTTP_X_TOKEN'] ?? ''))) {
        http_response_code(403);
        json(['ok' => false, 'error' => 'Неверный токен. Обновите страницу.']);
    }
}

// ───────────── 🤖 Автозащита ─────────────
const SCAN_CRITICAL_RE = '~/\.(env|git/|svn/|aws/|ssh/|htpasswd)|eval-stdin|/etc/passwd|\.\./\.\./|%2e%2e%2f|/(alfa|wso|c99|r57)\w*\.php|union[\s+]+select|<script~i';
const SCAN_RE_PHP = '~/wp-(login|admin|content|includes|config)|xmlrpc\.php|wlwmanifest|/\.(env|git|svn|aws|ssh|htpasswd|DS_Store|vscode)|phpmyadmin|/pma/|/myadmin|/vendor/phpunit|eval-stdin|/cgi-bin/|/boaform|/HNAP1|/actuator|/solr/|/owa/|/etc/passwd|\.\./|%2e%2e|<script|union[\s+]+select|/shell\.php|/(backup|dump|db|database|site)\.(sql|zip|tar|gz|rar)|/telescope|/_profiler|/server-status|/setup\.php|/sftp-config|/config\.(json|yml|yaml)|/info\.php|/phpinfo|/(alfa|wso|c99|r57)\w*\.php|/autodiscover~i';
const STATIC_RE_PHP = '~\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm|mp3)(\?|$)~i';

function autobanSettings(): array
{
    $s = storeRead('autoban_settings');
    $mode = in_array($s['mode'] ?? '', ['off', 'watch', 'ban'], true) ? $s['mode'] : AUTOBAN_MODE;
    $rules = AUTOBAN_RULES;
    foreach ($rules as $k => &$r) if (isset($s['rules'][$k])) $r['on'] = (bool)$s['rules'][$k];
    return ['mode' => $mode, 'rules' => $rules];
}
function autobanJournal(array $add = []): array
{
    if (!$add) return storeRead('autoban_journal');
    return storeUpdate('autoban_journal', function ($j) use ($add) {
        $j = array_merge($j, $add);
        return count($j) > 1500 ? array_slice($j, -1200) : $j;
    });
}
/** IP, с которых открывали эту страницу (их автозащита никогда не блокирует) */
function rememberAdmin(string $ip): void
{
    $ip = normIp($ip);
    if ($ip === '' || isLocalIp($ip)) return;
    $a = storeRead('admins');
    if (($a[$ip] ?? 0) > time() - 3600) return;
    storeUpdate('admins', function ($a) use ($ip) {
        $a[$ip] = time();
        return array_filter($a, fn($t) => $t > time() - 30 * 86400);
    });
}
/** Почему автозащите нельзя трогать IP ('' — можно) */
function autobanWhitelist(string $ip, array $x): string
{
    if (isLocalIp($ip)) return 'локальный адрес';
    if (in_array($ip, serverIps(), true)) return 'IP этого сервера';
    foreach (array_merge(BLOCK_PROTECT_IPS, ALLOW_IPS) as $p) {
        $p = normTarget((string)$p);
        if ($p !== '' && ($p === $ip || (str_contains($p, '/') && ipInCidr($ip, $p)))) return 'в списке защищённых';
    }
    if (isset(storeRead('admins')[$ip])) return 'с этого IP открывали панель логов (это вы)';
    if (in_array($x['n'] ?? '', AUTOBAN_SKIP_BOTS, true)) return 'полезный бот: ' . $x['n'];
    if (($x['k'] ?? '') === 'search' && isset(VERIFY_DOMAINS[$x['n'] ?? ''])) {
        if (verifyBot($x['n'], $ip, false)['res'] === 'ok') return 'подтверждённый ' . $x['n'];
    }
    return '';
}
function autobanCheck(string $ip, array $x, array $rules, int &$lookups): ?array
{
    $req = $scan = $n404 = $pages = 0; $peak = 0;
    foreach ($x['m'] as $b) { $req += $b[0]; $scan += $b[1]; $n404 += $b[2]; $pages += $b[3]; $peak = max($peak, $b[3]); }
    $r = $rules['scan'];
    if ($r['on'] && $scan >= $r['hits']) return ['scan', "сканер: {$scan} подозр. запрос(ов), например " . ($x['ex'] ?? ''), $r['timeout']];
    $r = $rules['badbot'];
    if ($r['on'] && in_array($x['n'] ?? '', $r['bots'], true)) return ['badbot', 'вредный бот: ' . $x['n'], $r['timeout']];
    $r = $rules['flood'];
    if ($r['on'] && $peak >= $r['per_min']) return ['flood', "флуд: {$peak} страниц в минуту", $r['timeout']];
    $r = $rules['e404'];
    if ($r['on'] && $n404 >= $r['hits'] && $req && $n404 / $req >= $r['share']) return ['e404', "перебор адресов: {$n404} ответов 404 из {$req}", $r['timeout']];
    $r = $rules['fake'];
    if ($r['on'] && ($x['k'] ?? '') === 'search' && isset(VERIFY_DOMAINS[$x['n'] ?? ''])) {
        $v = verifyBot($x['n'], $ip, $lookups < 15);
        if ($v['res'] !== 'pending') $lookups++;
        if ($v['res'] === 'fake') return ['fake', "представляется {$x['n']}, а rDNS: " . ($v['host'] ?: 'нет'), $r['timeout']];
    }
    return null;
}
/** Один проход автозащиты: читает новые строки логов, применяет правила, блокирует */
function runAutoban(string $trigger): array
{
    $cfg = autobanSettings();
    if ($cfg['mode'] === 'off') return ['ok' => true, 'skipped' => 'выключена'];
    $lock = @fopen(dataPath('autoban_lock'), 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) return ['ok' => true, 'skipped' => 'уже выполняется'];
    $t0 = microtime(true); $now = time();
    $st = storeRead('autoban_state', ['files' => [], 'ips' => []]);
    $logs = discoverLogs(); $lines = 0; $newIps = [];
    $fw = null;
    foreach ($logs as $key => $l) {
        if (!$l['readable'] || !empty($st['files'][$key]['x'])) continue;
        $file = $l['path']; clearstatcache(true, $file);
        $size = (int)@filesize($file); $inode = (int)@fileinode($file);
        $f = $st['files'][$key] ?? null;
        if ($f === null) { $st['files'][$key] = ['o' => $size, 'i' => $inode]; continue; }   // первый запуск — с текущего конца
        $off = ($f['i'] !== $inode || $f['o'] > $size) ? 0 : (int)$f['o'];
        [$arr, $newOff] = readFrom($file, $off);
        $st['files'][$key] = ['o' => $newOff, 'i' => $inode];
        $parsed = 0;
        foreach ($arr as $line) {
            if (trim($line) === '') continue;
            $e = parseLine($line);
            if ($e === null) continue;
            $parsed++;
            if ($e['t'] < $now - AUTOBAN_WINDOW || (HIDE_SELF && SELF_PATH !== '' && str_starts_with($e['p'], SELF_PATH))) continue;
            $ip = normIp($e['ip']); if ($ip === '') continue;
            $x = &$st['ips'][$ip];
            $x ??= ['m' => []];
            $min = (string)intdiv($e['t'], 60);
            $b = $x['m'][$min] ?? [0, 0, 0, 0];
            $b[0]++;
            $path = $e['p'] . ' ' . $e['m'];
            if (preg_match(SCAN_RE_PHP, $e['p']) || preg_match(SCAN_RE_PHP, $e['raw'] ?? '')) {
                $b[1] += preg_match(SCAN_CRITICAL_RE, $e['p']) || preg_match(SCAN_CRITICAL_RE, $e['raw'] ?? '') ? 2 : 1;
                $x['ex'] = mb_substr($e['p'], 0, 120);
            }
            if ($e['s'] === 404) $b[2]++;
            if (!preg_match(STATIC_RE_PHP, $e['p'])) $b[3]++;
            $x['m'][$min] = $b;
            $x['n'] = $e['n']; $x['k'] = $e['k']; $x['ua'] = mb_substr($e['ua'], 0, 200); $x['last'] = $e['t'];
            $newIps[$ip] = true;
            unset($x);
            $lines++;
        }
        if (!$parsed && count($arr) > 20 && $off === 0) $st['files'][$key]['x'] = 1;          // не access-лог
    }
    // чистим старые минуты и неактивные IP
    $minKeep = intdiv($now - AUTOBAN_WINDOW, 60);
    foreach ($st['ips'] as $ip => &$x) {
        foreach ($x['m'] as $m => $_) if ((int)$m < $minKeep) unset($x['m'][$m]);
        if (!$x['m'] && (($x['done'] ?? 0) < $now - AUTOBAN_WINDOW)) unset($st['ips'][$ip]);
    }
    unset($x);
    // решения
    $journal = autobanJournal(); $add = []; $lookups = 0;
    $bansHour = count(array_filter($journal, fn($j) => $j['act'] === 'ban' && $j['t'] > $now - 3600));
    $active = blockStore();
    foreach ($st['ips'] as $ip => &$x) {
        if (!isset($newIps[$ip]) || ($x['done'] ?? 0) > $now - AUTOBAN_WINDOW) continue;
        $hit = autobanCheck((string)$ip, $x, $cfg['rules'], $lookups);
        if (!$hit) continue;
        [$rule, $why, $timeout] = $hit;
        $x['done'] = $now;
        $rec = ['t' => $now, 'ip' => (string)$ip, 'rule' => $rule, 'why' => $why, 'n' => $x['n'] ?? '', 'k' => $x['k'] ?? '', 'by' => $trigger];
        if (($wl = autobanWhitelist((string)$ip, $x)) !== '') { $add[] = $rec + ['act' => 'skip', 'note' => $wl]; continue; }
        if (isset($active[$ip]) && ($active[$ip]['until'] ?? 0) > $now) { $add[] = $rec + ['act' => 'skip', 'note' => 'уже заблокирован']; continue; }
        $fw ??= blockEnabled() ? fwList() : ['list' => []];
        foreach ($fw['list'] ?? [] as $fe) {
            if ($fe['ip'] === $ip || (str_contains($fe['ip'], '/') && ipInCidr((string)$ip, $fe['ip']))) { $add[] = $rec + ['act' => 'skip', 'note' => 'уже в iptables: ' . $fe['ip']]; continue 2; }
        }
        if (AUTOBAN_REPEAT_X2) {
            $prev = count(array_filter($journal, fn($j) => $j['ip'] === (string)$ip && $j['act'] === 'ban' && $j['t'] > $now - 7 * 86400));
            if ($prev) { $timeout = min(2592000, $timeout * (2 ** $prev)); $rec['why'] .= " · повторно ({$prev}), срок ×" . (2 ** $prev); }
        }
        $rec['timeout'] = $timeout;
        if ($cfg['mode'] === 'watch') { $add[] = $rec + ['act' => 'watch']; continue; }
        if (!blockEnabled()) { $add[] = $rec + ['act' => 'error', 'note' => 'не настроен BLOCK_API_KEY']; continue; }
        if ($bansHour >= AUTOBAN_MAX_PER_HOUR) { $add[] = $rec + ['act' => 'limit', 'note' => 'предохранитель: ' . AUTOBAN_MAX_PER_HOUR . ' банов в час']; continue; }
        $r = blockApiCall('block', (string)$ip, $timeout);
        if ($r['ok']) {
            $bansHour++;
            blockStore(function ($d) use ($ip, $timeout, $rec) {
                $d[$ip] = ['ip' => (string)$ip, 'at' => time(), 'until' => time() + $timeout, 'timeout' => $timeout, 'reason' => '🤖 ' . $rec['why'], 'by' => 'автозащита'];
                return $d;
            });
            $add[] = $rec + ['act' => 'ban', 'note' => mb_substr($r['resp'], 0, 200)];
        } else {
            $add[] = $rec + ['act' => 'error', 'note' => mb_substr($r['err'] ?: ('HTTP ' . $r['code'] . ': ' . $r['resp']), 0, 200)];
        }
    }
    unset($x);
    if ($add) { autobanJournal($add); if (array_filter($add, fn($a) => $a['act'] === 'ban')) storeWrite('fwcache', []); }
    $st['last'] = $now; $st['trigger'] = $trigger;
    storeWrite('autoban_state', $st);
    $sum = ['ok' => true, 't' => $now, 'by' => $trigger, 'mode' => $cfg['mode'], 'lines' => $lines, 'ips' => count($st['ips']),
            'decisions' => count($add), 'ms' => (int)((microtime(true) - $t0) * 1000)];
    storeWrite('autoban_last', $sum + ($trigger === 'cron' ? ['cron' => $now] : ['cron' => storeRead('autoban_last')['cron'] ?? 0]));
    flock($lock, LOCK_UN); fclose($lock);
    return $sum + ['new' => $add];
}

// Запуск из командной строки / cron:  php logs.php --autoban
if (PHP_SAPI === 'cli' && in_array('--autoban', $argv ?? [], true)) {
    $r = runAutoban('cron');
    echo date('Y-m-d H:i:s') . ' ' . json_encode(array_diff_key($r, ['new' => 1]), JSON_UNESCAPED_UNICODE) . PHP_EOL;
    foreach ($r['new'] ?? [] as $n) echo "  {$n['act']}\t{$n['ip']}\t{$n['why']}" . (isset($n['note']) ? "\t({$n['note']})" : '') . PHP_EOL;
    exit(0);
}

$api = $_GET['api'] ?? '';

if ($api === 'autoban') {
    $st = storeRead('autoban_state');
    $cfg = autobanSettings();
    $user = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '') : '';
    json(['mode' => $cfg['mode'], 'rules' => $cfg['rules'], 'last' => storeRead('autoban_last'), 'journal' => array_slice(autobanJournal(), -400),
          'admins' => storeRead('admins'), 'tracked' => count($st['ips'] ?? []), 'enabled' => blockEnabled(),
          'dataDir' => dataDir(), 'dataOk' => rtrim(DATA_DIR, '/') === dataDir(), 'user' => $user, 'script' => __FILE__,
          'php' => is_file($pv = PHP_BINDIR . '/php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION) ? $pv : PHP_BINDIR . '/php', 'maxHour' => AUTOBAN_MAX_PER_HOUR, 'window' => AUTOBAN_WINDOW, 'skipBots' => AUTOBAN_SKIP_BOTS, 'now' => time()]);
}
if ($api === 'autoban_set') {
    requireCsrf();
    $mode = (string)($_POST['mode'] ?? '');
    $rule = (string)($_POST['rule'] ?? '');
    storeUpdate('autoban_settings', function ($s) use ($mode, $rule) {
        if (in_array($mode, ['off', 'watch', 'ban'], true)) $s['mode'] = $mode;
        if (isset(AUTOBAN_RULES[$rule])) $s['rules'][$rule] = ($_POST['on'] ?? '') === '1';
        return $s;
    });
    json(['ok' => true] + autobanSettings());
}
if ($api === 'autoban_run') {
    requireCsrf();
    json(runAutoban('вручную'));
}

if ($api === 'tail') {
    $logs = discoverLogs();
    $want = (string)($_GET['f'] ?? 'all');
    $keys = $want === 'all' ? array_keys(array_filter($logs, fn($l) => $l['readable'])) : array_intersect(explode(',', $want), array_keys($logs));
    $state = json_decode((string)($_GET['s'] ?? '{}'), true) ?: [];
    if (!$keys) {
        json(['error' => $logs ? 'Логи найдены, но PHP не может их прочитать. ' . permissionHint(reset($logs)['path'])
                               : 'Не найдено ни одного access-лога. Укажите путь в EXTRA_LOG_FILES в начале logs.php.',
              'diag' => diagnostics($logs)]);
    }
    $entries = []; $newState = []; $bad = 0; $badSample = []; $errors = []; $total = 0; $skipped = [];
    foreach ($keys as $key) {
        $file = $logs[$key]['path'];
        if (!empty($state[$key]['x'])) {                 // лог другого формата — пропускаем
            $newState[$key] = $state[$key];
            $skipped[] = $file;
            continue;
        }
        clearstatcache(true, $file);
        if (!is_readable($file)) { $errors[] = permissionHint($file); continue; }
        $offset = max(0, (int)($state[$key]['o'] ?? 0));
        $inode  = (int)($state[$key]['i'] ?? 0);
        $curInode = (int)fileinode($file);
        $size = (int)filesize($file);
        $total += $size;
        $begin = (int)($state[$key]['b'] ?? 0);
        if ($offset === 0 || $inode === 0) {             // первое открытие — последние строки
            [$lines, $begin, $newOffset] = readTail($file, INITIAL_LINES);
        } elseif ($inode !== $curInode || $offset > $size) { // ротация лога — новый файл читаем с начала
            [$lines, $newOffset] = readFrom($file, 0);
            $begin = 0;
        } else {
            [$lines, $newOffset] = readFrom($file, $offset);
        }
        $newState[$key] = ['o' => $newOffset, 'i' => $curInode, 'b' => $begin];
        $fileBad = 0; $fileSample = [];
        $parsed = parseLines($lines, $logs[$key]['label'], $fileBad, $fileSample);
        if (!$parsed && $fileBad > 0 && ($offset === 0 || $inode === 0)) {
            // ни одна строка не похожа на access-лог (например, лог upstream) — это не лог посещений
            $newState[$key] = ['o' => $newOffset, 'i' => $curInode, 'b' => 0, 'x' => 1];
            $skipped[] = $file;
            continue;
        }
        $bad += $fileBad;
        foreach ($fileSample as $l) if (count($badSample) < 3) $badSample[] = $l;
        array_push($entries, ...$parsed);
    }
    usort($entries, fn($a, $b) => $a['t'] <=> $b['t']);
    if (AUTOBAN_VIA_WEB && (storeRead('autoban_last')['t'] ?? 0) < time() - 55) {
        if (function_exists('fastcgi_finish_request')) register_shutdown_function(function () { fastcgi_finish_request(); runAutoban('страница'); });
        else runAutoban('страница');
    }
    json(['entries' => $entries, 'state' => $newState, 'size' => $total, 'files' => count($keys), 'bad' => $bad,
          'badSample' => $badSample, 'warn' => $errors, 'skipped' => $skipped, 'now' => time(),
          'diag' => ($entries || $state) ? null : diagnostics($logs)]);
}

if ($api === 'history') {                              // более старые строки (для выбора периода)
    $logs = discoverLogs();
    $state = json_decode((string)($_GET['s'] ?? '{}'), true) ?: [];
    $n = min(20000, max(100, (int)($_GET['n'] ?? 5000)));
    $entries = []; $newState = []; $bad = 0; $badSample = [];
    foreach ($state as $key => $st) {
        $key = (string)$key;
        if (!isset($logs[$key]) || !$logs[$key]['readable'] || !is_array($st)) continue;
        $file = $logs[$key]['path'];
        $b = (int)($st['b'] ?? 0);
        if ($b <= 0 || !empty($st['x']) || (int)@fileinode($file) !== (int)($st['i'] ?? 0)) { $newState[$key] = ['b' => 0]; continue; }
        [$lines, $start] = readBefore($file, $b, $n);
        $newState[$key] = ['b' => $start];
        array_push($entries, ...parseLines($lines, $logs[$key]['label'], $bad, $badSample));
    }
    usort($entries, fn($a, $b) => $a['t'] <=> $b['t']);
    json(['entries' => $entries, 'state' => $newState, 'bad' => $bad,
          'more' => (bool)array_filter($newState, fn($x) => $x['b'] > 0)]);
}

if ($api === 'blocks') {
    $list = blockEnabled() ? blockStore() : [];
    json(['enabled' => blockEnabled(), 'blocks' => array_values($list), 'now' => time()]);
}

if ($api === 'fwlist') {                                 // что сейчас реально заблокировано в iptables
    if (!blockEnabled()) json(['ok' => false, 'error' => 'Блокировка через API не настроена']);
    json(fwList(!empty($_GET['force'])));
}

if ($api === 'clearall') {                               // снять ВСЕ баны (IP + CIDR, v4 + v6)
    if (!blockEnabled()) json(['ok' => false, 'error' => 'Блокировка через API не настроена']);
    requireCsrf();
    if (($_POST['confirm'] ?? '') !== 'СНЯТЬ ВСЁ') json(['ok' => false, 'error' => 'Нет подтверждения']);
    $r = blockApiCall('clear', '');
    if ($r['ok']) blockStore(fn($d) => []);
    storeWrite('fwcache', []);
    json($r);
}

if ($api === 'block' || $api === 'unblock') {
    if (!blockEnabled()) json(['ok' => false, 'error' => 'Блокировка через API не настроена (BLOCK_API_KEY)']);
    requireCsrf();
    $ip = normTarget((string)($_POST['ip'] ?? ''));
    if ($ip === '') json(['ok' => false, 'error' => 'Неверный IP-адрес или подсеть']);
    storeWrite('fwcache', []);                            // список iptables изменится
    if ($api === 'unblock') {
        if (BLOCK_API_UNBLOCK === '') json(['ok' => false, 'error' => 'Разблокировка через API не настроена (BLOCK_API_UNBLOCK)']);
        $r = blockApiCall(BLOCK_API_UNBLOCK, $ip);
        if ($r['ok']) blockStore(function ($d) use ($ip) { unset($d[$ip]); return $d; });
        json($r + ['ip' => $ip]);
    }
    if (str_contains($ip, '/')) {
        $whyNet = protectCidr($ip, $remote);
        if ($whyNet !== '') json(['ok' => false, 'error' => "Нельзя заблокировать подсеть: {$whyNet}"]);
    }
    $why = str_contains($ip, '/') ? '' : protectReason($ip, $remote);
    if ($why !== '' && (isLocalIp($ip) || $ip === normIp($remote) || in_array($ip, serverIps(), true))) json(['ok' => false, 'error' => "Нельзя заблокировать: {$why}"]);
    if ($why !== '' && empty($_POST['force'])) json(['ok' => false, 'protected' => true, 'error' => "Этот IP защищён: {$why}"]);
    $timeout = (int)($_POST['timeout'] ?? BLOCK_DEFAULT);
    if (!isset(BLOCK_TIMEOUTS[$timeout])) $timeout = BLOCK_DEFAULT;
    $reason = mb_substr(trim((string)($_POST['reason'] ?? '')), 0, 200);
    $r = blockApiCall('block', $ip, $timeout);
    if ($r['ok']) {
        blockStore(function ($d) use ($ip, $timeout, $reason, $remote) {
            $d[$ip] = ['ip' => $ip, 'at' => time(), 'until' => time() + $timeout, 'timeout' => $timeout, 'reason' => $reason, 'by' => $remote];
            return $d;
        });
    }
    json($r + ['ip' => $ip, 'until' => time() + $timeout]);
}

if ($api === 'diag') {
    json(diagnostics(discoverLogs()));
}

if ($api === 'verify') {
    $ip = (string)($_GET['ip'] ?? '');
    json(['ip' => $ip] + verifyBot((string)($_GET['bot'] ?? ''), $ip));
}

// ───────────── Страница ─────────────
rememberAdmin($remote);
$logs = discoverLogs();
$readableCount = count(array_filter($logs, fn($l) => $l['readable']));
$jsonFlags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP;
header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Живые логи</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📜</text></svg>">
<style>
:root{
  --bg:#f4f5f9;--panel:#fff;--panel2:#f0f2f7;--text:#1b1f2a;--muted:#6b7280;--line:#e3e6ee;--accent:#4f46e5;
  --browser:#2563eb;--search:#16a34a;--ai:#9333ea;--bot:#ea580c;--fake:#dc2626;--threat:#be123c;
  --s2:#16a34a;--s3:#0891b2;--s4:#d97706;--s5:#dc2626;--shadow:0 1px 3px rgba(0,0,0,.06),0 4px 14px rgba(0,0,0,.04);
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0e1117;--panel:#161a23;--panel2:#1d2230;--text:#e6e8ee;--muted:#8b93a5;--line:#2a3040;--accent:#818cf8;
  --browser:#60a5fa;--search:#4ade80;--ai:#c084fc;--bot:#fb923c;--fake:#f87171;--threat:#fb7185;
  --s2:#4ade80;--s3:#22d3ee;--s4:#fbbf24;--s5:#f87171;--shadow:none;
}}
:root[data-theme=dark]{
  --bg:#0e1117;--panel:#161a23;--panel2:#1d2230;--text:#e6e8ee;--muted:#8b93a5;--line:#2a3040;--accent:#818cf8;
  --browser:#60a5fa;--search:#4ade80;--ai:#c084fc;--bot:#fb923c;--fake:#f87171;--threat:#fb7185;
  --s2:#4ade80;--s3:#22d3ee;--s4:#fbbf24;--s5:#f87171;--shadow:none;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line);padding:8px 16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
h1{font-size:17px;margin:0 6px 0 0;white-space:nowrap}
select,input,button,textarea{font:inherit;color:inherit;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
button{cursor:pointer;white-space:nowrap}button:hover{border-color:var(--muted)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--fake);border-color:color-mix(in srgb,var(--fake) 40%,transparent)}
button.sm,a.btn.sm{padding:2px 8px;font-size:12px;border-radius:6px}
a.btn{display:inline-block;color:inherit;text-decoration:none;background:var(--panel2);border:1px solid var(--line)}a.btn:hover{border-color:var(--muted)}
.live{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.dot{width:10px;height:10px;border-radius:50%;background:var(--search);animation:pulse 1.6s infinite}
.paused .dot{background:var(--muted);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--search) 60%,transparent)}100%{box-shadow:0 0 0 9px transparent}}
.spacer{flex:1}.muted{color:var(--muted)}
main{padding:14px 16px;max-width:1700px;margin:0 auto}
.error{background:color-mix(in srgb,var(--fake) 12%,var(--panel));border:1px solid var(--fake);border-radius:10px;padding:12px 14px;margin-bottom:14px;white-space:pre-wrap;font-family:ui-monospace,Consolas,monospace;font-size:13px}
.warnbox{background:color-mix(in srgb,var(--s4) 12%,var(--panel));border:1px solid var(--s4);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}
.warnbox pre{white-space:pre-wrap;word-break:break-all;margin:6px 0 0;font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:9px 13px;box-shadow:var(--shadow);cursor:pointer;border-top:3px solid var(--c,var(--muted));transition:transform .1s}
.card:hover{transform:translateY(-1px)}.card.on{outline:2px solid var(--c,var(--muted))}
.card .v{font-size:23px;font-weight:700;font-variant-numeric:tabular-nums}.card .l{color:var(--muted);font-size:12px}
.card .d{font-size:11px;color:var(--muted)}.dl{font-weight:700;margin-left:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);margin-bottom:14px}
.panel h2{font-size:14px;margin:0;padding:10px 14px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.chart{padding:8px 14px 4px}.chart svg{width:100%;height:130px;display:block}
.axis{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);padding:0 14px 8px}
.legend{display:flex;gap:12px;font-size:12px;color:var(--muted);flex-wrap:wrap}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:4px;vertical-align:-1px}
.tabs{display:flex;gap:4px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--line)}
.tabs button{border-radius:8px}.tabs button.on{background:var(--text);color:var(--panel);border-color:var(--text)}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}.seg button{border:0;border-radius:0;background:var(--panel2)}
.seg button.on{background:var(--c);color:#fff;font-weight:700}
.tabs .cnt{display:inline-block;min-width:18px;padding:0 5px;margin-left:4px;border-radius:9px;background:var(--threat);color:#fff;font-size:11px;font-weight:700;text-align:center}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line)}
.toolbar input[type=search]{flex:1;min-width:200px}
.chips{display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px;border-bottom:1px solid var(--line)}
.chip{display:inline-flex;gap:6px;align-items:center;background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);color:var(--accent);border-radius:999px;padding:2px 4px 2px 10px;font-size:12px;font-weight:600}
.chip button{border:0;background:none;padding:0 6px;color:inherit;font-size:14px;line-height:1}
label.chk{display:inline-flex;gap:6px;align-items:center;color:var(--muted);cursor:pointer;white-space:nowrap}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{position:sticky;top:var(--hdr,52px);background:var(--panel2);text-align:left;font-weight:600;color:var(--muted);padding:7px 10px;font-size:12px;z-index:1;white-space:nowrap}
.tbl th.sort{cursor:pointer}.tbl th.sort:hover{color:var(--text)}
.tbl td{padding:6px 10px;border-top:1px solid var(--line);vertical-align:top}
.tbl tr.row{cursor:pointer}.tbl tr.row:hover td{background:var(--panel2)}
.tbl tr.new td{animation:flash 2s ease-out}
.tbl tr.thr td:first-child{box-shadow:inset 3px 0 0 var(--threat)}
@keyframes flash{from{background:color-mix(in srgb,var(--search) 22%,transparent)}to{background:transparent}}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.path{max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;
  color:var(--c);background:color-mix(in srgb,var(--c) 13%,transparent);border:1px solid color-mix(in srgb,var(--c) 30%,transparent)}
.k-browser{--c:var(--browser)}.k-search{--c:var(--search)}.k-ai{--c:var(--ai)}.k-bot{--c:var(--bot)}.k-fake{--c:var(--fake)}.k-threat{--c:var(--threat)}
.st{font-weight:700;font-variant-numeric:tabular-nums}.s2{color:var(--s2)}.s3{color:var(--s3)}.s4{color:var(--s4)}.s5{color:var(--s5)}
.vf{font-size:11px;margin-left:4px}.vf.ok{color:var(--search)}.vf.fake{color:var(--fake);font-weight:700}
.qf{cursor:pointer;border-bottom:1px dashed transparent}.qf:hover{border-bottom-color:currentColor}
.detail td{background:var(--panel2);font-size:12.5px}.detail dl{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;margin:4px 0}.detail dt{color:var(--muted)}.detail dd{margin:0;word-break:break-all}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.bar{height:8px;border-radius:4px;background:var(--panel2);overflow:hidden;display:flex;min-width:100px}.bar span{height:100%}
.empty{padding:40px;text-align:center;color:var(--muted)}
.scroll{overflow:visible}
.sub{color:var(--muted);font-size:12px}.site{font-size:11px;color:var(--muted);display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px;padding:14px}
.top{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.top h3{margin:0;font-size:13px;padding:8px 12px;background:var(--panel2);display:flex;justify-content:space-between}
.top ol{list-style:none;margin:0;padding:4px 0}
.top li{display:grid;grid-template-columns:1fr auto;gap:2px 10px;padding:5px 12px;cursor:pointer;position:relative}
.top li:hover{background:var(--panel2)}
.top li .k{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.top li .n{font-weight:700;font-variant-numeric:tabular-nums;font-size:13px}
.top li .b{grid-column:1/3;height:4px;border-radius:2px;background:var(--c,var(--accent));opacity:.55}
.reason{display:inline-block;padding:1px 7px;margin:1px 3px 1px 0;border-radius:6px;font-size:11.5px;font-weight:600;background:color-mix(in srgb,var(--threat) 12%,transparent);color:var(--threat)}
pre.cfg{margin:0;padding:12px 14px;background:var(--panel2);border-radius:8px;overflow:auto;font-size:12.5px;max-height:420px}
.blockgrid{display:grid;grid-template-columns:minmax(260px,1fr) minmax(320px,1.4fr);gap:14px;padding:14px}
.blist{display:flex;flex-direction:column;gap:6px}
.bitem{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 10px;border:1px solid var(--line);border-radius:8px}
.help{font-size:12.5px;color:var(--muted);line-height:1.6}
.help code{background:var(--panel2);padding:1px 5px;border-radius:4px;color:var(--text)}
.diag summary{cursor:pointer;padding:10px 14px;font-weight:600}.diag>div{padding:0 14px 12px;font-size:13px}.diag code{font-size:12px}
dialog{border:1px solid var(--line);border-radius:14px;background:var(--panel);color:var(--text);padding:18px;width:min(460px,calc(100vw - 24px));box-shadow:0 20px 60px rgba(0,0,0,.35)}
dialog::backdrop{background:rgba(0,0,0,.45)}
.frow{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:10px}.frow input,.frow select{flex:1;max-width:260px}
button.primary-danger{background:var(--fake);border-color:var(--fake);color:#fff}
.ban{display:inline-block;margin-left:6px;padding:0 6px;border-radius:6px;font-size:11px;font-weight:700;background:color-mix(in srgb,var(--fake) 15%,transparent);color:var(--fake);font-family:system-ui,sans-serif}
#toasts{position:fixed;right:16px;bottom:16px;z-index:50;display:flex;flex-direction:column;gap:8px;max-width:min(420px,calc(100vw - 32px))}
.toast{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--accent));border-radius:10px;padding:10px 12px;box-shadow:0 8px 30px rgba(0,0,0,.18);font-size:13px;animation:tin .25s ease-out;cursor:pointer}
.toast b{display:block;margin-bottom:2px}.toast{word-break:break-word;overflow-wrap:anywhere}
@keyframes tin{from{transform:translateY(12px);opacity:0}}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(420px,100vw);background:var(--panel);border-left:1px solid var(--line);z-index:40;padding:16px;overflow:auto;box-shadow:-10px 0 40px rgba(0,0,0,.2);transform:translateX(105%);transition:transform .2s}
.drawer.open{transform:none}
.drawer h3{margin:16px 0 8px;font-size:14px}.drawer h3:first-of-type{margin-top:4px}
.drawer .row2{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:5px 0}
.drawer input[type=number]{width:80px}
.kbd{font-family:ui-monospace,monospace;font-size:11px;border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 5px}
.grid2{display:grid;grid-template-columns:repeat(auto-fill,minmax(520px,1fr));gap:12px;padding:14px}
.chartbox h3 .legend{font-weight:400}.chartbox .row2{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:13px}
.heat{display:grid;grid-template-columns:28px repeat(24,1fr);gap:3px;font-size:10px;color:var(--muted)}
.heat .hc{aspect-ratio:1.4;border-radius:3px;min-height:14px}.heat .hh{text-align:center}.heat .hd{display:flex;align-items:center}
.hbar{height:6px;border-radius:3px;margin:2px 0;min-width:1px}
.tbl.mini td{padding:4px 6px;font-size:12.5px}.tbl.mini .path{max-width:260px}
.path-list{margin:4px 0;padding-left:22px;line-height:1.8;font-size:12.5px}
@media (max-width:800px){.grid2{grid-template-columns:1fr;padding:10px}.heat{gap:1px}
.hide-sm{display:none}.path{max-width:160px}.blockgrid{grid-template-columns:1fr}.scroll{overflow-x:auto}.tbl th{position:static}
  #file{max-width:100%;flex:1 1 100%}#info{display:none}.grid{grid-template-columns:1fr;padding:10px}main{padding:10px}.detail dl{grid-template-columns:1fr}}
</style>
</head>
<body>
<header id="hdr">
  <h1>📜 Живые логи</h1>
  <select id="file" title="Какие логи показывать">
    <option value="all">📚 Все логи (<?= $readableCount ?>)</option>
    <?php foreach ($logs as $k => $l): ?>
      <option value="<?= htmlspecialchars($k) ?>" <?= $l['readable'] ? '' : 'disabled' ?>><?= htmlspecialchars($l['label']) ?> — <?= htmlspecialchars($l['path']) ?><?= $l['readable'] ? '' : ' (нет прав)' ?></option>
    <?php endforeach ?>
  </select>
  <select id="period" title="Период">
    <option value="0">⏱ Всё загруженное</option><option value="300">5 минут</option><option value="900">15 минут</option>
    <option value="3600">1 час</option><option value="21600">6 часов</option><option value="86400">24 часа</option><option value="today">Сегодня</option>
  </select>
  <button id="more" title="Подгрузить более старые строки из лога">⏪ Ещё</button>
  <select id="interval" title="Частота обновления">
    <option value="1000">1 с</option><option value="2000" selected>2 с</option><option value="5000">5 с</option><option value="15000">15 с</option>
  </select>
  <button id="pause" title="Пауза (пробел)"><span class="live"><span class="dot"></span><span id="liveTxt">В ЭФИРЕ</span></span></button>
  <span class="spacer"></span>
  <span class="muted sub" id="info"></span>
  <button id="csv" title="Скачать отфильтрованные запросы в CSV">⬇ CSV</button>
  <button id="settingsBtn" title="Уведомления и настройки">🔔 Настройки</button>
</header>

<main>
  <div id="err" class="error" hidden></div>
  <div id="warn" class="warnbox" hidden></div>
  <div id="skipped" class="sub" style="margin:-6px 0 10px" hidden></div>
  <details id="diag" class="panel diag" hidden><summary>🩺 Диагностика: где искались логи</summary><div id="diagBody"></div></details>
  <div class="cards" id="cards"></div>

  <div class="panel">
    <h2><span id="chartTitle">Запросы во времени</span><span class="spacer"></span>
      <span class="legend"><span><i style="background:var(--browser)"></i>Браузеры</span><span><i style="background:var(--search)"></i>Поисковики</span><span><i style="background:var(--ai)"></i>ИИ-боты</span><span><i style="background:var(--bot)"></i>Прочие боты</span><span><i style="background:var(--s5)"></i>Ошибки 5xx</span></span>
    </h2>
    <div class="chart"><svg id="chart" preserveAspectRatio="none"></svg></div>
    <div class="axis" id="axis"></div>
  </div>

  <div class="panel">
    <div class="tabs" id="tabs">
      <button data-tab="feed" class="on">📃 Лента</button>
      <button data-tab="overview">📊 Обзор</button>
      <button data-tab="analytics">📈 Аналитика</button>
      <button data-tab="seo">🔍 SEO</button>
      <button data-tab="visitors">👣 Посетители</button>
      <button data-tab="groups">🗂 Группы</button>
      <button data-tab="slow">🐢 Медленные</button>
      <button data-tab="threats">🚨 Угрозы<span class="cnt" id="thrCnt" hidden></span></button>
      <button data-tab="block">🚫 Блокировка<span class="cnt" id="blkCnt" hidden></span></button>
      <button data-tab="autoban">🤖 Автозащита<span class="cnt" id="abCnt" hidden></span></button>
    </div>
    <div class="toolbar" id="toolbar">
      <select id="groupBy" hidden>
        <option value="n">По боту / браузеру</option><option value="v">По сайту</option><option value="k">По типу посетителя</option><option value="ip">По IP</option>
        <option value="p">По URL</option><option value="s">По коду ответа</option><option value="r">По рефереру</option>
        <option value="os">По ОС</option><option value="d">По устройству</option><option value="m">По методу</option>
      </select>
      <input type="search" id="q" placeholder="Поиск: IP, URL, User-Agent, код…  (клавиша /)">
      <label class="chk"><input type="checkbox" id="noStatic"> без статики</label>
      <label class="chk"><input type="checkbox" id="onlyErr"> только ошибки</label>
    </div>
    <div class="chips" id="chips" hidden></div>
    <div class="scroll" id="view"></div>
  </div>
  <p class="sub" style="text-align:center">Клавиши: <span class="kbd">/</span> поиск · <span class="kbd">пробел</span> пауза · <span class="kbd">1</span>–<span class="kbd">0</span> вкладки · <span class="kbd">Esc</span> сбросить фильтры</p>
</main>

<aside class="drawer" id="drawer">
  <div style="display:flex;justify-content:space-between;align-items:center"><b style="font-size:16px">🔔 Уведомления и настройки</b><button id="drawerClose">✕</button></div>
  <h3>Как уведомлять</h3>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="sound"> 🔊 Звук</label><button class="sm" id="testSound">проверить</button></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="desktop"> 💻 Системные уведомления</label><span class="sub" id="notifState"></span></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="toast"> 💬 Всплывающие сообщения на странице</label></div>
  <h3>О чём уведомлять (только о новых строках)</h3>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="e5xx"> ❌ Ошибки 5xx, от</label><span><input type="number" min="1" data-set="e5xxN"> за минуту</span></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="eFake"> ⚠️ Поддельный поисковый робот</label></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="eScan"> 🔎 Сканер уязвимостей (/.env, /wp-login…)</label></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="eFlood"> 🌊 Флуд с одного IP, от</label><span><input type="number" min="10" data-set="flood"> в минуту</span></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="eSlow"> 🐢 Медленный ответ, от</label><span><input type="number" min="0.1" step="0.1" data-set="slowSec"> сек</span></div>
  <div class="row2"><label class="chk"><input type="checkbox" data-set="eSearch"> 🔍 Пришёл Googlebot / YandexBot</label></div>
  <h3>Вид</h3>
  <div class="row2"><span>Тема</span><select data-set="theme"><option value="auto">как в системе</option><option value="light">светлая</option><option value="dark">тёмная</option></select></div>
  <div class="row2"><span>Строк в ленте</span><select data-set="feedRows"><option>200</option><option>400</option><option>1000</option><option>3000</option></select></div>
  <p class="help">Настройки хранятся в этом браузере. Системные уведомления работают только по https или на localhost.</p>
</aside>
<div id="toasts"></div>
<dialog id="blockDlg">
  <form method="dialog" id="blockForm">
    <h3 style="margin:0 0 10px">⛔ Заблокировать на сервере</h3>
    <div id="blockInfo"></div>
    <label class="frow" id="blockTargetRow">Что блокировать <select id="blockTarget"></select></label>
    <label class="frow">На сколько <select id="blockTimeout"></select></label>
    <label class="frow">Причина <input id="blockReason" maxlength="200" placeholder="например: сканер /.env"></label>
    <div id="blockWarn" class="warnbox" hidden style="margin:10px 0 0"></div>
    <div class="actions" style="justify-content:flex-end;margin-top:14px">
      <button value="cancel" formnovalidate>Отмена</button>
      <button value="ok" class="danger primary-danger" id="blockOk">⛔ Заблокировать</button>
    </div>
  </form>
</dialog>

<script>
'use strict';
const BOT_RE = <?= json_encode(nginxPatterns(), $jsonFlags) ?>;
const BLOCK = <?= json_encode(['enabled' => blockEnabled(), 'token' => blockEnabled() ? csrfToken() : '', 'timeouts' => BLOCK_TIMEOUTS,
    'def' => BLOCK_DEFAULT, 'unblock' => BLOCK_API_UNBLOCK !== '', 'me' => normIp($remote)], $jsonFlags) ?>;
const VERIFIABLE = <?= json_encode(array_keys(VERIFY_DOMAINS), $jsonFlags) ?>;
const KINDS = {
  browser:{label:'Браузер',  plural:'Браузеры',    icon:'🧑‍💻'},
  search: {label:'Поисковик',plural:'Поисковики',  icon:'🔍'},
  ai:     {label:'ИИ-бот',   plural:'ИИ-боты',     icon:'🤖'},
  bot:    {label:'Бот',      plural:'Прочие боты', icon:'🕷️'},
};
const KIND_KEYS = ['browser', 'search', 'ai', 'bot'];
const MAX_ENTRIES = 150000;
const STATIC_RE = /\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm|mp3)(\?|$)/i;
const SCAN_RE = /\/wp-(login|admin|content|includes|config)|xmlrpc\.php|wlwmanifest|\/\.(env|git|svn|aws|ssh|htpasswd|DS_Store|vscode)|phpmyadmin|\/pma\/|\/myadmin|\/vendor\/phpunit|eval-stdin|\/cgi-bin\/|\/boaform|\/HNAP1|\/actuator|\/solr\/|\/owa\/|\/etc\/passwd|\.\.\/|%2e%2e|<script|union[\s+%20]+select|\/shell\.php|\/(backup|dump|db|database|site)\.(sql|zip|tar|gz|rar)|\/telescope|\/_profiler|\/server-status|\/setup\.php|\/sftp-config|\/config\.(json|yml|yaml)|\/info\.php|\/phpinfo|\/(alfa|wso|c99|r57)\w*\.php|\/autodiscover/i;
const SEARCH_REF = [['Яндекс', /(^|\.)(yandex|ya)\.[a-z.]+$/], ['Google', /(^|\.)google\.[a-z.]+$/], ['Bing', /(^|\.)bing\.com$/], ['DuckDuckGo', /duckduckgo\.com$/],
  ['Mail.ru', /(^|\.)go\.mail\.ru$/], ['Yahoo', /search\.yahoo\./], ['Baidu', /baidu\.com$/], ['Ecosia', /ecosia\.org$/], ['Brave', /search\.brave\.com$/]];
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const nf = n => n.toLocaleString('ru-RU');

// ───── Настройки ─────
const DEF = {interval:'2000', noStatic:false, groupBy:'n', period:'0', theme:'auto', feedRows:'400',
  sound:false, desktop:false, toast:true, e5xx:true, e5xxN:5, eFake:true, eScan:true, eFlood:true, flood:120, eSlow:false, slowSec:2, eSearch:false,
  blocks:{ips:[], bots:[], noUA:false}};
let cfg = {...DEF};
try { cfg = {...DEF, ...JSON.parse(localStorage.getItem('logviewer2') || '{}')}; cfg.blocks = {...DEF.blocks, ...cfg.blocks}; } catch {}
const save = () => { try { localStorage.setItem('logviewer2', JSON.stringify(cfg)); } catch {} };

const st = {
  file: 'all', fstate: {}, entries: [], seq: 0, lastSeenSeq: 0, more: true, loadingHist: false,
  paused: false, timer: null, tab: 'feed', kind: '', qf: {}, open: new Set(), verify: {}, vq: [], vBusy: false,
  sort: {slow:'p95'}, alerted: {}, unread: 0, badTotal: 0, badSample: [], warn: [], firstLoaded: false,
};

// ───── Загрузка ─────
async function getJSON(url) {
  const r = await fetch(url, {cache:'no-store'});
  const text = await r.text();
  try { return JSON.parse(text); } catch { throw new Error(`HTTP ${r.status}: ${text.replace(/<[^>]+>/g, ' ').slice(0, 300)}`); }
}
async function poll() {
  clearTimeout(st.timer);
  const reqFile = st.file;
  try {
    const d = await getJSON(`?api=tail&f=${encodeURIComponent(st.file)}&s=${encodeURIComponent(JSON.stringify(st.fstate))}`);
    if (reqFile !== st.file) return;
    showDiag(d.diag);
    if (d.error) showErr(d.error);
    else {
      showErr('');
      const first = !st.firstLoaded;
      for (const [k, v] of Object.entries(d.state)) st.fstate[k] = {...st.fstate[k], ...v};
      addEntries(d.entries, !first);
      st.warn = d.warn || [];
      st.skipped = d.skipped || [];
      noteBad(d, first);
      st.firstLoaded = true;
      st.more = Object.values(st.fstate).some(x => x.b > 0);
      $('#info').textContent = `${d.files} лог(ов) · ${fmtBytes(d.size)} · ${new Date().toLocaleTimeString('ru-RU')}`;
      if (first) await ensurePeriod();
      if (first || d.entries.length) render(first);
    }
  } catch (e) { showErr('Сервер недоступен: ' + e.message); }
  if (!st.paused) st.timer = setTimeout(poll, +cfg.interval);
}
function addEntries(list, live, prepend) {
  for (const e of list) { e.id = ++st.seq; e.live = live; e.thr = threatOf(e); queueVerify(e); }
  if (prepend) st.entries = list.concat(st.entries);
  else { st.entries.push(...list); if (!live) st.entries.sort((a, b) => a.t - b.t); }
  if (st.entries.length > MAX_ENTRIES) st.entries.splice(0, st.entries.length - MAX_ENTRIES);
  if (live && list.length) checkAlerts(list);
}
function noteBad(d, reset) {
  if (reset) { st.badTotal = 0; st.badSample = []; }
  st.badTotal += d.bad || 0;
  if (d.badSample?.length) st.badSample = d.badSample;
  const w = [...st.warn];
  if (st.badTotal) w.push(`Не удалось разобрать строк: ${st.badTotal}. Возможно, у лога нестандартный формат — пришлите пример строки. Примеры:\n` + st.badSample.join('\n'));
  const el = $('#warn'); el.hidden = !w.length; el.innerHTML = w.map(t => `<pre>⚠️ ${esc(t)}</pre>`).join('');
  $('#skipped').hidden = !st.skipped?.length;
  $('#skipped').textContent = st.skipped?.length ? `ℹ️ Пропущены логи другого формата (не посещения): ${st.skipped.join(', ')}` : '';
}
async function loadHistory(n = 5000) {
  if (st.loadingHist || !st.more) return 0;
  st.loadingHist = true; $('#more').disabled = true; $('#more').textContent = '⏳ Загрузка…';
  let got = 0;
  try {
    const s = {};
    for (const [k, v] of Object.entries(st.fstate)) if (v.b > 0) s[k] = {b: v.b, i: v.i};
    const d = await getJSON(`?api=history&n=${n}&s=${encodeURIComponent(JSON.stringify(s))}`);
    for (const [k, v] of Object.entries(d.state)) st.fstate[k] = {...st.fstate[k], ...v};
    st.more = d.more;
    got = d.entries.length;
    addEntries(d.entries, false, true);
    st.entries.sort((a, b) => a.t - b.t);
  } catch (e) { toast('Не удалось загрузить историю', e.message, 'var(--fake)'); }
  st.loadingHist = false; updateMoreBtn();
  return got;
}
function updateMoreBtn() {
  const b = $('#more'); b.disabled = !st.more || st.loadingHist;
  b.textContent = st.more ? '⏪ Ещё' : '⏪ Начало лога';
}
async function ensurePeriod() {
  let from = periodFrom();
  if (!from) return;
  from -= Date.now() / 1000 - from;                 // плюс предыдущий такой же период — для сравнения
  for (let i = 0; i < 15 && st.more && st.entries.length < MAX_ENTRIES - 20000; i++) {
    if (st.entries.length && st.entries[0].t <= from) break;
    if (!await loadHistory(20000)) break;
  }
}
function showErr(t) { const el = $('#err'); el.hidden = !t; el.textContent = t; }
async function loadDiag() { try { showDiag(await getJSON('?api=diag'), true); } catch {} }
function showDiag(g, keepClosed) {
  if (!g) return;
  const el = $('#diag'); el.hidden = false; if (!keepClosed) el.open = true;
  $('#diagBody').innerHTML = `<p>PHP работает от пользователя <b>${esc(g.user)}</b>, скрипт: <code>${esc(g.script)}</code></p>
    <p>open_basedir: ${g.open_basedir ? `<code>${esc(g.open_basedir)}</code> — PHP видит только эти папки` : 'не ограничен'}</p>
    <p>${Object.entries(g.dirs).map(([d, s]) => `<code>${esc(d)}</code>: ${esc(s)}`).join('<br>')}</p>
    <p><b>Найденные логи:</b><br>${g.found.length ? g.found.map(f => `${f.readable ? '✅' : '⛔'} <code>${esc(f.path)}</code> ${fmtBytes(f.size)}`).join('<br>') : 'ни одного'}</p>`;
}

// ───── Проверка подлинности поисковиков (rDNS) ─────
function queueVerify(e) {
  if (e.k !== 'search' || !VERIFIABLE.includes(e.n)) return;
  const key = e.n + '|' + e.ip;
  if (st.verify[key]) return;
  st.verify[key] = {res:'pending', live: e.live}; st.vq.push([e.n, e.ip]); runVerify();
}
async function runVerify() {
  if (st.vBusy || !st.vq.length) return;
  st.vBusy = true;
  const [bot, ip] = st.vq.shift(), key = bot + '|' + ip, wasLive = st.verify[key]?.live;
  try {
    st.verify[key] = await getJSON(`?api=verify&ip=${encodeURIComponent(ip)}&bot=${encodeURIComponent(bot)}`);
    if (st.verify[key].res === 'fake') {
      for (const e of st.entries) if (e.ip === ip && e.n === bot) e.thr = threatOf(e);
      if (wasLive && cfg.eFake) alertOnce('fake:' + ip, `⚠️ Поддельный ${bot}`, `IP ${ip} представляется ${bot}, но rDNS: ${st.verify[key].host || 'нет'}`, 'var(--fake)', {ip});
    }
    scheduleRender();
  } catch { st.verify[key] = {res:'unknown'}; }
  st.vBusy = false; runVerify();
}
const vOf = e => st.verify[e.n + '|' + e.ip];
const isFake = e => vOf(e)?.res === 'fake';
const kindOf = e => isFake(e) ? 'fake' : e.k;
function threatOf(e) {
  if (SCAN_RE.test(e.p)) return 'scan';
  if (isFake(e)) return 'fake';
  return '';
}

// ───── Уведомления ─────
let audioCtx;
function beep(freq = 880, dur = 0.15, times = 2) {
  try {
    audioCtx ||= new (window.AudioContext || window.webkitAudioContext)();
    for (let i = 0; i < times; i++) {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain(), t = audioCtx.currentTime + i * (dur + 0.08);
      o.frequency.value = freq; o.type = 'sine'; o.connect(g); g.connect(audioCtx.destination);
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.25, t + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      o.start(t); o.stop(t + dur + 0.02);
    }
  } catch {}
}
function toast(title, body, color, qf) {
  const el = document.createElement('div');
  el.className = 'toast'; el.style.setProperty('--c', color || 'var(--accent)');
  el.innerHTML = `<b>${esc(title)}</b>${esc(body)}`;
  el.onclick = () => { if (qf) { st.qf = {...qf}; switchTab('feed'); } el.remove(); };
  $('#toasts').prepend(el);
  while ($('#toasts').children.length > 5) $('#toasts').lastChild.remove();
  setTimeout(() => el.remove(), 9000);
}
function alertOnce(key, title, body, color, qf, cooldown = 300) {
  const now = Date.now() / 1000;
  if (st.alerted[key] && now - st.alerted[key] < cooldown) return;
  st.alerted[key] = now;
  if (cfg.toast) toast(title, body, color, qf);
  if (cfg.sound) beep(color === 'var(--search)' ? 660 : 880, 0.15, color === 'var(--search)' ? 1 : 2);
  if (cfg.desktop && 'Notification' in window && Notification.permission === 'granted') {
    try { const n = new Notification(title, {body, tag: key}); n.onclick = () => { window.focus(); if (qf) { st.qf = {...qf}; switchTab('feed'); } }; } catch {}
  }
  if (document.hidden) { st.unread++; document.title = `(${st.unread}) Живые логи`; }
}
function checkAlerts(list) {
  const now = Date.now() / 1000, recent = st.entries.filter(e => e.live && e.t >= now - 60);
  if (cfg.e5xx) {
    const n5 = recent.filter(e => e.s >= 500).length;
    if (n5 >= cfg.e5xxN) alertOnce('5xx', `❌ Ошибки сервера: ${n5} за минуту`, 'Последняя: ' + (recent.filter(e => e.s >= 500).pop()?.p || ''), 'var(--s5)', {s: '5xx'}, 120);
  }
  for (const e of list) {
    const abOn = st.ab && st.ab.mode !== 'off';           // автозащита сама сообщит о сканерах и флуде — без дублей
    if (cfg.eScan && !abOn && e.thr === 'scan') alertOnce('scan:' + e.ip, '🔎 Сканер уязвимостей', `${e.ip} запросил ${e.p}`, 'var(--threat)', {ip: e.ip}, 600);
    if (cfg.eSlow && e.rt !== undefined && e.rt >= cfg.slowSec) alertOnce('slow:' + e.p, `🐢 Медленный ответ: ${fmtRt(e.rt)}`, e.p, 'var(--s4)', {p: e.p}, 300);
    if (cfg.eSearch && e.k === 'search' && /Googlebot|YandexBot/.test(e.n)) alertOnce('se:' + e.n, `🔍 Пришёл ${e.n}`, e.p, 'var(--search)', {n: e.n}, 600);
  }
  if (cfg.eFlood && !(st.ab && st.ab.mode !== 'off')) {
    const per = {};
    for (const e of recent) if (!STATIC_RE.test(e.p) && !(e.k === 'search' && vOf(e)?.res === 'ok') && e.n !== 'UptimeRobot') per[e.ip] = (per[e.ip] || 0) + 1;
    for (const [ip, n] of Object.entries(per)) if (n >= cfg.flood) alertOnce('flood:' + ip, `🌊 Флуд: ${n} запросов/мин`, `IP ${ip}`, 'var(--threat)', {ip}, 600);
  }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) { st.unread = 0; document.title = 'Живые логи'; } });

// ───── Фильтры ─────
function periodFrom() {
  if (cfg.period === 'today') { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime() / 1000; }
  return +cfg.period ? Date.now() / 1000 - +cfg.period : 0;
}
function baseList() {
  const from = periodFrom();
  if (!from) return st.entries;
  let lo = 0, hi = st.entries.length;
  while (lo < hi) { const m = (lo + hi) >> 1; if (st.entries[m].t < from) lo = m + 1; else hi = m; }
  return st.entries.slice(lo);
}
const QF_LABELS = {ip:'IP', n:'Кто', p:'URL', s:'Код', v:'Сайт', os:'ОС', d:'Устройство', r:'Реферер', thr:'Угроза', se:'Из поиска'};
function matchQf(e) {
  const q = st.qf;
  if (q.ip && e.ip !== q.ip) return false;
  if (q.n && e.n !== q.n) return false;
  if (q.p && e.p !== q.p) return false;
  if (q.v && e.v !== q.v) return false;
  if (q.os && e.os !== q.os) return false;
  if (q.d && e.d !== q.d) return false;
  if (q.r && refHost(e.r) !== q.r) return false;
  if (q.se && searchEngine(e.r) !== q.se) return false;
  if (q.thr && !e.thr) return false;
  if (q.s && (q.s.endsWith('xx') ? Math.floor(e.s / 100) !== +q.s[0] : String(e.s) !== q.s)) return false;
  return true;
}
function filtered(base) {
  const q = $('#q').value.trim().toLowerCase(), ns = cfg.noStatic, oe = $('#onlyErr').checked, k = st.kind;
  const hasQf = Object.keys(st.qf).length;
  return base.filter(e =>
    (!k || (k === 'fake' ? isFake(e) : k === 'err' ? e.s >= 400 : k === 'thr' ? !!e.thr : e.k === k)) &&
    (!ns || !STATIC_RE.test(e.p)) && (!oe || e.s >= 400) && (!hasQf || matchQf(e)) &&
    (!q || (e.ip + ' ' + e.p + ' ' + e.ua + ' ' + e.s + ' ' + e.n + ' ' + e.r + ' ' + e.v).toLowerCase().includes(q)));
}
const refHost = r => { const m = /^https?:\/\/([^/:?#]+)/i.exec(r || ''); return m ? m[1].toLowerCase().replace(/^www\./, '') : ''; };
const searchEngine = r => { const h = refHost(r); if (!h) return ''; for (const [n, re] of SEARCH_REF) if (re.test(h)) return n; return ''; };

// ───── Анализ угроз ─────
function analyzeThreats(base) {
  const ips = new Map();
  for (const e of base) {
    let x = ips.get(e.ip);
    if (!x) ips.set(e.ip, x = {ip: e.ip, n: 0, n404: 0, scan: 0, scanEx: '', fake: '', mins: {}, last: 0, sample: e});
    x.n++; if (e.s === 404) x.n404++;
    if (e.thr === 'scan') { x.scan++; x.scanEx ||= e.p; }
    if (isFake(e)) x.fake = e.n;
    const m = Math.floor(e.t / 60); x.mins[m] = (x.mins[m] || 0) + 1;
    if (e.t >= x.last) { x.last = e.t; x.sample = e; }
  }
  const out = [];
  for (const x of ips.values()) {
    x.peak = Math.max(...Object.values(x.mins));
    const r = [];
    if (x.scan) r.push(['🔎 сканер', x.scan, `например ${x.scanEx}`]);
    if (x.fake) r.push([`⚠️ поддельный ${x.fake}`, '', 'rDNS не совпадает']);
    if (x.peak >= cfg.flood) r.push(['🌊 флуд', x.peak + '/мин', 'пик запросов в минуту']);
    if (x.n404 >= 30 && x.n404 / x.n > 0.5) r.push(['❓ много 404', x.n404, 'перебор адресов']);
    if (r.length) { x.reasons = r; x.score = x.scan * 5 + (x.fake ? 50 : 0) + (x.peak >= cfg.flood ? x.peak : 0) + x.n404; out.push(x); }
  }
  return out.sort((a, b) => b.score - a.score);
}

// ───── Отрисовка ─────
let renderTimer = null;
function scheduleRender() { if (!renderTimer) renderTimer = setTimeout(() => { renderTimer = null; render(false, true); }, 400); }
function render(reset, soft) {
  const base = baseList(), list = filtered(base), threats = analyzeThreats(base);
  st.multi = new Set(st.entries.slice(-3000).map(e => e.v)).size > 1;
  renderCards(base, threats); renderChart(list); renderChips();
  $('#thrCnt').hidden = !threats.length; $('#thrCnt').textContent = threats.length;
  const nb = (st.fw.list.length || Object.values(st.bans).filter(b => b.until > Date.now() / 1000).length) + cfg.blocks.ips.length + cfg.blocks.bots.length + (cfg.blocks.noUA ? 1 : 0);
  $('#blkCnt').hidden = !nb; $('#blkCnt').textContent = nb; $('#blkCnt').style.background = 'var(--muted)';
  $('#groupBy').hidden = st.tab !== 'groups';
  $('#toolbar').hidden = st.tab === 'block' || st.tab === 'autoban';
  ({feed: renderFeed, overview: renderOverview, analytics: renderAnalytics, seo: renderSeo, visitors: renderVisitors, groups: renderGroups, slow: renderSlow, threats: renderThreats, block: renderBlock, autoban: renderAutoban})[st.tab](list, reset, soft, threats, base);
  updateMoreBtn();
}
function prevPeriod() {
  const from = periodFrom(); if (!from || !st.entries.length) return null;
  const span = Date.now() / 1000 - from;
  if (st.entries[0].t > from - span * 0.97) return null;            // предыдущий период загружен не полностью
  const c = {all:0, browser:0, search:0, err:0};
  for (const e of st.entries) { if (e.t >= from) break; if (e.t < from - span) continue; c.all++; if (e.k === 'browser') c.browser++; if (e.k === 'search') c.search++; if (e.s >= 400) c.err++; }
  return c;
}
function delta(cur, prev, badUp) {
  if (!prev) return '';
  const d = Math.round((cur - prev) / prev * 100); if (!isFinite(d) || d === 0) return '<span class="dl">= как раньше</span>';
  const good = badUp ? d < 0 : d > 0;
  return `<span class="dl" style="color:var(${good ? '--s2' : '--s5'})" title="Было: ${nf(prev)}">${d > 0 ? '▲' : '▼'} ${Math.abs(d)}%</span>`;
}
function renderCards(base, threats) {
  const c = {all:0, browser:0, search:0, ai:0, bot:0, fake:0, err:0}, ips = new Set(), pv = prevPeriod();
  let rtSum = 0, rtN = 0;
  for (const e of base) { c.all++; c[e.k]++; if (isFake(e)) c.fake++; if (e.s >= 400) c.err++; ips.add(e.ip); if (e.rt !== undefined) { rtSum += e.rt; rtN++; } }
  const span = base.length ? base[base.length - 1].t - base[0].t : 0;
  const pct = n => c.all ? Math.round(n / c.all * 100) + '%' : '';
  const cards = [
    ['', 'Всего запросов', nf(c.all), 'var(--muted)', (span > 60 ? `≈ ${nf(Math.round(c.all / span * 60))}/мин ` : '') + delta(c.all, pv?.all)],
    ['browser', '🧑‍💻 Люди (браузеры)', nf(c.browser), 'var(--browser)', pct(c.browser) + ' ' + delta(c.browser, pv?.browser)],
    ['search', '🔍 Поисковики', nf(c.search), 'var(--search)', pct(c.search) + ' ' + delta(c.search, pv?.search)],
    ['ai', '🤖 ИИ-боты', nf(c.ai), 'var(--ai)', pct(c.ai)],
    ['bot', '🕷️ Прочие боты', nf(c.bot), 'var(--bot)', pct(c.bot)],
    ['fake', '⚠️ Поддельные', nf(c.fake), 'var(--fake)', ''],
    ['err', '❌ Ошибки 4xx/5xx', nf(c.err), 'var(--s4)', pct(c.err) + ' ' + delta(c.err, pv?.err, true)],
    ['thr', '🚨 Угрозы (IP)', nf(threats.length), 'var(--threat)', ''],
    [null, '🌐 Уникальных IP', nf(ips.size), 'var(--s3)', ''],
  ];
  if (rtN) cards.push([null, '⚡ Ср. время ответа', fmtRt(rtSum / rtN), 'var(--accent)', '']);
  $('#cards').innerHTML = cards.map(([k, l, v, col, d]) =>
    `<div class="card ${k && st.kind === k ? 'on' : ''}" ${k !== null ? `data-kind="${k}"` : ''} style="--c:${col};${k === null ? 'cursor:default' : ''}"><div class="v">${v}</div><div class="l">${l}</div>${d ? `<div class="d">${d}</div>` : ''}</div>`).join('');
}
function renderChart(list) {
  const N = 60, now = Date.now() / 1000;
  const from = periodFrom() || (list.length ? Math.min(list[0].t, now - 600) : now - 3600);
  const span = Math.max(60, now - from), bw = span / N;
  const bins = Array.from({length: N}, () => ({browser:0, search:0, ai:0, bot:0, e5:0}));
  for (const e of list) { const i = Math.floor((e.t - from) / bw); if (i >= 0 && i < N) { bins[i][e.k]++; if (e.s >= 500) bins[i].e5++; } }
  const max = Math.max(1, ...bins.map(b => b.browser + b.search + b.ai + b.bot)), W = 1000, H = 130, w = W / N;
  let svg = '';
  bins.forEach((b, i) => {
    let y = H;
    const t0 = from + i * bw, tip = `${fmtShort(t0)}–${fmtShort(t0 + bw)}\n` + KIND_KEYS.map(k => `${KINDS[k].plural}: ${b[k]}`).join('\n') + (b.e5 ? `\nОшибки 5xx: ${b.e5}` : '');
    svg += `<g><title>${esc(tip)}</title><rect x="${i * w}" y="0" width="${w}" height="${H}" fill="transparent"/>`;
    for (const k of KIND_KEYS) {
      if (!b[k]) continue; const h = b[k] / max * (H - 16); y -= h;
      svg += `<rect x="${i * w + 1}" y="${y}" width="${w - 2}" height="${h}" fill="var(--${k})" rx="1"/>`;
    }
    if (b.e5) svg += `<rect x="${i * w + 1}" y="${H - 3}" width="${w - 2}" height="3" fill="var(--s5)"/>`;
    svg += '</g>';
  });
  svg += `<text x="4" y="11" font-size="11" fill="var(--muted)">макс ${max} за ${fmtDur(bw)}</text>`;
  $('#chart').setAttribute('viewBox', `0 0 ${W} ${H}`); $('#chart').innerHTML = svg;
  $('#axis').innerHTML = [0, .25, .5, .75, 1].map(f => `<span>${fmtShort(from + span * f)}</span>`).join('');
  $('#chartTitle').textContent = `Запросы во времени — по ${fmtDur(bw)} на столбец`;
}
function renderChips() {
  const items = Object.entries(st.qf);
  $('#chips').hidden = !items.length;
  $('#chips').innerHTML = items.map(([k, v]) => `<span class="chip">${QF_LABELS[k] || k}: ${esc(v === true ? 'да' : v)}<button data-unqf="${k}" title="Убрать фильтр">×</button></span>`).join('')
    + (items.length > 1 ? `<button class="sm" data-unqf="*">сбросить всё</button>` : '');
}

// ───── Форматирование ─────
const stCls = s => 's' + Math.floor(s / 100);
const fmtTime = t => new Date(t * 1000).toLocaleTimeString('ru-RU');
const fmtDate = t => new Date(t * 1000).toLocaleString('ru-RU');
const fmtShort = t => { const d = new Date(t * 1000), today = new Date().toDateString() === d.toDateString();
  return (today ? '' : d.toLocaleDateString('ru-RU', {day:'2-digit', month:'2-digit'}) + ' ') + d.toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'}); };
const fmtDur = s => s < 60 ? Math.round(s) + ' с' : s < 3600 ? Math.round(s / 60) + ' мин' : (s / 3600).toFixed(s < 36000 ? 1 : 0) + ' ч';
const fmtRt = s => s < 1 ? Math.round(s * 1000) + ' мс' : s.toFixed(2) + ' с';
const fmtBytes = b => b < 1024 ? b + ' Б' : b < 1048576 ? (b / 1024).toFixed(1) + ' КБ' : b < 1073741824 ? (b / 1048576).toFixed(1) + ' МБ' : (b / 1073741824).toFixed(2) + ' ГБ';
const ago = t => { const s = Math.max(0, Math.floor(Date.now() / 1000 - t)); return s < 60 ? s + ' с назад' : s < 3600 ? Math.floor(s / 60) + ' мин назад' : s < 86400 ? Math.floor(s / 3600) + ' ч назад' : fmtDate(t); };
const qfAttr = (k, v) => `class="qf" data-qf="${k}" data-v="${esc(v)}" title="Показать только это"`;

function badge(e, noVerify) {
  const own = e.n === 'Панель логов (мы)' || e.n === 'Сервер (сам к себе)';
  const k = kindOf(e), meta = own ? {icon:'🛠'} : k === 'fake' ? {icon:'⚠️'} : KINDS[e.k], v = vOf(e);
  let vf = '';
  if (!noVerify) {
    if (v?.res === 'ok') vf = `<span class="vf ok" title="${esc(v.host)}">✓ подлинный</span>`;
    else if (v?.res === 'fake') vf = `<span class="vf fake" title="rDNS: ${esc(v.host || 'нет')}">ПОДДЕЛКА</span>`;
    else if (v?.res === 'pending') vf = `<span class="vf muted">проверка…</span>`;
    else if (v?.res === 'unknown') vf = `<span class="vf muted" title="Нет обратной DNS-записи">не подтверждён</span>`;
  }
  return `<span class="badge k-${k} qf" data-qf="n" data-v="${esc(e.n)}" title="Показать только ${esc(e.n)}">${meta.icon} ${esc(e.n)}</span>${vf}`;
}
const HEAD = `<thead><tr><th>Время</th><th>Кто</th><th>IP</th><th>Запрос</th><th>Код</th><th class="hide-sm">Размер / время</th><th class="hide-sm">Откуда пришёл</th></tr></thead>`;
function rowsHtml(list, markNew) {
  return list.map(e => {
    const isNew = markNew && e.id > st.lastSeenSeq, open = st.open.has(e.id), se = searchEngine(e.r);
    let h = `<tr class="row${isNew ? ' new' : ''}${e.thr ? ' thr' : ''}" data-id="${e.id}">
      <td class="mono" title="${esc(fmtDate(e.t))}">${fmtTime(e.t)}${st.multi ? `<span class="site qf" data-qf="v" data-v="${esc(e.v)}">${esc(e.v)}</span>` : ''}</td>
      <td>${badge(e)}${e.k === 'browser' ? `<div class="sub">${esc(e.os)} · ${esc(e.d)}</div>` : ''}${e.thr === 'scan' ? `<div><span class="reason">🔎 сканер</span></div>` : ''}</td>
      <td class="mono"><span ${qfAttr('ip', e.ip)}>${esc(e.ip)}</span>${banBadge(e.ip)}</td>
      <td class="mono path" title="${esc(e.p)}"><span class="muted">${esc(e.m)}</span> ${esc(e.p)}</td>
      <td class="st ${stCls(e.s)}"><span ${qfAttr('s', String(e.s))}>${e.s}</span></td>
      <td class="mono hide-sm">${fmtBytes(e.b)}${e.rt !== undefined ? `<span class="site ${e.rt >= 1 ? 's5' : e.rt >= 0.3 ? 's4' : ''}">${fmtRt(e.rt)}</span>` : ''}</td>
      <td class="mono path hide-sm muted" title="${esc(e.r)}">${se ? `<span class="badge k-search">🔍 ${esc(se)}</span>` : esc(e.r.replace(/^https?:\/\//, ''))}</td></tr>`;
    if (open) {
      const blocked = cfg.blocks.ips.includes(e.ip), botBlocked = cfg.blocks.bots.includes(e.n), canBot = !!BOT_RE[e.n];
      h += `<tr class="detail"><td colspan="7"><dl>
        <dt>Дата и время</dt><dd>${esc(fmtDate(e.t))} (${ago(e.t)})</dd>
        <dt>Запрос</dt><dd class="mono">${esc(e.m)} ${esc(e.p)}</dd>
        ${e.raw ? `<dt>Как в логе</dt><dd class="mono">${esc(e.raw)}</dd>` : ''}
        ${e.rt !== undefined ? `<dt>Время ответа</dt><dd>${fmtRt(e.rt)}</dd>` : ''}
        <dt>User-Agent</dt><dd class="mono">${esc(e.ua || '—')}</dd>
        ${e.line ? `<dt>Строка лога</dt><dd class="mono sub">${esc(e.line)}</dd>` : ''}
        <dt>Реферер</dt><dd class="mono">${esc(e.r || '—')}</dd>
        <dt>Сайт / лог</dt><dd class="mono">${esc(e.v)}${e.f && e.f !== e.v ? ` (${esc(e.f)})` : ''}</dd>
        ${vOf(e)?.host ? `<dt>rDNS</dt><dd class="mono">${esc(vOf(e).host)}</dd>` : ''}
        <dt>От этого IP</dt><dd>${nf(st.entries.filter(x => x.ip === e.ip).length)} запросов в загруженных данных</dd></dl>
        <div class="actions">
          <button class="sm" data-qf="ip" data-v="${esc(e.ip)}">🔎 Все запросы IP</button>
          <button class="sm" data-qf="n" data-v="${esc(e.n)}">🔎 Все запросы «${esc(e.n)}»</button>
          <button class="sm" data-qf="p" data-v="${esc(e.p)}">🔎 Все запросы этого URL</button>
          <a class="btn sm" href="https://ipinfo.io/${encodeURIComponent(e.ip)}" target="_blank" rel="noopener noreferrer">🌍 Кто это (ipinfo)</a>
          ${BLOCK.enabled ? `<button class="sm primary-danger" data-ban="${esc(e.ip)}" ${isBanned(e.ip) ? 'disabled' : ''}>⛔ ${isBanned(e.ip) ? 'Уже заблокирован' : 'Заблокировать на сервере'}</button>` : ''}
          <button class="sm danger" data-block-ip="${esc(e.ip)}" ${blocked ? 'disabled' : ''}>📝 ${blocked ? 'IP уже в конфиге nginx' : 'В конфиг nginx'}</button>
          ${e.k !== 'browser' ? (canBot ? `<button class="sm danger" data-block-bot="${esc(e.n)}" data-kind="${e.k}" ${botBlocked ? 'disabled' : ''}>🚫 ${botBlocked ? 'Бот уже в списке' : 'Заблокировать бота ' + esc(e.n)}</button>`
            : e.n === 'Без User-Agent' ? `<button class="sm danger" data-block-noua="1" ${cfg.blocks.noUA ? 'disabled' : ''}>🚫 Блокировать запросы без User-Agent</button>` : '') : ''}
        </div></td></tr>`;
    }
    return h;
  }).join('');
}

// ───── Вкладки ─────
function renderFeed(list, reset, soft) {
  const rows = list.slice(-(+cfg.feedRows)).reverse();
  $('#view').innerHTML = rows.length
    ? `<table class="tbl">${HEAD}<tbody>${rowsHtml(rows, !reset && !soft)}</tbody></table>`
      + (list.length > rows.length ? `<div class="empty">Показаны последние ${nf(rows.length)} из ${nf(list.length)}. Уточните фильтр или используйте «Группы».</div>` : '')
    : `<div class="empty">Нет запросов под этот фильтр${periodFrom() ? ' за выбранный период' : ''}.</div>`;
  if (!soft) st.lastSeenSeq = st.seq;
}

function topBlock(title, items, total, color, qfKey, fmtKey) {
  const max = items[0]?.[1] || 1;
  return `<div class="top"><h3><span>${title}</span><span class="muted">${total !== undefined ? nf(total) : ''}</span></h3><ol>${
    items.length ? items.map(([k, n, extra]) => `<li ${qfKey ? `data-qf="${qfKey}" data-v="${esc(k)}"` : ''} title="${esc(k)}"><span class="k">${fmtKey ? fmtKey(k) : esc(k)}${extra ? ` <span class="sub">${extra}</span>` : ''}</span><span class="n">${nf(n)}</span><span class="b" style="width:${n / max * 100}%;--c:${color}"></span></li>`).join('')
    : '<li class="muted">нет данных</li>'}</ol></div>`;
}
function countBy(list, fn, limit = 10) {
  const m = new Map();
  for (const e of list) { const k = fn(e); if (k === null || k === undefined || k === '') continue; m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}
function renderOverview(list) {
  const humans = list.filter(e => e.k === 'browser'), bots = list.filter(e => e.k !== 'browser');
  const own = new Set(list.map(e => e.v.toLowerCase().replace(/^www\./, '')));
  const fromSearch = humans.filter(e => searchEngine(e.r) && !STATIC_RE.test(e.p));
  const ipSample = {}; for (const e of list) ipSample[e.ip] = e;
  const pages = list.filter(e => !STATIC_RE.test(e.p) && e.s < 400);
  $('#view').innerHTML = `<div class="grid">
    ${topBlock('📄 Популярные страницы', countBy(pages, e => e.p), pages.length, 'var(--browser)', 'p')}
    ${topBlock('🧑‍💻 Страницы, которые смотрят люди', countBy(humans.filter(e => !STATIC_RE.test(e.p)), e => e.p), humans.length, 'var(--browser)', 'p')}
    ${topBlock('🔍 Переходы из поисковиков', countBy(fromSearch, e => searchEngine(e.r)), fromSearch.length, 'var(--search)', 'se')}
    ${topBlock('🎯 Куда приходят из поиска', countBy(fromSearch, e => e.p), fromSearch.length, 'var(--search)', 'p')}
    ${topBlock('🔗 Внешние сайты-источники', countBy(humans, e => { const h = refHost(e.r); return h && !own.has(h) && !searchEngine(e.r) ? h : null; }), undefined, 'var(--s3)', 'r')}
    ${topBlock('🌐 Самые активные IP', countBy(list, e => e.ip), undefined, 'var(--bot)', 'ip', ip => `<span class="mono">${esc(ip)}</span> ${badge(ipSample[ip], true)}`)}
    ${topBlock('🤖 Боты по числу запросов', countBy(bots, e => e.n), bots.length, 'var(--ai)', 'n')}
    ${topBlock('❓ Битые ссылки (404)', countBy(list.filter(e => e.s === 404), e => e.p), list.filter(e => e.s === 404).length, 'var(--s4)', 'p')}
    ${topBlock('🔥 Ошибки сервера (5xx)', countBy(list.filter(e => e.s >= 500), e => e.p), list.filter(e => e.s >= 500).length, 'var(--s5)', 'p')}
    ${topBlock('📶 Коды ответа', countBy(list, e => String(e.s), 12), list.length, 'var(--s3)', 's', s => `<span class="st ${stCls(+s)}">${esc(s)}</span>`)}
    ${topBlock('🧭 Браузеры', countBy(humans, e => e.n), humans.length, 'var(--browser)', 'n')}
    ${topBlock('💻 ОС и устройства', countBy(humans, e => e.os + ' · ' + e.d), humans.length, 'var(--browser)')}
    ${st.multi ? topBlock('🏠 Сайты', countBy(list, e => e.v), list.length, 'var(--accent)', 'v') : ''}
  </div>`;
}

function renderGroups(list) {
  const by = cfg.groupBy, groups = new Map();
  const keyOf = e => by === 'k' ? (isFake(e) ? 'fake' : e.k) : by === 'r' ? (refHost(e.r) || '(прямой заход)') : by === 's' ? String(e.s) : e[by] || '—';
  for (const e of list) {
    const k = keyOf(e);
    let g = groups.get(k);
    if (!g) groups.set(k, g = {key:k, n:0, kinds:{browser:0, search:0, ai:0, bot:0}, ips:new Set(), last:0, sample:e, err:0, bytes:0, rt:0, rtn:0});
    g.n++; g.kinds[e.k]++; g.ips.add(e.ip); g.err += e.s >= 400; g.bytes += e.b;
    if (e.rt !== undefined) { g.rt += e.rt; g.rtn++; }
    if (e.t >= g.last) { g.last = e.t; g.sample = e; }
  }
  const arr = [...groups.values()].sort((a, b) => b.n - a.n), max = arr[0]?.n || 1;
  if (!arr.length) { $('#view').innerHTML = `<div class="empty">Нет данных</div>`; return; }
  const label = g => {
    if (by === 'k') { const m = g.key === 'fake' ? {icon:'⚠️', plural:'Поддельные поисковики'} : KINDS[g.key]; return `<span class="badge k-${g.key}">${m.icon} ${m.plural}</span>`; }
    if (by === 'n') return badge(g.sample, true);
    if (by === 's') return `<span class="st ${stCls(+g.key)}">${esc(g.key)}</span>`;
    if (by === 'ip') return `<span class="mono">${esc(g.key)}</span> ${badge(g.sample, true)}`;
    return `<span class="mono">${esc(g.key)}</span>`;
  };
  $('#view').innerHTML = `<table class="tbl"><thead><tr><th>Группа</th><th>Запросов</th><th>Состав</th><th class="hide-sm">IP</th><th class="hide-sm">Ошибок</th><th class="hide-sm">Трафик</th><th class="hide-sm">Ср. ответ</th><th>Последний</th></tr></thead><tbody>` +
    arr.slice(0, 300).map(g => {
      const open = st.open.has('g:' + g.key);
      const seg = KIND_KEYS.map(k => g.kinds[k] ? `<span style="width:${g.kinds[k] / g.n * 100}%;background:var(--${k})" title="${KINDS[k].plural}: ${g.kinds[k]}"></span>` : '').join('');
      let h = `<tr class="row" data-g="${esc(g.key)}"><td>${open ? '▾' : '▸'} ${label(g)}</td>
        <td><b>${nf(g.n)}</b> <span class="sub">${Math.round(g.n / list.length * 100)}%</span><div class="bar" style="width:${Math.max(4, g.n / max * 100)}%;min-width:0;margin-top:4px"><span style="width:100%;background:var(--muted);opacity:.5"></span></div></td>
        <td><div class="bar">${seg}</div></td><td class="hide-sm">${nf(g.ips.size)}</td>
        <td class="hide-sm ${g.err ? 's4 st' : 'muted'}">${nf(g.err)}</td><td class="hide-sm mono">${fmtBytes(g.bytes)}</td>
        <td class="hide-sm mono">${g.rtn ? fmtRt(g.rt / g.rtn) : '—'}</td>
        <td class="muted" title="${esc(fmtDate(g.last))}">${ago(g.last)}</td></tr>`;
      if (open) {
        const items = list.filter(e => keyOf(e) === g.key).slice(-30).reverse();
        h += `<tr class="detail"><td colspan="8"><table class="tbl">${HEAD}<tbody>${rowsHtml(items, false)}</tbody></table></td></tr>`;
      }
      return h;
    }).join('') + `</tbody></table>`;
}

function renderSlow(list) {
  const withRt = list.filter(e => e.rt !== undefined);
  if (!withRt.length) {
    $('#view').innerHTML = `<div class="empty">В логе нет времени ответа.<br><br><span class="help">Добавьте в <code>log_format</code> nginx поле <code>rt=$request_time</code> — и здесь появится рейтинг медленных страниц.</span></div>`;
    return;
  }
  const g = new Map();
  for (const e of withRt) {
    const k = e.p.split('?')[0];
    let x = g.get(k); if (!x) g.set(k, x = {p: k, a: [], last: 0, err: 0});
    x.a.push(e.rt); x.err += e.s >= 500; x.last = Math.max(x.last, e.t);
  }
  const all = withRt.map(e => e.rt).sort((a, b) => a - b), q = (a, f) => a[Math.min(a.length - 1, Math.floor(a.length * f))];
  const rows = [...g.values()].map(x => { x.a.sort((a, b) => a - b); x.n = x.a.length; x.avg = x.a.reduce((s, v) => s + v, 0) / x.n; x.p95 = q(x.a, .95); x.max = x.a[x.n - 1]; x.sum = x.avg * x.n; return x; });
  const key = st.sort.slow;
  rows.sort((a, b) => b[key] - a[key]);
  const slowN = all.filter(v => v >= 1).length;
  const th = (k, l) => `<th class="sort num" data-sort="${k}">${l}${key === k ? ' ▾' : ''}</th>`;
  const cls = v => v >= 1 ? 's5 st' : v >= 0.3 ? 's4 st' : '';
  $('#view').innerHTML = `<div class="cards" style="padding:14px 14px 0">
      <div class="card" style="--c:var(--accent);cursor:default"><div class="v">${fmtRt(q(all, .5))}</div><div class="l">Медиана</div></div>
      <div class="card" style="--c:var(--s4);cursor:default"><div class="v">${fmtRt(q(all, .95))}</div><div class="l">95% запросов быстрее</div></div>
      <div class="card" style="--c:var(--s5);cursor:default"><div class="v">${fmtRt(all[all.length - 1])}</div><div class="l">Самый медленный</div></div>
      <div class="card" style="--c:var(--s5);cursor:default"><div class="v">${nf(slowN)}</div><div class="l">Дольше 1 секунды</div><div class="d">${(slowN / all.length * 100).toFixed(1)}%</div></div>
    </div>
    <table class="tbl"><thead><tr><th>Страница (без параметров)</th>${th('n', 'Запросов')}${th('avg', 'Среднее')}${th('p95', '95%')}${th('max', 'Макс')}${th('sum', 'Суммарно')}<th class="hide-sm num">5xx</th><th class="hide-sm">Последний</th></tr></thead><tbody>${
    rows.slice(0, 200).map(x => `<tr class="row" data-qf="p" data-v="${esc(x.p)}" title="Показать запросы"><td class="mono path">${esc(x.p)}</td><td class="num">${nf(x.n)}</td>
      <td class="num mono ${cls(x.avg)}">${fmtRt(x.avg)}</td><td class="num mono ${cls(x.p95)}">${fmtRt(x.p95)}</td><td class="num mono ${cls(x.max)}">${fmtRt(x.max)}</td>
      <td class="num mono">${fmtDur(x.sum)}</td><td class="hide-sm num ${x.err ? 's5 st' : 'muted'}">${x.err}</td><td class="hide-sm muted">${ago(x.last)}</td></tr>`).join('')
    }</tbody></table><p class="help" style="padding:0 14px">«Суммарно» — сколько всего времени сервер потратил на страницу: самые полезные кандидаты на оптимизацию сверху при сортировке по этой колонке.</p>`;
}

function renderThreats(list, reset, soft, threats) {
  if (!threats.length) { $('#view').innerHTML = `<div class="empty">🎉 Подозрительной активности не найдено за выбранный период.</div>`; return; }
  $('#view').innerHTML = `<table class="tbl"><thead><tr><th>IP</th><th>Кто</th><th>Признаки</th><th class="num">Запросов</th><th class="hide-sm">Последний</th><th></th></tr></thead><tbody>${
    threats.slice(0, 300).map(x => {
      const blocked = cfg.blocks.ips.includes(x.ip);
      return `<tr><td class="mono"><span ${qfAttr('ip', x.ip)}>${esc(x.ip)}</span></td><td>${badge(x.sample)}</td>
        <td>${x.reasons.map(([l, n, t]) => `<span class="reason" title="${esc(t)}">${esc(l)}${n !== '' ? ' ' + esc(n) : ''}</span>`).join('')}</td>
        <td class="num">${nf(x.n)}</td><td class="hide-sm muted">${ago(x.last)}</td>
        <td style="white-space:nowrap"><button class="sm" data-qf="ip" data-v="${esc(x.ip)}">запросы</button>
          ${BLOCK.enabled ? `<button class="sm primary-danger" data-ban="${esc(x.ip)}" ${isBanned(x.ip) ? 'disabled' : ''}>${isBanned(x.ip) ? '⛔ заблокирован' : '⛔ блок'}</button>` : ''}
          <button class="sm danger" data-block-ip="${esc(x.ip)}" ${blocked ? 'disabled' : ''} title="Добавить в конфиг nginx">${blocked ? 'в nginx' : '📝 nginx'}</button></td></tr>`;
    }).join('')}</tbody></table>
    <div class="actions" style="padding:10px 14px">${BLOCK.enabled ? '<button class="primary-danger" id="banAllThreats">⛔ Заблокировать все на сервере</button>' : ''}<button class="danger" id="blockAllThreats">📝 Добавить все в конфиг nginx</button></div>`;
}

function nginxConfig() {
  const b = cfg.blocks, out = [];
  if (b.ips.length) {
    out.push('# ── 1. Блокировка IP — вставьте внутрь server { … } вашего сайта', '#    (или в http { … }, чтобы закрыть для всех сайтов сразу)');
    for (const ip of b.ips) out.push(`deny ${ip};`);
    out.push('');
  }
  if (b.bots.length || b.noUA) {
    const pats = b.bots.map(n => BOT_RE[n]).filter(Boolean);
    out.push('# ── 2. Блокировка ботов по User-Agent', '#    а) в http { … } (например, файл /etc/nginx/conf.d/block-bots.conf):', 'map $http_user_agent $blocked_bot {', '    default 0;');
    if (b.noUA) out.push('    ""      1;   # пустой User-Agent', '    "-"     1;');
    for (const p of pats) out.push(`    "~*${p.replace(/"/g, '\\"')}" 1;`);
    out.push('}', '', '#    б) внутри server { … } вашего сайта:', 'if ($blocked_bot) {', '    return 403;', '}', '');
  }
  if (!out.length) return '';
  out.push('# ── 3. Проверить и применить:', '#    sudo nginx -t && sudo systemctl reload nginx');
  return out.join('\n');
}
function renderBlock() {
  const b = cfg.blocks, cfgText = nginxConfig();
  const item = (label, attr) => `<div class="bitem"><span class="mono">${label}</span><button class="sm" ${attr} title="Убрать из списка">✕</button></div>`;
  $('#view').innerHTML = banSectionHtml() + `<div class="blockgrid"><div>
      <h3 style="margin:0 0 8px;font-size:14px">IP-адреса (${b.ips.length})</h3>
      <div class="blist">${b.ips.map(ip => item(esc(ip), `data-unblock-ip="${esc(ip)}"`)).join('') || '<span class="muted">пусто</span>'}</div>
      <div style="display:flex;gap:6px;margin-top:8px"><input id="addIp" placeholder="добавить IP или подсеть: 1.2.3.0/24" style="flex:1"><button id="addIpBtn">+</button></div>
      <h3 style="margin:18px 0 8px;font-size:14px">Боты (${b.bots.length + (b.noUA ? 1 : 0)})</h3>
      <div class="blist">${b.bots.map(n => item(esc(n), `data-unblock-bot="${esc(n)}"`)).join('')}${b.noUA ? item('Без User-Agent', 'data-unblock-noua="1"') : ''}${!b.bots.length && !b.noUA ? '<span class="muted">пусто</span>' : ''}</div>
      <div style="display:flex;gap:6px;margin-top:8px"><select id="addBot" style="flex:1"><option value="">добавить бота…</option>${Object.keys(BOT_RE).filter(n => !b.bots.includes(n)).map(n => `<option>${esc(n)}</option>`).join('')}</select><button id="addBotBtn">+</button></div>
      ${b.ips.length || b.bots.length || b.noUA ? '<p><button class="sm danger" id="clearBlocks">очистить списки</button></p>' : ''}
    </div><div>
      <h3 style="margin:0 0 8px;font-size:14px;display:flex;justify-content:space-between;align-items:center">📝 Готовый конфиг nginx (вручную) ${cfgText ? '<button class="primary sm" id="copyCfg">📋 Скопировать</button>' : ''}</h3>
      ${cfgText ? `<pre class="cfg" id="cfgText">${esc(cfgText)}</pre>` : '<p class="muted">Добавьте IP или ботов — здесь появится конфиг. Кнопки «🚫» есть в ленте (раскройте строку) и на вкладке «Угрозы».</p>'}
      <div class="help">
        <p>⚙️ Скрипт <b>ничего не меняет на сервере сам</b> — он только готовит конфиг. Скопируйте его в nginx и выполните <code>sudo nginx -t &amp;&amp; sudo systemctl reload nginx</code>.</p>
        <p>☁️ Если сайт за <b>Cloudflare</b> или другим прокси, <code>deny</code> по IP сработает только при настроенном <code>real_ip_header</code> (модуль realip). Иначе блокируйте IP в панели Cloudflare.</p>
        <p>🔍 Не блокируйте <b>настоящих</b> Googlebot и YandexBot — сайт пропадёт из поиска. Поддельных блокируйте по IP, а не по имени бота.</p>
      </div>
    </div></div>`;
}

// ───── Общие помощники для графиков ─────
function timeRange(list) {
  const now = Date.now() / 1000;
  const from = periodFrom() || (list.length ? Math.min(list[0].t, now - 600) : now - 3600);
  return {from, span: Math.max(60, now - from), now};
}
const quant = (a, f) => a.length ? a[Math.min(a.length - 1, Math.floor(a.length * f))] : null;
function axisHtml(from, span) { return `<div class="axis">${[0, .25, .5, .75, 1].map(f => `<span>${fmtShort(from + span * f)}</span>`).join('')}</div>`; }
function linePath(vals, W, H, max, top = 8) {
  const w = W / vals.length; let d = '', pen = false;
  vals.forEach((v, i) => {
    if (v === null) { pen = false; return; }
    const x = (i + .5) * w, y = H - (v / max) * (H - top);
    d += (pen ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1); pen = true;
  });
  return d;
}
const chartBox = (title, legend, body, note = '') => `<div class="top chartbox"><h3><span>${title}</span><span class="legend">${legend}</span></h3><div style="padding:8px 12px 4px">${body}</div>${note ? `<p class="help" style="padding:0 12px 8px;margin:0">${note}</p>` : ''}</div>`;
const lg = (color, label) => `<span><i style="background:${color}"></i>${label}</span>`;

// ───── 📈 Аналитика ─────
function speedChart(list) {
  const N = 60, {from, span} = timeRange(list), bw = span / N;
  const b = Array.from({length: N}, () => ({a: [], e5: 0, n: 0}));
  for (const e of list) { const i = Math.floor((e.t - from) / bw); if (i < 0 || i >= N) continue; b[i].n++; if (e.s >= 500) b[i].e5++; if (e.rt !== undefined) b[i].a.push(e.rt); }
  if (!b.some(x => x.a.length)) return chartBox('⚡ Скорость сайта', '', '<div class="empty">В логе нет времени ответа. Добавьте <code>rt=$request_time</code> в log_format nginx.</div>');
  b.forEach(x => x.a.sort((p, q) => p - q));
  const med = b.map(x => quant(x.a, .5)), p95 = b.map(x => quant(x.a, .95));
  const max = Math.max(0.05, ...p95.filter(v => v !== null)) * 1.1, W = 1000, H = 190, w = W / N;
  const e5max = Math.max(1, ...b.map(x => x.e5));
  let svg = [0.25, 0.5, 0.75, 1].map(f => `<line x1="0" x2="${W}" y1="${H - f * (H - 8)}" y2="${H - f * (H - 8)}" stroke="var(--line)" stroke-dasharray="3 4"/><text x="4" y="${H - f * (H - 8) + (f === 1 ? 12 : -3)}" font-size="11" fill="var(--muted)">${fmtRt(max * f)}</text>`).join('');
  b.forEach((x, i) => { if (x.e5) svg += `<rect x="${i * w + 2}" y="${H - x.e5 / e5max * 40}" width="${w - 4}" height="${x.e5 / e5max * 40}" fill="var(--s5)" opacity=".55" rx="1"/>`; });
  svg += `<path d="${linePath(p95, W, H, max)}" fill="none" stroke="var(--s4)" stroke-width="2.2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
  svg += `<path d="${linePath(med, W, H, max)}" fill="none" stroke="var(--accent)" stroke-width="2.2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
  b.forEach((x, i) => { svg += `<rect x="${i * w}" y="0" width="${w}" height="${H}" fill="transparent"><title>${esc(`${fmtShort(from + i * bw)}–${fmtShort(from + (i + 1) * bw)}\nЗапросов: ${x.n}\nМедиана: ${med[i] !== null ? fmtRt(med[i]) : '—'}\n95%: ${p95[i] !== null ? fmtRt(p95[i]) : '—'}\nОшибок 5xx: ${x.e5}`)}</title></rect>`; });
  return chartBox('⚡ Скорость сайта во времени', lg('var(--accent)', 'медиана') + lg('var(--s4)', '95% запросов быстрее') + lg('var(--s5)', 'ошибки 5xx'),
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:190px;display:block">${svg}</svg>${axisHtml(from, span)}`,
    'Если оранжевая линия резко растёт — часть посетителей ждёт ответа долго. Красные столбики — когда сайт отдавал ошибки.');
}
function shareChart(list) {
  const N = 60, {from, span} = timeRange(list), bw = span / N;
  const b = Array.from({length: N}, () => ({browser: 0, search: 0, ai: 0, bot: 0}));
  for (const e of list) { const i = Math.floor((e.t - from) / bw); if (i >= 0 && i < N) b[i][e.k]++; }
  const W = 1000, H = 150, w = W / N;
  let svg = '';
  b.forEach((x, i) => {
    const tot = KIND_KEYS.reduce((s, k) => s + x[k], 0); if (!tot) return;
    let y = H;
    for (const k of KIND_KEYS) { const h = x[k] / tot * H; y -= h; if (h) svg += `<rect x="${i * w}" y="${y}" width="${w + .5}" height="${h}" fill="var(--${k})"/>`; }
    svg += `<rect x="${i * w}" y="0" width="${w}" height="${H}" fill="transparent"><title>${esc(fmtShort(from + i * bw) + '\n' + KIND_KEYS.map(k => `${KINDS[k].plural}: ${Math.round(x[k] / tot * 100)}% (${x[k]})`).join('\n'))}</title></rect>`;
  });
  svg += `<line x1="0" x2="${W}" y1="${H / 2}" y2="${H / 2}" stroke="#fff" stroke-opacity=".5" stroke-dasharray="4 4"/>`;
  return chartBox('🧑‍💻 Люди и боты — доля нагрузки', KIND_KEYS.map(k => lg(`var(--${k})`, KINDS[k].plural)).join(''),
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:150px;display:block;border-radius:6px;overflow:hidden">${svg}</svg>${axisHtml(from, span)}`,
    'Пунктир — 50%. Если боты занимают больше половины, стоит подумать о блокировке лишних.');
}
function heatmap(list) {
  const mode = st.heat || 'browser', days = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
  const g = Array.from({length: 7}, () => Array(24).fill(0)), dayset = new Set();
  for (const e of list) {
    if (mode === 'browser' ? e.k !== 'browser' : mode === 'bots' ? e.k === 'browser' : false) continue;
    const d = new Date(e.t * 1000); g[(d.getDay() + 6) % 7][d.getHours()]++; dayset.add(d.toDateString());
  }
  const max = Math.max(1, ...g.flat());
  const btn = (m, l) => `<button class="sm ${mode === m ? 'primary' : ''}" data-heat="${m}">${l}</button>`;
  const color = mode === 'browser' ? 'var(--browser)' : mode === 'bots' ? 'var(--bot)' : 'var(--accent)';
  let html = `<div class="heat"><div></div>${Array.from({length: 24}, (_, h) => `<div class="hh">${h}</div>`).join('')}`;
  g.forEach((row, d) => {
    html += `<div class="hd">${days[d]}</div>` + row.map((v, h) => `<div class="hc" style="background:color-mix(in srgb,${color} ${v ? Math.round(12 + v / max * 88) : 0}%,var(--panel2))" title="${days[d]}, ${h}:00–${h}:59 — ${nf(v)} запросов"></div>`).join('');
  });
  html += '</div>';
  return chartBox('🗓 Когда приходят: день недели × час', btn('browser', 'люди') + btn('bots', 'боты') + btn('all', 'все'), html,
    `В данных ${dayset.size} дн. ${dayset.size < 7 ? 'Для полной картины по неделе выберите период побольше или нажмите «⏪ Ещё».' : ''}`);
}
function trafficBlock(list) {
  const by = {browser: 0, search: 0, ai: 0, bot: 0}, who = new Map();
  let tot = 0;
  for (const e of list) { by[e.k] += e.b; tot += e.b; if (e.k !== 'browser') who.set(e.n, (who.get(e.n) || 0) + e.b); }
  const bar = `<div class="bar" style="height:14px;border-radius:7px;margin:6px 0 10px">${KIND_KEYS.map(k => by[k] ? `<span style="width:${by[k] / tot * 100}%;background:var(--${k})" title="${KINDS[k].plural}: ${fmtBytes(by[k])}"></span>` : '').join('')}</div>`;
  const rows = KIND_KEYS.map(k => `<div class="row2"><span>${KINDS[k].icon} ${KINDS[k].plural}</span><span class="mono">${fmtBytes(by[k])} <span class="sub">${tot ? Math.round(by[k] / tot * 100) : 0}%</span></span></div>`).join('');
  const top = [...who.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  return chartBox('📦 Трафик: кто сколько скачал', `<b>${fmtBytes(tot)}</b>`, bar + rows +
    (top.length ? `<p class="sub" style="margin:10px 0 4px">Больше всего трафика у ботов:</p>` + top.map(([n, v]) => `<div class="row2 qf" data-qf="n" data-v="${esc(n)}"><span>${esc(n)}</span><span class="mono">${fmtBytes(v)}</span></div>`).join('') : ''));
}
function renderAnalytics(list) {
  $('#view').innerHTML = `<div class="grid2">${speedChart(list)}${shareChart(list)}${heatmap(list)}${trafficBlock(list)}</div>`;
}

// ───── 🔍 SEO ─────
function section(p) {
  const path = p.split('?')[0];
  if (path === '/' || path === '') return '🏠 главная';
  if (/^\/[^/]+\.html$/.test(path)) return '📄 материалы /*.html';
  if (path === '/index.php') { const m = /[?&]do=([\w-]+)/.exec(p); return m ? '/index.php?do=' + m[1] : '/index.php'; }
  const m = /^\/([^/]+)\//.exec(path);
  return m ? `/${m[1]}/` : path;
}
function renderSeo(list) {
  const se = list.filter(e => e.k === 'search'), real = se.filter(e => !isFake(e)), fakes = se.length - real.length;
  if (!se.length) { $('#view').innerHTML = '<div class="empty">За выбранный период поисковые роботы не заходили.</div>'; return; }
  const bots = new Map();
  for (const e of real) {
    let x = bots.get(e.n); if (!x) bots.set(e.n, x = {n: e.n, cnt: 0, urls: new Set(), c: {2: 0, 3: 0, 4: 0, 5: 0}, rt: 0, rtn: 0, last: 0, ips: new Set(), ok: 0});
    x.cnt++; x.urls.add(e.p); x.c[Math.floor(e.s / 100)] = (x.c[Math.floor(e.s / 100)] || 0) + 1; x.ips.add(e.ip);
    if (e.rt !== undefined) { x.rt += e.rt; x.rtn++; } x.last = Math.max(x.last, e.t); if (vOf(e)?.res === 'ok') x.okIps = (x.okIps || new Set()).add(e.ip);
  }
  const arr = [...bots.values()].sort((a, b) => b.cnt - a.cnt);
  const uniq = new Set(real.map(e => e.p)).size, errs = real.filter(e => e.s >= 300).length;
  const rtB = real.filter(e => e.rt !== undefined), rtH = list.filter(e => e.k === 'browser' && e.rt !== undefined);
  const avg = a => a.length ? a.reduce((s, e) => s + e.rt, 0) / a.length : null;
  const pctC = (n, t) => t ? `<span class="sub">${Math.round(n / t * 100)}%</span>` : '';
  // обход во времени
  const N = 60, {from, span} = timeRange(list), bw = span / N, main = arr.slice(0, 3).map(x => x.n);
  const colors = ['var(--search)', 'var(--s4)', 'var(--browser)'];
  const bins = Array.from({length: N}, () => main.map(() => 0));
  for (const e of real) { const i = Math.floor((e.t - from) / bw), j = main.indexOf(e.n); if (i >= 0 && i < N && j >= 0) bins[i][j]++; }
  const bmax = Math.max(1, ...bins.map(b => b.reduce((s, v) => s + v, 0))), W = 1000, H = 120, w = W / N;
  let svg = '';
  bins.forEach((b, i) => { let y = H; b.forEach((v, j) => { if (!v) return; const h = v / bmax * (H - 14); y -= h; svg += `<rect x="${i * w + 1}" y="${y}" width="${w - 2}" height="${h}" fill="${colors[j]}" rx="1"/>`; });
    svg += `<rect x="${i * w}" y="0" width="${w}" height="${H}" fill="transparent"><title>${esc(fmtShort(from + i * bw) + '\n' + main.map((n, j) => `${n}: ${b[j]}`).join('\n'))}</title></rect>`; });
  svg += `<text x="4" y="11" font-size="11" fill="var(--muted)">макс ${bmax} за ${fmtDur(bw)}</text>`;
  // потери краулингового бюджета
  const waste = new Map();
  for (const e of real) if (e.s >= 300) { const k = e.s + ' ' + e.p; let x = waste.get(k); if (!x) waste.set(k, x = {p: e.p, s: e.s, n: 0, bots: new Set()}); x.n++; x.bots.add(e.n); }
  const wasteArr = [...waste.values()].sort((a, b) => b.n - a.n).slice(0, 25);
  // разделы
  const sec = new Map();
  for (const e of list) {
    if (STATIC_RE.test(e.p) || (e.k !== 'browser' && e.k !== 'search') || isFake(e)) continue;
    const k = section(e.p); let x = sec.get(k); if (!x) sec.set(k, x = {k, h: 0, s: 0, last: 0});
    if (e.k === 'browser') x.h++; else { x.s++; x.last = Math.max(x.last, e.t); }
  }
  const secArr = [...sec.values()].sort((a, b) => (b.h + b.s) - (a.h + a.s)).slice(0, 30), smax = Math.max(1, ...secArr.map(x => Math.max(x.h, x.s)));
  $('#view').innerHTML = `
    <div class="cards" style="padding:14px 14px 0">
      <div class="card" style="--c:var(--search);cursor:default"><div class="v">${nf(real.length)}</div><div class="l">Запросов роботов</div><div class="d">${fakes ? `+ ${nf(fakes)} поддельных` : 'поддельных нет'}</div></div>
      <div class="card" style="--c:var(--browser);cursor:default"><div class="v">${nf(uniq)}</div><div class="l">Разных URL обошли</div></div>
      <div class="card" style="--c:${errs / real.length > .1 ? 'var(--s5)' : 'var(--s4)'};cursor:default"><div class="v">${Math.round(errs / real.length * 100)}%</div><div class="l">Впустую (3xx/4xx/5xx)</div><div class="d">${nf(errs)} запросов</div></div>
      ${rtB.length ? `<div class="card" style="--c:var(--accent);cursor:default"><div class="v">${fmtRt(avg(rtB))}</div><div class="l">Ср. ответ роботам</div><div class="d">людям: ${rtH.length ? fmtRt(avg(rtH)) : '—'}</div></div>` : ''}
    </div>
    <table class="tbl"><thead><tr><th>Робот</th><th class="num">Запросов</th><th class="num">Разных URL</th><th class="num">2xx</th><th class="num">3xx</th><th class="num">4xx</th><th class="num">5xx</th><th class="num hide-sm">Ср. ответ</th><th class="hide-sm">Подлинность</th><th>Последний визит</th></tr></thead><tbody>${
      arr.map(x => `<tr class="row" data-qf="n" data-v="${esc(x.n)}"><td>${badge({k: 'search', n: x.n, ip: ''}, true)}</td><td class="num"><b>${nf(x.cnt)}</b></td><td class="num">${nf(x.urls.size)}</td>
        <td class="num s2">${nf(x.c[2])} ${pctC(x.c[2], x.cnt)}</td><td class="num ${x.c[3] ? 's3' : 'muted'}">${nf(x.c[3])} ${pctC(x.c[3], x.cnt)}</td><td class="num ${x.c[4] ? 's4 st' : 'muted'}">${nf(x.c[4])} ${pctC(x.c[4], x.cnt)}</td><td class="num ${x.c[5] ? 's5 st' : 'muted'}">${nf(x.c[5])} ${pctC(x.c[5], x.cnt)}</td>
        <td class="num mono hide-sm">${x.rtn ? fmtRt(x.rt / x.rtn) : '—'}</td><td class="hide-sm sub">${VERIFIABLE.includes(x.n) ? (x.okIps?.size ? `✓ подлинных IP: ${x.okIps.size} из ${x.ips.size}` : `IP: ${x.ips.size}, rDNS не подтвердил`) : 'не проверяется'}</td><td class="muted">${ago(x.last)}</td></tr>`).join('')
    }</tbody></table>
    <div class="grid2">
      ${chartBox('🕷 Обход сайта роботами во времени', main.map((n, j) => lg(colors[j], n)).join(''), `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:120px;display:block">${svg}</svg>${axisHtml(from, span)}`)}
      ${chartBox('🧭 Разделы сайта: люди и роботы', lg('var(--browser)', 'люди') + lg('var(--search)', 'поисковики'),
        `<table class="tbl mini"><tbody>${secArr.map(x => { const warn = x.h >= 20 && x.s < x.h * 0.02;
          return `<tr><td class="mono path" title="${esc(x.k)}">${esc(x.k)}${warn ? ' <span class="reason" title="Людям интересно, а роботы почти не заходят">⚠ роботы не ходят</span>' : ''}</td>
          <td style="width:40%"><div class="hbar" style="width:${x.h / smax * 100}%;background:var(--browser)" title="Людей: ${x.h}"></div><div class="hbar" style="width:${x.s / smax * 100}%;background:var(--search)" title="Поисковиков: ${x.s}"></div></td>
          <td class="num sub">${nf(x.h)} / ${nf(x.s)}</td></tr>`; }).join('')}</tbody></table>`,
        'Разделы, которые смотрят люди, но не обходят роботы, хуже попадают в поиск: проверьте ссылки на них, sitemap.xml и robots.txt.')}
    </div>
    <div class="panel" style="margin:0 14px 14px"><h2>💸 Куда роботы тратят обход впустую <span class="sub">редиректы и ошибки — их стоит исправить в ссылках или sitemap</span></h2>
    ${wasteArr.length ? `<table class="tbl"><thead><tr><th>URL</th><th>Код</th><th class="num">Раз</th><th>Роботы</th></tr></thead><tbody>${wasteArr.map(x => `<tr class="row" data-qf="p" data-v="${esc(x.p)}"><td class="mono path" title="${esc(x.p)}">${esc(x.p)}</td><td class="st ${stCls(x.s)}">${x.s}</td><td class="num">${nf(x.n)}</td><td class="sub">${esc([...x.bots].join(', '))}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">🎉 Роботы получают только 2xx</div>'}</div>`;
}

// ───── 👣 Посетители (сессии) ─────
const SESSION_GAP = 1800;
function buildSessions(list) {
  const by = new Map();
  for (const e of list) {
    if (e.k !== 'browser' || STATIC_RE.test(e.p) || e.m === 'POST' || e.m === 'HEAD' || /^\/(engine|uploads|templates)\//.test(e.p) || (e.s >= 300 && e.s !== 404)) continue;
    const key = e.ip + '|' + e.ua; let a = by.get(key); if (!a) by.set(key, a = []); a.push(e);
  }
  const out = [];
  for (const [key, hits] of by) {
    let cur = null;
    for (const e of hits) {
      if (!cur || e.t - cur.end > SESSION_GAP) { cur = {key: key + '|' + e.t, ip: e.ip, e, hits: [], start: e.t, end: e.t}; out.push(cur); }
      cur.hits.push(e); cur.end = e.t;
    }
  }
  for (const s of out) {
    const f = s.hits[0]; s.dur = s.end - s.start; s.pages = s.hits.length;
    s.src = searchEngine(f.r) ? '🔍 ' + searchEngine(f.r) : refHost(f.r) && refHost(f.r) !== (f.v || '').replace(/^www\./, '') ? '🔗 ' + refHost(f.r) : '⌨️ прямой заход';
    s.entry = f.p; s.exit = s.hits[s.hits.length - 1].p;
  }
  return out.sort((a, b) => b.end - a.end);
}
const fmtClock = s => s < 60 ? Math.round(s) + ' с' : s >= 600 ? Math.round(s / 60) + ' мин' : Math.floor(s / 60) + ' мин ' + String(Math.round(s % 60)).padStart(2, '0') + ' с';
function renderVisitors(list) {
  const ss = buildSessions(list);
  if (!ss.length) { $('#view').innerHTML = '<div class="empty">Нет визитов людей за выбранный период.</div>'; return; }
  const multi = ss.filter(s => s.pages > 1), bounce = ss.length - multi.length;
  const avgPages = ss.reduce((a, s) => a + s.pages, 0) / ss.length, avgDur = multi.length ? multi.reduce((a, s) => a + s.dur, 0) / multi.length : 0;
  const fromSe = ss.filter(s => s.src.startsWith('🔍')).length, uniq = new Set(ss.map(s => s.e.ip + '|' + s.e.ua)).size;
  const cnt = (arr, fn) => { const m = new Map(); for (const x of arr) { const k = fn(x); m.set(k, (m.get(k) || 0) + 1); } return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10); };
  const rows = ss.slice(0, 300).map(s => {
    const open = st.open.has('s:' + s.key);
    let h = `<tr class="row" data-s="${esc(s.key)}"><td class="mono" title="${esc(fmtDate(s.start))}">${open ? '▾' : '▸'} ${fmtTime(s.start)}</td>
      <td>${badge(s.e, true)}<div class="sub">${esc(s.e.os)} · ${esc(s.e.d)} · <span class="mono">${esc(s.ip)}</span></div></td>
      <td>${esc(s.src)}</td><td class="mono path" title="${esc(s.entry)}">${esc(s.entry)}</td>
      <td class="num"><b>${s.pages}</b></td><td class="num mono">${s.pages > 1 ? fmtClock(s.dur) : '—'}</td>
      <td class="mono path hide-sm" title="${esc(s.exit)}">${s.pages > 1 ? esc(s.exit) : '<span class="muted">отказ</span>'}</td></tr>`;
    if (open) h += `<tr class="detail"><td colspan="7"><ol class="path-list">${s.hits.map((e, i) => `<li><span class="mono sub">+${fmtClock(e.t - s.start)}</span> <span class="st ${stCls(e.s)}">${e.s}</span> <span class="mono">${esc(e.p)}</span>${i === 0 && e.r ? ` <span class="sub">← ${esc(e.r)}</span>` : ''}</li>`).join('')}</ol>
      <div class="actions"><button class="sm" data-qf="ip" data-v="${esc(s.ip)}">🔎 Все запросы этого IP</button></div></td></tr>`;
    return h;
  }).join('');
  $('#view').innerHTML = `
    <div class="cards" style="padding:14px 14px 0">
      <div class="card" style="--c:var(--browser);cursor:default"><div class="v">${nf(ss.length)}</div><div class="l">Визитов</div><div class="d">${nf(uniq)} посетителей</div></div>
      <div class="card" style="--c:var(--accent);cursor:default"><div class="v">${avgPages.toFixed(1)}</div><div class="l">Страниц за визит</div></div>
      <div class="card" style="--c:var(--s3);cursor:default"><div class="v">${fmtClock(avgDur)}</div><div class="l">Ср. длительность</div><div class="d">без отказов</div></div>
      <div class="card" style="--c:var(--s4);cursor:default"><div class="v">${Math.round(bounce / ss.length * 100)}%</div><div class="l">Отказы</div><div class="d">ушли после 1 страницы</div></div>
      <div class="card" style="--c:var(--search);cursor:default"><div class="v">${Math.round(fromSe / ss.length * 100)}%</div><div class="l">Пришли из поиска</div><div class="d">${nf(fromSe)} визитов</div></div>
    </div>
    <div class="grid">
      ${topBlock('🚪 Страницы входа', cnt(ss, s => s.entry), ss.length, 'var(--browser)', 'p')}
      ${topBlock('🏃 Страницы выхода', cnt(multi, s => s.exit), multi.length, 'var(--s4)', 'p')}
      ${topBlock('🧲 Источники визитов', cnt(ss, s => s.src), ss.length, 'var(--search)')}
    </div>
    <table class="tbl"><thead><tr><th>Начало</th><th>Посетитель</th><th>Откуда</th><th>Вход</th><th class="num">Стр.</th><th class="num">Время</th><th class="hide-sm">Выход</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="help" style="padding:0 14px">Визит — запросы одного посетителя (IP + браузер) с перерывами меньше 30 минут. Учитываются только страницы, без картинок, стилей и служебных запросов. Нажмите на визит, чтобы увидеть путь по сайту.</p>`;
}

// ───── Блокировка на сервере через API ─────
st.bans = {};
st.fw = {list: [], at: 0, ok: null, sample: '', loading: false};
// ── сопоставление IP с адресами и подсетями из iptables
function ipToBig(ip) {
  if (ip.includes('.') && !ip.includes(':')) { const p = ip.split('.').map(Number); return p.length === 4 && p.every(x => x >= 0 && x < 256) ? {v: 4, n: BigInt(((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3])} : null; }
  let [h, t] = ip.split('::'); const hp = h ? h.split(':') : [], tp = t !== undefined ? (t ? t.split(':') : []) : [];
  if (t === undefined && hp.length !== 8) return null;
  const parts = [...hp, ...Array(8 - hp.length - tp.length).fill('0'), ...tp];
  if (parts.length !== 8) return null;
  return {v: 6, n: parts.reduce((a, x) => (a << 16n) + BigInt(parseInt(x || '0', 16)), 0n)};
}
let fwIndex = null;
function buildFwIndex() {
  const exact = new Set(), nets = [];
  for (const f of st.fw.list) {
    const [a, b] = f.ip.split('/');
    if (b === undefined) { exact.add(a); continue; }
    const x = ipToBig(a); if (!x) continue;
    const bits = BigInt(x.v === 4 ? 32 : 128), pre = BigInt(+b), mask = pre === 0n ? 0n : ((1n << pre) - 1n) << (bits - pre);
    nets.push({v: x.v, net: x.n & mask, mask, f});
  }
  fwIndex = {exact, nets, cache: new Map()};
}
function fwMatch(ip) {
  if (!st.fw.list.length) return null;
  if (!fwIndex) buildFwIndex();
  if (fwIndex.cache.has(ip)) return fwIndex.cache.get(ip);
  let r = fwIndex.exact.has(ip) ? st.fw.list.find(f => f.ip === ip) : null;
  if (!r && fwIndex.nets.length) { const x = ipToBig(ip); if (x) r = fwIndex.nets.find(n => n.v === x.v && (x.n & n.mask) === n.net)?.f || null; }
  fwIndex.cache.set(ip, r); return r;
}
const ownBan = ip => { const b = st.bans[ip]; return b && b.until > Date.now() / 1000 ? b : null; };
const isBanned = ip => !!(ownBan(ip) || fwMatch(ip));
const banBadge = ip => {
  const b = ownBan(ip), f = fwMatch(ip);
  if (b) return `<span class="ban" title="Заблокирован до ${esc(fmtDate(b.until))}">⛔ до ${fmtShort(b.until)}</span>`;
  if (f) return `<span class="ban" title="В iptables: ${esc(f.ip)}">⛔ ${f.ip.includes('/') ? esc(f.ip) : 'в iptables'}</span>`;
  return '';
};
async function loadBans() {
  if (!BLOCK.enabled) return;
  try { const d = await getJSON('?api=blocks'); st.bans = {}; for (const b of d.blocks) st.bans[b.ip] = b; } catch {}
  await loadFw();
}
async function loadFw(force) {
  if (!BLOCK.enabled || st.fw.loading) return;
  st.fw.loading = true;
  try {
    const d = await getJSON('?api=fwlist' + (force ? '&force=1' : ''));
    st.fw = {list: d.list || [], at: d.at || Date.now() / 1000, ok: !!d.ok, sample: d.sample || '', code: d.code, err: d.err || d.error || '', loading: false};
  } catch (e) { st.fw.ok = false; st.fw.err = e.message; st.fw.loading = false; }
  fwIndex = null;
}
async function banRequest(action, ip, extra = {}) {
  const body = new URLSearchParams({ip, ...extra});
  const r = await fetch(`?api=${action}`, {method: 'POST', headers: {'X-Token': BLOCK.token}, body, cache: 'no-store'});
  const text = await r.text();
  try { return JSON.parse(text); } catch { return {ok: false, error: `HTTP ${r.status}: ${text.slice(0, 200)}`}; }
}
function ipSummary(ip) {
  const list = st.entries.filter(e => e.ip === ip), s = list[list.length - 1];
  if (!s) return {html: `<p class="mono" style="font-size:16px;margin:0">${esc(ip)}</p>`, reason: ''};
  const thr = analyzeThreats(list)[0];
  const reason = thr ? thr.reasons.map(r => r[0].replace(/^\S+\s/, '') + (r[1] !== '' ? ' ' + r[1] : '')).join(', ') : '';
  return {reason, search: s.k === 'search' && !isFake(s), html: `<p class="mono" style="font-size:16px;margin:0 0 6px">${esc(ip)} ${badge(s, true)}</p>
    <p class="sub" style="margin:0">${nf(list.length)} запросов в загруженных данных · последний ${ago(s.t)}${s.k === 'browser' ? ` · ${esc(s.os)}, ${esc(s.d)}` : ''}</p>
    ${thr ? `<p style="margin:6px 0 0">${thr.reasons.map(([l, n]) => `<span class="reason">${esc(l)}${n !== '' ? ' ' + esc(n) : ''}</span>`).join('')}</p>` : ''}`};
}
/** Подсеть /24 (IPv4) или /64 (IPv6) для IP */
function subnetOf(ip) {
  if (ip.includes('/')) return '';
  const x = ipToBig(ip); if (!x) return '';
  if (x.v === 4) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  const n = (x.n >> 64n) << 64n, h = [];
  for (let i = 7; i >= 0; i--) h.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  return h.slice(0, 4).join(':') + '::/64';
}
function subnetCount(cidr) {
  const [a, b] = cidr.split('/'), x = ipToBig(a); if (!x) return {req: 0, ips: 0};
  const bits = BigInt(x.v === 4 ? 32 : 128), pre = BigInt(+b), mask = ((1n << pre) - 1n) << (bits - pre), net = x.n & mask, ips = new Set();
  let req = 0;
  for (const e of st.entries) { const y = ipToBig(e.ip); if (y && y.v === x.v && (y.n & mask) === net) { req++; ips.add(e.ip); } }
  return {req, ips: ips.size};
}
function askBan(ip) {
  const dlg = $('#blockDlg'), info = ipSummary(ip), sn = subnetOf(ip);
  $('#blockInfo').innerHTML = info.html;
  $('#blockTimeout').innerHTML = Object.entries(BLOCK.timeouts).map(([v, l]) => `<option value="${v}" ${+v === BLOCK.def ? 'selected' : ''}>${esc(l)}</option>`).join('');
  $('#blockReason').value = info.reason;
  const meIn = sn && ipToBig(BLOCK.me) && subnetOf(BLOCK.me) === sn;
  $('#blockTarget').innerHTML = `<option value="${esc(ip)}">только этот IP</option>` + (sn ? (() => { const c = subnetCount(sn); return `<option value="${esc(sn)}" ${meIn ? 'disabled' : ''}>всю подсеть ${esc(sn)} — ${nf(c.ips)} IP, ${nf(c.req)} запросов${meIn ? ' (там ваш IP)' : ''}</option>`; })() : '');
  $('#blockTargetRow').hidden = !sn;
  const warn = ip === BLOCK.me ? '⛔ Это ваш собственный IP — блокировка запрещена.' : info.search ? '⚠️ Это поисковый робот. Если он настоящий, сайт может выпасть из поиска.' : '';
  $('#blockWarn').hidden = !warn; $('#blockWarn').textContent = warn;
  $('#blockOk').disabled = ip === BLOCK.me;
  dlg.returnValue = '';
  dlg.onclose = async () => {
    if (dlg.returnValue !== 'ok') return;
    await doBan($('#blockTarget').value || ip, +$('#blockTimeout').value, $('#blockReason').value);
  };
  dlg.showModal();
}
async function doBan(ip, timeout, reason, quiet) {
  let d = await banRequest('block', ip, {timeout, reason});
  if (!d.ok && d.protected && !quiet && confirm(d.error + '\n\nВсё равно заблокировать?')) d = await banRequest('block', ip, {timeout, reason, force: 1});
  if (d.ok) {
    const key = d.ip || ip;
    st.bans[key] = {ip: key, until: d.until, at: Date.now() / 1000, timeout, reason};
    if (!st.fw.list.some(f => f.ip === key)) { st.fw.list.push({ip: key}); fwIndex = null; }
    if (!quiet) toast(`⛔ ${key} заблокирован`, `на ${BLOCK.timeouts[timeout] || timeout + ' с'}` + (d.resp ? ` · ответ API: ${d.resp.slice(0, 120)}` : ''), 'var(--fake)', key.includes('/') ? null : {ip: key});
  } else if (!quiet) toast(`Не удалось заблокировать ${ip}`, d.error || `API ответил ${d.code}: ${d.resp || d.err || 'пусто'}`, 'var(--s4)');
  render(false, true);
  return d;
}
async function doUnban(ip) {
  if (!confirm(`Разблокировать ${ip}?`)) return;
  const d = await banRequest('unblock', ip);
  if (d.ok) {
    delete st.bans[ip]; st.fw.list = st.fw.list.filter(f => f.ip !== ip); fwIndex = null;
    toast(`✅ ${ip} разблокирован`, d.resp ? 'Ответ API: ' + d.resp.slice(0, 120) : '', 'var(--s2)');
  } else toast(`Не удалось разблокировать ${ip}`, d.error || `API ответил ${d.code}: ${d.resp || d.err || 'пусто'}`, 'var(--s4)');
  render(false, true);
}
async function clearAll() {
  const n = st.fw.list.length;
  const ans = prompt(`Снять ВСЕ баны на сервере (IP и подсети, IPv4 и IPv6)${n ? ` — сейчас в iptables ${n} записей` : ''}?\n\nЭто нельзя отменить. Для подтверждения введите: СНЯТЬ ВСЁ`);
  if (ans === null) return;
  if (ans.trim().toUpperCase() !== 'СНЯТЬ ВСЁ') { toast('Отменено', 'Фраза подтверждения не совпала', 'var(--muted)'); return; }
  const r = await fetch('?api=clearall', {method: 'POST', headers: {'X-Token': BLOCK.token}, body: new URLSearchParams({confirm: 'СНЯТЬ ВСЁ'}), cache: 'no-store'});
  let d; try { d = JSON.parse(await r.text()); } catch { d = {ok: false, error: 'HTTP ' + r.status}; }
  if (d.ok) { st.bans = {}; st.fw.list = []; fwIndex = null; toast('✅ Все баны сняты', d.resp ? 'Ответ API: ' + d.resp.slice(0, 150) : '', 'var(--s2)'); }
  else toast('Не удалось снять баны', d.error || `API ответил ${d.code}: ${d.resp || d.err || 'пусто'}`, 'var(--s4)');
  await loadFw(true); render(false, true);
}
async function banAll(ips) {
  ips = ips.filter(ip => !isBanned(ip) && ip !== BLOCK.me);
  if (!ips.length) { toast('Нечего блокировать', 'Все IP уже заблокированы', 'var(--muted)'); return; }
  const t = Object.entries(BLOCK.timeouts).find(([v]) => +v === BLOCK.def)?.[1] || '';
  if (!confirm(`Заблокировать на сервере ${ips.length} IP на ${t}?\n\n${ips.slice(0, 15).join('\n')}${ips.length > 15 ? '\n…' : ''}`)) return;
  let ok = 0, fail = [];
  for (const ip of ips) {
    const info = ipSummary(ip), d = await doBan(ip, BLOCK.def, info.reason, true);
    d.ok ? ok++ : fail.push(`${ip}: ${d.error || d.resp || d.code}`);
  }
  toast(`⛔ Заблокировано: ${ok} из ${ips.length}`, fail.length ? 'Ошибки: ' + fail.slice(0, 3).join('; ') : '', fail.length ? 'var(--s4)' : 'var(--fake)');
  render(false, true);
}
function banSectionHtml() {
  if (!BLOCK.enabled) return `<div class="help" style="padding:14px 14px 0">⛔ Блокировка через API выключена — укажите <code>BLOCK_API_KEY</code> в начале logs.php.</div>`;
  const now = Date.now() / 1000, q = (st.fwq || '').trim().toLowerCase();
  const left = s => s < 3600 ? Math.ceil(s / 60) + ' мин' : s < 86400 ? (s / 3600).toFixed(1) + ' ч' : (s / 86400).toFixed(1) + ' дн';
  // счётчик запросов из логов для каждой записи iptables
  const hits = new Map(), lastE = new Map();
  for (const e of st.entries) { const f = fwMatch(e.ip); if (f) { hits.set(f.ip, (hits.get(f.ip) || 0) + 1); lastE.set(f.ip, e); } }
  const rows = st.fw.list.map(f => ({...f, own: st.bans[f.ip], n: hits.get(f.ip) || 0, e: lastE.get(f.ip)}));
  const gone = Object.values(st.bans).filter(b => b.until > now && !st.fw.list.some(f => f.ip === b.ip));
  rows.sort((a, b) => (b.own?.at || b.at || 0) - (a.own?.at || a.at || 0) || b.n - a.n);
  const shown = rows.filter(r => !q || r.ip.includes(q) || (r.own?.reason || r.comment || '').toLowerCase().includes(q) || (r.e?.n || '').toLowerCase().includes(q));
  const v4 = rows.filter(r => !r.ip.includes(':')).length, nets = rows.filter(r => r.ip.includes('/')).length;
  const status = st.fw.ok === null ? '<span class="sub">загрузка…</span>' : st.fw.ok
    ? `<span class="sub">обновлено ${fmtTime(st.fw.at)}</span>` : `<span class="reason">не удалось получить список: ${esc(st.fw.err || 'HTTP ' + st.fw.code)}</span>`;
  const tr = r => {
    const until = r.own?.until || r.until, at = r.own?.at || r.at, reason = r.own?.reason || r.comment || '';
    return `<tr><td class="mono">${r.ip.includes('/') ? `<b>${esc(r.ip)}</b> <span class="sub">подсеть</span>` : `<span ${qfAttr('ip', r.ip)}>${esc(r.ip)}</span>`}</td>
      <td>${r.e ? badge(r.e, true) : '<span class="muted">—</span>'}</td><td class="num">${r.n ? nf(r.n) : '<span class="muted">0</span>'}</td>
      <td class="sub">${esc(reason || '—')}</td><td class="muted">${at ? ago(at) : '—'}</td>
      <td>${until ? (until > now ? `<b>${left(until - now)}</b> <span class="sub">до ${fmtShort(until)}</span>` : '<span class="muted">истекает</span>') : '<span class="muted">—</span>'}</td>
      <td>${BLOCK.unblock ? `<button class="sm" data-unban="${esc(r.ip)}">Разблокировать</button>` : ''}</td></tr>`;
  };
  return `<div style="padding:14px 14px 0">
    <h3 style="margin:0 0 8px;font-size:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">🧱 Сейчас в iptables: ${nf(rows.length)}
      <span class="sub">IPv4: ${nf(v4)} · IPv6: ${nf(rows.length - v4)} · подсетей: ${nf(nets)}</span> ${status}
      <button class="sm" id="fwReload" title="Перечитать список из API">🔄</button>
      <span class="spacer"></span>
      <input id="banIp" placeholder="IP или подсеть: 1.2.3.4, 1.2.3.0/24, 2a03::/64" style="width:280px"><button class="primary-danger sm" id="banIpBtn">⛔ Заблокировать</button>
      <button class="sm danger" id="clearAll" title="Снять все баны на сервере">🧹 Снять все</button></h3>
    ${gone.length ? `<div class="warnbox">⚠️ Заблокированы через эту страницу, но в iptables их нет (уже сняты вручную или после перезагрузки): ${gone.map(b => `<span class="mono">${esc(b.ip)}</span> <button class="sm primary-danger" data-ban="${esc(b.ip)}">⛔ снова</button>`).join(' ')}</div>` : ''}
    ${rows.length > 15 ? `<input type="search" id="fwq" placeholder="Поиск по списку: IP, причина, бот…" value="${esc(st.fwq || '')}" style="width:100%;margin-bottom:8px">` : ''}
    ${shown.length ? `<table class="tbl"><thead><tr><th>IP / подсеть</th><th>Кто (по логам)</th><th class="num">Запросов в логах</th><th>Причина</th><th>Когда</th><th>Осталось</th><th></th></tr></thead><tbody>${shown.slice(0, 500).map(tr).join('')}</tbody></table>
      ${shown.length > 500 ? `<p class="sub">Показаны первые 500 из ${nf(shown.length)} — уточните поиск.</p>` : ''}`
      : `<p class="muted">${rows.length ? 'Ничего не найдено.' : st.fw.ok ? 'В iptables пусто. Блокируйте из ленты (раскройте строку), на вкладке «Угрозы» или введите IP выше.' : ''}</p>`}
    ${st.fw.sample && (!st.fw.ok || !rows.length) ? `<details class="sub"><summary>Ответ API на action=list (для проверки)</summary><pre class="cfg">${esc(st.fw.sample)}</pre></details>` : ''}
    <p class="help">Список берётся из вашего API (<code>action=list</code>) и обновляется раз в минуту. «Запросов в логах» — сколько запросов от этого IP или подсети есть в загруженных данных: если число растёт, блокировка не работает (например, сайт за Cloudflare). Ключ API хранится только на сервере.</p></div>`;
}

// ───── 🤖 Автозащита ─────
st.ab = null; st.abSeen = 0; st.abFilter = '';
const AB_ACT = {ban: ['⛔ заблокирован', 'var(--fake)'], watch: ['👁 заблокировал бы', 'var(--s3)'], skip: ['✋ пропущен', 'var(--muted)'], error: ['⚠️ ошибка', 'var(--s4)'], limit: ['🛑 предохранитель', 'var(--s4)']};
const AB_MODES = {off: ['⏸ Выключена', 'var(--muted)'], watch: ['👁 Наблюдение', 'var(--s3)'], ban: ['⛔ Блокирует', 'var(--fake)']};
async function loadAutoban() {
  try {
    const d = await getJSON('?api=autoban'), first = !st.ab;
    st.ab = d;
    const maxT = Math.max(0, ...d.journal.map(j => j.t));
    if (!first) for (const j of d.journal) {
      if (j.t <= st.abSeen) continue;
      if (j.act === 'ban') { alertOnce('ab:' + j.ip, `🤖 Автозащита заблокировала ${j.ip}`, j.why, 'var(--fake)', {ip: j.ip}, 60); }
      else if (j.act === 'watch') { if (cfg.toast) toast(`👁 Автозащита заблокировала бы ${j.ip}`, j.why + ' — включите режим «Блокирует»', 'var(--s3)', {ip: j.ip}); }
      else if (j.act === 'error' || j.act === 'limit') toast(`🤖 ${AB_ACT[j.act][0]}: ${j.ip}`, j.note || '', 'var(--s4)');
    }
    if (d.journal.some(j => j.t > st.abSeen && j.act === 'ban')) await loadBans();
    st.abSeen = Math.max(st.abSeen, maxT);
    const b = $('#abCnt'), n24 = d.journal.filter(j => j.t > Date.now() / 1000 - 86400 && (j.act === 'ban' || j.act === 'watch')).length;
    b.hidden = d.mode === 'off' && !n24; b.textContent = d.mode === 'off' ? 'выкл' : n24 || '✓'; b.style.background = AB_MODES[d.mode][1];
  } catch {}
}
async function abPost(api, data) {
  const r = await fetch('?api=' + api, {method: 'POST', headers: {'X-Token': BLOCK.token}, body: new URLSearchParams(data), cache: 'no-store'});
  try { return JSON.parse(await r.text()); } catch { return {ok: false, error: 'HTTP ' + r.status}; }
}
async function abSetMode(mode) {
  if (mode === 'ban' && !confirm('Включить автоматическую блокировку?\n\nАвтозащита будет сама блокировать IP через ваш API по правилам. Ваши IP, подтверждённые поисковики и полезные боты не блокируются. Предохранитель: не больше ' + (st.ab?.maxHour || 60) + ' банов в час.\n\nСовет: сначала посмотрите журнал режима «Наблюдение».')) return;
  const d = await abPost('autoban_set', {mode});
  if (d.ok) toast('🤖 Автозащита: ' + AB_MODES[d.mode][0], d.mode === 'ban' ? 'Блокировка включена' : d.mode === 'watch' ? 'Только записываю, кого заблокировала бы' : 'Выключена', AB_MODES[d.mode][1]);
  await loadAutoban(); render(false, true);
}
async function abRun() {
  const btn = $('#abRun'); if (btn) { btn.disabled = true; btn.textContent = '⏳ Проверяю…'; }
  const d = await abPost('autoban_run', {});
  if (d.skipped) toast('🤖 Проверка пропущена', d.skipped, 'var(--muted)');
  else if (d.ok) toast('🤖 Проверка выполнена', `строк: ${nf(d.lines)}, IP под наблюдением: ${nf(d.ips)}, решений: ${d.decisions}, ${d.ms} мс`, 'var(--accent)');
  else toast('Ошибка проверки', d.error || '', 'var(--s4)');
  await loadAutoban(); render(false, true);
}
function abDesc(r) {
  return esc(r.desc).replace('{hits}', r.hits).replace('{per_min}', r.per_min).replace('{share_pct}', Math.round((r.share || 0) * 100)).replace('{bots}', esc((r.bots || []).join(', ')));
}
function renderAutoban() {
  const d = st.ab;
  if (!d) { $('#view').innerHTML = '<div class="empty">Загрузка…</div>'; loadAutoban().then(() => st.tab === 'autoban' && render(false, true)); return; }
  const now = Date.now() / 1000, day = d.journal.filter(j => j.t > now - 86400);
  const c = a => day.filter(j => j.act === a).length;
  const last = d.last || {}, cronAgo = last.cron ? now - last.cron : Infinity;
  const cronOk = cronAgo < 180;
  const cronLine = `* * * * * ${d.user || 'nginx'} ${d.php} ${d.script} --autoban >/dev/null 2>&1`;
  const ruleHits = {}; for (const j of day) if (j.act === 'ban' || j.act === 'watch') ruleHits[j.rule] = (ruleHits[j.rule] || 0) + 1;
  const flt = st.abFilter, list = d.journal.filter(j => !flt || j.act === flt).slice().reverse().slice(0, 300);
  const sample = ip => { const e = st.entries.findLast?.(x => x.ip === ip); return e ? badge(e, true) : ''; };
  const dur = s => s >= 86400 ? Math.round(s / 86400) + ' дн' : s >= 3600 ? Math.round(s / 3600) + ' ч' : Math.round(s / 60) + ' мин';
  $('#view').innerHTML = `
  <div style="padding:14px">
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <div class="seg">${Object.entries(AB_MODES).map(([m, [l, col]]) => `<button data-abmode="${m}" class="${d.mode === m ? 'on' : ''}" style="--c:${col}">${l}</button>`).join('')}</div>
      <button id="abRun" ${d.mode === 'off' ? 'disabled' : ''}>▶ Проверить сейчас</button>
      <span class="sub">Последняя проверка: ${last.t ? `<b>${ago(last.t)}</b> (${esc(last.by || '')}, ${nf(last.lines || 0)} строк, ${last.ms || 0} мс)` : 'ещё не было'} · под наблюдением IP: ${nf(d.tracked)}</span>
    </div>
    ${d.mode === 'watch' ? `<div class="warnbox" style="margin-top:12px;border-color:var(--s3);background:color-mix(in srgb,var(--s3) 10%,var(--panel))">👁 <b>Режим наблюдения:</b> автозащита ничего не блокирует, только записывает в журнал, кого заблокировала бы. Посмотрите журнал день-два — если решения правильные, включите «⛔ Блокирует».</div>` : ''}
    ${d.mode === 'ban' && !d.enabled ? `<div class="error" style="margin-top:12px">Не настроен BLOCK_API_KEY — блокировать нечем.</div>` : ''}
    ${!cronOk && d.mode !== 'off' ? `<div class="warnbox" style="margin-top:12px">⏰ <b>Cron не настроен</b>${last.cron ? ` (последний запуск ${ago(last.cron)})` : ''} — сейчас защита работает только пока открыта эта страница. Настройка — ниже, в «Подключение cron».</div>` : ''}
  </div>
  <div class="cards" style="padding:0 14px">
    <div class="card" style="--c:var(--fake);cursor:default"><div class="v">${nf(c('ban'))}</div><div class="l">⛔ Заблокировано за 24 ч</div></div>
    <div class="card" style="--c:var(--s3);cursor:default"><div class="v">${nf(c('watch'))}</div><div class="l">👁 Заблокировал бы</div><div class="d">в режиме наблюдения</div></div>
    <div class="card" style="--c:var(--muted);cursor:default"><div class="v">${nf(c('skip'))}</div><div class="l">✋ Пропущено</div><div class="d">белый список</div></div>
    <div class="card" style="--c:var(--s4);cursor:default"><div class="v">${nf(c('error') + c('limit'))}</div><div class="l">⚠️ Ошибки</div><div class="d">и срабатывания предохранителя</div></div>
    <div class="card" style="--c:${cronOk ? 'var(--s2)' : 'var(--s4)'};cursor:default"><div class="v">${cronOk ? '✓' : '—'}</div><div class="l">⏰ Cron</div><div class="d">${last.cron ? 'был ' + ago(last.cron) : 'не запускался'}</div></div>
  </div>
  <div class="panel" style="margin:0 14px 14px"><h2>📏 Правила <span class="sub">окно анализа — ${Math.round(d.window / 60)} мин · не больше ${d.maxHour} банов в час · повторным нарушителям срок ×2</span></h2>
    <table class="tbl"><thead><tr><th style="width:40px"></th><th>Правило</th><th>Когда срабатывает</th><th>Срок</th><th class="num">За 24 ч</th></tr></thead><tbody>${
      Object.entries(d.rules).map(([k, r]) => `<tr style="${r.on ? '' : 'opacity:.5'}"><td><input type="checkbox" data-abrule="${k}" ${r.on ? 'checked' : ''} title="Включить / выключить"></td>
        <td><b>${esc(r.title)}</b></td><td class="sub">${abDesc(r)}</td><td>${dur(r.timeout)}</td><td class="num">${ruleHits[k] || 0}</td></tr>`).join('')
    }</tbody></table>
    <p class="help" style="padding:0 14px">Никогда не блокируются: ваши IP (с которых открывали эту панель), локальные адреса, <code>BLOCK_PROTECT_IPS</code>, подтверждённые по rDNS Googlebot / YandexBot / Bingbot…, полезные боты (${esc(d.skipBots.join(', '))}). Пороги меняются в начале logs.php (<code>AUTOBAN_RULES</code>).</p>
  </div>
  <div class="panel" style="margin:0 14px 14px"><h2>📒 Журнал решений
    <select id="abFilter" style="margin-left:8px"><option value="">все</option>${Object.entries(AB_ACT).map(([k, [l]]) => `<option value="${k}" ${flt === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
    <span class="sub">${nf(d.journal.length)} записей</span></h2>
    ${list.length ? `<table class="tbl"><thead><tr><th>Время</th><th>IP</th><th>Правило</th><th>Почему</th><th>Решение</th><th></th></tr></thead><tbody>${list.map(j => {
      const [al, ac] = AB_ACT[j.act] || [j.act, 'var(--muted)'], banned = isBanned(j.ip);
      return `<tr><td class="mono" title="${esc(fmtDate(j.t))}">${fmtShort(j.t)}<span class="site">${ago(j.t)}</span></td>
        <td class="mono"><span ${qfAttr('ip', j.ip)}>${esc(j.ip)}</span> ${sample(j.ip) || (j.n ? `<span class="sub">${esc(j.n)}</span>` : '')}${banBadge(j.ip)}</td>
        <td>${esc(d.rules[j.rule]?.title || j.rule)}</td><td class="sub" style="max-width:420px">${esc(j.why)}</td>
        <td><b style="color:${ac}">${al}</b>${j.timeout && j.act !== 'skip' ? ` <span class="sub">на ${dur(j.timeout)}</span>` : ''}${j.note ? `<div class="sub">${esc(j.note)}</div>` : ''}<div class="site">${esc(j.by || '')}</div></td>
        <td style="white-space:nowrap">${banned && BLOCK.unblock ? `<button class="sm" data-unban="${esc(j.ip)}">Разблокировать</button>` : ''}${!banned && (j.act === 'watch' || j.act === 'error' || j.act === 'limit') && BLOCK.enabled ? `<button class="sm primary-danger" data-ban="${esc(j.ip)}">⛔ блок</button>` : ''}</td></tr>`;
    }).join('')}</tbody></table>` : `<div class="empty">${d.journal.length ? 'Нет записей под фильтр.' : 'Пока пусто — как только появится зараза, решения будут здесь.'}</div>`}
  </div>
  <details class="panel" style="margin:0 14px 14px" ${cronOk ? '' : 'open'}><summary style="padding:10px 14px;cursor:pointer;font-weight:600">⏰ Подключение cron — чтобы защита работала круглосуточно</summary>
    <div style="padding:0 14px 14px" class="help">
      <p>Выполните на сервере одну команду (cron будет запускать проверку каждую минуту от пользователя <code>${esc(d.user || 'nginx')}</code> — того же, что и PHP):</p>
      <pre class="cfg" id="cronCmd">echo '${esc(cronLine)}' | sudo tee /etc/cron.d/logviewer-autoban</pre>
      <p><button class="sm primary" id="copyCron">📋 Скопировать</button> Проверить вручную: <code>sudo -u ${esc(d.user || 'nginx')} ${esc(d.php)} ${esc(d.script)} --autoban</code></p>
      <p>Если путь к PHP другой — узнайте его командой <code>which php</code> (или <code>php8.3</code>).</p>
      <p>📁 Данные хранятся в <code>${esc(d.dataDir)}</code> ${d.dataOk ? '✅' : `⚠️ — не удалось использовать папку из DATA_DIR, сейчас временная. Создайте её: <code>sudo mkdir -p ${esc(d.script.replace(/[^/]+$/, ''))}logviewer-data && sudo chown ${esc(d.user || 'nginx')} ${esc(d.script.replace(/[^/]+$/, ''))}logviewer-data</code>`}. Файлы защищены от чтения через браузер.</p>
      <p>👤 Ваши IP (не блокируются): ${Object.keys(d.admins).length ? Object.entries(d.admins).map(([ip, t]) => `<code>${esc(ip)}</code> <span class="sub">${ago(t)}</span>`).join(', ') : 'появятся, когда откроете панель не с localhost'}</p>
    </div></details>`;
}

// ───── Блокировка: действия ─────
function blockIp(ip) { if (!cfg.blocks.ips.includes(ip)) { cfg.blocks.ips.push(ip); save(); toast('🚫 IP добавлен в список', ip + ' — конфиг на вкладке «Блокировка»', 'var(--threat)'); } }
function blockBot(name, kind) {
  if (kind === 'search' && !confirm(`${name} — поисковый робот. Если заблокировать его по имени, сайт может пропасть из поиска.\n\nДля поддельных ботов лучше блокировать IP. Всё равно добавить?`)) return;
  if (!cfg.blocks.bots.includes(name)) { cfg.blocks.bots.push(name); save(); toast('🚫 Бот добавлен в список', name + ' — конфиг на вкладке «Блокировка»', 'var(--threat)'); }
}

// ───── CSV ─────
function exportCsv() {
  const list = filtered(baseList());
  const cols = [['Время', e => fmtDate(e.t)], ['Сайт', e => e.v], ['IP', e => e.ip], ['Тип', e => isFake(e) ? 'поддельный' : KINDS[e.k].label], ['Кто', e => e.n],
    ['Метод', e => e.m], ['URL', e => e.p], ['Код', e => e.s], ['Байт', e => e.b], ['Время ответа, с', e => e.rt ?? ''], ['Реферер', e => e.r], ['User-Agent', e => e.ua], ['Угроза', e => e.thr]];
  const q = v => { const s = String(v ?? ''); return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const csv = '﻿' + [cols.map(c => c[0]).join(';'), ...list.map(e => cols.map(c => q(c[1](e))).join(';'))].join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8'}));
  a.download = `logs-${new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-')}.csv`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast('⬇ CSV готов', `${nf(list.length)} строк`, 'var(--accent)');
}

// ───── События ─────
function switchTab(tab) {
  st.tab = tab;
  $$('#tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === tab));
  render(false, true);
}
function setQf(k, v) {
  if (st.qf[k] === v) delete st.qf[k]; else st.qf[k] = v;
  if (st.tab !== 'groups') st.tab = 'feed';
  switchTab(st.tab);
  const y = $('#tabs').getBoundingClientRect().top + scrollY - $('#hdr').offsetHeight - 8;
  if (scrollY > y) window.scrollTo({top: y, behavior: 'smooth'});
}
document.addEventListener('click', ev => {
  const t = ev.target;
  const qf = t.closest('[data-qf]');
  if (qf) { ev.stopPropagation(); setQf(qf.dataset.qf, qf.dataset.v); return; }
  const un = t.closest('[data-unqf]');
  if (un) { if (un.dataset.unqf === '*') st.qf = {}; else delete st.qf[un.dataset.unqf]; render(false, true); return; }
  const bi = t.closest('[data-block-ip]'); if (bi) { blockIp(bi.dataset.blockIp); render(false, true); return; }
  const bb = t.closest('[data-block-bot]'); if (bb) { blockBot(bb.dataset.blockBot, bb.dataset.kind); render(false, true); return; }
  if (t.closest('[data-block-noua]')) { cfg.blocks.noUA = true; save(); render(false, true); return; }
  const ui = t.closest('[data-unblock-ip]'); if (ui) { cfg.blocks.ips = cfg.blocks.ips.filter(x => x !== ui.dataset.unblockIp); save(); render(false, true); return; }
  const ub = t.closest('[data-unblock-bot]'); if (ub) { cfg.blocks.bots = cfg.blocks.bots.filter(x => x !== ub.dataset.unblockBot); save(); render(false, true); return; }
  if (t.closest('[data-unblock-noua]')) { cfg.blocks.noUA = false; save(); render(false, true); return; }
  if (t.id === 'addIpBtn') { const v = $('#addIp').value.trim(); if (/^[0-9a-f.:]+(\/\d{1,3})?$/i.test(v)) { blockIp(v); render(false, true); } else toast('Неверный IP', v, 'var(--fake)'); return; }
  if (t.id === 'addBotBtn') { const v = $('#addBot').value; if (v) { blockBot(v); render(false, true); } return; }
  if (t.id === 'clearBlocks') { if (confirm('Очистить списки блокировки?')) { cfg.blocks = {ips: [], bots: [], noUA: false}; save(); render(false, true); } return; }
  const bn = t.closest('[data-ban]'); if (bn) { askBan(bn.dataset.ban); return; }
  const ubn = t.closest('[data-unban]'); if (ubn) { doUnban(ubn.dataset.unban); return; }
  if (t.id === 'banAllThreats') { banAll(analyzeThreats(baseList()).map(x => x.ip)); return; }
  if (t.id === 'banIpBtn') { const v = $('#banIp').value.trim(); if (/^[0-9a-f.:]+(\/\d{1,3})?$/i.test(v) && v.length > 2) askBan(v); else toast('Неверный IP', v, 'var(--fake)'); return; }
  const abm = t.closest('[data-abmode]'); if (abm) { abSetMode(abm.dataset.abmode); return; }
  if (t.id === 'abRun') { abRun(); return; }
  if (t.id === 'copyCron') { navigator.clipboard?.writeText($('#cronCmd').textContent).then(() => toast('📋 Скопировано', 'Вставьте в терминал сервера', 'var(--accent)')); return; }
  if (t.id === 'fwReload') { loadFw(true).then(() => render(false, true)); return; }
  if (t.id === 'clearAll') { clearAll(); return; }
  if (t.id === 'blockAllThreats') { const th = analyzeThreats(baseList()); th.forEach(x => { if (!cfg.blocks.ips.includes(x.ip)) cfg.blocks.ips.push(x.ip); }); save(); toast('🚫 Добавлено IP: ' + th.length, 'Конфиг на вкладке «Блокировка»', 'var(--threat)'); render(false, true); return; }
  if (t.id === 'copyCfg') { navigator.clipboard?.writeText(nginxConfig()).then(() => toast('📋 Скопировано', 'Вставьте в конфиг nginx', 'var(--accent)'), () => { const r = document.createRange(); r.selectNodeContents($('#cfgText')); getSelection().removeAllRanges(); getSelection().addRange(r); toast('Выделено', 'Нажмите Ctrl+C', 'var(--accent)'); }); return; }
  const hm = t.closest('[data-heat]'); if (hm) { st.heat = hm.dataset.heat; render(false, true); return; }
  const srt = t.closest('[data-sort]'); if (srt) { st.sort.slow = srt.dataset.sort; render(false, true); return; }
  const card = t.closest('.card[data-kind]');
  if (card) {
    const k = card.dataset.kind;
    if (k === 'thr') { switchTab('threats'); return; }
    st.kind = st.kind === k ? '' : k; render(false, true); return;
  }
  const tab = t.closest('#tabs button'); if (tab) { switchTab(tab.dataset.tab); return; }
  const tr = t.closest('#view tr.row');
  if (tr && !t.closest('a,button')) {
    const id = tr.dataset.id ? +tr.dataset.id : tr.dataset.g !== undefined ? 'g:' + tr.dataset.g : tr.dataset.s ? 's:' + tr.dataset.s : null;
    if (id === null) return;
    st.open.has(id) ? st.open.delete(id) : st.open.add(id); render(false, true);
  }
});
$('#q').addEventListener('input', () => render(false, true));
$('#onlyErr').addEventListener('input', () => render(false, true));
$('#noStatic').addEventListener('input', () => { cfg.noStatic = $('#noStatic').checked; save(); render(false, true); });
$('#groupBy').addEventListener('input', () => { cfg.groupBy = $('#groupBy').value; save(); render(false, true); });
$('#interval').onchange = () => { cfg.interval = $('#interval').value; save(); if (!st.paused) poll(); };
$('#period').onchange = async () => { cfg.period = $('#period').value; save(); render(false, true); await ensurePeriod(); render(false, true); };
$('#more').onclick = async () => { await loadHistory(20000); render(false, true); };
$('#csv').onclick = exportCsv;
$('#file').onchange = () => { st.file = $('#file').value; st.fstate = {}; st.entries = []; st.open.clear(); st.firstLoaded = false; st.more = true; poll(); };
function togglePause() {
  st.paused = !st.paused; $('#hdr').classList.toggle('paused', st.paused);
  $('#liveTxt').textContent = st.paused ? 'ПАУЗА' : 'В ЭФИРЕ'; if (!st.paused) poll(); else clearTimeout(st.timer);
}
$('#pause').onclick = togglePause;
document.addEventListener('keydown', ev => {
  if (ev.target.matches('input,textarea,select')) { if (ev.key === 'Escape') ev.target.blur(); return; }
  if (ev.key === '/') { ev.preventDefault(); $('#q').focus(); }
  else if (ev.key === ' ') { ev.preventDefault(); togglePause(); }
  else if (ev.key === 'Escape') { st.qf = {}; st.kind = ''; $('#q').value = ''; $('#drawer').classList.remove('open'); render(false, true); }
  else if (/^[0-9]$/.test(ev.key)) { const b = $$('#tabs button')[ev.key === '0' ? 9 : +ev.key - 1]; if (b) switchTab(b.dataset.tab); }
});

// ───── Настройки (шторка) ─────
function applyTheme() { document.documentElement.dataset.theme = cfg.theme === 'auto' ? '' : cfg.theme; if (cfg.theme === 'auto') delete document.documentElement.dataset.theme; }
function notifState() { $('#notifState').textContent = !('Notification' in window) ? 'не поддерживается' : {granted:'разрешены', denied:'запрещены в браузере', default:''}[Notification.permission]; }
$$('[data-set]').forEach(el => {
  const k = el.dataset.set;
  if (el.type === 'checkbox') el.checked = !!cfg[k]; else el.value = cfg[k];
  el.addEventListener('change', async () => {
    cfg[k] = el.type === 'checkbox' ? el.checked : el.type === 'number' ? +el.value : el.value;
    if (k === 'desktop' && el.checked && 'Notification' in window && Notification.permission !== 'granted') {
      const p = await Notification.requestPermission(); if (p !== 'granted') { cfg.desktop = false; el.checked = false; }
      notifState();
    }
    if (k === 'sound' && el.checked) beep();
    save(); applyTheme(); render(false, true);
  });
});
$('#testSound').onclick = () => { beep(); toast('🔔 Так выглядит уведомление', 'Нажмите на него, чтобы перейти к запросам', 'var(--accent)'); };
$('#settingsBtn').onclick = () => $('#drawer').classList.toggle('open');
$('#drawerClose').onclick = () => $('#drawer').classList.remove('open');

// ───── Старт ─────
$('#noStatic').checked = cfg.noStatic; $('#groupBy').value = cfg.groupBy; $('#interval').value = cfg.interval; $('#period').value = cfg.period;
applyTheme(); notifState();
new ResizeObserver(() => document.documentElement.style.setProperty('--hdr', $('#hdr').offsetHeight + 'px')).observe($('#hdr'));
setInterval(() => { if (!st.paused) render(false, true); }, 30000);
poll(); loadDiag(); loadBans().then(() => render(false, true));
setInterval(() => loadBans().then(() => { if (st.tab === 'block') render(false, true); }), 60000);
loadAutoban(); setInterval(() => loadAutoban().then(() => { if (st.tab === 'autoban') render(false, true); }), 30000);
document.addEventListener('change', async ev => {
  if (ev.target.id === 'abFilter') { st.abFilter = ev.target.value; render(false, true); }
  if (ev.target.dataset.abrule) { await abPost('autoban_set', {rule: ev.target.dataset.abrule, on: ev.target.checked ? '1' : '0'}); await loadAutoban(); render(false, true); }
});
document.addEventListener('input', ev => { if (ev.target.id === 'fwq') { st.fwq = ev.target.value; const pos = ev.target.selectionStart; render(false, true); const el = $('#fwq'); if (el) { el.focus(); el.setSelectionRange(pos, pos); } } });
</script>
</body>
</html>
