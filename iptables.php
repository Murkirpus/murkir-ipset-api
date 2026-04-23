<?php
/**
 * iptables.php - Управление блокировкой IP/CIDR через ipset
 * Версия: 3.3 (CIDR support)
 *
 * Блокирует весь трафик от IP или подсети CIDR на уровне INPUT.
 * Сеты используют hash:net — поддерживают как одиночные IP, так и CIDR.
 * Авто-разбан через timeout (дефолт 1 час).
 * После reboot сеты пересоздаются при первом запросе.
 *
 * Настройка sudoers (/etc/sudoers.d/iptables-api):
 *   www-data ALL=(root) NOPASSWD: /usr/sbin/ipset, /sbin/iptables, /sbin/ip6tables
 *
 * Веб-интерфейс: /iptables.php?api_key=ВАШ_КЛЮЧ
 *
 * API (добавить &api=1 для JSON-ответа):
 *   block   - ?action=block&ip=IP_ИЛИ_CIDR&api_key=KEY[&timeout=СЕК]&api=1
 *   unblock - ?action=unblock&ip=IP_ИЛИ_CIDR&api_key=KEY&api=1
 *   list    - ?action=list&api_key=KEY&api=1      (IPv4: одиночные IP + CIDR)
 *   list6   - ?action=list6&api_key=KEY&api=1     (IPv6: одиночные IP + CIDR)
 *   clear   - ?action=clear&api_key=KEY&api=1
 *   debug   - ?action=debug&api_key=KEY&api=1
 *   diag    - ?action=diag&api_key=KEY&api=1
 *   init    - ?action=init&api_key=KEY&api=1
 *
 * Примеры:
 *   ?action=block&ip=192.168.1.10
 *   ?action=block&ip=192.168.0.0/24
 *   ?action=block&ip=2001:db8::/32
 *   ?action=unblock&ip=192.168.0.0/24
 *
 * Готовые URL с твоим ключом — см. вкладку «Блокировка» → «📡 Примеры API-запросов».
 */

error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
require_once 'settings.php';

// --- Константы (могут быть переопределены в settings.php) ---
if (!defined('IPSET_V4'))      define('IPSET_V4',      'banlist4');
if (!defined('IPSET_V6'))      define('IPSET_V6',      'banlist6');
if (!defined('BAN_TIMEOUT'))   define('BAN_TIMEOUT',   3600);
if (!defined('IPSET_MAXELEM')) define('IPSET_MAXELEM', 1000000);

$API_KEY  = defined('API_BLOCK_KEY') ? API_BLOCK_KEY : 'default-key';
$api_mode = isset($_REQUEST['api']) && $_REQUEST['api'] == 1;

// --- Проверка доступа ---
$req_key = isset($_REQUEST['api_key']) ? $_REQUEST['api_key'] : '';
if (!hash_equals((string)$API_KEY, (string)$req_key)) {
    header("HTTP/1.1 403 Forbidden");
    if ($api_mode) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array('status' => 'error', 'message' => 'Forbidden'));
    } else {
        echo "Доступ запрещен. Требуется авторизация.";
    }
    exit;
}

// --- Утилиты ---

function getUserIP() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        if (strpos($ip, ',') !== false) $ip = trim(explode(',', $ip)[0]);
        return $ip;
    }
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) return $_SERVER['HTTP_CLIENT_IP'];
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
}

function ipVersion($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 4;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 6;
    return 0;
}

/**
 * Разбирает IP или CIDR. Возвращает массив или false.
 *   ip      — сам адрес (без маски)
 *   mask    — длина префикса (для /N), или полная ширина для одиночного IP (32/128)
 *   version — 4 или 6
 *   is_cidr — true, если во входе была маска
 *   raw     — нормализованная строка для передачи в ipset
 */
function parseIpOrCidr($input) {
    $input = trim((string)$input);
    if ($input === '') return false;

    $is_cidr = false;
    if (strpos($input, '/') !== false) {
        $parts = explode('/', $input, 2);
        if (count($parts) !== 2) return false;
        $ip   = $parts[0];
        $mask = $parts[1];
        if ($mask === '' || !ctype_digit($mask)) return false;
        $mask = (int)$mask;
        $is_cidr = true;
    } else {
        $ip = $input;
        $mask = null;
    }

    $v = ipVersion($ip);
    if (!$v) return false;

    $max_bits = ($v === 4) ? 32 : 128;
    if ($mask === null) $mask = $max_bits;
    if ($mask < 0 || $mask > $max_bits) return false;

    return array(
        'ip'      => $ip,
        'mask'    => $mask,
        'version' => $v,
        'is_cidr' => $is_cidr,
        'raw'     => $is_cidr ? ($ip . '/' . $mask) : $ip,
    );
}

/**
 * Проверяет, пересекаются ли два CIDR/IP (одна из сторон содержит другую).
 * Каждый вход — "IP" или "IP/mask". Только в пределах одной IP-версии.
 */
function cidrsOverlap($a, $b) {
    $pa = parseIpOrCidr($a);
    $pb = parseIpOrCidr($b);
    if (!$pa || !$pb) return false;
    if ($pa['version'] !== $pb['version']) return false;

    $bin_a = @inet_pton($pa['ip']);
    $bin_b = @inet_pton($pb['ip']);
    if ($bin_a === false || $bin_b === false) return false;

    $min_mask = min($pa['mask'], $pb['mask']);
    $full_bytes = (int)($min_mask / 8);
    $remainder  = $min_mask % 8;
    $mask_bin = str_repeat("\xff", $full_bytes);
    if ($remainder > 0) $mask_bin .= chr(0xff << (8 - $remainder) & 0xff);
    $mask_bin = str_pad($mask_bin, strlen($bin_a), "\x00");

    return ($bin_a & $mask_bin) === ($bin_b & $mask_bin);
}

/**
 * Проверяет, входит ли IP в подсеть CIDR.
 * Поддерживает IPv4 и IPv6. Возвращает true/false.
 */
function ipInCidr($ip, $cidr) {
    // Одиночный IP без маски — прямое сравнение
    if (strpos($cidr, '/') === false) {
        // Нормализуем IPv6 к бинарному виду для корректного сравнения
        $a = @inet_pton($ip);
        $b = @inet_pton($cidr);
        return ($a !== false && $b !== false && $a === $b);
    }

    list($subnet, $mask) = explode('/', $cidr, 2);
    $mask = (int)$mask;

    $ip_bin     = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    if ($ip_bin === false || $subnet_bin === false) return false;

    // Длины должны совпадать (обе IPv4 = 4 байта, обе IPv6 = 16 байт)
    if (strlen($ip_bin) !== strlen($subnet_bin)) return false;

    $max_bits = strlen($ip_bin) * 8;
    if ($mask < 0 || $mask > $max_bits) return false;

    // Собираем бинарную маску
    $full_bytes = (int)($mask / 8);
    $remainder  = $mask % 8;
    $mask_bin   = str_repeat("\xff", $full_bytes);
    if ($remainder > 0) {
        $mask_bin .= chr(0xff << (8 - $remainder) & 0xff);
    }
    $mask_bin = str_pad($mask_bin, strlen($ip_bin), "\x00");

    return ($ip_bin & $mask_bin) === ($subnet_bin & $mask_bin);
}

/**
 * Проверяет, пересекается ли IP/CIDR с whitelist из settings.php.
 * Для одиночного IP — обычное "IP ∈ CIDR" из whitelist.
 * Для CIDR — пересечение в любую сторону (чтобы нельзя было заблокировать
 * 0.0.0.0/0 и похоронить всех whitelisted).
 * Loopback (127.0.0.0/8 и ::1) всегда в whitelist.
 */
function isWhitelisted($target) {
    global $IP_WHITELIST;

    // Дефолтный whitelist — loopback всегда защищён
    $defaults = array('127.0.0.0/8', '::1');

    $list = is_array($IP_WHITELIST) ? array_merge($defaults, $IP_WHITELIST) : $defaults;

    foreach ($list as $entry) {
        $entry = trim($entry);
        if ($entry === '') continue;
        if (cidrsOverlap($target, $entry)) return $entry;
    }
    return false;
}

function formatDuration($s) {
    $s = (int)$s;
    if ($s <= 0) return '—';
    $h = (int)($s / 3600);
    $m = (int)(($s % 3600) / 60);
    $sec = $s % 60;
    $p = array();
    if ($h)              $p[] = $h . ' ч';
    if ($m)              $p[] = $m . ' мин';
    if ($sec && !$h)     $p[] = $sec . ' сек';
    return implode(' ', $p);
}

/**
 * Возвращает тип существующего сета ('hash:ip', 'hash:net', ...) или null.
 */
function getSetType($setName) {
    exec("sudo ipset list " . escapeshellarg($setName) . " -t 2>/dev/null", $out, $rc);
    if ($rc !== 0) return null;
    foreach ($out as $line) {
        if (preg_match('/^Type:\s*(\S+)/i', trim($line), $m)) {
            return strtolower($m[1]);
        }
    }
    return null;
}

function ensureSetsReady() {
    static $ready = false;
    if ($ready) return;

    exec("sudo ipset list " . IPSET_V4 . " -name 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:net timeout %d maxelem %d 2>&1",
            IPSET_V4, BAN_TIMEOUT, IPSET_MAXELEM));
    }

    exec("sudo ipset list " . IPSET_V6 . " -name 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:net family inet6 timeout %d maxelem %d 2>&1",
            IPSET_V6, BAN_TIMEOUT, IPSET_MAXELEM));
    }

    exec("sudo iptables -C INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) exec("sudo iptables -I INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>&1");

    exec("sudo ip6tables -C INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) exec("sudo ip6tables -I INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>&1");

    $ready = true;
}

// --- Операции ---

function blockIP($input, $timeout = 0) {
    $p = parseIpOrCidr($input);
    if (!$p) return array('status' => 'error', 'message' => "Неверный формат IP/CIDR: $input");

    $label = $p['raw'];

    // Защита от самострела — whitelist из settings.php
    $matched = isWhitelisted($label);
    if ($matched !== false) {
        return array(
            'status'  => 'warning',
            'message' => "$label пересекается с белым списком — блокировка отклонена",
            'details' => "Совпадение с правилом: $matched",
        );
    }

    $timeout = ($timeout > 0) ? (int)$timeout : BAN_TIMEOUT;
    ensureSetsReady();

    $set = ($p['version'] === 4) ? IPSET_V4 : IPSET_V6;

    // Проверка: если сет существующего типа hash:ip — CIDR не поддержится
    if ($p['is_cidr']) {
        $type = getSetType($set);
        if ($type !== null && $type !== 'hash:net') {
            return array(
                'status'  => 'error',
                'message' => "Сет $set имеет тип $type и не поддерживает CIDR",
                'details' => 'Откройте вкладку "Диагностика" и нажмите «Инициализировать» для миграции на hash:net',
            );
        }
    }

    $cmd = sprintf("sudo ipset add %s %s timeout %d -exist 2>&1",
        $set, escapeshellarg($label), $timeout);

    exec($cmd, $out, $rc);

    if ($rc !== 0) {
        return array('status' => 'error', 'message' => "Ошибка блокировки: $label", 'details' => implode("\n", $out));
    }

    $kind = $p['is_cidr'] ? 'CIDR' : 'IP';
    return array(
        'status'  => 'success',
        'message' => "$kind $label заблокирован на " . formatDuration($timeout),
        'details' => "Set: $set, timeout: $timeout сек",
    );
}

function unblockIP($input) {
    $p = parseIpOrCidr($input);
    if (!$p) return array('status' => 'error', 'message' => "Неверный формат IP/CIDR: $input");

    $label = $p['raw'];

    ensureSetsReady();

    $set = ($p['version'] === 4) ? IPSET_V4 : IPSET_V6;
    $cmd = sprintf("sudo ipset del %s %s 2>&1", $set, escapeshellarg($label));

    exec($cmd, $out, $rc);

    if ($rc !== 0) {
        return array('status' => 'warning', 'message' => "$label не найден в списке или уже разблокирован");
    }

    return array('status' => 'success', 'message' => "$label успешно разблокирован", 'details' => "Удалён из $set");
}

function listBlockedIPs($version) {
    ensureSetsReady();
    $set = ($version === 6) ? IPSET_V6 : IPSET_V4;

    exec("sudo ipset list " . $set . " 2>/dev/null", $out, $rc);

    $ips = array();
    $details = array();

    if ($rc === 0) {
        $inMembers = false;
        foreach ($out as $line) {
            if (!$inMembers) {
                if (strpos($line, 'Members:') === 0) $inMembers = true;
                continue;
            }
            $line = trim($line);
            if ($line === '') continue;

            if (preg_match('/^(\S+)(?:\s+timeout\s+(\d+))?/', $line, $m)) {
                $ip = $m[1];
                $remaining = isset($m[2]) ? (int)$m[2] : 0;
                $ips[] = $ip;
                $details[] = array(
                    'ip'              => $ip,
                    'ports'           => array('all'),
                    'remaining'       => $remaining,
                    'remaining_human' => formatDuration($remaining),
                );
            }
        }
    }

    return array(
        'status'          => 'success',
        'version'         => ($version === 6) ? 'IPv6' : 'IPv4',
        'set'             => $set,
        'count'           => count($ips),
        'blocked_ips'     => $ips,
        'blocked_details' => $details,
    );
}

function clearAllRules() {
    ensureSetsReady();
    $results = array();
    $ok = true;

    exec("sudo ipset flush " . IPSET_V4 . " 2>&1", $o4, $c4);
    $results[] = ($c4 === 0) ? IPSET_V4 . ' очищен' : 'Ошибка ' . IPSET_V4;
    if ($c4 !== 0) $ok = false;

    exec("sudo ipset flush " . IPSET_V6 . " 2>&1", $o6, $c6);
    $results[] = ($c6 === 0) ? IPSET_V6 . ' очищен' : 'Ошибка ' . IPSET_V6;
    if ($c6 !== 0) $ok = false;

    return array(
        'status'  => $ok ? 'success' : 'warning',
        'message' => $ok ? 'Все баны сняты' : 'Частичная очистка',
        'details' => implode(', ', $results),
    );
}

function getDebugInfo() {
    ensureSetsReady();
    $d = array();

    exec("sudo ipset list " . IPSET_V4 . " 2>&1", $o);  $d['ipset_' . IPSET_V4] = implode("\n", $o);
    exec("sudo ipset list " . IPSET_V6 . " 2>&1", $o);  $d['ipset_' . IPSET_V6] = implode("\n", $o);
    exec("sudo iptables -L INPUT -n -v 2>&1", $o);      $d['iptables_ipv4']     = implode("\n", $o);
    exec("sudo ip6tables -L INPUT -n -v 2>&1", $o);     $d['iptables_ipv6']     = implode("\n", $o);

    $d['default_timeout'] = BAN_TIMEOUT;
    $d['blocked_ipv4']    = listBlockedIPs(4);
    $d['blocked_ipv6']    = listBlockedIPs(6);

    return array('status' => 'success', 'debug_info' => $d);
}

/**
 * Диагностика окружения. Возвращает массив проверок со статусами:
 *   'ok'    — всё в порядке
 *   'warn'  — работает, но могут быть проблемы
 *   'fail'  — критично, API не работает
 */
function runDiagnostics() {
    $checks = array();

    // --- 1. PHP и функции ---
    $checks[] = array(
        'name'   => 'Версия PHP',
        'status' => version_compare(PHP_VERSION, '5.6.0', '>=') ? 'ok' : 'fail',
        'value'  => PHP_VERSION,
        'hint'   => 'Требуется PHP 5.6 или новее',
    );

    // exec()
    $exec_disabled = false;
    $disabled = explode(',', str_replace(' ', '', (string)ini_get('disable_functions')));
    if (in_array('exec', $disabled, true) || !function_exists('exec')) {
        $exec_disabled = true;
    }
    $checks[] = array(
        'name'   => 'Функция exec()',
        'status' => $exec_disabled ? 'fail' : 'ok',
        'value'  => $exec_disabled ? 'ОТКЛЮЧЕНА' : 'доступна',
        'hint'   => $exec_disabled
            ? 'Удали "exec" из disable_functions в php.ini. Без exec() скрипт работать не может.'
            : '',
    );

    // escapeshellarg
    $checks[] = array(
        'name'   => 'Функция escapeshellarg()',
        'status' => function_exists('escapeshellarg') ? 'ok' : 'fail',
        'value'  => function_exists('escapeshellarg') ? 'доступна' : 'отсутствует',
        'hint'   => 'Нужна для защиты от shell-injection',
    );

    // filter_var
    $checks[] = array(
        'name'   => 'Функция filter_var()',
        'status' => function_exists('filter_var') ? 'ok' : 'fail',
        'value'  => function_exists('filter_var') ? 'доступна' : 'отсутствует',
        'hint'   => 'Установи пакет php-filter',
    );

    // hash_equals
    $checks[] = array(
        'name'   => 'Функция hash_equals()',
        'status' => function_exists('hash_equals') ? 'ok' : 'warn',
        'value'  => function_exists('hash_equals') ? 'доступна' : 'отсутствует',
        'hint'   => function_exists('hash_equals') ? '' : 'Без hash_equals сравнение API-ключа уязвимо к timing-атакам',
    );

    // Если exec нет — дальше не проверяем, бесполезно
    if ($exec_disabled) {
        return array('status' => 'fail', 'checks' => $checks);
    }

    // Вспомогательная функция поиска бинарника без shell_exec
    // (shell_exec часто отключен в disable_functions на production-серверах)
    $find_binary = function($name) {
        // 1. Пробуем через exec + command -v
        $out = array(); $rc = 0;
        @exec("command -v " . escapeshellarg($name) . " 2>/dev/null", $out, $rc);
        if ($rc === 0 && !empty($out[0])) {
            return trim($out[0]);
        }
        // 2. Фоллбек: проверяем стандартные пути
        foreach (array('/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin', '/usr/local/bin') as $dir) {
            if (is_executable("$dir/$name")) return "$dir/$name";
        }
        return '';
    };

    // --- 2. Бинарники в системе ---
    $bins = array('sudo', 'ipset', 'iptables', 'ip6tables');
    foreach ($bins as $bin) {
        $path = $find_binary($bin);
        $hint = '';
        if (!$path) {
            if ($bin === 'ipset') {
                $hint = 'sudo apt install ipset   (или: yum install ipset)';
            } elseif ($bin === 'sudo') {
                $hint = 'sudo не установлен. Переустанови coreutils/sudo пакет.';
            } else {
                $hint = "sudo apt install $bin";
            }
        }
        $checks[] = array(
            'name'   => "Бинарник $bin",
            'status' => $path ? 'ok' : 'fail',
            'value'  => $path ? $path : 'не найден',
            'hint'   => $hint,
        );
    }

    // --- 3. Модуль ядра xt_set ---
    $xt_loaded = false;
    if (is_readable('/proc/modules')) {
        $modules = @file_get_contents('/proc/modules');
        if ($modules && (strpos($modules, 'xt_set') !== false || strpos($modules, 'ip_set') !== false)) {
            $xt_loaded = true;
        }
    }
    // Альтернативный способ: modinfo
    if (!$xt_loaded) {
        $out = array();
        exec('lsmod 2>/dev/null | grep -E "^(xt_set|ip_set)" 2>/dev/null', $out);
        if (!empty($out)) $xt_loaded = true;
    }
    $checks[] = array(
        'name'   => 'Модуль ядра xt_set',
        'status' => $xt_loaded ? 'ok' : 'warn',
        'value'  => $xt_loaded ? 'загружен' : 'не обнаружен (или /proc/modules недоступен)',
        'hint'   => $xt_loaded ? '' : 'Загрузится автоматически при первом использовании ipset. Принудительно: sudo modprobe xt_set',
    );

    // --- 4. Проверка sudoers (sudo без пароля) ---
    // sudo -n = non-interactive, не запрашивать пароль. Код возврата 0 = можно выполнять.
    $sudo_path = $find_binary('sudo');

    if (!$sudo_path) {
        // Если sudo не установлен — пропускаем sudoers-проверки
        $checks[] = array(
            'name'   => 'sudoers',
            'status' => 'fail',
            'value'  => 'пропущено (sudo не установлен)',
            'hint'   => 'Сначала установи sudo',
        );
    } else {
        // Определяем реального пользователя PHP (для шаблона sudoers)
        $real_user = 'www-data';
        if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            $info = @posix_getpwuid(posix_geteuid());
            if ($info) $real_user = $info['name'];
        } elseif (function_exists('get_current_user')) {
            $u = get_current_user();
            if ($u) $real_user = $u;
        }

        $sudo_tests = array(
            array('cmd' => 'sudo -n ipset list -name 2>&1',      'name' => 'sudoers: ipset'),
            array('cmd' => 'sudo -n iptables -L INPUT -n 2>&1',  'name' => 'sudoers: iptables'),
            array('cmd' => 'sudo -n ip6tables -L INPUT -n 2>&1', 'name' => 'sudoers: ip6tables'),
        );
        $sudoers_hint = "Создай /etc/sudoers.d/iptables-api:\n" .
            "  Cmnd_Alias IPSET_CMDS = /usr/sbin/ipset, /sbin/ipset, /bin/ipset\n" .
            "  Cmnd_Alias IPT4_CMDS  = /sbin/iptables, /usr/sbin/iptables\n" .
            "  Cmnd_Alias IPT6_CMDS  = /sbin/ip6tables, /usr/sbin/ip6tables\n" .
            "  " . $real_user . " ALL=(root) NOPASSWD: IPSET_CMDS, IPT4_CMDS, IPT6_CMDS\n" .
            "Затем: sudo chmod 440 /etc/sudoers.d/iptables-api && sudo visudo -cf /etc/sudoers.d/iptables-api";

        foreach ($sudo_tests as $t) {
            $out = array(); $rc = 0;
            exec($t['cmd'], $out, $rc);
            $outStr = implode(' ', $out);
            // Удаляем control chars, которые ломают JSON
            $outStr = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f]/', '', $outStr);

            $status = 'ok';
            $value  = 'работает';
            $hint   = '';

            if ($rc !== 0) {
                $status = 'fail';
                if (stripos($outStr, 'password is required') !== false ||
                    stripos($outStr, 'a password is required') !== false ||
                    stripos($outStr, 'askpass') !== false) {
                    $value = 'требует пароль';
                    $hint  = 'sudoers не настроен для NOPASSWD. ' . $sudoers_hint;
                } elseif (stripos($outStr, 'not allowed') !== false ||
                          stripos($outStr, 'not in the sudoers') !== false) {
                    $value = 'не разрешено';
                    $hint  = 'Пользователь ' . $real_user . ' не в sudoers. ' . $sudoers_hint;
                } elseif (stripos($outStr, 'command not found') !== false ||
                          stripos($outStr, 'not found') !== false) {
                    $value = 'команда не найдена';
                    $hint  = 'Бинарник отсутствует. Проверь предыдущие шаги.';
                } else {
                    $value = 'ошибка (rc=' . $rc . ')';
                    $hint  = (trim($outStr) ? 'Вывод: ' . trim($outStr) . "\n" : '') . $sudoers_hint;
                }
            }
            $checks[] = array(
                'name'   => $t['name'],
                'status' => $status,
                'value'  => $value,
                'hint'   => $hint,
            );
        }
    }

    // --- 5. Текущий пользователь PHP ---
    $user = 'unknown';
    if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
        $info = @posix_getpwuid(posix_geteuid());
        if ($info) $user = $info['name'];
    }
    if ($user === 'unknown') $user = get_current_user() ?: 'unknown';
    $checks[] = array(
        'name'   => 'Пользователь PHP',
        'status' => 'ok',
        'value'  => $user,
        'hint'   => 'Именно этот пользователь должен быть в /etc/sudoers.d/iptables-api',
    );

    // --- 6. Состояние сетов ipset ---
    $check_set = function($setName) {
        $type = getSetType($setName);
        if ($type === null) {
            return array(
                'status' => 'warn',
                'value'  => 'не создан',
                'hint'   => 'Будет создан автоматически при первой блокировке',
            );
        }
        if ($type !== 'hash:net') {
            return array(
                'status' => 'warn',
                'value'  => 'тип ' . $type . ' (без поддержки CIDR)',
                'hint'   => 'Нажмите «Инициализировать» — сет будет пересоздан как hash:net. Все текущие баны в нём сбросятся.',
            );
        }
        return array(
            'status' => 'ok',
            'value'  => 'существует (hash:net)',
            'hint'   => '',
        );
    };

    $r4 = $check_set(IPSET_V4);
    $checks[] = array('name' => 'ipset: ' . IPSET_V4) + $r4;

    $r6 = $check_set(IPSET_V6);
    $checks[] = array('name' => 'ipset: ' . IPSET_V6) + $r6;

    // --- 7. Правила INPUT ---
    exec("sudo -n iptables -C INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>/dev/null", $o, $rci4);
    $checks[] = array(
        'name'   => 'Правило iptables INPUT',
        'status' => ($rci4 === 0) ? 'ok' : 'warn',
        'value'  => ($rci4 === 0) ? 'установлено' : 'отсутствует',
        'hint'   => ($rci4 === 0) ? '' : 'Будет создано автоматически при первой блокировке',
    );

    exec("sudo -n ip6tables -C INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>/dev/null", $o, $rci6);
    $checks[] = array(
        'name'   => 'Правило ip6tables INPUT',
        'status' => ($rci6 === 0) ? 'ok' : 'warn',
        'value'  => ($rci6 === 0) ? 'установлено' : 'отсутствует',
        'hint'   => ($rci6 === 0) ? '' : 'Будет создано автоматически при первой блокировке',
    );

    // --- 7.5. Whitelist ---
    global $IP_WHITELIST;
    $wl_user = is_array($IP_WHITELIST) ? count($IP_WHITELIST) : 0;
    $wl_total = $wl_user + 2; // +loopback v4 и v6
    $wl_invalid = array();
    if (is_array($IP_WHITELIST)) {
        foreach ($IP_WHITELIST as $entry) {
            $entry = trim($entry);
            if ($entry === '') continue;
            if (!parseIpOrCidr($entry)) $wl_invalid[] = $entry;
        }
    }
    $checks[] = array(
        'name'   => 'Белый список (whitelist)',
        'status' => empty($wl_invalid) ? 'ok' : 'warn',
        'value'  => "$wl_total записей (" . $wl_user . " из settings.php + 2 loopback)",
        'hint'   => empty($wl_invalid)
            ? 'IP из белого списка не будут блокироваться. Редактируется в settings.php (массив $IP_WHITELIST)'
            : 'Некорректные записи: ' . implode(', ', $wl_invalid) . '. Проверь формат в settings.php',
    );

    // --- 8. Права на запись в /tmp (для логов PHP) ---
    $tmp_writable = is_writable(sys_get_temp_dir());
    $checks[] = array(
        'name'   => 'Запись в ' . sys_get_temp_dir(),
        'status' => $tmp_writable ? 'ok' : 'warn',
        'value'  => $tmp_writable ? 'доступна' : 'запрещена',
        'hint'   => $tmp_writable ? '' : 'Может не работать логирование ошибок PHP',
    );

    // --- Итоговый статус ---
    $has_fail = false;
    $has_warn = false;
    foreach ($checks as $c) {
        if ($c['status'] === 'fail') $has_fail = true;
        if ($c['status'] === 'warn') $has_warn = true;
    }

    $overall = 'ok';
    if ($has_fail)      $overall = 'fail';
    elseif ($has_warn)  $overall = 'warn';

    // Есть ли незавершённая инициализация (можно запустить init)?
    $can_init = !$has_fail && $has_warn;

    return array(
        'status'   => $overall,
        'can_init' => $can_init,
        'summary'  => ($overall === 'ok')
            ? 'Все проверки пройдены. Система готова к работе.'
            : (($overall === 'warn')
                ? 'Есть предупреждения. Нажми «Инициализировать» чтобы создать сеты и правила.'
                : 'Критические ошибки — API работать не будет. Смотри подсказки ниже.'),
        'checks'   => $checks,
    );
}

/**
 * Принудительная инициализация: создаёт сеты и правила сейчас,
 * а не лениво при первом запросе. Возвращает подробный лог.
 * Если существующий сет имеет тип hash:ip — пересоздаёт его как hash:net
 * (для поддержки CIDR). Все текущие баны в этом сете сбрасываются.
 */
function initSystem() {
    $log = array();
    $success = true;

    $ensure_hashnet = function($setName, $family, &$log, &$success) {
        $current = getSetType($setName);
        if ($current === null) {
            // Не существует — создаём
            $family_flag = ($family === 6) ? ' family inet6' : '';
            exec(sprintf("sudo ipset create %s hash:net%s timeout %d maxelem %d 2>&1",
                $setName, $family_flag, BAN_TIMEOUT, IPSET_MAXELEM), $o2, $rc2);
            if ($rc2 === 0) {
                $log[] = '✅ Создан сет ' . $setName . ' (hash:net)';
            } else {
                $log[] = '❌ Не удалось создать ' . $setName . ': ' . implode(' ', $o2);
                $success = false;
            }
            return;
        }

        if ($current === 'hash:net') {
            $log[] = '✓ ' . $setName . ' уже существует (hash:net)';
            return;
        }

        // Миграция: старый тип → hash:net. Снимаем правило, удаляем сет, создаём заново.
        $ipt = ($family === 6) ? 'ip6tables' : 'iptables';
        exec("sudo $ipt -D INPUT -m set --match-set $setName src -j DROP 2>&1");

        exec("sudo ipset destroy " . escapeshellarg($setName) . " 2>&1", $o_del, $rc_del);
        if ($rc_del !== 0) {
            $log[] = '❌ Не удалось уничтожить старый ' . $setName . ' (' . $current . '): ' . implode(' ', $o_del);
            $success = false;
            return;
        }

        $family_flag = ($family === 6) ? ' family inet6' : '';
        exec(sprintf("sudo ipset create %s hash:net%s timeout %d maxelem %d 2>&1",
            $setName, $family_flag, BAN_TIMEOUT, IPSET_MAXELEM), $o2, $rc2);
        if ($rc2 === 0) {
            $log[] = '⚡ Миграция: ' . $setName . ' пересоздан как hash:net (прошлые баны сброшены)';
        } else {
            $log[] = '❌ Не удалось создать новый ' . $setName . ': ' . implode(' ', $o2);
            $success = false;
        }
    };

    $ensure_hashnet(IPSET_V4, 4, $log, $success);
    $ensure_hashnet(IPSET_V6, 6, $log, $success);

    // iptables правило
    exec("sudo iptables -C INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec("sudo iptables -I INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>&1", $o2, $rc2);
        if ($rc2 === 0) {
            $log[] = '✅ Создано правило iptables INPUT';
        } else {
            $log[] = '❌ Не удалось создать правило iptables: ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ Правило iptables INPUT уже существует';
    }

    // ip6tables правило
    exec("sudo ip6tables -C INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec("sudo ip6tables -I INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>&1", $o2, $rc2);
        if ($rc2 === 0) {
            $log[] = '✅ Создано правило ip6tables INPUT';
        } else {
            $log[] = '❌ Не удалось создать правило ip6tables: ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ Правило ip6tables INPUT уже существует';
    }

    return array(
        'status'  => $success ? 'success' : 'error',
        'message' => $success ? 'Инициализация завершена' : 'Инициализация с ошибками',
        'details' => implode("\n", $log),
    );
}

// --- Роутинг ---

$action  = isset($_REQUEST['action'])  ? $_REQUEST['action']  : '';
$ip      = isset($_REQUEST['ip'])      ? $_REQUEST['ip']      : '';
$timeout = isset($_REQUEST['timeout']) ? (int)$_REQUEST['timeout'] : 0;
$result  = array();

switch ($action) {
    case 'block':   $result = $ip ? blockIP($ip, $timeout) : array('status' => 'error', 'message' => 'IP не указан'); break;
    case 'unblock': $result = $ip ? unblockIP($ip)         : array('status' => 'error', 'message' => 'IP не указан'); break;
    case 'list':    $result = listBlockedIPs(4); break;
    case 'list6':   $result = listBlockedIPs(6); break;
    case 'clear':   $result = clearAllRules();   break;
    case 'debug':   $result = getDebugInfo();    break;
    case 'diag':    $result = runDiagnostics();  break;
    case 'init':    $result = initSystem();      break;
}

// --- API-режим: JSON и выход ---
if ($api_mode) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// --- HTML UI ---
header('Cache-Control: no-store');
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Управление блокировкой IP (ipset)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white; border-radius: 12px; padding: 30px;
            margin-bottom: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        .header h1 { color: #333; font-size: 32px; margin-bottom: 10px; }
        .header p  { color: #666; font-size: 16px; }
        .info-box {
            background: #e3f2fd; border-left: 4px solid #2196f3;
            padding: 15px; margin: 20px 0; border-radius: 4px;
        }
        .info-box strong { color: #1976d2; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab {
            background: rgba(255,255,255,0.9); border: none; padding: 15px 30px;
            border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 500;
            color: #666; transition: all 0.3s ease;
        }
        .tab:hover { background: white; transform: translateY(-2px); }
        .tab.active { background: white; color: #667eea; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .tab-content {
            display: none; background: white; border-radius: 12px;
            padding: 30px; box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        .tab-content.active { display: block; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
        .form-group input {
            width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0;
            border-radius: 8px; font-size: 16px;
        }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .btn {
            padding: 12px 30px; border: none; border-radius: 8px;
            font-size: 16px; font-weight: 500; cursor: pointer; transition: all 0.3s ease;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; transform: translateY(-2px); }
        .btn-danger  { background: #f44336; color: white; }
        .btn-danger:hover { background: #d32f2f; transform: translateY(-2px); }
        .btn-warning { background: #ff9800; color: white; }
        .btn-warning:hover { background: #f57c00; transform: translateY(-2px); }
        .alert { padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; }
        .alert-success { background: #e8f5e9; color: #2e7d32; border-left: 4px solid #4caf50; }
        .alert-error   { background: #ffebee; color: #c62828; border-left: 4px solid #f44336; }
        .alert-info    { background: #e3f2fd; color: #1565c0; border-left: 4px solid #2196f3; }
        .alert-warning { background: #fff3e0; color: #e65100; border-left: 4px solid #ff9800; }
        .ip-item {
            display: flex; justify-content: space-between; align-items: center;
            background: #f5f5f5; padding: 15px 20px; border-radius: 8px;
            margin-bottom: 10px; flex-wrap: wrap; gap: 10px;
        }
        .ip-details { display: flex; flex-direction: column; gap: 4px; word-break: break-all; }
        .ip-address { font-weight: 600; color: #333; font-family: monospace; font-size: 15px; }
        .ip-remaining {
            display: inline-block; background: #fff3e0; color: #e65100;
            padding: 2px 8px; border-radius: 4px; font-size: 12px;
        }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 20px; border-radius: 12px; text-align: center;
        }
        .diag-item {
            display: flex; align-items: flex-start; gap: 12px;
            padding: 12px 16px; border-radius: 8px; margin-bottom: 8px;
            background: #f5f5f5; border-left: 4px solid #ccc;
        }
        .diag-item.ok   { background: #e8f5e9; border-left-color: #4caf50; }
        .diag-item.warn { background: #fff3e0; border-left-color: #ff9800; }
        .diag-item.fail { background: #ffebee; border-left-color: #f44336; }
        .diag-icon { font-size: 20px; min-width: 24px; }
        .diag-body { flex: 1; min-width: 0; }
        .diag-name { font-weight: 600; color: #333; }
        .diag-value { color: #666; font-size: 14px; margin-top: 2px; font-family: monospace; }
        .diag-hint {
            margin-top: 6px; padding: 8px 10px; background: rgba(0,0,0,0.04);
            border-radius: 4px; font-size: 13px; white-space: pre-wrap; word-break: break-word;
            color: #444; font-family: monospace;
        }
        .diag-summary {
            padding: 20px; border-radius: 12px; margin-bottom: 20px; font-size: 18px; font-weight: 500;
        }
        .diag-summary.ok   { background: #e8f5e9; color: #2e7d32; }
        .diag-summary.warn { background: #fff3e0; color: #e65100; }
        .diag-summary.fail { background: #ffebee; color: #c62828; }
        .stat-card h3 { font-size: 36px; margin-bottom: 10px; }
        .stat-card p  { font-size: 14px; opacity: 0.9; }
        .button-group { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Управление блокировкой IP / CIDR (ipset)</h1>
            <p>Поддержка одиночных IP и подсетей CIDR. Авто-разбан через <?php echo formatDuration(BAN_TIMEOUT); ?>. Сеты: <code><?php echo IPSET_V4; ?></code> / <code><?php echo IPSET_V6; ?></code> (hash:net)</p>
            <div class="info-box"><strong>Ваш IP:</strong> <span id="userIP"><?php echo htmlspecialchars(getUserIP()); ?></span></div>
        </div>

        <?php if (!empty($result)): ?>
            <?php
            $alertClass = 'alert-info';
            if ($result['status'] === 'success')       $alertClass = 'alert-success';
            elseif ($result['status'] === 'error')     $alertClass = 'alert-error';
            elseif ($result['status'] === 'warning')   $alertClass = 'alert-warning';
            ?>
            <div class="alert <?php echo $alertClass; ?>">
                <strong><?php echo htmlspecialchars($result['message']); ?></strong>
                <?php if (isset($result['details'])): ?>
                    <br><small><?php echo htmlspecialchars($result['details']); ?></small>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('block')">Блокировка</button>
            <button class="tab" onclick="switchTab('list')">Список IP</button>
            <button class="tab" onclick="switchTab('stats')">Статистика</button>
            <button class="tab" onclick="switchTab('diag')">🔍 Диагностика</button>
        </div>

        <div id="block-tab" class="tab-content active">
            <h2>Блокировка / Разблокировка IP или CIDR</h2>

            <form method="post" action="">
                <div class="form-group">
                    <label for="ip">IP-адрес или CIDR (IPv4 / IPv6)</label>
                    <input type="text" id="ip" name="ip" placeholder="192.168.1.10, 192.168.0.0/24, 2001:db8::1 или 2001:db8::/32" required>
                    <small style="display:block; margin-top:6px; color:#666;">
                        Примеры: <code>192.168.1.10</code>, <code>192.168.0.0/24</code>, <code>10.0.0.0/8</code>, <code>2001:db8::/32</code>
                    </small>
                </div>

                <div class="form-group">
                    <label for="timeout">Таймаут бана в секундах (0 = дефолт <?php echo BAN_TIMEOUT; ?>)</label>
                    <input type="number" id="timeout" name="timeout" value="0" min="0" max="31536000">
                </div>

                <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($API_KEY); ?>">

                <div class="button-group">
                    <button type="submit" name="action" value="block" class="btn btn-primary">🔒 Заблокировать</button>
                    <button type="submit" name="action" value="unblock" class="btn btn-danger">🔓 Разблокировать</button>
                </div>
            </form>

            <div style="margin-top: 30px; padding-top: 30px; border-top: 2px solid #e0e0e0;">
                <h3>Быстрые действия</h3>
                <div class="button-group">
                    <button onclick="blockCurrentIP()" class="btn btn-warning">Заблокировать мой IP</button>
                    <form method="post" action="" style="display: inline;">
                        <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($API_KEY); ?>">
                        <button type="submit" name="action" value="clear" class="btn btn-danger"
                                onclick="return confirm('Вы уверены? Это снимет ВСЕ баны!')">
                            🗑️ Снять все баны
                        </button>
                    </form>
                </div>
            </div>

            <div style="margin-top: 30px; padding-top: 30px; border-top: 2px solid #e0e0e0;">
                <h3>📡 Примеры API-запросов</h3>
                <p style="color: #666; margin-top: 8px; margin-bottom: 15px;">
                    Готовые URL с твоим реальным API-ключом. Можно копировать и вставлять в браузер, curl или скрипты.
                    Добавь <code>&amp;api=1</code> чтобы получить JSON (без — вернётся HTML со страницей).
                </p>
                <?php
                $_base = '' . basename(__FILE__);
                $_key  = urlencode($API_KEY);
                $_examples = array(
                    array(
                        'title' => '🔒 Блокировка одного IPv4 на 1 час (дефолт)',
                        'url'   => "$_base?action=block&ip=203.0.113.45&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка IPv4 на 30 минут (1800 сек)',
                        'url'   => "$_base?action=block&ip=198.51.100.23&api_key=$_key&timeout=1800&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка IPv4 на сутки (86400 сек)',
                        'url'   => "$_base?action=block&ip=192.0.2.77&api_key=$_key&timeout=86400&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка подсети IPv4 /24 (CIDR)',
                        'url'   => "$_base?action=block&ip=" . urlencode('203.0.113.0/24') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка большой подсети IPv4 /16 на 2 часа',
                        'url'   => "$_base?action=block&ip=" . urlencode('198.51.0.0/16') . "&api_key=$_key&timeout=7200&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка одного IPv6',
                        'url'   => "$_base?action=block&ip=" . urlencode('2001:db8:abcd::15') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка подсети IPv6 /64',
                        'url'   => "$_base?action=block&ip=" . urlencode('2001:db8:abcd::/64') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔒 Блокировка большой IPv6-подсети /32 на 12 часов',
                        'url'   => "$_base?action=block&ip=" . urlencode('2001:db8::/32') . "&api_key=$_key&timeout=43200&api=1",
                    ),
                    array(
                        'title' => '🔓 Разблокировка IPv4',
                        'url'   => "$_base?action=unblock&ip=203.0.113.45&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔓 Разблокировка подсети IPv4 /24',
                        'url'   => "$_base?action=unblock&ip=" . urlencode('203.0.113.0/24') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔓 Разблокировка IPv6',
                        'url'   => "$_base?action=unblock&ip=" . urlencode('2001:db8:abcd::15') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔓 Разблокировка подсети IPv6 /64',
                        'url'   => "$_base?action=unblock&ip=" . urlencode('2001:db8:abcd::/64') . "&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '📋 Список заблокированных IPv4 (одиночные + CIDR)',
                        'url'   => "$_base?action=list&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '📋 Список заблокированных IPv6 (одиночные + CIDR)',
                        'url'   => "$_base?action=list6&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🗑️ Снять ВСЕ баны (IP + CIDR, v4 + v6)',
                        'url'   => "$_base?action=clear&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🔍 Диагностика системы (PHP, бинарники, sudoers, сеты)',
                        'url'   => "$_base?action=diag&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🛠️ Отладочная информация (состояние сетов и правил)',
                        'url'   => "$_base?action=debug&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '⚡ Принудительная инициализация сетов и правил (миграция hash:ip → hash:net)',
                        'url'   => "$_base?action=init&api_key=$_key&api=1",
                    ),
                );
                ?>
                <div style="display:flex; flex-direction:column; gap:12px;">
                <?php foreach ($_examples as $ex): ?>
                    <div style="background:#f8f9fa; border:1px solid #e0e0e0; border-radius:8px; padding:12px 14px;">
                        <div style="font-weight:600; color:#333; margin-bottom:6px; font-size:14px;"><?php echo htmlspecialchars($ex['title']); ?></div>
                        <div style="display:flex; gap:8px; align-items:flex-start; flex-wrap:wrap;">
                            <code style="flex:1; min-width:200px; background:#fff; padding:8px 10px; border:1px solid #e0e0e0; border-radius:6px; font-size:12px; font-family:monospace; color:#1565c0; word-break:break-all; user-select:all;"><?php echo htmlspecialchars($ex['url']); ?></code>
                            <button type="button" class="btn btn-primary" style="padding:6px 12px; font-size:12px; white-space:nowrap;" onclick="copyExample(this, <?php echo htmlspecialchars(json_encode($ex['url']), ENT_QUOTES); ?>)">📋 Копировать</button>
                            <a href="<?php echo htmlspecialchars($ex['url']); ?>" target="_blank" class="btn btn-warning" style="padding:6px 12px; font-size:12px; white-space:nowrap; text-decoration:none; display:inline-block;">▶ Выполнить</a>
                        </div>
                    </div>
                <?php endforeach; ?>
                </div>

                <div style="margin-top:20px; padding:15px; background:#fff3e0; border-left:4px solid #ff9800; border-radius:4px; font-size:13px; color:#333;">
                    💡 <strong>Подсказка:</strong> для curl используй кавычки вокруг URL (из-за <code>&amp;</code>):<br>
                    <code style="display:block; margin-top:6px; background:#fff; padding:8px 10px; border:1px solid #e0e0e0; border-radius:6px; word-break:break-all; user-select:all;">curl "https://ваш-домен.ru/<?php echo htmlspecialchars("$_base?action=block&ip=203.0.113.45&api_key=$_key&api=1"); ?>"</code>
                </div>
            </div>
        </div>

        <div id="list-tab" class="tab-content">
            <h2>Заблокированные IP и подсети (CIDR)</h2>
            <h3>IPv4 (<span id="ipv4-count">...</span>)</h3>
            <div id="ipv4-list">Загрузка...</div>
            <h3 style="margin-top: 30px;">IPv6 (<span id="ipv6-count">...</span>)</h3>
            <div id="ipv6-list">Загрузка...</div>
            <div class="button-group">
                <button id="btn-refresh-list" onclick="refreshLists()" class="btn btn-primary">🔄 Обновить</button>
            </div>
        </div>

        <div id="stats-tab" class="tab-content">
            <h2>Статистика</h2>
            <div class="stats">
                <div class="stat-card"><h3 id="total-ipv4">0</h3><p>Заблокировано IPv4</p></div>
                <div class="stat-card"><h3 id="total-ipv6">0</h3><p>Заблокировано IPv6</p></div>
                <div class="stat-card"><h3 id="total-all">0</h3><p>Всего</p></div>
            </div>
            <div style="margin-top: 30px;">
                <button id="btn-refresh-stats" onclick="updateStats()" class="btn btn-primary">🔄 Обновить</button>
            </div>
        </div>

        <div id="diag-tab" class="tab-content">
            <h2>Диагностика системы</h2>
            <p style="color: #666; margin-bottom: 20px;">Проверка всех компонентов, необходимых для работы API</p>
            <div id="diag-summary"></div>
            <div id="diag-list">Загрузка...</div>
            <div style="margin-top: 20px;">
                <button id="btn-refresh-diag" onclick="runDiag()" class="btn btn-primary">🔄 Перепроверить</button>
            </div>
        </div>
    </div>

    <script>
        var apiKey = <?php echo json_encode($API_KEY); ?>;

        function switchTab(tabName) {
            var tabs = document.querySelectorAll('.tab');
            var contents = document.querySelectorAll('.tab-content');
            for (var i = 0; i < tabs.length; i++)    tabs[i].classList.remove('active');
            for (var i = 0; i < contents.length; i++) contents[i].classList.remove('active');
            document.querySelector('[onclick="switchTab(\'' + tabName + '\')"]').classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            if (tabName === 'list')  refreshLists();
            if (tabName === 'stats') updateStats();
            if (tabName === 'diag')  runDiag();
        }

        function escapeHtml(s) {
            if (s === null || s === undefined) return '';
            return String(s).replace(/[&<>"']/g, function(c) {
                return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
            });
        }

        function runDiag() {
            var btn = document.getElementById('btn-refresh-diag');
            if (btn) { btn.disabled = true; setTimeout(function() { btn.disabled = false; }, 1500); }

            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=diag&api=1&api_key=' + encodeURIComponent(apiKey) + '&_t=' + Date.now(), true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        var data = JSON.parse(xhr.responseText);
                        renderDiag(data);
                    } catch (e) {
                        document.getElementById('diag-list').innerHTML =
                            '<p style="color: #f44336;">Ошибка парсинга ответа: ' + escapeHtml(e.message) + '</p>';
                    }
                } else {
                    document.getElementById('diag-list').innerHTML =
                        '<p style="color: #f44336;">HTTP ' + xhr.status + '</p>';
                }
            };
            xhr.send();
        }

        function renderDiag(data) {
            var icons = {ok: '✅', warn: '⚠️', fail: '❌'};
            var summaryEl = document.getElementById('diag-summary');
            summaryEl.className = 'diag-summary ' + data.status;

            var summaryHtml = icons[data.status] + ' ' + escapeHtml(data.summary);

            // Кнопка принудительной инициализации, если можно
            if (data.can_init) {
                summaryHtml += '<div style="margin-top: 12px;">' +
                    '<button onclick="initSystem()" class="btn btn-primary" id="btn-init">⚡ Инициализировать сеты и правила</button>' +
                    '</div>';
            }
            summaryEl.innerHTML = summaryHtml;

            var html = '';
            for (var i = 0; i < data.checks.length; i++) {
                var c = data.checks[i];
                html += '<div class="diag-item ' + c.status + '">' +
                    '<div class="diag-icon">' + icons[c.status] + '</div>' +
                    '<div class="diag-body">' +
                        '<div class="diag-name">' + escapeHtml(c.name) + '</div>' +
                        '<div class="diag-value">' + escapeHtml(c.value) + '</div>' +
                        (c.hint ? '<div class="diag-hint">💡 ' + escapeHtml(c.hint) + '</div>' : '') +
                    '</div>' +
                '</div>';
            }
            document.getElementById('diag-list').innerHTML = html;
        }

        function initSystem() {
            var btn = document.getElementById('btn-init');
            if (btn) { btn.disabled = true; btn.textContent = '⏳ Инициализация...'; }

            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=init&api=1&api_key=' + encodeURIComponent(apiKey) + '&_t=' + Date.now(), true);
            xhr.onload = function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    alert((data.status === 'success' ? '✅ ' : '❌ ') + data.message + '\n\n' + data.details);
                } catch (e) {
                    alert('Ошибка: ' + xhr.responseText);
                }
                runDiag(); // Перечитываем диагностику
            };
            xhr.onerror = function() {
                alert('Сетевая ошибка');
                if (btn) { btn.disabled = false; btn.textContent = '⚡ Инициализировать сеты и правила'; }
            };
            xhr.send();
        }

        // Автоматическая фоновая проверка при загрузке — если fail, переключаемся на диагностику
        function autoHealthCheck() {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=diag&api=1&api_key=' + encodeURIComponent(apiKey) + '&_t=' + Date.now(), true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        var data = JSON.parse(xhr.responseText);
                        if (data.status === 'fail') {
                            switchTab('diag');
                        }
                    } catch (e) {}
                }
            };
            xhr.send();
        }

        function loadIPs(version, callback) {
            var action = version === 6 ? 'list6' : 'list';
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=' + action + '&api=1&api_key=' + encodeURIComponent(apiKey) + '&_t=' + Date.now(), true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        var data = JSON.parse(xhr.responseText);
                        if (typeof callback === 'function') callback(data);
                    } catch (e) { console.error('JSON error:', e); }
                }
            };
            xhr.send();
        }

        function refreshLists() {
            loadIPs(4, function(data) { renderList('ipv4', data); });
            loadIPs(6, function(data) { renderList('ipv6', data); });
        }

        function renderList(type, data) {
            var listEl  = document.getElementById(type + '-list');
            var countEl = document.getElementById(type + '-count');
            if (countEl) countEl.textContent = data.count;

            if (!data.count) {
                listEl.innerHTML = '<p style="color: #666;">Заблокированных адресов не найдено</p>';
                return;
            }

            var html = '';
            for (var i = 0; i < data.blocked_details.length; i++) {
                var info = data.blocked_details[i];
                html += '<div class="ip-item">' +
                    '<div class="ip-details">' +
                        '<span class="ip-address">' + info.ip + '</span>' +
                        '<span class="ip-remaining">⏱️ Осталось: ' + (info.remaining_human || '—') + '</span>' +
                    '</div>' +
                    '<form method="post" action="" style="display: inline;">' +
                        '<input type="hidden" name="ip" value="' + info.ip + '">' +
                        '<input type="hidden" name="api_key" value="' + apiKey + '">' +
                        '<button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 8px 16px;">Разблокировать</button>' +
                    '</form>' +
                '</div>';
            }
            listEl.innerHTML = html;
        }

        function blockCurrentIP() {
            var userIP = document.getElementById('userIP').textContent;
            if (!confirm('Заблокировать свой IP (' + userIP + ')?\nЭто приведёт к потере доступа!')) return;
            var form = document.createElement('form');
            form.method = 'post'; form.action = '';
            var fields = {ip: userIP, api_key: apiKey, action: 'block'};
            for (var k in fields) {
                var el = document.createElement('input');
                el.type = 'hidden'; el.name = k; el.value = fields[k];
                form.appendChild(el);
            }
            document.body.appendChild(form);
            form.submit();
        }

        function copyExample(btn, text) {
            var origin = window.location.origin;
            var pathname = window.location.pathname;
            // Склеиваем с полным путём, чтобы копировать абсолютный URL
            var dir = pathname.substring(0, pathname.lastIndexOf('/') + 1);
            var fullUrl = origin + dir + text;
            var done = function() {
                var old = btn.innerHTML;
                btn.innerHTML = '✓ Готово';
                btn.disabled = true;
                setTimeout(function() { btn.innerHTML = old; btn.disabled = false; }, 1500);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(fullUrl).then(done, function() {
                    fallbackCopy(fullUrl); done();
                });
            } else {
                fallbackCopy(fullUrl); done();
            }
        }

        function fallbackCopy(text) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed'; ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch(e) {}
            document.body.removeChild(ta);
        }

        function updateStats() {
            loadIPs(4, function(d) { document.getElementById('total-ipv4').textContent = d.count; updateTotal(); });
            loadIPs(6, function(d) { document.getElementById('total-ipv6').textContent = d.count; updateTotal(); });
        }

        function updateTotal() {
            var v4 = parseInt(document.getElementById('total-ipv4').textContent) || 0;
            var v6 = parseInt(document.getElementById('total-ipv6').textContent) || 0;
            document.getElementById('total-all').textContent = v4 + v6;
        }

        document.addEventListener('DOMContentLoaded', function() {
            <?php if ($action === 'unblock' || $action === 'clear'): ?>
                switchTab('list');
            <?php else: ?>
                autoHealthCheck();
            <?php endif; ?>
        });
    </script>
</body>
</html>
