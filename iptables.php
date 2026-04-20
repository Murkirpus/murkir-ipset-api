<?php
/**
 * iptables.php - Управление блокировкой IP через ipset
 * Версия: 3.2 (minimal + UI)
 *
 * Блокирует весь трафик от IP на уровне INPUT.
 * Авто-разбан через timeout (дефолт 1 час).
 * После reboot сеты пересоздаются при первом запросе.
 *
 * Настройка sudoers (/etc/sudoers.d/iptables-api):
 *   www-data ALL=(root) NOPASSWD: /usr/sbin/ipset, /sbin/iptables, /sbin/ip6tables
 *
 * Веб-интерфейс: /iptables.php?api_key=ВАШ_КЛЮЧ
 *
 * API (добавить &api=1 для JSON-ответа):
 *   block   - ?action=block&ip=IP&api_key=KEY[&timeout=СЕК]&api=1
 *   unblock - ?action=unblock&ip=IP&api_key=KEY&api=1
 *   list    - ?action=list&api_key=KEY&api=1      (IPv4)
 *   list6   - ?action=list6&api_key=KEY&api=1     (IPv6)
 *   clear   - ?action=clear&api_key=KEY&api=1
 *   debug   - ?action=debug&api_key=KEY&api=1
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
 * Проверяет, находится ли IP в whitelist из settings.php.
 * Loopback (127.0.0.0/8 и ::1) всегда в whitelist.
 */
function isWhitelisted($ip) {
    global $IP_WHITELIST;

    // Дефолтный whitelist — loopback всегда защищён
    $defaults = array('127.0.0.0/8', '::1');

    $list = is_array($IP_WHITELIST) ? array_merge($defaults, $IP_WHITELIST) : $defaults;

    foreach ($list as $entry) {
        $entry = trim($entry);
        if ($entry === '') continue;
        if (ipInCidr($ip, $entry)) return $entry;
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

function ensureSetsReady() {
    static $ready = false;
    if ($ready) return;

    exec("sudo ipset list " . IPSET_V4 . " -name 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:ip timeout %d maxelem %d 2>&1",
            IPSET_V4, BAN_TIMEOUT, IPSET_MAXELEM));
    }

    exec("sudo ipset list " . IPSET_V6 . " -name 2>/dev/null", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:ip family inet6 timeout %d maxelem %d 2>&1",
            IPSET_V6, BAN_TIMEOUT, IPSET_MAXELEM));
    }

    exec("sudo iptables -C INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) exec("sudo iptables -I INPUT -m set --match-set " . IPSET_V4 . " src -j DROP 2>&1");

    exec("sudo ip6tables -C INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>/dev/null", $o, $rc);
    if ($rc !== 0) exec("sudo ip6tables -I INPUT -m set --match-set " . IPSET_V6 . " src -j DROP 2>&1");

    $ready = true;
}

// --- Операции ---

function blockIP($ip, $timeout = 0) {
    $v = ipVersion($ip);
    if (!$v) return array('status' => 'error', 'message' => "Неверный формат IP: $ip");

    // Защита от самострела — whitelist из settings.php
    $matched = isWhitelisted($ip);
    if ($matched !== false) {
        return array(
            'status'  => 'warning',
            'message' => "IP $ip в белом списке — блокировка отклонена",
            'details' => "Совпадение с правилом: $matched",
        );
    }

    $timeout = ($timeout > 0) ? (int)$timeout : BAN_TIMEOUT;
    ensureSetsReady();

    $set = ($v === 4) ? IPSET_V4 : IPSET_V6;
    $cmd = sprintf("sudo ipset add %s %s timeout %d -exist 2>&1",
        $set, escapeshellarg($ip), $timeout);

    exec($cmd, $out, $rc);

    if ($rc !== 0) {
        return array('status' => 'error', 'message' => "Ошибка блокировки IP: $ip", 'details' => implode("\n", $out));
    }

    return array(
        'status'  => 'success',
        'message' => "IP $ip заблокирован на " . formatDuration($timeout),
        'details' => "Set: $set, timeout: $timeout сек",
    );
}

function unblockIP($ip) {
    $v = ipVersion($ip);
    if (!$v) return array('status' => 'error', 'message' => "Неверный формат IP: $ip");

    ensureSetsReady();

    $set = ($v === 4) ? IPSET_V4 : IPSET_V6;
    $cmd = sprintf("sudo ipset del %s %s 2>&1", $set, escapeshellarg($ip));

    exec($cmd, $out, $rc);

    if ($rc !== 0) {
        return array('status' => 'warning', 'message' => "IP $ip не найден в списке или уже разблокирован");
    }

    return array('status' => 'success', 'message' => "IP $ip успешно разблокирован", 'details' => "Удалён из $set");
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
    exec("sudo -n ipset list " . IPSET_V4 . " -name 2>/dev/null", $o4, $rc4);
    $checks[] = array(
        'name'   => 'ipset: ' . IPSET_V4,
        'status' => ($rc4 === 0) ? 'ok' : 'warn',
        'value'  => ($rc4 === 0) ? 'существует' : 'не создан',
        'hint'   => ($rc4 === 0) ? '' : 'Будет создан автоматически при первой блокировке IPv4',
    );

    exec("sudo -n ipset list " . IPSET_V6 . " -name 2>/dev/null", $o6, $rc6);
    $checks[] = array(
        'name'   => 'ipset: ' . IPSET_V6,
        'status' => ($rc6 === 0) ? 'ok' : 'warn',
        'value'  => ($rc6 === 0) ? 'существует' : 'не создан',
        'hint'   => ($rc6 === 0) ? '' : 'Будет создан автоматически при первой блокировке IPv6',
    );

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
            $check_ip = (strpos($entry, '/') !== false) ? explode('/', $entry)[0] : $entry;
            if (!ipVersion($check_ip)) $wl_invalid[] = $entry;
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
 */
function initSystem() {
    $log = array();
    $success = true;

    // IPv4 сет
    exec("sudo ipset list " . IPSET_V4 . " -name 2>&1", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:ip timeout %d maxelem %d 2>&1",
            IPSET_V4, BAN_TIMEOUT, IPSET_MAXELEM), $o2, $rc2);
        if ($rc2 === 0) {
            $log[] = '✅ Создан сет ' . IPSET_V4;
        } else {
            $log[] = '❌ Не удалось создать ' . IPSET_V4 . ': ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ ' . IPSET_V4 . ' уже существует';
    }

    // IPv6 сет
    exec("sudo ipset list " . IPSET_V6 . " -name 2>&1", $o, $rc);
    if ($rc !== 0) {
        exec(sprintf("sudo ipset create %s hash:ip family inet6 timeout %d maxelem %d 2>&1",
            IPSET_V6, BAN_TIMEOUT, IPSET_MAXELEM), $o2, $rc2);
        if ($rc2 === 0) {
            $log[] = '✅ Создан сет ' . IPSET_V6;
        } else {
            $log[] = '❌ Не удалось создать ' . IPSET_V6 . ': ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ ' . IPSET_V6 . ' уже существует';
    }

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
            <h1>🛡️ Управление блокировкой IP (ipset)</h1>
            <p>Авто-разбан через <?php echo formatDuration(BAN_TIMEOUT); ?>. Сеты: <code><?php echo IPSET_V4; ?></code> / <code><?php echo IPSET_V6; ?></code></p>
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
            <h2>Блокировка / Разблокировка IP</h2>

            <form method="post" action="">
                <div class="form-group">
                    <label for="ip">IP-адрес (IPv4 или IPv6)</label>
                    <input type="text" id="ip" name="ip" placeholder="192.168.1.10 или 2001:db8::1" required>
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
        </div>

        <div id="list-tab" class="tab-content">
            <h2>Заблокированные IP-адреса</h2>
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
