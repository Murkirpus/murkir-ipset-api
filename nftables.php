<?php
/**
 * nftables.php - Управление блокировкой IP через nftables (dual-stack)
 * Версия: 3.2 (minimal + UI, API-совместимо с iptables.php)
 *
 * Блокирует весь трафик от IP на уровне INPUT (семейство inet — v4+v6).
 * Авто-разбан через timeout (дефолт 1 час).
 * После reboot таблица/сеты пересоздаются при первом запросе.
 *
 * Настройка sudoers (/etc/sudoers.d/nftables-api):
 *   www-data ALL=(root) NOPASSWD: /usr/sbin/nft
 *
 * Веб-интерфейс: /nftables.php?api_key=ВАШ_КЛЮЧ
 *
 * API (добавить &api=1 для JSON-ответа):
 *   block      - ?action=block&ip=IP_или_CIDR&api_key=KEY[&timeout=СЕК]&api=1
 *   unblock    - ?action=unblock&ip=IP_или_CIDR&api_key=KEY&api=1
 *   bulk_block - ?action=bulk_block&ips=ip1,ip2,10.0.0.0/8&api_key=KEY[&timeout=СЕК]&api=1
 *   list       - ?action=list&api_key=KEY&api=1      (IPv4 — одиночные IP + CIDR)
 *   list6      - ?action=list6&api_key=KEY&api=1     (IPv6 — одиночные IP + CIDR)
 *   clear      - ?action=clear&api_key=KEY&api=1
 *   debug      - ?action=debug&api_key=KEY&api=1
 *   diag       - ?action=diag&api_key=KEY&api=1
 *   init       - ?action=init&api_key=KEY&api=1
 */

error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
require_once 'settings.php';

// --- Константы (могут быть переопределены в settings.php) ---
if (!defined('NFT_FAMILY'))   define('NFT_FAMILY',   'inet');
if (!defined('NFT_TABLE'))    define('NFT_TABLE',    'filter');
if (!defined('NFT_CHAIN'))    define('NFT_CHAIN',    'input');
if (!defined('NFT_SET_V4'))     define('NFT_SET_V4',     'banned');
if (!defined('NFT_SET_V6'))     define('NFT_SET_V6',     'banned6');
if (!defined('NFT_SET_V4_NET')) define('NFT_SET_V4_NET', 'banned_net');   // CIDR IPv4
if (!defined('NFT_SET_V6_NET')) define('NFT_SET_V6_NET', 'banned_net6');  // CIDR IPv6
if (!defined('BAN_TIMEOUT'))    define('BAN_TIMEOUT',    3600);

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
    if (strpos($cidr, '/') === false) {
        $a = @inet_pton($ip);
        $b = @inet_pton($cidr);
        return ($a !== false && $b !== false && $a === $b);
    }

    list($subnet, $mask) = explode('/', $cidr, 2);
    $mask = (int)$mask;

    $ip_bin     = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    if ($ip_bin === false || $subnet_bin === false) return false;
    if (strlen($ip_bin) !== strlen($subnet_bin)) return false;

    $max_bits = strlen($ip_bin) * 8;
    if ($mask < 0 || $mask > $max_bits) return false;

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

/**
 * Безопасный запуск nft с sudo. Возвращает [rc, output_array].
 */
function nftExec($args) {
    $cmd = 'sudo -n nft ' . $args . ' 2>&1';
    $out = array();
    $rc  = 0;
    exec($cmd, $out, $rc);
    return array($rc, $out);
}

function ensureSetsReady() {
    static $ready = false;
    if ($ready) return;

    $f   = NFT_FAMILY;
    $t   = NFT_TABLE;
    $c   = NFT_CHAIN;
    $s4  = NFT_SET_V4;
    $s6  = NFT_SET_V6;
    $n4  = NFT_SET_V4_NET;
    $n6  = NFT_SET_V6_NET;

    // Таблица (idempotent — "add" не падает, если уже есть)
    nftExec("add table $f $t");

    // Цепочка (policy accept — чтобы не отрезать SSH при первом создании)
    nftExec("add chain $f $t $c { type filter hook input priority 0 \\; policy accept \\; }");

    // IPv4 set (одиночные IP)
    list($rc4, $out4) = nftExec("list set $f $t $s4");
    if ($rc4 !== 0) {
        nftExec("add set $f $t $s4 { type ipv4_addr \\; flags timeout \\; timeout " . (int)BAN_TIMEOUT . "s \\; }");
    }

    // IPv6 set (одиночные IP)
    list($rc6, $out6) = nftExec("list set $f $t $s6");
    if ($rc6 !== 0) {
        nftExec("add set $f $t $s6 { type ipv6_addr \\; flags timeout \\; timeout " . (int)BAN_TIMEOUT . "s \\; }");
    }

    // IPv4 CIDR set (flags interval — для подсетей)
    list($rcn4, $outn4) = nftExec("list set $f $t $n4");
    if ($rcn4 !== 0) {
        nftExec("add set $f $t $n4 { type ipv4_addr \\; flags interval,timeout \\; timeout " . (int)BAN_TIMEOUT . "s \\; }");
    }

    // IPv6 CIDR set
    list($rcn6, $outn6) = nftExec("list set $f $t $n6");
    if ($rcn6 !== 0) {
        nftExec("add set $f $t $n6 { type ipv6_addr \\; flags interval,timeout \\; timeout " . (int)BAN_TIMEOUT . "s \\; }");
    }

    // Правила drop — только если их ещё нет
    list($rc_r, $rules) = nftExec("list chain $f $t $c");
    $rules_str = implode("\n", $rules);
    if ($rc_r === 0) {
        if (strpos($rules_str, "@$s4") === false) {
            nftExec("insert rule $f $t $c ip saddr @$s4 drop");
        }
        if (strpos($rules_str, "@$s6") === false) {
            nftExec("insert rule $f $t $c ip6 saddr @$s6 drop");
        }
        if (strpos($rules_str, "@$n4") === false) {
            nftExec("insert rule $f $t $c ip saddr @$n4 drop");
        }
        if (strpos($rules_str, "@$n6") === false) {
            nftExec("insert rule $f $t $c ip6 saddr @$n6 drop");
        }
    }

    $ready = true;
}

/**
 * Разбирает ввод "IP" или "IP/MASK". Возвращает:
 *   ['ver' => 4|6, 'is_cidr' => bool, 'value' => нормализованная строка]
 * или false при ошибке.
 */
function parseIpOrCidr($input) {
    $input = trim((string)$input);
    if ($input === '') return false;

    if (strpos($input, '/') !== false) {
        list($ip, $mask) = explode('/', $input, 2);
        $ip = trim($ip);
        $v = ipVersion($ip);
        if (!$v) return false;
        if (!preg_match('/^\d+$/', $mask)) return false;
        $mask = (int)$mask;
        $max = ($v === 4) ? 32 : 128;
        if ($mask < 0 || $mask > $max) return false;
        // /32 для v4 и /128 для v6 — это одиночный IP, кладём в обычный set
        if (($v === 4 && $mask === 32) || ($v === 6 && $mask === 128)) {
            return array('ver' => $v, 'is_cidr' => false, 'value' => $ip);
        }
        return array('ver' => $v, 'is_cidr' => true, 'value' => $ip . '/' . $mask);
    }

    $v = ipVersion($input);
    if (!$v) return false;
    return array('ver' => $v, 'is_cidr' => false, 'value' => $input);
}

/**
 * Проверяет, попадает ли хоть одна запись из whitelist в указанную CIDR-подсеть
 * (чтобы не забанить свой же IP одним движением).
 */
function cidrContainsWhitelisted($cidr) {
    global $IP_WHITELIST;
    $defaults = array('127.0.0.0/8', '::1');
    $list = is_array($IP_WHITELIST) ? array_merge($defaults, $IP_WHITELIST) : $defaults;

    foreach ($list as $entry) {
        $entry = trim($entry);
        if ($entry === '') continue;
        $wl_ip = (strpos($entry, '/') !== false) ? explode('/', $entry)[0] : $entry;
        if (!ipVersion($wl_ip)) continue;
        if (ipInCidr($wl_ip, $cidr)) return $entry;
    }
    return false;
}

// --- Операции ---

function blockIP($input, $timeout = 0) {
    $parsed = parseIpOrCidr($input);
    if (!$parsed) return array('status' => 'error', 'message' => "Неверный формат IP/CIDR: $input");

    // Защита от самострела — whitelist из settings.php
    if ($parsed['is_cidr']) {
        $matched = cidrContainsWhitelisted($parsed['value']);
        if ($matched !== false) {
            return array(
                'status'  => 'warning',
                'message' => "CIDR {$parsed['value']} содержит IP из белого списка — блокировка отклонена",
                'details' => "Совпадение: $matched",
            );
        }
    } else {
        $matched = isWhitelisted($parsed['value']);
        if ($matched !== false) {
            return array(
                'status'  => 'warning',
                'message' => "IP {$parsed['value']} в белом списке — блокировка отклонена",
                'details' => "Совпадение с правилом: $matched",
            );
        }
    }

    $timeout = ($timeout > 0) ? (int)$timeout : BAN_TIMEOUT;
    ensureSetsReady();

    $f = NFT_FAMILY;
    $t = NFT_TABLE;
    $v = $parsed['ver'];

    if ($parsed['is_cidr']) {
        $set = ($v === 4) ? NFT_SET_V4_NET : NFT_SET_V6_NET;
        $label = "CIDR {$parsed['value']}";
    } else {
        $set = ($v === 4) ? NFT_SET_V4 : NFT_SET_V6;
        $label = "IP {$parsed['value']}";
    }

    // nft не умеет "заменить" элемент — сначала удаляем, потом добавляем
    nftExec("delete element $f $t $set { " . escapeshellarg($parsed['value']) . " }");

    list($rc, $out) = nftExec("add element $f $t $set { " . escapeshellarg($parsed['value']) . " timeout " . $timeout . "s }");

    if ($rc !== 0) {
        return array('status' => 'error', 'message' => "Ошибка блокировки $label", 'details' => implode("\n", $out));
    }

    return array(
        'status'  => 'success',
        'message' => "$label заблокирован на " . formatDuration($timeout),
        'details' => "Set: $set, timeout: $timeout сек",
    );
}

function unblockIP($input) {
    $parsed = parseIpOrCidr($input);
    if (!$parsed) return array('status' => 'error', 'message' => "Неверный формат IP/CIDR: $input");

    ensureSetsReady();

    $f = NFT_FAMILY;
    $t = NFT_TABLE;
    $v = $parsed['ver'];

    if ($parsed['is_cidr']) {
        $set = ($v === 4) ? NFT_SET_V4_NET : NFT_SET_V6_NET;
    } else {
        $set = ($v === 4) ? NFT_SET_V4 : NFT_SET_V6;
    }

    list($rc, $out) = nftExec("delete element $f $t $set { " . escapeshellarg($parsed['value']) . " }");

    if ($rc !== 0) {
        return array('status' => 'warning', 'message' => "{$parsed['value']} не найден в списке или уже разблокирован");
    }

    return array('status' => 'success', 'message' => "{$parsed['value']} успешно разблокирован", 'details' => "Удалён из $set");
}

/**
 * Массовая блокировка — принимает строку с IP/CIDR, разделёнными запятыми,
 * точками с запятой, пробелами или переводом строк.
 */
function bulkBlock($list, $timeout = 0) {
    $raw = preg_split('/[\s,;]+/', (string)$list);
    $items = array();
    foreach ($raw as $entry) {
        $entry = trim($entry);
        if ($entry !== '') $items[] = $entry;
    }

    if (empty($items)) {
        return array('status' => 'error', 'message' => 'Список пуст');
    }

    $ok = 0;
    $skipped = 0;
    $errors = 0;
    $invalid = 0;
    $details = array();

    foreach ($items as $entry) {
        $res = blockIP($entry, $timeout);
        $status = isset($res['status']) ? $res['status'] : 'error';
        if ($status === 'success') {
            $ok++;
            $details[] = "✓ $entry";
        } elseif ($status === 'warning') {
            $skipped++;
            $details[] = "⚠ $entry — " . $res['message'];
        } else {
            if (strpos($res['message'], 'Неверный формат') === 0) {
                $invalid++;
            } else {
                $errors++;
            }
            $details[] = "✗ $entry — " . $res['message'];
        }
    }

    $total = count($items);
    $overall = ($ok === $total) ? 'success' : (($ok > 0) ? 'warning' : 'error');

    return array(
        'status'  => $overall,
        'message' => "Обработано: $total (успешно: $ok, пропущено: $skipped, невалидных: $invalid, ошибок: $errors)",
        'details' => implode("\n", array_slice($details, 0, 50))
                   . (count($details) > 50 ? "\n... и ещё " . (count($details) - 50) : ''),
        'total'    => $total,
        'ok'       => $ok,
        'skipped'  => $skipped,
        'invalid'  => $invalid,
        'errors'   => $errors,
    );
}

/**
 * Извлекает значение (IP или CIDR) из элемента nft set. Возвращает строку.
 */
function extractSetElemValue($val) {
    // Одиночный IP: val = "1.2.3.4"
    if (is_string($val)) return $val;
    // CIDR: val = {"prefix": {"addr": "10.0.0.0", "len": 8}}
    if (is_array($val)) {
        if (isset($val['prefix']['addr'], $val['prefix']['len'])) {
            return $val['prefix']['addr'] . '/' . $val['prefix']['len'];
        }
        // Диапазон: val = {"range": ["1.2.3.4", "1.2.3.10"]}
        if (isset($val['range']) && is_array($val['range'])) {
            return $val['range'][0] . '-' . $val['range'][1];
        }
    }
    return '?';
}

function listSetElements($setName) {
    $f = NFT_FAMILY;
    $t = NFT_TABLE;
    list($rc, $out) = nftExec("-j list set $f $t $setName");

    $result = array();
    if ($rc !== 0) return $result;

    $json = implode("\n", $out);
    $data = json_decode($json, true);
    if (!is_array($data) || empty($data['nftables'])) return $result;

    foreach ($data['nftables'] as $item) {
        if (!isset($item['set']['elem'])) continue;
        foreach ($item['set']['elem'] as $e) {
            if (is_string($e)) {
                $result[] = array(
                    'ip'              => $e,
                    'remaining'       => 0,
                    'remaining_human' => '—',
                    'is_cidr'         => false,
                );
            } elseif (isset($e['elem'])) {
                $val = isset($e['elem']['val']) ? $e['elem']['val'] : '?';
                $ip_str = extractSetElemValue($val);
                $remaining = isset($e['elem']['expires']) ? (int)$e['elem']['expires'] : 0;
                $result[] = array(
                    'ip'              => $ip_str,
                    'remaining'       => $remaining,
                    'remaining_human' => formatDuration($remaining),
                    'is_cidr'         => (strpos($ip_str, '/') !== false || strpos($ip_str, '-') !== false),
                );
            } elseif (is_array($e)) {
                // Иногда элемент — это просто prefix-объект без обёртки "elem"
                $ip_str = extractSetElemValue($e);
                if ($ip_str !== '?') {
                    $result[] = array(
                        'ip'              => $ip_str,
                        'remaining'       => 0,
                        'remaining_human' => '—',
                        'is_cidr'         => (strpos($ip_str, '/') !== false || strpos($ip_str, '-') !== false),
                    );
                }
            }
        }
    }
    return $result;
}

function listBlockedIPs($version) {
    ensureSetsReady();

    $set_ip   = ($version === 6) ? NFT_SET_V6     : NFT_SET_V4;
    $set_cidr = ($version === 6) ? NFT_SET_V6_NET : NFT_SET_V4_NET;

    $items = array_merge(
        listSetElements($set_ip),
        listSetElements($set_cidr)
    );

    // Дополняем поле ports для обратной совместимости с iptables.php API
    foreach ($items as &$it) {
        $it['ports'] = array('all');
    }
    unset($it);

    $ips = array();
    foreach ($items as $it) $ips[] = $it['ip'];

    return array(
        'status'          => 'success',
        'version'         => ($version === 6) ? 'IPv6' : 'IPv4',
        'set'             => $set_ip,
        'set_cidr'        => $set_cidr,
        'count'           => count($items),
        'blocked_ips'     => $ips,
        'blocked_details' => $items,
    );
}

function clearAllRules() {
    ensureSetsReady();
    $results = array();
    $ok = true;
    $f = NFT_FAMILY;
    $t = NFT_TABLE;

    $sets = array(NFT_SET_V4, NFT_SET_V6, NFT_SET_V4_NET, NFT_SET_V6_NET);
    foreach ($sets as $s) {
        list($rc, $out) = nftExec("flush set $f $t $s");
        $results[] = ($rc === 0) ? "$s очищен" : "Ошибка $s";
        if ($rc !== 0) $ok = false;
    }

    return array(
        'status'  => $ok ? 'success' : 'warning',
        'message' => $ok ? 'Все баны сняты (IP + CIDR, v4 + v6)' : 'Частичная очистка',
        'details' => implode(', ', $results),
    );
}

function getDebugInfo() {
    ensureSetsReady();
    $d = array();
    $f = NFT_FAMILY;
    $t = NFT_TABLE;

    list($rc, $o) = nftExec("list set $f $t " . NFT_SET_V4);     $d['set_' . NFT_SET_V4]     = implode("\n", $o);
    list($rc, $o) = nftExec("list set $f $t " . NFT_SET_V6);     $d['set_' . NFT_SET_V6]     = implode("\n", $o);
    list($rc, $o) = nftExec("list set $f $t " . NFT_SET_V4_NET); $d['set_' . NFT_SET_V4_NET] = implode("\n", $o);
    list($rc, $o) = nftExec("list set $f $t " . NFT_SET_V6_NET); $d['set_' . NFT_SET_V6_NET] = implode("\n", $o);
    list($rc, $o) = nftExec("list chain $f $t " . NFT_CHAIN);    $d['chain_' . NFT_CHAIN]    = implode("\n", $o);
    list($rc, $o) = nftExec("list ruleset");                     $d['ruleset']               = implode("\n", $o);

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

    $checks[] = array(
        'name'   => 'Функция escapeshellarg()',
        'status' => function_exists('escapeshellarg') ? 'ok' : 'fail',
        'value'  => function_exists('escapeshellarg') ? 'доступна' : 'отсутствует',
        'hint'   => 'Нужна для защиты от shell-injection',
    );

    $checks[] = array(
        'name'   => 'Функция filter_var()',
        'status' => function_exists('filter_var') ? 'ok' : 'fail',
        'value'  => function_exists('filter_var') ? 'доступна' : 'отсутствует',
        'hint'   => 'Установи пакет php-filter',
    );

    $checks[] = array(
        'name'   => 'Функция hash_equals()',
        'status' => function_exists('hash_equals') ? 'ok' : 'warn',
        'value'  => function_exists('hash_equals') ? 'доступна' : 'отсутствует',
        'hint'   => function_exists('hash_equals') ? '' : 'Без hash_equals сравнение API-ключа уязвимо к timing-атакам',
    );

    if ($exec_disabled) {
        return array('status' => 'fail', 'checks' => $checks);
    }

    $find_binary = function($name) {
        $out = array(); $rc = 0;
        @exec("command -v " . escapeshellarg($name) . " 2>/dev/null", $out, $rc);
        if ($rc === 0 && !empty($out[0])) {
            return trim($out[0]);
        }
        foreach (array('/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin', '/usr/local/bin') as $dir) {
            if (is_executable("$dir/$name")) return "$dir/$name";
        }
        return '';
    };

    // --- 2. Бинарники в системе ---
    $bins = array('sudo', 'nft');
    foreach ($bins as $bin) {
        $path = $find_binary($bin);
        $hint = '';
        if (!$path) {
            if ($bin === 'nft') {
                $hint = 'sudo apt install nftables   (или: yum install nftables)';
            } elseif ($bin === 'sudo') {
                $hint = 'sudo не установлен. Переустанови coreutils/sudo пакет.';
            }
        }
        $checks[] = array(
            'name'   => "Бинарник $bin",
            'status' => $path ? 'ok' : 'fail',
            'value'  => $path ? $path : 'не найден',
            'hint'   => $hint,
        );
    }

    // --- 3. Модуль ядра nf_tables ---
    // Проверяем несколькими способами, т.к. модуль может быть встроен в ядро (builtin)
    // или /proc/modules может быть недоступен для www-data
    $nft_loaded = false;
    $nft_source = '';

    // Способ 1: /sys/module/nf_tables — работает и для загружаемого, и для builtin
    if (is_dir('/sys/module/nf_tables')) {
        $nft_loaded = true;
        $nft_source = '/sys/module';
    }
    // Способ 2: /proc/modules
    if (!$nft_loaded && is_readable('/proc/modules')) {
        $modules = @file_get_contents('/proc/modules');
        if ($modules && preg_match('/^nf_tables\s/m', $modules)) {
            $nft_loaded = true;
            $nft_source = '/proc/modules';
        }
    }
    // Способ 3: lsmod
    if (!$nft_loaded) {
        $out = array();
        exec('lsmod 2>/dev/null | grep -E "^nf_tables" 2>/dev/null', $out);
        if (!empty($out)) {
            $nft_loaded = true;
            $nft_source = 'lsmod';
        }
    }
    // Способ 4 (финальный): если nft работает через sudo — значит модуль есть
    if (!$nft_loaded) {
        $out = array(); $rc = 0;
        exec("sudo -n nft list tables 2>/dev/null", $out, $rc);
        if ($rc === 0) {
            $nft_loaded = true;
            $nft_source = 'nft работает';
        }
    }
    $checks[] = array(
        'name'   => 'Модуль ядра nf_tables',
        'status' => $nft_loaded ? 'ok' : 'warn',
        'value'  => $nft_loaded ? ('загружен (' . $nft_source . ')') : 'не обнаружен',
        'hint'   => $nft_loaded ? '' : 'Загрузится автоматически при первом использовании nft. Принудительно: sudo modprobe nf_tables',
    );

    // --- 4. Проверка sudoers (sudo без пароля) ---
    $sudo_path = $find_binary('sudo');

    if (!$sudo_path) {
        $checks[] = array(
            'name'   => 'sudoers',
            'status' => 'fail',
            'value'  => 'пропущено (sudo не установлен)',
            'hint'   => 'Сначала установи sudo',
        );
    } else {
        $real_user = 'www-data';
        if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            $info = @posix_getpwuid(posix_geteuid());
            if ($info) $real_user = $info['name'];
        } elseif (function_exists('get_current_user')) {
            $u = get_current_user();
            if ($u) $real_user = $u;
        }

        $sudo_tests = array(
            array('cmd' => 'sudo -n nft list tables 2>&1', 'name' => 'sudoers: nft'),
        );
        $sudoers_hint = "Создай /etc/sudoers.d/nftables-api:\n" .
            "  Cmnd_Alias NFT_CMDS = /usr/sbin/nft, /sbin/nft, /usr/local/sbin/nft\n" .
            "  " . $real_user . " ALL=(root) NOPASSWD: NFT_CMDS\n" .
            "Затем: sudo chmod 440 /etc/sudoers.d/nftables-api && sudo visudo -cf /etc/sudoers.d/nftables-api";

        foreach ($sudo_tests as $t) {
            $out = array(); $rc = 0;
            exec($t['cmd'], $out, $rc);
            $outStr = implode(' ', $out);
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
        'hint'   => 'Именно этот пользователь должен быть в /etc/sudoers.d/nftables-api',
    );

    // --- 6. Таблица и цепочка ---
    $f = NFT_FAMILY; $t = NFT_TABLE; $c = NFT_CHAIN;

    exec("sudo -n nft list table $f $t 2>/dev/null", $o_tbl, $rc_tbl);
    $checks[] = array(
        'name'   => "Таблица $f $t",
        'status' => ($rc_tbl === 0) ? 'ok' : 'warn',
        'value'  => ($rc_tbl === 0) ? 'существует' : 'не создана',
        'hint'   => ($rc_tbl === 0) ? '' : 'Будет создана автоматически при первой блокировке',
    );

    exec("sudo -n nft list chain $f $t $c 2>/dev/null", $o_chn, $rc_chn);
    $checks[] = array(
        'name'   => "Цепочка $c",
        'status' => ($rc_chn === 0) ? 'ok' : 'warn',
        'value'  => ($rc_chn === 0) ? 'существует' : 'не создана',
        'hint'   => ($rc_chn === 0) ? '' : 'Будет создана автоматически при первой блокировке',
    );

    // --- 7. Состояние сетов ---
    $sets_check = array(
        array(NFT_SET_V4,     'IPv4 одиночные IP'),
        array(NFT_SET_V6,     'IPv6 одиночные IP'),
        array(NFT_SET_V4_NET, 'IPv4 CIDR'),
        array(NFT_SET_V6_NET, 'IPv6 CIDR'),
    );
    foreach ($sets_check as $sc) {
        list($sname, $sdesc) = $sc;
        $o = array(); $rc = 0;
        exec("sudo -n nft list set $f $t $sname 2>/dev/null", $o, $rc);
        $checks[] = array(
            'name'   => "set: $sname",
            'status' => ($rc === 0) ? 'ok' : 'warn',
            'value'  => ($rc === 0) ? "существует ($sdesc)" : 'не создан',
            'hint'   => ($rc === 0) ? '' : "Будет создан автоматически при первой блокировке ($sdesc)",
        );
    }

    // --- 8. Правила drop в цепочке ---
    $chain_rules = ($rc_chn === 0) ? implode("\n", $o_chn) : '';
    $rules_check = array(
        array(NFT_SET_V4,     'IPv4 одиночные IP'),
        array(NFT_SET_V6,     'IPv6 одиночные IP'),
        array(NFT_SET_V4_NET, 'IPv4 CIDR'),
        array(NFT_SET_V6_NET, 'IPv6 CIDR'),
    );
    foreach ($rules_check as $rc_item) {
        list($rset, $rdesc) = $rc_item;
        $has = (strpos($chain_rules, '@' . $rset) !== false);
        $checks[] = array(
            'name'   => "Правило drop $rdesc",
            'status' => $has ? 'ok' : 'warn',
            'value'  => $has ? 'установлено' : 'отсутствует',
            'hint'   => $has ? '' : 'Будет создано автоматически при первой блокировке',
        );
    }

    // --- 8.5. Whitelist ---
    global $IP_WHITELIST;
    $wl_user = is_array($IP_WHITELIST) ? count($IP_WHITELIST) : 0;
    $wl_total = $wl_user + 2;
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

    // --- 9. Права на запись в /tmp ---
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
    foreach ($checks as $ch) {
        if ($ch['status'] === 'fail') $has_fail = true;
        if ($ch['status'] === 'warn') $has_warn = true;
    }

    $overall = 'ok';
    if ($has_fail)      $overall = 'fail';
    elseif ($has_warn)  $overall = 'warn';

    $can_init = !$has_fail && $has_warn;

    return array(
        'status'   => $overall,
        'can_init' => $can_init,
        'summary'  => ($overall === 'ok')
            ? 'Все проверки пройдены. Система готова к работе.'
            : (($overall === 'warn')
                ? 'Есть предупреждения. Нажми «Инициализировать» чтобы создать таблицу, сеты и правила.'
                : 'Критические ошибки — API работать не будет. Смотри подсказки ниже.'),
        'checks'   => $checks,
    );
}

/**
 * Принудительная инициализация: создаёт таблицу/цепочку/сеты/правила сейчас.
 */
function initSystem() {
    $log = array();
    $success = true;

    $f  = NFT_FAMILY;
    $t  = NFT_TABLE;
    $c  = NFT_CHAIN;
    $s4 = NFT_SET_V4;
    $s6 = NFT_SET_V6;
    $n4 = NFT_SET_V4_NET;
    $n6 = NFT_SET_V6_NET;

    // Таблица
    list($rc, $o) = nftExec("list table $f $t");
    if ($rc !== 0) {
        list($rc2, $o2) = nftExec("add table $f $t");
        if ($rc2 === 0) {
            $log[] = '✅ Создана таблица ' . $f . ' ' . $t;
        } else {
            $log[] = '❌ Не удалось создать таблицу: ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ Таблица ' . $f . ' ' . $t . ' уже существует';
    }

    // Цепочка
    list($rc, $o) = nftExec("list chain $f $t $c");
    if ($rc !== 0) {
        list($rc2, $o2) = nftExec("add chain $f $t $c { type filter hook input priority 0 \\; policy accept \\; }");
        if ($rc2 === 0) {
            $log[] = '✅ Создана цепочка ' . $c;
        } else {
            $log[] = '❌ Не удалось создать цепочку: ' . implode(' ', $o2);
            $success = false;
        }
    } else {
        $log[] = '✓ Цепочка ' . $c . ' уже существует';
    }

    // Сеты: IP v4, IP v6, CIDR v4, CIDR v6
    $sets = array(
        array($s4, 'ipv4_addr', 'timeout',          'IPv4 одиночный'),
        array($s6, 'ipv6_addr', 'timeout',          'IPv6 одиночный'),
        array($n4, 'ipv4_addr', 'interval,timeout', 'IPv4 CIDR'),
        array($n6, 'ipv6_addr', 'interval,timeout', 'IPv6 CIDR'),
    );
    foreach ($sets as $s) {
        list($sname, $stype, $sflags, $sdesc) = $s;
        list($rc, $o) = nftExec("list set $f $t $sname");
        if ($rc !== 0) {
            list($rc2, $o2) = nftExec("add set $f $t $sname { type $stype \\; flags $sflags \\; timeout " . (int)BAN_TIMEOUT . "s \\; }");
            if ($rc2 === 0) {
                $log[] = "✅ Создан set $sname ($sdesc)";
            } else {
                $log[] = "❌ Не удалось создать $sname: " . implode(' ', $o2);
                $success = false;
            }
        } else {
            $log[] = "✓ $sname уже существует ($sdesc)";
        }
    }

    // Правила drop
    list($rc_r, $o_r) = nftExec("list chain $f $t $c");
    $rules_str = implode("\n", $o_r);

    $rules = array(
        array($s4, 'ip',  'IPv4 одиночный'),
        array($s6, 'ip6', 'IPv6 одиночный'),
        array($n4, 'ip',  'IPv4 CIDR'),
        array($n6, 'ip6', 'IPv6 CIDR'),
    );
    foreach ($rules as $r) {
        list($rset, $rproto, $rdesc) = $r;
        if (strpos($rules_str, "@$rset") === false) {
            list($rc2, $o2) = nftExec("insert rule $f $t $c $rproto saddr @$rset drop");
            if ($rc2 === 0) {
                $log[] = "✅ Создано правило drop $rdesc";
            } else {
                $log[] = "❌ Не удалось создать правило $rdesc: " . implode(' ', $o2);
                $success = false;
            }
        } else {
            $log[] = "✓ Правило drop $rdesc уже существует";
        }
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
$ips_raw = isset($_REQUEST['ips'])     ? $_REQUEST['ips']     : '';
$timeout = isset($_REQUEST['timeout']) ? (int)$_REQUEST['timeout'] : 0;
$result  = array();

switch ($action) {
    case 'block':      $result = $ip ? blockIP($ip, $timeout) : array('status' => 'error', 'message' => 'IP/CIDR не указан'); break;
    case 'unblock':    $result = $ip ? unblockIP($ip)         : array('status' => 'error', 'message' => 'IP/CIDR не указан'); break;
    case 'bulk_block': $result = $ips_raw ? bulkBlock($ips_raw, $timeout) : array('status' => 'error', 'message' => 'Список IP/CIDR не указан'); break;
    case 'list':       $result = listBlockedIPs(4); break;
    case 'list6':      $result = listBlockedIPs(6); break;
    case 'clear':      $result = clearAllRules();   break;
    case 'debug':      $result = getDebugInfo();    break;
    case 'diag':       $result = runDiagnostics();  break;
    case 'init':       $result = initSystem();      break;
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
    <title>Управление блокировкой IP (nftables)</title>
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
            <h1>🛡️ Управление блокировкой IP (nftables)</h1>
            <p>Авто-разбан через <?php echo formatDuration(BAN_TIMEOUT); ?>. Таблица: <code><?php echo NFT_FAMILY . ' ' . NFT_TABLE; ?></code> · Сеты: <code><?php echo NFT_SET_V4; ?></code> / <code><?php echo NFT_SET_V6; ?></code></p>
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
            <h2>Блокировка / Разблокировка</h2>
            <p style="color: #666; margin-bottom: 20px;">Поддерживаются одиночные IP (IPv4/IPv6) и подсети в формате CIDR.</p>

            <form method="post" action="">
                <div class="form-group">
                    <label for="ip">IP-адрес или CIDR-подсеть</label>
                    <input type="text" id="ip" name="ip" placeholder="192.168.1.10  ·  10.0.0.0/8  ·  2001:db8::1  ·  2001:db8::/32" required>
                    <small style="color: #888; display: block; margin-top: 6px;">
                        Примеры: <code>192.168.1.10</code>, <code>10.0.0.0/8</code>, <code>2001:db8::1</code>, <code>2001:db8::/32</code>
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
                <h3>📋 Массовая блокировка</h3>
                <p style="color: #666; margin-top: 8px; margin-bottom: 15px;">
                    Вставь список IP и/или CIDR — по одному на строку, или через запятую/пробел.
                    Поддерживается смесь IPv4 и IPv6.
                </p>
                <form method="post" action="">
                    <div class="form-group">
                        <label for="ips">Список IP/CIDR</label>
                        <textarea id="ips" name="ips" rows="6" required
                            style="width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; font-family: monospace; resize: vertical;"
                            placeholder="1.2.3.4&#10;10.0.0.0/8&#10;2001:db8::1&#10;5.5.5.5, 6.6.6.6; 7.7.7.7"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="bulk_timeout">Таймаут бана в секундах (0 = дефолт <?php echo BAN_TIMEOUT; ?>)</label>
                        <input type="number" id="bulk_timeout" name="timeout" value="0" min="0" max="31536000">
                    </div>
                    <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($API_KEY); ?>">
                    <div class="button-group">
                        <button type="submit" name="action" value="bulk_block" class="btn btn-primary">📦 Заблокировать всех</button>
                    </div>
                </form>
            </div>

            <div style="margin-top: 30px; padding-top: 30px; border-top: 2px solid #e0e0e0;">
                <h3>⚡ Быстрые действия</h3>
                <div class="button-group">
                    <button onclick="blockCurrentIP()" class="btn btn-warning">Заблокировать мой IP</button>
                    <form method="post" action="" style="display: inline;">
                        <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($API_KEY); ?>">
                        <button type="submit" name="action" value="clear" class="btn btn-danger"
                                onclick="return confirm('Вы уверены? Это снимет ВСЕ баны (IP + CIDR, v4 + v6)!')">
                            🗑️ Снять все баны
                        </button>
                    </form>
                </div>
            </div>

            <div style="margin-top: 30px; padding-top: 30px; border-top: 2px solid #e0e0e0;">
                <h3>📡 Примеры API-запросов</h3>
                <p style="color: #666; margin-top: 8px; margin-bottom: 15px;">
                    Готовые URL с твоим реальным API-ключом. Можно копировать и вставлять в браузер, curl или скрипты.
                    Добавь <code>&amp;api=1</code> чтобы получить JSON (без — вернётся HTML с сообщением).
                </p>
                <?php
                // Путь к скрипту относительно корня сайта — работает из любой вложенной папки
                // SCRIPT_NAME: "/api/nftables.php", "/tools/firewall/nftables.php" и т.д.
                $_base = isset($_SERVER['SCRIPT_NAME']) && $_SERVER['SCRIPT_NAME'] !== ''
                    ? $_SERVER['SCRIPT_NAME']
                    : '/' . basename(__FILE__);
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
                        'title' => '🔒 Блокировка большой подсети IPv4 /16',
                        'url'   => "$_base?action=block&ip=" . urlencode('198.51.100.0/16') . "&api_key=$_key&timeout=7200&api=1",
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
                        'title' => '🔒 Блокировка большой IPv6-подсети /32',
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
                        'title' => '📦 Массовая блокировка (GET, смесь IPv4+IPv6+CIDR)',
                        'url'   => "$_base?action=bulk_block&ips=" . urlencode('203.0.113.1, 198.51.100.0/24, 2001:db8::1, 2001:db8:cafe::/48') . "&api_key=$_key&timeout=3600&api=1",
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
                        'title' => '🔍 Диагностика системы',
                        'url'   => "$_base?action=diag&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '🛠️ Отладочная информация (состояние сетов и правил)',
                        'url'   => "$_base?action=debug&api_key=$_key&api=1",
                    ),
                    array(
                        'title' => '⚡ Принудительная инициализация таблицы/сетов/правил',
                        'url'   => "$_base?action=init&api_key=$_key&api=1",
                    ),
                );
                ?>
                <div style="display:flex; flex-direction:column; gap:12px;">
                <?php foreach ($_examples as $ex): ?>
                    <div style="background:#f8f9fa; border:1px solid #e0e0e0; border-radius:8px; padding:12px 14px;">
                        <div style="font-weight:600; color:#333; margin-bottom:6px; font-size:14px;"><?php echo htmlspecialchars($ex['title']); ?></div>
                        <div style="display:flex; gap:8px; align-items:flex-start;">
                            <code style="flex:1; background:#fff; padding:8px 10px; border:1px solid #e0e0e0; border-radius:6px; font-size:12px; font-family:monospace; color:#1565c0; word-break:break-all; user-select:all;"><?php echo htmlspecialchars($ex['url']); ?></code>
                            <button type="button" class="btn btn-primary" style="padding:6px 12px; font-size:12px; white-space:nowrap;" onclick="copyExample(this, <?php echo htmlspecialchars(json_encode($ex['url']), ENT_QUOTES); ?>)">📋 Копировать</button>
                            <a href="<?php echo htmlspecialchars($ex['url']); ?>" target="_blank" class="btn btn-warning" style="padding:6px 12px; font-size:12px; white-space:nowrap; text-decoration:none; display:inline-block;">▶ Выполнить</a>
                        </div>
                    </div>
                <?php endforeach; ?>
                </div>

                <div style="margin-top:20px; padding:15px; background:#fff3e0; border-left:4px solid #ff9800; border-radius:4px; font-size:13px; color:#333;">
                    💡 <strong>Подсказка:</strong> для curl используй кавычки вокруг URL (из-за <code>&amp;</code>):<br>
                    <code style="display:block; margin-top:6px; background:#fff; padding:8px 10px; border:1px solid #e0e0e0; border-radius:6px; word-break:break-all; user-select:all;">curl "https://ваш-домен.ru<?php echo htmlspecialchars("$_base?action=block&ip=203.0.113.45&api_key=$_key&api=1"); ?>"</code>
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

            if (data.can_init) {
                summaryHtml += '<div style="margin-top: 12px;">' +
                    '<button onclick="initSystem()" class="btn btn-primary" id="btn-init">⚡ Инициализировать таблицу, сеты и правила</button>' +
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
                runDiag();
            };
            xhr.onerror = function() {
                alert('Сетевая ошибка');
                if (btn) { btn.disabled = false; btn.textContent = '⚡ Инициализировать таблицу, сеты и правила'; }
            };
            xhr.send();
        }

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

            // Сортировка: CIDR сверху, потом одиночные IP
            var items = data.blocked_details.slice();
            items.sort(function(a, b) {
                if (a.is_cidr !== b.is_cidr) return a.is_cidr ? -1 : 1;
                return 0;
            });

            var html = '';
            for (var i = 0; i < items.length; i++) {
                var info = items[i];
                var badge = info.is_cidr
                    ? '<span style="display:inline-block; background:#ede7f6; color:#5e35b1; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; margin-right:6px;">CIDR</span>'
                    : '<span style="display:inline-block; background:#e3f2fd; color:#1565c0; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; margin-right:6px;">IP</span>';
                html += '<div class="ip-item">' +
                    '<div class="ip-details">' +
                        '<span>' + badge + '<span class="ip-address">' + escapeHtml(info.ip) + '</span></span>' +
                        '<span class="ip-remaining">⏱️ Осталось: ' + escapeHtml(info.remaining_human || '—') + '</span>' +
                    '</div>' +
                    '<form method="post" action="" style="display: inline;">' +
                        '<input type="hidden" name="ip" value="' + escapeHtml(info.ip) + '">' +
                        '<input type="hidden" name="api_key" value="' + apiKey + '">' +
                        '<button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 8px 16px;">Разблокировать</button>' +
                    '</form>' +
                '</div>';
            }
            listEl.innerHTML = html;
        }

        function copyExample(btn, text) {
            var origin = window.location.origin;
            var fullUrl = origin + text;
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
