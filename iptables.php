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
            <?php endif; ?>
        });
    </script>
</body>
</html>
