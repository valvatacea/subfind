<?php
// ============================================================
// ADMIN HALAMAN - Khusus Administrator
// Tanpa link ke halaman lain, akses hanya lewat URL langsung.
// ============================================================
session_start();

// Konfigurasi admin (dibaca dari .env di bawah ini)

$BASE_DIR = dirname(__FILE__);
$OUT_DIR = $BASE_DIR . '/output';
$SERVER_TIME_MS = round(microtime(true) * 1000);

// Muat kredensial dari .env (satu level di atas web/)
$env_file = $BASE_DIR . '/../.env';
if (is_file($env_file)) {
    $env = parse_ini_file($env_file, false);
    define('ADMIN_USER', $env['ADMIN_USER'] ?? 'admin');
    define('ADMIN_PASS', $env['ADMIN_PASS'] ?? 'admin123');
} else {
    define('ADMIN_USER', 'admin');
    define('ADMIN_PASS', 'admin123');
}

// Logout via POST (tanpa link)
if (isset($_POST['logout'])) {
    session_destroy();
    header('Location: admin.php');
    exit;
}

// Login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['logout'])) {
    if ($_POST['user'] === ADMIN_USER && $_POST['pass'] === ADMIN_PASS) {
        $_SESSION['admin_logged_in'] = true;
        header('Location: admin.php');
        exit;
    } else {
        $error = 'Username atau password salah.';
    }
}

// Jika belum login, tampilkan form login
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    ?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surfinder</title>
    <link rel="stylesheet" href="./css/style.css?v=62">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>
        <form method="post" class="admin-form">
            <div class="login-field">
                <label class="login-label">Username:</label>
                <input type="text" name="user" required autofocus>
            </div>
            <div class="login-field">
                <label class="login-label">Password:</label>
                <div class="password-input-wrapper">
                    <input type="password" name="pass" required id="admin-pass">
                    <button type="button" class="password-toggle" onclick="toggleAdminPassword()" id="admin-pass-toggle">
                        <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    </button>
                </div>
            </div>
            <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
            <button type="submit" class="btn-login">Login</button>
        </form>
    </div>
    <script>
        const eyeOpen = '<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
        const eyeClosed = '<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';

        function toggleAdminPassword() {
            const input = document.getElementById('admin-pass');
            const btn = document.getElementById('admin-pass-toggle');
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = eyeOpen;
            } else {
                input.type = 'password';
                btn.innerHTML = eyeClosed;
            }
        }
    </script>
</body>
</html>
    <?php
    exit;
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surfinder</title>
    <link rel="stylesheet" href="./css/style.css?v=62">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>

        <div class="admin-bar">
            <span class="admin-status" id="admin-datetime">Memuat waktu...</span>
            <button type="button" name="logout" class="btn-logout" id="btn-logout">Logout</button>
        </div>

        <div class="spacer"></div>

        <nav class="tabs">
            <div class="tab-row">
                <button class="tab active" onclick="showTab('d2ip', this)">D2IP</button>
                <button class="tab" onclick="showTab('rdns', this)">IP2D</button>
                <button class="tab" onclick="showTab('cdnscan', this)">CDNScan</button>
            </div>
            <div class="tab-row">
                <button class="tab" onclick="showTab('subfind', this)">SubFind</button>
                <button class="tab" onclick="showTab('sniscan', this)">SNIScan</button>
            </div>
        </nav>

        <div id="tab-content">
            <!-- D2IP -->
            <div class="tab-panel active" id="panel-d2ip">
                <form id="form-d2ip" onsubmit="handleScan(event, 'd2ip')">
                    <label>Domain:</label>
                    <input type="text" name="target" placeholder="google.com" required>
                    <button type="submit">Scan</button>
                </form>
                <div id="result-d2ip" class="result-area"></div>
            </div>

            <!-- IP2D -->
            <div class="tab-panel" id="panel-rdns">
                <form id="form-rdns" onsubmit="handleScan(event, 'rdns')">
                    <label>IP:</label>
                    <input type="text" name="target" placeholder="8.8.8.8" required>
                    <button type="submit">Scan</button>
                </form>
                <div id="result-rdns" class="result-area"></div>
            </div>
        </div>
    </div>
    <script src="./js/script.js?v=34"></script>
    <script>
        // Di admin, hanya D2IP & IP2D yang punya panel; tab lain diabaikan (seperti sebelumnya)
        (function() {
            const _orig = showTab;
            showTab = function(tabName, btn) {
                if (!document.getElementById('panel-' + tabName)) return;
                _orig(tabName, btn);
            };
        })();
    </script>
    <script>
        const serverTimeMs = <?php echo json_encode($SERVER_TIME_MS); ?>;
        const timeOffsetMs = serverTimeMs - Date.now();

        function updateAdminDateTime() {
            const now = new Date(Date.now() + timeOffsetMs);
            const formatted = now.toLocaleString('id-ID', {
                weekday: 'short', day: '2-digit', month: 'short', year: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
                timeZone: 'Asia/Jakarta', hour12: false
            }).replace(/\./g, ':');
            document.getElementById('admin-datetime').textContent = formatted + ' WIB';
        }
        setInterval(updateAdminDateTime, 1000);
        updateAdminDateTime();

        document.getElementById('btn-logout').addEventListener('click', function() {
            if(confirm('Yakin ingin logout?')) {
                fetch('admin.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'logout=1'
                }).then(function() {
                    window.location.href = 'admin.php';
                });
            }
        });
    </script>
</body>
</html>