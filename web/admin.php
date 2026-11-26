<?php
// ============================================================
// ADMIN HALAMAN - Khusus Administrator
// Tanpa link ke halaman lain, akses hanya lewat URL langsung.
// ============================================================
session_start();

// Konfigurasi admin (dibaca dari .env di bawah ini)

$BASE_DIR = dirname(__FILE__);
$OUT_DIR = $BASE_DIR . '/output';

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
    <link rel="stylesheet" href="style.css?v=22">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>
        <form method="post" class="admin-form">
            <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
            <div class="login-field">
                <label>Username:</label><br>
                <input type="text" name="user" required autofocus><br>
            </div>
            <div class="login-field password-input-wrapper">
                <label>Password:</label><br>
                <input type="password" name="pass" required id="admin-pass">
                <button type="button" class="password-toggle" onclick="toggleAdminPassword()" id="admin-pass-toggle">👁️</button><br>
                <button type="submit" class="btn-login">Login</button>
            </div>
        </form>
    </div>
    <script>
        function toggleAdminPassword() {
            const input = document.getElementById('admin-pass');
            const btn = document.getElementById('admin-pass-toggle');
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        }
    </script>
</body>
</html>
    <?php
    exit;
}

// Hapus file output (hanya via POST, tanpa link)
if (isset($_POST['delete'])) {
    $f = basename($_POST['delete']);
    $path = $OUT_DIR . '/' . $f;
    if (file_exists($path) && is_file($path)) {
        unlink($path);
    }
    header('Location: admin.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surfinder</title>
    <link rel="stylesheet" href="style.css?v=22">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>
        <form method="post">
            <button type="submit" name="logout" class="btn-logout">Logout</button>
        </form>
    </div>
</body>
</html>
