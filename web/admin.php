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
    $env = parse_ini_file($env_file, false, INI_SCANNER_TRIM);
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
    <link rel="stylesheet" href="style.css?v=19">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>
        <form method="post" style="max-width:400px;margin:20px auto;">
            <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
            <div class="login-field" style="margin-bottom:10px;">
                <label style="margin:0;padding:0;">Username:</label><br>
                <input type="text" name="user" required autofocus style="width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:4px;color:#e0e0e0;font-size:14px;margin:0;padding:0;"><br>
            </div>
            <div class="login-field" style="margin-bottom:10px;">
                <label style="margin:0;padding:0;">Password:</label><br>
                <input type="password" name="pass" required style="width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:4px;color:#e0e0e0;font-size:14px;margin:0;padding:0;"><br>
                <button type="submit" style="background:#4CAF50;color:white;border:none;padding:10px 24px;border-radius:4px;cursor:pointer;font-size:14px;font-weight:600;width:100%;margin-top:10px;">Login</button>
            </div>
        </form>
    </div>
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
    <link rel="stylesheet" href="style.css?v=19">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>
        <form method="post" style="margin-bottom:20px;">
            <button type="submit" name="logout" style="background:#f44336;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:13px;">Logout</button>
        </form>

        <h3>🛠️ Admin Dashboard</h3>
        <p>Waktu server: <?= date('Y-m-d H:i:s') ?></p>
        <p>PHP Version: <?= phpversion() ?></p>

        <h3>File Output Scan</h3>
        <?php
        $files = [];
        if (is_dir($OUT_DIR)) {
            $all = scandir($OUT_DIR);
            foreach ($all as $f) {
                if ($f === '.' || $f === '..') continue;
                $files[] = $f;
            }
            rsort($files);
        }
        if (empty($files)) {
            echo '<p>Tidak ada file output.</p>';
        } else {
            echo '<table border="1" cellpadding="6" cellspacing="0" style="width:100%;border-collapse:collapse;">';
            echo '<tr><th>File</th><th>Ukuran</th><th>Terakhir Diubah</th><th>Aksi</th></tr>';
            foreach ($files as $f) {
                $path = $OUT_DIR . '/' . $f;
                if (!is_file($path)) continue;
                $size = filesize($path);
                $mtime = date('Y-m-d H:i:s', filemtime($path));
                echo '<tr>';
                echo '<td>' . htmlspecialchars($f) . '</td>';
                echo '<td>' . number_format($size) . ' bytes</td>';
                echo '<td>' . htmlspecialchars($mtime) . '</td>';
                echo '<td><button type="submit" form="del-' . urlencode($f) . '" style="color:#f44336;border:none;background:transparent;cursor:pointer;">Hapus</button></td>';
                echo '</tr>';
                echo '<form id="del-' . urlencode($f) . '" method="post" style="display:none;"><input type="hidden" name="delete" value="' . htmlspecialchars($f) . '"></form>';
            }
            echo '</table>';
        }
        ?>
    </div>
</body>
</html>
