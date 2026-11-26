<?php
// ============================================================
// ADMIN HALAMAN - Khusus Administrator
// Ubah username/password di bawah ini sesuai keinginanmu.
// ============================================================
session_start();

// Konfigurasi admin (GANTI INI)
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'admin123');

$BASE_DIR = dirname(__FILE__);
$OUT_DIR = $BASE_DIR . '/output';

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: admin.php');
    exit;
}

// Login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Admin — Surfinder</title>
    <link rel="stylesheet" href="style.css?v=12">
</head>
<body>
    <div class="container">
        <h2>🔐 Login Admin</h2>
        <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="post">
            <label>Username:</label><br>
            <input type="text" name="user" required autofocus><br>
            <label>Password:</label><br>
            <input type="password" name="pass" required><br><br>
            <button type="submit">Login</button>
        </form>
        <p style="margin-top:15px;"><a href="index.php">← Kembali ke Beranda</a></p>
    </div>
</body>
</html>
    <?php
    exit;
}

// Hapus file output (opsional)
if (isset($_GET['delete'])) {
    $f = basename($_GET['delete']);
    $path = $OUT_DIR . '/' . $f;
    if (file_exists($path) && is_file($path)) {
        unlink($path);
    }
    header('Location: admin.php');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin — Surfinder</title>
    <link rel="stylesheet" href="style.css?v=12">
</head>
<body>
    <div class="container">
        <h2>🛠️ Admin Dashboard</h2>
        <p><a href="admin.php?logout=1" style="background:#f44336;color:#fff;padding:6px 12px;border-radius:4px;text-decoration:none;">Logout</a> | <a href="index.php" style="margin-left:10px;">Kembali ke Beranda</a></p>

        <h3>Status Sistem</h3>
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
                echo '<td><a href="admin.php?delete=' . urlencode($f) . '" onclick="return confirm(\'Hapus ' . htmlspecialchars($f, ENT_QUOTES) . '?\')" style="color:#f44336;">Hapus</a></td>';
                echo '</tr>';
            }
            echo '</table>';
        }
        ?>
        <p style="margin-top:20px;"><a href="index.php">← Kembali ke Beranda</a></p>
    </div>
</body>
</html>
