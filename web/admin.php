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
if ($_POST['user'] !== ADMIN_USER) {
        $error = 'Username salah.';
    } elseif ($_POST['pass'] !== ADMIN_PASS) {
        $error = 'Password salah.';
    } else {
        $_SESSION['admin_logged_in'] = true;
        header('Location: admin.php');
        exit;
    }
}

// Ubah username/password via AJAX (khusus admin yang sudah login)
if (isset($_POST['change_creds']) && isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header('Content-Type: application/json');
    $newUser = trim((string)($_POST['new_user'] ?? ''));
    $newPass = (string)($_POST['new_pass'] ?? '');
    if ($newUser === '' || $newPass === '') {
        echo json_encode(['success' => false, 'message' => 'Username dan password tidak boleh kosong.']);
        exit;
    }
    $envFile = $BASE_DIR . '/../.env';
    $lines = is_file($envFile) ? file($envFile, FILE_IGNORE_NEW_LINES) : [];
    if ($lines === false) $lines = [];
    $foundUser = false;
    $foundPass = false;
    foreach ($lines as $i => $line) {
        if (preg_match('/^\s*ADMIN_USER\s*=/', $line)) {
            $lines[$i] = 'ADMIN_USER=' . $newUser;
            $foundUser = true;
        } elseif (preg_match('/^\s*ADMIN_PASS\s*=/', $line)) {
            $lines[$i] = 'ADMIN_PASS=' . $newPass;
            $foundPass = true;
        }
    }
    if (!$foundUser) $lines[] = 'ADMIN_USER=' . $newUser;
    if (!$foundPass) $lines[] = 'ADMIN_PASS=' . $newPass;
    $written = file_put_contents($envFile, implode("\n", $lines) . "\n", LOCK_EX);
    if ($written === false) {
        echo json_encode(['success' => false, 'message' => 'Gagal menyimpan .env (izin file).']);
        exit;
    }
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Kredensial berhasil diubah. Silakan login ulang.']);
    exit;
}

// --- Riwayat (upload/list/download/hapus) untuk cdnscan/subfind/sniscan ---
$history_types = ['cdnscan', 'subfind', 'sniscan'];
$action = $_POST['action'] ?? ($_GET['action'] ?? '');
if (in_array($action, ['upload_history','list_uploads','delete_history','download_history','download_file'], true)) {
    // download_file boleh tanpa login? tetap wajib login
    if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
        if ($action === 'download_file') { http_response_code(403); exit; }
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Belum login.']);
        exit;
    }
    $type = $_POST['type'] ?? ($_GET['type'] ?? '');
    if ($action !== 'download_file' && !in_array($type, $history_types, true)) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Tipe tidak valid.']);
        exit;
    }
    $OUTPUT_DIR = $BASE_DIR . '/../output';
    $RIWAYAT_DIR = $OUTPUT_DIR . '/riwayat';
    $UPLOAD_DIR = $RIWAYAT_DIR . '/upload';
    if (!is_dir($OUTPUT_DIR)) @mkdir($OUTPUT_DIR, 0777, true);
    if (!is_dir($RIWAYAT_DIR)) @mkdir($RIWAYAT_DIR, 0777, true);
    if (!is_dir($UPLOAD_DIR)) @mkdir($UPLOAD_DIR, 0777, true);

    if ($action === 'upload_history') {
        header('Content-Type: application/json');
        if (!isset($_FILES['upload_file']) || $_FILES['upload_file']['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['success' => false, 'message' => 'File upload gagal.']);
            exit;
        }
        $file = $_FILES['upload_file'];
        if ($file['size'] > 10 * 1024 * 1024) {
            echo json_encode(['success' => false, 'message' => 'File terlalu besar (maks 10MB).']);
            exit;
        }
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if ($ext !== 'json') {
            echo json_encode(['success' => false, 'message' => 'Hanya file JSON yang diizinkan.']);
            exit;
        }
        $raw = file_get_contents($file['tmp_name']);
        $data = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            echo json_encode(['success' => false, 'message' => 'JSON tidak valid: ' . json_last_error_msg()]);
            exit;
        }
        // validasi struktur minimal
        $ok = false;
        if ($type === 'sniscan') {
            $ok = is_array($data) || (is_array($data) && isset($data['results']));
            // terima list atau object dengan results
            $ok = is_array($data);
        } else {
            $ok = is_array($data);
        }
        if (!$ok) {
            echo json_encode(['success' => false, 'message' => 'Struktur JSON tidak sesuai.']);
            exit;
        }
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file['name']));
        $dest = $UPLOAD_DIR . '/' . $type . '_' . date('Ymd_His') . '_' . $safe;
        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            echo json_encode(['success' => false, 'message' => 'Gagal menyimpan file.']);
            exit;
        }
        echo json_encode(['success' => true, 'message' => 'Upload berhasil.', 'filename' => basename($dest)]);
        exit;
    }

    if ($action === 'list_uploads') {
        header('Content-Type: application/json');
        $files = glob($UPLOAD_DIR . '/' . $type . '_*.json');
        if ($files === false) $files = [];
        usort($files, function($a, $b) { return filemtime($b) - filemtime($a); });
        $out = [];
        foreach ($files as $f) $out[] = basename($f);
        echo json_encode(['success' => true, 'files' => $out]);
        exit;
    }

    if ($action === 'delete_history') {
        header('Content-Type: application/json');
        $patterns = [];
        if ($type === 'cdnscan') {
            $patterns = [
                $OUTPUT_DIR . '/cdnscan_*.json',
                $OUTPUT_DIR . '/cdnscan_*.txt',
                $OUTPUT_DIR . '/states/cdnscan_*.json',
                $RIWAYAT_DIR . '/cdnscan_*',
                $UPLOAD_DIR . '/cdnscan_*',
            ];
        } elseif ($type === 'subfind') {
            $patterns = [
                $OUTPUT_DIR . '/subfind_*.json',
                $OUTPUT_DIR . '/subfind_*.txt',
                $OUTPUT_DIR . '/states/subfind_*.json',
                $RIWAYAT_DIR . '/subfind_*',
                $UPLOAD_DIR . '/subfind_*',
            ];
        } elseif ($type === 'sniscan') {
            $patterns = [
                $OUTPUT_DIR . '/sniscan_*.json',
                $OUTPUT_DIR . '/sniscan_*.txt',
                $OUTPUT_DIR . '/states/sniscan_*.json',
                $RIWAYAT_DIR . '/sniscan_*',
                $UPLOAD_DIR . '/sniscan_*',
            ];
        }
        $deleted = 0;
        foreach ($patterns as $pat) {
            foreach (glob($pat) as $f) {
                if (is_file($f) && @unlink($f)) $deleted++;
            }
        }
        echo json_encode(['success' => true, 'message' => "Riwayat $type dihapus ($deleted file).", 'deleted' => $deleted]);
        exit;
    }

    if ($action === 'download_history') {
        header('Content-Type: application/json');
        $files = glob($OUTPUT_DIR . '/' . $type . '_*.json');
        if ($files === false) $files = [];
        $collected = [];
        foreach ($files as $f) {
            $data = json_decode(file_get_contents($f), true);
            if (!is_array($data)) continue;
            if ($type === 'sniscan') {
                // data bisa object dengan results
                $results = [];
                if (isset($data['results']) && is_array($data['results'])) {
                    $results = $data['results'];
                    $domain = $data['domain'] ?? '';
                } elseif (is_array($data)) {
                    $results = $data;
                    $domain = '';
                }
                foreach ($results as $r) {
                    if (is_array($r) && ($r['status'] ?? '') === '200') {
                        if ($domain !== '' && !isset($r['domain'])) $r['domain'] = $domain;
                        $collected[] = $r;
                    }
                }
            } else {
                foreach ($data as $r) {
                    if (is_array($r) && ($r['status'] ?? '') === '200') {
                        $collected[] = $r;
                    }
                }
            }
        }
        $dest = $RIWAYAT_DIR . '/' . $type . '_200_' . date('Ymd_His') . '.json';
        file_put_contents($dest, json_encode($collected, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        $fname = basename($dest);
        echo json_encode(['success' => true, 'message' => count($collected) . ' entri status 200.', 'filename' => $fname, 'download_url' => 'admin.php?action=download_file&type=' . urlencode($type) . '&file=' . urlencode($fname)]);
        exit;
    }

    if ($action === 'download_file') {
        $fname = basename($_GET['file'] ?? '');
        if ($fname === '' || !preg_match('/^[a-zA-Z0-9._-]+\.json$/', $fname)) {
            http_response_code(400);
            exit;
        }
        $path = $RIWAYAT_DIR . '/' . $fname;
        if (!is_file($path)) {
            http_response_code(404);
            exit;
        }
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $fname . '"');
        readfile($path);
        exit;
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
    <link rel="stylesheet" href="./css/style.css?v=73">
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
    <link rel="stylesheet" href="./css/style.css?v=73">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>

        <div class="admin-bar">
            <span class="admin-status" id="admin-datetime">Memuat waktu...</span>
            <div class="admin-actions">
                <button type="button" class="btn-change" id="btn-change-creds">Akun</button>
                <button type="button" class="btn-logout" id="btn-logout">Logout</button>
            </div>
        </div>

        <div id="creds-modal" class="hidden">
            <div class="admin-form">
                <h3 style="margin-top:0;">Perubahan Akun</h3>
                <div class="login-field">
                    <label class="login-label">Username baru:</label>
                    <input type="text" id="new-user" required>
                </div>
                <div class="login-field">
                    <label class="login-label">Password baru:</label>
                    <div class="password-input-wrapper">
                        <input type="password" id="new-pass" required>
                        <button type="button" class="password-toggle" onclick="togglePwd('new-pass','toggle-new-pass')" id="toggle-new-pass">
                            <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        </button>
                    </div>
                </div>
                <div class="login-field">
                    <label class="login-label">Konfirmasi password:</label>
                    <div class="password-input-wrapper">
                        <input type="password" id="new-pass-confirm" required>
                        <button type="button" class="password-toggle" onclick="togglePwd('new-pass-confirm','toggle-new-pass-confirm')" id="toggle-new-pass-confirm">
                            <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        </button>
                    </div>
                </div>
                <div id="creds-error" class="error hidden"></div>
                <div id="creds-success" class="success hidden"></div>
                <div class="spacer"></div>
                <div class="creds-actions">
                    <button type="button" class="btn-login" id="btn-save-creds">Simpan</button>
                    <button type="button" class="btn-logout" id="btn-cancel-creds">Batal</button>
                </div>
                <div class="divider"></div>
            </div>
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

        const eyeOpenCreds = '<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
        const eyeClosedCreds = '<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        function togglePwd(inputId, btnId) {
            const input = document.getElementById(inputId);
            const btn = document.getElementById(btnId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = eyeOpenCreds;
            } else {
                input.type = 'password';
                btn.innerHTML = eyeClosedCreds;
            }
        }

        // Ubah akun (AJAX)
        (function() {
            const modal = document.getElementById('creds-modal');
            const btnOpen = document.getElementById('btn-change-creds');
            const btnCancel = document.getElementById('btn-cancel-creds');
            const btnSave = document.getElementById('btn-save-creds');
            const errBox = document.getElementById('creds-error');
            const succBox = document.getElementById('creds-success');
            function showBox(box, msg) { box.textContent = msg; box.classList.remove('hidden'); }
            function hideBoxes() { errBox.classList.add('hidden'); succBox.classList.add('hidden'); errBox.textContent=''; succBox.textContent=''; }
            btnOpen.addEventListener('click', function() {
                hideBoxes();
                document.getElementById('new-user').value = '';
                document.getElementById('new-pass').value = '';
                document.getElementById('new-pass-confirm').value = '';
                modal.classList.remove('hidden');
            });
            btnCancel.addEventListener('click', function() {
                modal.classList.add('hidden');
                hideBoxes();
            });
            btnSave.addEventListener('click', async function() {
                hideBoxes();
                const u = document.getElementById('new-user').value.trim();
                const p = document.getElementById('new-pass').value;
                const c = document.getElementById('new-pass-confirm').value;
                if (!u || !p) { showBox(errBox, 'Username dan password tidak boleh kosong.'); return; }
                if (p !== c) { showBox(errBox, 'Konfirmasi password tidak cocok.'); return; }
                const body = 'change_creds=1&new_user=' + encodeURIComponent(u) + '&new_pass=' + encodeURIComponent(p);
                try {
                    const resp = await fetch('admin.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: body
                    });
                    const data = await resp.json();
                    if (data.success) {
                        showBox(succBox, data.message || 'Berhasil.');
                        setTimeout(function() { window.location.href = 'admin.php'; }, 1200);
                    } else {
                        showBox(errBox, data.message || 'Gagal.');
                    }
                } catch (e) {
                    showBox(errBox, 'Error: ' + e.message);
                }
            });
        })();
    </script>
</body>
</html>