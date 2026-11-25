<?php
// scan.php - Backend AJAX: jalankan skrip Python di latar belakang, polling hasil
header('Content-Type: application/json');
set_time_limit(0);

$BASE_DIR = '/root/subfind';
$OUTPUT_DIR = $BASE_DIR . '/output';
$PYTHON = file_exists($BASE_DIR . '/.venv/bin/python') ? $BASE_DIR . '/.venv/bin/python' : 'python3';

$action = $_POST['action'] ?? ($_GET['action'] ?? '');
$target = $_POST['target'] ?? ($_GET['target'] ?? '');
$limit = $_POST['limit'] ?? ($_GET['limit'] ?? '');
$poll = $_GET['poll'] ?? '';

// Validasi action
$allowed_actions = ['d2ip', 'subfind', 'cdnscan', 'cdnscan_ranges', 'sniscan', 'rdns'];
if (!in_array($action, $allowed_actions)) {
    echo json_encode(['success' => false, 'error' => 'Aksi tidak valid']);
    exit;
}

// Validasi target: hanya alfanumerik, titik, strip, slash
if (!preg_match('/^[a-zA-Z0-9.\/-]+$/', $target)) {
    echo json_encode(['success' => false, 'error' => 'Target tidak valid']);
    exit;
}

// --- POLLING: cek status scan yang berjalan ---
if ($poll || isset($_GET['scan_id'])) {
    $scan_id = $_GET['scan_id'] ?? '';
    if ($scan_id !== '') {
        $outFile = $OUTPUT_DIR . "/scan_" . $scan_id . ".txt";
        $pidFile = $OUTPUT_DIR . "/scan_" . $scan_id . ".pid";
        $pid = file_exists($pidFile) ? (int)trim(file_get_contents($pidFile)) : 0;
    } else {
        $pid = (int)$poll;
        $outFile = $OUTPUT_DIR . "/scan_$pid.txt";
        $pidFile = null;
    }
    if ($pid <= 0) {
        // scan baru dimulai, pidFile belum siap
        $running = file_exists($outFile) ? 'starting' : '';
    } else {
        $running = trim(shell_exec("ps -p $pid -o pid="));
    }
    $jsonFile = null;

    // Tentukan file JSON output berdasarkan action dan target
    if ($action === 'subfind') {
        $jsonFile = $OUTPUT_DIR . "/subfind_$target.json";
    } elseif ($action === 'sniscan') {
        $jsonFile = $OUTPUT_DIR . "/sniscan_$target.json";
    } elseif ($action === 'rdns') {
        $safe = str_replace(':', '_', $target);
        $jsonFile = $OUTPUT_DIR . "/rdns_$safe.json";
    } elseif ($action === 'cdnscan') {
        // CDNScan menyimpan per range dengan safe name, cari file terbaru
        $files = glob($OUTPUT_DIR . '/cdnscan_*.json');
        if ($files) {
            usort($files, function($a, $b) {
                return filemtime($b) - filemtime($a);
            });
            $jsonFile = $files[0];
        }
    }

    $output = file_exists($outFile) ? file_get_contents($outFile) : '';
    // Anggap selesai hanya jika output berisi marker penyelesaian
    $completed = (!$running) && file_exists($outFile) && (
        stripos($output, 'Hasil disimpan') !== false ||
        stripos($output, 'Selesai') !== false ||
        stripos($output, 'Error:') !== false ||
        stripos($output, 'Scan semua target selesai') !== false
    );

    if ($completed) {
        // Scan selesai

        $jsonData = null;
        if ($jsonFile && file_exists($jsonFile)) {
            $jsonData = json_decode(file_get_contents($jsonFile), true);
        }

        echo json_encode([
            'success' => true,
            'status' => 'completed',
            'output' => $output,
            'json' => $jsonData,
            'pid' => $pid
        ]);
        exit;
    } elseif ($running) {
        echo json_encode([
            'success' => true,
            'status' => 'running',
            'pid' => $pid
        ]);
        exit;
    } elseif (file_exists($outFile)) {
        // Scan masih berjalan (belum ada marker penyelesaian)
        echo json_encode([
            'success' => true,
            'status' => 'running',
            'pid' => $pid
        ]);
        exit;
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'Scan tidak ditemukan atau sudah dihapus',
            'pid' => $pid
        ]);
        exit;
    }
}

// --- LIST RANGES PROVIDER (CDNScan) ---
if ($action === 'cdnscan_ranges') {
    $provider = strtolower(trim($target));
    if (!in_array($provider, ['cloudflare', 'cloudfront'])) {
        echo json_encode(['success' => false, 'error' => 'Provider tidak valid']);
        exit;
    }
    $cmd = "cd " . escapeshellarg($BASE_DIR) . " && $PYTHON -c " . escapeshellarg(
        "import sys,json; sys.path.insert(0,'.'); from cdnscan import get_provider_ips; ips,err=get_provider_ips('$provider'); print(json.dumps(ips or []))"
    );
    $out = shell_exec($cmd . " 2>/dev/null");
    $ranges = json_decode($out, true);
    if (!is_array($ranges)) $ranges = [];
    echo json_encode(['success' => true, 'provider' => $provider, 'ranges' => $ranges]);
    exit;
}

// Validasi limit (opsional)
$limit_arg = '';
if ($limit !== '' && ctype_digit((string)$limit)) {
    $l = (int)$limit;
    if ($l >= 1 && $l <= 1000) {
        $limit_arg = " --limit " . $l;
    }
}

// --- MULAI SCAN BARU ---
$target_escaped = escapeshellarg($target);

if ($action === 'd2ip') {
    $script = "bash d2ip.sh $target_escaped";
} else {
    $script_map = [
        'subfind' => 'subfind.py',
        'cdnscan' => 'cdnscan.py',
        'sniscan' => 'sniscan.py',
        'rdns' => 'rdns.py',
    ];
    $script = "$PYTHON " . $script_map[$action] . " $target_escaped" . ($action === 'cdnscan' ? $limit_arg : '');
}

// ID unik untuk scan ini (untuk file progress & pid)
$scan_id = uniqid('scan', true);
$outFile = $OUTPUT_DIR . "/scan_" . $scan_id . ".txt";
$pidFile = $OUTPUT_DIR . "/scan_" . $scan_id . ".pid";

$command = "cd $BASE_DIR && nohup $script > " . escapeshellarg($outFile) . " 2>&1 & echo \$! > " . escapeshellarg($pidFile);
$descriptorSpec = [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"],
];
$process = proc_open($command, $descriptorSpec, $pipes, $BASE_DIR);
if (!is_resource($process)) {
    echo json_encode(['success' => false, 'error' => 'Gagal memulai scan']);
    exit;
}
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Tunggu sebentar agar pidFile terisi
usleep(200000);
$pid = 0;
if (file_exists($pidFile)) {
    $pid = (int)trim(file_get_contents($pidFile));
}

echo json_encode([
    'success' => true,
    'status' => 'started',
    'scan_id' => $scan_id,
    'pid' => $pid,
    'message' => "Scan dimulai untuk $target"
]);
exit;
