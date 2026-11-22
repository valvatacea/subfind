<?php
// scan.php - Backend AJAX: jalankan skrip Python di latar belakang, polling hasil
header('Content-Type: application/json');
set_time_limit(0);

$BASE_DIR = '/root/subfind';
$OUTPUT_DIR = $BASE_DIR . '/output';

$action = $_POST['action'] ?? '';
$target = $_POST['target'] ?? '';
$poll = $_GET['poll'] ?? '';

// Validasi action
$allowed_actions = ['d2ip', 'subfind', 'cdnscan', 'sniscan'];
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
if ($poll) {
    $pid = (int)$poll;
    $running = shell_exec("ps -p $pid -o pid=");
    $running = trim($running);

    $outFile = $OUTPUT_DIR . "/scan_$pid.txt";
    $jsonFile = null;

    // Tentukan file JSON output berdasarkan action dan target
    if ($action === 'subfind') {
        $jsonFile = $OUTPUT_DIR . "/subfind_$target.json";
    } elseif ($action === 'sniscan') {
        $jsonFile = $OUTPUT_DIR . "/sniscan_$target.json";
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

    if (!$running && file_exists($outFile)) {
        // Scan selesai
        $output = file_get_contents($outFile);
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
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'Scan tidak ditemukan atau sudah dihapus',
            'pid' => $pid
        ]);
        exit;
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
    ];
    $script = "python3 " . $script_map[$action] . " $target_escaped";
}

$command = "cd $BASE_DIR && nohup $script > $OUTPUT_DIR/scan_%d.txt 2>&1 & echo \$!";
// Jalankan dan ambil PID
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
$pid = proc_get_status($process)['pid'];
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

echo json_encode([
    'success' => true,
    'status' => 'started',
    'pid' => $pid,
    'message' => "Scan dimulai untuk $target"
]);
exit;
