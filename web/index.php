<?php
// ============================================================
// SURFIND WEB — CACHE-BUSTING NOTE
// Setiap perubahan index.php / script.css / script.js: selalu naikkan query-string cache-busting dari v=N ke v=N+1 (jangan pertahankan v=2), biar browser fetch versi terbaru.
// Contoh: v=2 -> v=3, dst.
// ============================================================
// index.php - Web antarmuka untuk CDNScan, SubFind, SNIScan, D2IP (AJAX)
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surfinder</title>
    <link rel="stylesheet" href="./css/style.css?v=30">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder</h1>

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

            <!-- SubFind -->
            <div class="tab-panel" id="panel-subfind">
                <form id="form-subfind" onsubmit="handleScan(event, 'subfind')">
                    <label>Domain:</label>
                    <input type="text" name="target" placeholder="example.com" required>
                    <button type="submit">Scan</button>
                </form>
                <div id="result-subfind" class="result-area"></div>
            </div>

            <!-- CDNScan -->
            <div class="tab-panel" id="panel-cdnscan">
                <div style="margin-bottom:10px;">
                    <label>Provider:</label>
                    <select id="cdnscan-provider" class="provider-select" onchange="loadCdnRanges(this.value)">
                        <option value="">-- Pilih Provider --</option>
                        <option value="cloudflare">Cloudflare</option>
                        <option value="cloudfront">CloudFront</option>
                    </select>
                </div>
                <div id="cdnscan-ranges" class="result-area" style="margin-bottom:10px;"></div>
                <form id="form-cdnscan" onsubmit="handleScan(event, 'cdnscan')">
                    <label>Atau masukkan IP/CIDR manual:</label>
                    <input type="text" name="target" placeholder="173.245.48.0/20" required>
                    <input type="hidden" name="limit" id="cdnscan-limit-input" value="">
                    <button type="submit">Scan</button>
                </form>
                <div id="result-cdnscan" class="result-area"></div>
            </div>

            <!-- SNIScan -->
            <div class="tab-panel" id="panel-sniscan">
                <form id="form-sniscan" onsubmit="handleScan(event, 'sniscan')">
                    <label>Domain:</label>
                    <input type="text" name="target" placeholder="google.com" required>
                    <button type="submit">Scan</button>
                </form>
                <div id="result-sniscan" class="result-area"></div>
            </div>
        </div>
    </div>

    <script src="./js/script.js?v=34"></script>
</body>
</html>
