<?php
// index.php - Web antarmuka untuk CDNScan, SubFind, SNIScan, D2IP (AJAX)
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surfinder Web</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>&#127983; Surfinder Web</h1>

        <nav class="tabs">
            <button class="tab active" onclick="showTab('d2ip', this)">D2IP</button>
            <button class="tab" onclick="showTab('rdns', this)">IP2D</button>
            <button class="tab" onclick="showTab('subfind', this)">SubFind</button>
            <button class="tab" onclick="showTab('cdnscan', this)">CDNScan</button>
            <button class="tab" onclick="showTab('sniscan', this)">SNIScan</button>
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
                <form id="form-cdnscan" onsubmit="handleScan(event, 'cdnscan')">
                    <label>Target (CIDR / IP / Provider):</label>
                    <input type="text" name="target" placeholder="173.245.48.0/20 atau cloudflare" required>
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

    <script src="script.js"></script>
</body>
</html>
