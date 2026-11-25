// script.js - AJAX logic untuk scan seamless (background + polling)

function showTab(tabName, btn) {
    // Sembunyikan semua panel
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));

    // Tampilkan panel yang dipilih
    document.getElementById('panel-' + tabName).classList.add('active');
    btn.classList.add('active');
}

function handleScanDirect(action, target) {
    handleScan(null, action, target);
}

async function loadCdnRanges(provider) {
    const container = document.getElementById('cdnscan-ranges');
    if (!provider) { container.innerHTML = ''; return; }
    container.innerHTML = '<div class="scanning"><div class="spinner"></div><span class="status-text">Memuat IP range...</span></div>';
    try {
        const resp = await fetch(`scan.php?action=cdnscan_ranges&target=${encodeURIComponent(provider)}`);
        const data = await resp.json();
        if (!data.success) { container.innerHTML = `<div class="error">${escapeHtml(data.error || 'Gagal')}</div>`; return; }
        const ranges = data.ranges || [];
        if (ranges.length === 0) { container.innerHTML = '<div class="error">Tidak ada range</div>'; return; }
        let html = `<h3>IP Range ${escapeHtml(provider)} (${ranges.length})</h3>`;
        html += `<button type="button" onclick="handleScanDirect('cdnscan','${provider}')" style="margin-bottom:8px;">Scan semua range</button><br>`;
        ranges.forEach(r => {
            html += `<button type="button" onclick="handleScanDirect('cdnscan','${escapeHtml(r)}')" style="margin:2px;">${escapeHtml(r)}</button> `;
        });
        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = `<div class="error">Error: ${escapeHtml(err.message)}</div>`;
    }
}

async function handleScan(event, action, targetOverride = null) {
    if (event) event.preventDefault();

    const form = event ? event.target : document.getElementById('form-' + action);
    const targetInput = form ? form.querySelector('input[name="target"]') : null;
    const target = (targetOverride !== null && targetOverride !== undefined) ? String(targetOverride).trim() : (targetInput ? targetInput.value.trim() : '');

    // Jika dipanggil via tombol provider, isi input juga
    if (targetOverride !== null && targetOverride !== undefined && targetInput) {
        targetInput.value = target;
    }

    if (!target) {
        showError(form, 'Masukkan target terlebih dahulu');
        return;
    }

    const resultArea = document.getElementById('result-' + action);
    resultArea.innerHTML = '';

    // Tombol loading
    const btn = form.querySelector('button[type="submit"]');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Sedang memindai...';

    // Tampilkan spinner
    resultArea.innerHTML = `
        <div class="scanning" style="margin-top:15px;">
            <div class="spinner"></div>
            <span class="status-text"><span id="status-text-${action}">Memulai...</span></span>
        </div>
    `;

    try {
        // 1. Mulai scan di backend
        const startResp = await fetch('scan.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=${encodeURIComponent(action)}&target=${encodeURIComponent(target)}`
        });
        const startData = await startResp.json();

        if (!startData.success) {
            showError(resultArea, startData.error || 'Gagal memulai scan');
            btn.disabled = false;
            btn.textContent = originalText;
            return;
        }

        const scanId = startData.scan_id;

        // 2. Polling setiap 2 detik
        const statusText = document.getElementById('status-text-' + action);
        const pollInterval = setInterval(async () => {
            const pollResp = await fetch(`scan.php?scan_id=${encodeURIComponent(scanId)}&action=${encodeURIComponent(action)}&target=${encodeURIComponent(target)}`);
            const pollData = await pollResp.json();

            if (!pollData.success) {
                clearInterval(pollInterval);
                showError(resultArea, pollData.error || 'Scan gagal');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }

            if (pollData.status === 'running') {
                const msgMap = {
                    'd2ip': ['Resolve domain', 'Query DNS', 'Mengumpulkan IP'],
                    'subfind': ['Enumerasi subdomain', 'Resolve IP', 'Scan port', 'Deteksi CDN'],
                    'cdnscan': ['Parse IP range', 'Deteksi CDN', 'Scan port'],
                    'sniscan': ['TLS handshake', 'Scan port', 'Deteksi CDN'],
                    'rdns': ['Reverse DNS lookup', 'Query PTR'],
                };
                const msgs = msgMap[action] || ['Memindai target', 'Mengumpulkan data', 'Memproses hasil'];
                const idx = (statusText.dataset.idx || 0);
                const next = (parseInt(idx) + 1) % msgs.length;
                statusText.dataset.idx = next;
                const dots = '.'.repeat((parseInt(idx) % 3) + 1);
                statusText.textContent = msgs[idx % msgs.length] + dots;
                return;
            }

            if (pollData.status === 'completed') {
                clearInterval(pollInterval);
                btn.disabled = false;
                btn.textContent = originalText;

                // Tampilkan hasil
                const statusBadge = `<span class="status-badge status-completed">Selesai</span>`;
                resultArea.innerHTML = statusBadge + '<br><br>';

                if (pollData.json) {
                    renderJsonResults(resultArea, pollData.json, action);
                }

                if (pollData.output) {
                    resultArea.innerHTML += `<h3>Result:</h3><pre>${escapeHtml(pollData.output)}</pre>`;
                }
            }
        }, 2000);

    } catch (err) {
        showError(resultArea, 'Terjadi kesalahan jaringan: ' + err.message);
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

function showError(container, message) {
    container.innerHTML = `<div class="error">&#128561; ${message}</div>`;
}

function renderJsonResults(container, jsonData, action) {
    // Normalisasi: CLI sniscan/cdnscan mungkin membungkus hasil di .results
    if (jsonData && !Array.isArray(jsonData) && Array.isArray(jsonData.results)) {
        jsonData = jsonData.results;
    }
    if (!jsonData || (Array.isArray(jsonData) && jsonData.length === 0)) {
        container.innerHTML += `<div class="error">Tidak ada hasil ditemukan</div>`;
        return;
    }

    // Tentukan kolom berdasarkan action
    let columns = [];
    let rows = [];

    if (action === 'subfind') {
        columns = ['Subdomain', 'IP', 'Ports', 'Status', 'CDN'];
        rows = jsonData.map(r => [
            r.subdomain || '-',
            r.ip || '-',
            r.ports || '-',
            r.status || '-',
            r.cdn || '-'
        ]);
    } else if (action === 'cdnscan') {
        columns = ['IP', 'Ports', 'CDN', 'Status'];
        rows = jsonData.map(r => [
            r.ip || '-',
            r.ports || '-',
            r.cdn || '-',
            r.status || '-'
        ]);
    } else if (action === 'sniscan') {
        columns = ['SNI Host', 'IP', 'TLS Version', 'ALPN', 'Port TLS', 'Extra Ports', 'Response Time', 'Status'];
        rows = jsonData.map(r => [
            r.sni_host || '-',
            r.ip || '-',
            r.tls_version || '-',
            r.alpn || '-',
            r.tls_port || '-',
            r.extra_ports || '-',
            r.response_time_ms || '-',
            r.status || '-'
        ]);
    } else if (action === 'd2ip') {
        // d2ip biasanya output teks, bukan JSON terstruktur
        container.innerHTML += `<h3>Hasil D2IP:</h3>`;
        return;
    } else if (action === 'rdns') {
        if (jsonData && jsonData.error) {
            container.innerHTML += `<div class="error">${escapeHtml(jsonData.error)}</div>`;
            return;
        }
        const names = (jsonData && jsonData.hostnames) || [];
        if (names.length === 0) {
            container.innerHTML += `<div class="error">Tidak ada PTR record</div>`;
            return;
        }
        let html = `<h3>Hasil IP2D (${names.length} hostname)</h3><ul>`;
        names.forEach(n => html += `<li>${escapeHtml(n)}</li>`);
        html += `</ul>`;
        container.innerHTML += html;
        return;
    }

    if (rows.length === 0) {
        container.innerHTML += `<div class="error">Tidak ada hasil ditemukan</div>`;
        return;
    }

    let html = `<h3>Hasil Scan (${rows.length} data)</h3>`;
    html += `<table><thead><tr>`;
    columns.forEach(col => html += `<th>${escapeHtml(col)}</th>`);
    html += `</tr></thead><tbody>`;
    rows.forEach(row => {
        html += `<tr>`;
        row.forEach(cell => html += `<td>${escapeHtml(cell)}</td>`);
        html += `</tr>`;
    });
    html += `</tbody></table>`;

    container.innerHTML += html;
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '-';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
