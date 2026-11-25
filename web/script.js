// script.js - AJAX logic untuk scan seamless (background + polling)

function showTab(tabName, btn) {
    // Sembunyikan semua panel
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));

    // Tampilkan panel yang dipilih
    document.getElementById('panel-' + tabName).classList.add('active');
    btn.classList.add('active');
}

async function handleScan(event, action) {
    event.preventDefault();

    const form = event.target;
    const targetInput = form.querySelector('input[name="target"]');
    const target = targetInput.value.trim();

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
            <span class="status-text">Memulai scan... <span id="status-text-${action}">Memindai target.</span></span>
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
                const msgs = ['Memindai target', 'Mengumpulkan data', 'Memproses hasil', 'Hampir selesai'];
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
                    resultArea.innerHTML += `<h3>Output CLI:</h3><pre>${escapeHtml(pollData.output)}</pre>`;
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
