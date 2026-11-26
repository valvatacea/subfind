// script.js - AJAX logic untuk scan seamless (background + polling)

function showTab(tabName, btn) {
    // Sembunyikan semua panel
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));

    // Tampilkan panel yang dipilih
    document.getElementById('panel-' + tabName).classList.add('active');
    btn.classList.add('active');
}

function handleScanDirect(action, target, limit = null) {
    handleScan(null, action, target, limit);
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
        html += `<div style="margin-bottom:8px;">`;
        ranges.forEach(r => {
            html += `<button type="button" class="range-btn" onclick="selectCdnTarget('${escapeHtml(r)}')">${escapeHtml(r)}</button> `;
        });
        html += `</div>`;
        html += `<div id="cdnscan-limit-picker" style="margin-top:10px;"></div>`;
        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = `<div class="error">Error: ${escapeHtml(err.message)}</div>`;
    }
}

let currentCdnTarget = null;

function selectCdnTarget(target) {
    currentCdnTarget = target;
    const form = document.getElementById('form-cdnscan');
    const targetInput = document.querySelector('#form-cdnscan input[name="target"]');
    if (targetInput) {
        targetInput.value = target;
        targetInput.readOnly = true;
    }
    const scanBtn = form ? form.querySelector('button[type="submit"]') : null;
    const picker = document.getElementById('cdnscan-limit-picker');
    if (!picker) return;
    picker.innerHTML = `
        <div class="limit-picker">
            <b>Target:</b> ${escapeHtml(target)}<br>
            <b>Pilih limit IP (maks 1000):</b><br>
            <button type="button" class="limit-btn" onclick="setCdnLimit(500)">500</button>
            <button type="button" class="limit-btn" onclick="setCdnLimit(1000)">1000</button>
            <button type="button" class="limit-btn" onclick="showCustomLimit('${escapeHtml(target)}')">Custom</button>
            <button type="button" class="limit-btn" onclick="unlockCdnForm()">Batal</button>
        </div>
    `;
}

function unlockCdnForm() {
    const form = document.getElementById('form-cdnscan');
    if (form) {
        const targetInput = form.querySelector('input[name="target"]');
        if (targetInput) {
            targetInput.readOnly = false;
            targetInput.value = '';
        }
        const limitInput = form.querySelector('input[name="limit"]');
        if (limitInput) {
            limitInput.value = '';
        }
    }
    currentCdnTarget = null;
    const picker = document.getElementById('cdnscan-limit-picker');
    if (picker) {
        picker.innerHTML = '';
    }
}

function showCustomLimit(target) {
    const picker = document.getElementById('cdnscan-limit-picker');
    picker.innerHTML = `
        <div class="limit-picker">
            <b>Target:</b> ${escapeHtml(target)}<br>
            <label>Limit (1-1000):</label>
            <input type="number" id="cdnscan-custom-limit" min="1" max="1000" value="500" style="width:80px;">
            <button type="button" class="limit-btn" onclick="setCustomLimit()">Set</button>
            <button type="button" class="limit-btn" onclick="unlockCdnForm()">Batal</button>
        </div>
    `;
}

function setCdnLimit(limit) {
    const input = document.getElementById('cdnscan-limit-input');
    if (input) {
        input.value = limit;
    }
    const picker = document.getElementById('cdnscan-limit-picker');
    if (picker) {
        picker.innerHTML = `<div class="limit-picker" style="color:#4CAF50;"><b>Target:</b> <b>${escapeHtml(currentCdnTarget || target)}</b><br>Limit IP: <b>${limit}</b><br><button type="button" class="limit-btn" onclick="selectCdnTarget('${escapeHtml(currentCdnTarget || target)}')">Ubah limit</button> <button type="button" class="limit-btn" onclick="unlockCdnForm()">Batal</button></div>`;
    }
}

function setCustomLimit() {
    const input = document.getElementById('cdnscan-custom-limit');
    const hidden = document.getElementById('cdnscan-limit-input');
    if (!input || !hidden) return;
    const v = parseInt(input.value, 10);
    if (isNaN(v) || v < 1 || v > 1000) {
        alert('Limit harus 1-1000');
        return;
    }
    hidden.value = v;
    const picker = document.getElementById('cdnscan-limit-picker');
    if (picker) {
        picker.innerHTML = `<div class="limit-picker" style="color:#4CAF50;"><b>Target:</b> <b>${escapeHtml(currentCdnTarget)}</b><br>Limit IP: <b>${v}</b><br><button type="button" class="limit-btn" onclick="selectCdnTarget('${escapeHtml(currentCdnTarget)}')">Ubah limit</button> <button type="button" class="limit-btn" onclick="unlockCdnForm()">Batal</button></div>`;
    }
}

function setScanningState(scanning) {
    const selectors = ['.range-btn', '.limit-btn', '#form-cdnscan button[type="submit"]', '#form-cdnscan input'];
    selectors.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => { el.disabled = scanning; });
    });
    const ps = document.querySelector('.provider-select');
    if (ps) ps.disabled = scanning;
    if (scanning) {
        // Hapus elemen "Selesai." lama saat scan baru dimulai
        document.querySelectorAll('.status-selesai-d2ip, .status-selesai-rdns').forEach(el => el.remove());
    }
    if (!scanning) {
        const form = document.getElementById('form-cdnscan');
        if (form) {
            const targetInput = form.querySelector('input[name="target"]');
            if (targetInput) targetInput.readOnly = false;
        }
        const picker = document.getElementById('cdnscan-limit-picker');
        if (picker) picker.innerHTML = '';
    }
}

async function handleScan(event, action, targetOverride = null, limitOverride = null) {
    if (event) event.preventDefault();

    const form = event ? event.target : document.getElementById('form-' + action);
    const targetInput = form ? form.querySelector('input[name="target"]') : null;
    const limitInput = form ? form.querySelector('input[name="limit"]') : null;
    const target = (targetOverride !== null && targetOverride !== undefined) ? String(targetOverride).trim() : (targetInput ? targetInput.value.trim() : '');
    const formLimit = limitInput ? limitInput.value.trim() : '';

    // Jika dipanggil via tombol provider, isi input juga
    if (targetOverride !== null && targetOverride !== undefined && targetInput) {
        targetInput.value = target;
    }

    if (!target) {
        showError(form, 'Masukkan target terlebih dahulu');
        return;
    }

    setScanningState(true);

    // Hilangkan konfirmasi limit (tombol Ubah limit) setelah scan dimulai
    if (action === 'cdnscan') {
        const picker = document.getElementById('cdnscan-limit-picker');
        if (picker) picker.innerHTML = '';
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
            <span class="status-text"><span id="status-text-${action}">Memindai...</span></span>
            <div class="progress-wrap">
                <div class="progress-bar indeterminate"></div>
            </div>
        </div>
    `;

    try {
        // 1. Mulai scan di backend
        const startResp = await fetch('scan.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=${encodeURIComponent(action)}&target=${encodeURIComponent(target)}${limitOverride ? '&limit=' + encodeURIComponent(limitOverride) : (formLimit ? '&limit=' + encodeURIComponent(formLimit) : '')}`
        });
        const startData = await startResp.json();

        if (!startData.success) {
            showError(resultArea, startData.error || 'Gagal memulai scan');
            btn.disabled = false;
            btn.textContent = originalText;
            setScanningState(false);
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
                setScanningState(false);
                setScanningState(false);
                return;
            }

            if (pollData.status === 'running') {
                const pb = document.querySelector('#result-' + action + ' .progress-bar');
                if (pollData.progress_percent !== null && pollData.progress_percent !== undefined) {
                    // Gunakan persen numerik dari CLI sebagai acuan progress bar (deterministik)
                    const pct = Math.min(100, Math.max(0, parseInt(pollData.progress_percent, 10)));
                    statusText.textContent = 'Memindai... ' + pct + '%';
                    pb.classList.remove('indeterminate');
                    pb.classList.add('determinate');
                    pb.style.width = pct + '%';
                } else if (pollData.progress_text) {
                    statusText.textContent = pollData.progress_text;
                    const m = pollData.progress_text.match(/(\d+)\s*%/);
                    if (m && pb) {
                        const pct = Math.min(100, Math.max(0, parseInt(m[1], 10)));
                        pb.classList.remove('indeterminate');
                        pb.classList.add('determinate');
                        pb.style.width = pct + '%';
                    }
                } else {
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
                    if (pb) {
                        pb.classList.remove('determinate');
                        pb.classList.add('indeterminate');
                        pb.style.width = '';
                    }
                }
                return;
            }

            if (pollData.status === 'completed') {
                clearInterval(pollInterval);
                btn.disabled = false;
                btn.textContent = originalText;
                setScanningState(false);
                // Buka kunci form target setelah scan selesai
                const form = document.getElementById('form-cdnscan');
                if (form) {
                    const targetInput = form.querySelector('input[name="target"]');
                    if (targetInput) targetInput.readOnly = false;
                }

                // Hapus spinner dan progress bar sebelum menampilkan hasil (seluruh action, termasuk d2ip)
                resultArea.querySelectorAll('.spinner, .progress-bar, .progress-wrap, .scanning').forEach(el => el.remove());

                // Tampilkan hasil (tanpa badge "Selesai")
                if (pollData.json && action !== 'rdns') {
                    renderJsonResults(resultArea, pollData.json, action);
                    if (_tableData) {
                        _tableData.prefixHtml = '<br><br>';
                        _tableData.suffixHtml = '';
                        renderTablePage(resultArea, 1);
                    } else {
                        resultArea.insertAdjacentHTML('afterbegin', '<br><br>');
                    }
                } else {
                    // Tidak ada tabel: tampilkan output mentah penuh (d2ip, rdns, dst.)
                    resultArea.innerHTML = '<br><br>';
                    if (pollData.output) {
                        resultArea.innerHTML += `<h3>Hasil:</h3><pre>${escapeHtml(cleanCliOutput(pollData.output))}</pre>`;
                    }
                    // Tampilkan "Selesai." di bawah form (bukan di dalam hasil)
                    const form = document.getElementById('form-' + action);
                    if (form) {
                        const oldStatus = form.parentNode.querySelector('.status-selesai-' + action);
                        if (oldStatus) oldStatus.remove();
                        form.insertAdjacentHTML('afterend', `<span class="status-selesai status-selesai-${action}">Selesai.</span>`);
                    }
                }
            }
        }, 2000);

    } catch (err) {
        showError(resultArea, 'Terjadi kesalahan jaringan: ' + err.message);
        btn.disabled = false;
        btn.textContent = originalText;
        setScanningState(false);
    }
}

function showError(container, message) {
    container.innerHTML = `<div class="error">&#128561; ${message}</div>`;
}

let _tableData = null;
const TABLE_PER_PAGE = 20;

function renderTablePageById(containerId, page) {
    const c = document.getElementById(containerId);
    if (c && _tableData) { _tableData.container = c; renderTablePage(c, page); }
}

function renderTablePage(container, page) {
    if (!_tableData) return;
    const { columns, rows, action } = _tableData;
    const total = rows.length;
    const totalPages = Math.max(1, Math.ceil(total / TABLE_PER_PAGE));
    page = Math.max(1, Math.min(page, totalPages));
    const start = (page - 1) * TABLE_PER_PAGE;
    const chunk = rows.slice(start, start + TABLE_PER_PAGE);

    let html = `<h3>Hasil Scan (${total} data) — Halaman ${page}/${totalPages}</h3>`;
    html += `<div class="table-wrap"><table><thead><tr>`;
    columns.forEach(col => html += `<th>${escapeHtml(col)}</th>`);
    html += `</tr></thead><tbody>`;
    chunk.forEach(row => {
        html += `<tr>`;
        row.forEach(cell => html += `<td>${escapeHtml(cell)}</td>`);
        html += `</tr>`;
    });
    html += `</tbody></table></div>`;

    // Navigasi
    html += `<div class="pagination">`;
    if (page > 1) html += `<button type="button" class="page-btn" onclick="renderTablePageById('${_tableData.container.id}', ${page-1})">◀ Prev</button>`;
    html += `<span class="page-info">${page} / ${totalPages}</span>`;
    if (page < totalPages) html += `<button type="button" class="page-btn" onclick="renderTablePageById('${_tableData.container.id}', ${page+1})">Next ▶</button>`;
    html += `</div>`;

    // Render ke container yang disimpan
    const c = _tableData.container || container;
    const prefix = (_tableData.prefixHtml || '');
    const suffix = (_tableData.suffixHtml || '');
    if (c) c.innerHTML = prefix + html + suffix;
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
        columns = ['SNI Host', 'IP', 'TLS Version', 'ALPN', 'Port TLS', 'Extra Ports', 'Response Time', 'Status', 'CDN'];
        rows = jsonData.map(r => [
            r.sni_host || '-',
            r.ip || '-',
            r.tls_version || '-',
            r.alpn || '-',
            r.tls_port || '-',
            r.extra_ports || '-',
            r.response_time_ms || '-',
            r.status || '-',
            r.cdn || '-'
        ]);
    } else if (action === 'd2ip') {
        // d2ip biasanya output teks, bukan JSON terstruktur
        container.innerHTML += `<h3>Hasil D2IP:</h3>`;
        return;
    }

    if (rows.length === 0) {
        container.innerHTML += `<div class="error">Tidak ada hasil ditemukan</div>`;
        return;
    }

    // Urutkan tabel: Status (terendah dulu) → Memiliki Port → Memiliki CDN
    const statusCol = action === 'sniscan' ? 7 : 3;
    const portCol = action === 'cdnscan' ? 1 : (action === 'sniscan' ? 4 : 2);
    const cdnCol = action === 'cdnscan' ? 2 : (action === 'sniscan' ? 8 : 4);
    const extraPortsCol = action === 'sniscan' ? 5 : -1;
    const toNum = (v) => {
        const n = parseInt(String(v || '-'), 10);
        return isNaN(n) ? Infinity : n;
    };
    const hasPort = (r) => {
        const p1 = String(r[portCol] || '-').trim();
        const p2 = extraPortsCol >= 0 ? String(r[extraPortsCol] || '-').trim() : '-';
        return p1 !== '-' || p2 !== '-';
    };
    const hasCdn = (r) => String(r[cdnCol] || '-').trim() !== '-';
    rows.sort((a, b) => {
        const na = toNum(a[statusCol]);
        const nb = toNum(b[statusCol]);
        if (na !== nb) return na - nb;
        const pa = hasPort(a) ? 1 : 0;
        const pb = hasPort(b) ? 1 : 0;
        if (pa !== pb) return pb - pa;
        const ca = hasCdn(a) ? 1 : 0;
        const cb = hasCdn(b) ? 1 : 0;
        if (ca !== cb) return cb - ca;
        return String(a[statusCol] || '-').localeCompare(String(b[statusCol] || '-'));
    });

    // Simpan data untuk pagination
    _tableData = { columns, rows, action, container, prefixHtml: '', suffixHtml: '', extraHtml: '' };
    _tableData.container = container;
    renderTablePage(container, 1);
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '-';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// Bersihkan baris progres mentah dan header/footer CLI dari output akhir (lapisan frontend)
function cleanCliOutput(text) {
    if (!text) return text;
    return text.split('\n').filter(line => {
        const t = line.trim();
        if (t === '') return true;
        if (/[█░]|\d+%|Elapsed|ETA/.test(t)) return false;
        if (/═══|-{5,}/.test(t)) return false;
        if (/^Scanning:/.test(t)) return false;
        return true;
    }).join('\n').trim();
}
