/**
 * SENTINEL v6.0.0 — Web Dashboard
 */

document.addEventListener('DOMContentLoaded', () => {
    // State
    let selectedModules = new Set();
    let ws = null;
    let vulnCounter = 0;
    let currentScanId = localStorage.getItem('sentinel_latest_scan_id');
    let currentPocData = null;
    let currentScanResults = [];
    let totalExpectedModules = 0;
    let completedModulesCount = 0;
    let completedModulesSet = new Set();
    let scanHistory = JSON.parse(localStorage.getItem('sentinel_archives') || '[]');
    const launchTime = Date.now();

    // Elements
    const modulesGrid = document.getElementById('modules-grid');
    const startBtn = document.getElementById('start-scan-btn');
    const targetUrlInput = document.getElementById('target-url');
    const resultsSection = document.getElementById('results-section');
    const logViewer = document.getElementById('log-viewer');
    const progressPercent = document.getElementById('progress-percent');
    const progressLine = document.getElementById('progress-line');
    const vulnCountEl = document.getElementById('vuln-count');
    const activeModEl = document.getElementById('active-mod');
    const findingsGrid = document.getElementById('findings-grid');
    const aiIntelSection = document.getElementById('ai-intel-section');
    const aiReportContainer = document.getElementById('ai-report-container');
    const aiReportContent = document.getElementById('ai-report-content');
    const aiLoading = document.getElementById('ai-loading');
    const aiLanguage = document.getElementById('ai-language');
    const pocModal = document.getElementById('poc-modal');
    const pocCode = document.getElementById('poc-code');

    // ── Toast Notifications ─────────────────────────
    function showToast(message, title = 'Notice', type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: 'fa-circle-check', error: 'fa-triangle-exclamation',
            warning: 'fa-circle-exclamation', info: 'fa-circle-info'
        };

        toast.innerHTML = `
            <div class="toast-icon"><i class="fa-solid ${icons[type] || icons.info}"></i></div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-msg">${message}</div>
            </div>
            <div class="toast-close">&times;</div>
        `;

        container.appendChild(toast);
        const close = () => { toast.classList.add('closing'); setTimeout(() => toast.remove(), 400); };
        toast.querySelector('.toast-close').onclick = close;
        if (duration > 0) setTimeout(close, duration);
    }

    // ── Session Timer ───────────────────────────────
    setInterval(() => {
        const diff = Date.now() - launchTime;
        const h = Math.floor(diff / 3600000).toString().padStart(2, '0');
        const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
        const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
        const el = document.getElementById('session-clock');
        if (el) el.textContent = `${h}:${m}:${s}`;
    }, 1000);

    // ── Navigation ──────────────────────────────────
    document.querySelectorAll('.nav-item').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = link.dataset.target;
            document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            link.classList.add('active');
            const view = document.getElementById(target);
            if (view) view.classList.add('active');

            if (target === 'history-view') loadScanHistory();
            if (target === 'payloads-view') { renderPayloads('all'); initPayloadCategories(); }
            if (target === 'templates-view') loadTemplates();
            if (target === 'settings-view') loadSettings();
        });
    });

    // ── Module Loading ──────────────────────────────
    async function initializeMatrix() {
        try {
            const response = await fetch('/api/modules');
            const modules = await response.json();
            modulesGrid.innerHTML = '';

            modules.forEach(mod => {
                const unit = document.createElement('div');
                unit.className = 'mod-unit active';
                unit.dataset.id = mod.id;
                selectedModules.add(mod.id);

                unit.innerHTML = `
                    <div class="mod-check"></div>
                    <div class="mod-name">${mod.name}</div>
                `;

                unit.onclick = () => {
                    if (selectedModules.has(mod.id)) {
                        selectedModules.delete(mod.id);
                        unit.classList.remove('active');
                    } else {
                        selectedModules.add(mod.id);
                        unit.classList.add('active');
                    }
                };

                modulesGrid.appendChild(unit);
            });
        } catch (err) {
            log('System', 'Failed to load modules. Check server connection.', 'error');
        }
    }

    document.getElementById('select-all').onclick = () => {
        document.querySelectorAll('.mod-unit').forEach(u => {
            selectedModules.add(u.dataset.id);
            u.classList.add('active');
        });
    };

    document.getElementById('deselect-all').onclick = () => {
        document.querySelectorAll('.mod-unit').forEach(u => {
            selectedModules.delete(u.dataset.id);
            u.classList.remove('active');
        });
    };

    // ── WebSocket ───────────────────────────────────
    let wsReconnectAttempts = 0;

    function connectWS() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        try {
            ws = new WebSocket(`${protocol}//${location.host}/ws`);
            ws.onopen = () => { wsReconnectAttempts = 0; log('System', 'Connected to server.', 'success'); };
            ws.onmessage = (e) => { try { processMessage(JSON.parse(e.data)); } catch (_) {} };
            ws.onclose = () => {
                if (wsReconnectAttempts < 10) {
                    wsReconnectAttempts++;
                    setTimeout(connectWS, Math.min(1000 * 2 ** (wsReconnectAttempts - 1), 30000));
                }
            };
        } catch (_) { setTimeout(connectWS, 1000); }
    }
    connectWS();

    function log(source, message, status = 'info') {
        const line = document.createElement('div');
        line.className = `log-line ${status}`;
        const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
        line.innerHTML = `<span class="timestamp">[${time}]</span><span class="caller">${source}</span> ${message}`;
        logViewer.appendChild(line);
        logViewer.scrollTop = logViewer.scrollHeight;
    }

    function processMessage(data) {
        if (data.type === 'progress') {
            activeModEl.textContent = data.module;
            if ((data.status === 'completed' || data.percentage === 100) && !completedModulesSet.has(data.module)) {
                completedModulesSet.add(data.module);
                completedModulesCount++;
            }
            const pct = totalExpectedModules > 0 ? Math.min((completedModulesCount / totalExpectedModules) * 100, 100) : Math.min(data.percentage, 100);
            progressPercent.textContent = `${Math.round(pct)}%`;
            progressLine.style.width = `${pct}%`;
            log(data.module, data.status, 'info');
        } else if (data.type === 'module_result') {
            currentScanResults.push(data);
            renderFindings(currentScanResults);
            if (data.vulnerabilities?.length > 0) {
                log(data.module, `${data.vulnerabilities.length} vulnerability found`, 'error');
            }
        } else if (data.type === 'complete') {
            log('Scan', 'Scan completed.', 'success');
            activeModEl.textContent = 'Done';
            progressLine.style.width = '100%';
            progressPercent.textContent = '100%';
            currentScanId = data.scan_id;
            localStorage.setItem('sentinel_latest_scan_id', data.scan_id);
            currentScanResults = data.results;
            renderFindings(data.results);
            document.querySelectorAll('.ai-btn').forEach(b => { b.disabled = false; });
            if (aiIntelSection) aiIntelSection.classList.remove('hidden');
            archiveScan({ url: targetUrlInput.value, timestamp: new Date().toLocaleString(), vulns: vulnCounter, scan_id: data.scan_id });
        } else if (data.type === 'error') {
            log('Error', data.message, 'error');
            activeModEl.textContent = 'Failed';
        } else if (data.type === 'ai_report') {
            handleAIReport(data);
        }
    }

    // ── Scan Launch ─────────────────────────────────
    startBtn.onclick = async () => {
        const url = targetUrlInput.value.trim();
        if (!url) return showToast('Please enter a target URL.', 'Error', 'error');
        if (selectedModules.size === 0) return showToast('No modules selected.', 'Error', 'error');

        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
        resultsSection.classList.remove('hidden');
        if (aiReportContainer) aiReportContainer.style.display = 'none';
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        logViewer.innerHTML = '';
        currentScanResults = [];
        completedModulesCount = 0;
        completedModulesSet = new Set();
        totalExpectedModules = selectedModules.size;
        document.querySelectorAll('.ai-btn').forEach(b => { b.disabled = true; });
        findingsGrid.innerHTML = '';
        vulnCounter = 0;
        vulnCountEl.textContent = '0';
        if (vulnChart) { vulnChart.data.datasets[0].data = [0, 0, 0, 0, 0]; vulnChart.update(); }
        activeModEl.textContent = 'Starting...';
        progressLine.style.width = '0%';

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, modules: Array.from(selectedModules) })
            });
            const data = await response.json();
            currentScanId = data.scan_id;
            log('Scan', `Started scanning ${url}`, 'success');
        } catch (err) {
            log('Error', 'Failed to start scan.', 'error');
            showToast('Cannot connect to scan engine.', 'Error', 'error');
        } finally {
            startBtn.disabled = false;
            startBtn.innerHTML = '<i class="fa-solid fa-play"></i> Start Scan';
        }
    };

    // ── Findings Renderer ───────────────────────────
    let vulnChart = null;

    function initChart() {
        if (typeof Chart === 'undefined') return;
        const ctx = document.getElementById('vuln-chart')?.getContext('2d');
        if (!ctx) return;
        vulnChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'], borderWidth: 0 }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, cutout: '70%',
                plugins: { legend: { position: 'right', labels: { color: '#a0a0ab', font: { size: 11, family: 'Inter' } } } }
            }
        });
    }
    setTimeout(initChart, 500);

    function renderFindings(results) {
        findingsGrid.innerHTML = '';
        vulnCounter = 0;
        let vulnIndex = 0;
        const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

        results.forEach(res => {
            (res.vulnerabilities || []).forEach(v => {
                const idx = vulnIndex++;
                vulnCounter++;
                let s = (v.severity || 'info').toLowerCase();
                if (s === 'crit') s = 'critical';
                if (!sev.hasOwnProperty(s)) s = 'info';
                sev[s]++;

                const card = document.createElement('div');
                card.className = `finding-card ${s}`;

                const cvss = v.cvss_score || 0;
                const cvssClass = cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';

                const isChain = res.module === 'ChainAnalyzer';

                card.innerHTML = `
                    <div class="finding-header">
                        <div class="finding-title">${isChain ? '🔗 ' : ''}${v.title || 'Vulnerability'}</div>
                        <div class="finding-meta">
                            ${cvss > 0 ? `<span class="cvss-badge ${cvssClass}">CVSS ${cvss.toFixed(1)}</span>` : ''}
                            <span class="badge badge-${s}">${s}</span>
                        </div>
                    </div>
                    <div class="finding-desc">${v.description || ''}</div>
                    ${v.cwe_id ? `<div class="finding-cwe"><i class="fa-solid fa-tag"></i> ${v.cwe_id}</div>` : ''}
                    ${isChain && v.evidence && Array.isArray(v.evidence) ? `
                        <div style="margin-bottom:10px; font-size:12px;">
                            ${v.evidence.map((step, i) => `<div style="margin:4px 0; padding-left:12px; border-left:2px solid var(--red)"><strong>Step ${i + 1}:</strong> ${step.step || ''}</div>`).join('')}
                        </div>
                    ` : ''}
                    ${v.remediation ? `<div class="finding-fix"><strong>Fix</strong>${v.remediation}</div>` : ''}
                    <button class="btn-ghost poc-btn" data-index="${idx}" style="margin-top:8px">
                        <i class="fa-solid fa-code"></i> PoC
                    </button>
                `;

                card.querySelector('.poc-btn').addEventListener('click', () => showPoCModal(idx));
                findingsGrid.appendChild(card);
            });
        });

        vulnCountEl.textContent = vulnCounter;
        if (vulnChart) {
            vulnChart.data.datasets[0].data = [sev.critical, sev.high, sev.medium, sev.low, sev.info];
            vulnChart.update();
        }
        if (vulnCounter === 0) {
            findingsGrid.innerHTML = '<div class="empty-state" style="padding:40px">No vulnerabilities found.</div>';
        }
    }

    // ── PoC Modal ────────────────────────────────────
    async function showPoCModal(vulnIndex) {
        if (!currentScanId) return;
        try {
            const response = await fetch(`/api/poc/${currentScanId}/${vulnIndex}`);
            if (!response.ok) throw new Error('Failed to generate PoC');
            currentPocData = await response.json();
            const formats = Object.keys(currentPocData.pocs).sort((a, b) => {
                const p = { nuclei: 0, python: 1, curl: 2, burp_request: 3, html: 4 };
                return (p[a] || 9) - (p[b] || 9);
            });
            if (formats.length > 0) showPoCFormat(formats[0]);
            document.querySelectorAll('.poc-tab').forEach(tab => {
                const fmt = tab.dataset.format;
                tab.style.display = currentPocData.pocs[fmt] ? 'block' : 'none';
                tab.classList.toggle('active', fmt === formats[0]);
            });
            pocModal.classList.remove('hidden');
        } catch (err) { log('PoC', err.message, 'error'); }
    }

    function showPoCFormat(format) {
        if (!currentPocData?.pocs[format]) return;
        pocCode.querySelector('code').textContent = currentPocData.pocs[format];
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.toggle('active', t.dataset.format === format));
    }

    document.querySelectorAll('.poc-tab').forEach(t => t.addEventListener('click', () => showPoCFormat(t.dataset.format)));
    document.getElementById('close-poc-modal')?.addEventListener('click', () => pocModal.classList.add('hidden'));
    document.getElementById('copy-poc')?.addEventListener('click', async () => {
        const code = pocCode.querySelector('code').textContent;
        try { await navigator.clipboard.writeText(code); showToast('Copied to clipboard.', 'Success', 'success', 2000); } catch (_) {}
    });
    pocModal?.addEventListener('click', (e) => { if (e.target.classList.contains('modal-backdrop')) pocModal.classList.add('hidden'); });

    // ── AI Reports ──────────────────────────────────
    function handleAIReport(data) {
        if (aiLoading) aiLoading.style.display = 'none';
        if (data.status === 'error') {
            if (aiReportContent) aiReportContent.innerHTML = `<div class="ai-section"><div class="ai-alert ai-alert-critical"><i class="fa-solid fa-circle-xmark ai-alert-icon"></i><div><div class="ai-alert-title">Failed</div><div class="ai-alert-text">${data.message}</div></div></div></div>`;
            return;
        }
        if (aiReportContent && data.data) {
            const types = { executive_summary: { icon: 'fa-chart-pie', title: 'Executive Summary' }, technical_report: { icon: 'fa-code', title: 'Technical Analysis' }, risk_narrative: { icon: 'fa-shield-halved', title: 'Risk Assessment' }, remediation_plan: { icon: 'fa-screwdriver-wrench', title: 'Remediation Plan' }, attack_scenarios: { icon: 'fa-crosshairs', title: 'Attack Scenarios' } };
            let html = `<div class="ai-report-header"><div class="ai-report-meta"><div class="ai-report-badge"><i class="fa-solid fa-brain"></i> AI</div><div class="ai-report-badge"><i class="fa-solid fa-clock"></i> ${new Date().toLocaleTimeString()}</div></div><div class="ai-report-actions"><button class="ai-action-btn" onclick="window.print()"><i class="fa-solid fa-print"></i> Print</button><button class="ai-action-btn" id="copy-report-btn"><i class="fa-solid fa-copy"></i> Copy</button></div></div>`;
            Object.entries(types).forEach(([key, cfg]) => {
                if (data.data[key]) html += `<div class="ai-section"><div class="ai-section-header"><div class="ai-section-icon"><i class="fa-solid ${cfg.icon}"></i></div><span class="ai-section-title">${cfg.title}</span></div><div class="ai-section-body">${formatAIText(data.data[key])}</div></div>`;
            });
            html += `<div class="ai-report-footer"><span>Generated by SENTINEL AI</span><span>${new Date().toLocaleString()}</span></div>`;
            aiReportContent.innerHTML = html;
            document.getElementById('copy-report-btn')?.addEventListener('click', async () => {
                try { await navigator.clipboard.writeText(aiReportContent.innerText); showToast('Report copied.', 'Success', 'success', 2000); } catch (_) {}
            });
        }
    }

    function formatAIText(text) {
        if (!text) return '';
        let html = text
            .replace(/^### (.+)$/gm, '<h4 class="ai-subsection-title">$1</h4>')
            .replace(/^## (.+)$/gm, '<h3 class="ai-subsection-title">$1</h3>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.+?)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\b(CRITICAL)\b/gi, '<span style="color:var(--red);font-weight:700">$1</span>')
            .replace(/\b(HIGH)\b/gi, '<span style="color:var(--orange);font-weight:700">$1</span>')
            .replace(/\b(MEDIUM)\b/gi, '<span style="color:var(--yellow);font-weight:700">$1</span>')
            .replace(/\b(LOW)\b/gi, '<span style="color:var(--green);font-weight:700">$1</span>')
            .replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>')
            .replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*?<\/li>\n?)+/gs, m => `<ul>${m}</ul>`);
        const parts = html.split(/\n\n+/);
        html = parts.map(p => p.trim().startsWith('<') ? p : p.trim() ? `<p>${p.replace(/\n/g, '<br>')}</p>` : '').join('');
        return html.replace(/<p>\s*<\/p>/g, '').replace(/<ul>\s*<\/ul>/g, '');
    }

    async function generateAIReport(reportType) {
        if (!currentScanId) { log('AI', 'No scan results. Run a scan first.', 'error'); return; }
        if (aiReportContainer) aiReportContainer.style.display = 'block';
        if (aiLoading) aiLoading.style.display = 'flex';
        if (aiReportContent) aiReportContent.innerHTML = '';
        try {
            await fetch('/api/ai/generate', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: currentScanId, report_type: reportType, language: aiLanguage?.value || 'en' })
            });
        } catch (err) {
            if (aiLoading) aiLoading.style.display = 'none';
            if (aiReportContent) { aiReportContent.innerHTML = `<div style="text-align:center;padding:2rem;color:var(--red)"><p>${err.message}</p><p style="font-size:11px;color:var(--text-3);margin-top:8px">Set GOOGLE_AI_API_KEY in .env to enable AI reports.</p></div>`; aiReportContainer.style.display = 'block'; }
        }
    }

    document.addEventListener('click', async (e) => {
        const aiBtn = e.target.closest('.ai-btn');
        if (!aiBtn) return;
        const type = aiBtn.dataset.type;
        if (!type || !currentScanId) return;
        const orig = aiBtn.innerHTML;
        aiBtn.disabled = true;
        aiBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating...';
        try { await generateAIReport(type); } finally { aiBtn.disabled = false; aiBtn.innerHTML = orig; }
    });

    // ── Scan History ────────────────────────────────
    function archiveScan(scan) {
        scanHistory.unshift(scan);
        if (scanHistory.length > 50) scanHistory.pop();
        localStorage.setItem('sentinel_archives', JSON.stringify(scanHistory));
    }

    async function loadScanHistory() {
        const list = document.getElementById('history-list');
        if (!list) return;
        try {
            const res = await fetch('/api/scans/history?limit=50');
            const data = await res.json();
            if (data.scans?.length > 0) { renderHistoryTable(data.scans); return; }
        } catch (_) {}
        if (scanHistory.length > 0) renderHistoryTable(scanHistory);
        else list.innerHTML = '<tr><td colspan="4" class="empty-state">No scan history yet</td></tr>';
    }

    function renderHistoryTable(scans) {
        const list = document.getElementById('history-list');
        if (!list) return;
        list.innerHTML = '';
        scans.forEach(scan => {
            const tr = document.createElement('tr');
            const count = scan.vulnerability_count || scan.vulns || 0;
            tr.innerHTML = `
                <td style="font-family:var(--mono);font-size:12px">${scan.url || scan.target || '—'}</td>
                <td>${scan.timestamp || scan.completed_at || '—'}</td>
                <td><span class="badge badge-${count > 0 ? 'critical' : 'low'}">${count}</span></td>
                <td><button class="btn-ghost re-run-btn" data-url="${scan.url || scan.target || ''}">Re-scan</button></td>
            `;
            tr.querySelector('.re-run-btn').onclick = () => {
                targetUrlInput.value = tr.querySelector('.re-run-btn').dataset.url;
                document.querySelector('[data-target="scan-view"]').click();
            };
            list.appendChild(tr);
        });
    }

    document.getElementById('clear-history')?.addEventListener('click', () => {
        if (!confirm('Clear all scan history?')) return;
        scanHistory = [];
        localStorage.setItem('sentinel_archives', '[]');
        loadScanHistory();
    });

    // ── Payloads ────────────────────────────────────
    const payloadModal = document.getElementById('payload-modal');
    let currentPayload = null;

    async function renderPayloads(category) {
        const tbody = document.getElementById('payload-table-body');
        if (!tbody) return;
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</td></tr>';
        try {
            const url = category === 'all' ? '/api/payloads' : `/api/payloads?category=${category}`;
            const res = await fetch(url);
            const payloads = await res.json();
            tbody.innerHTML = '';
            if (payloads.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No payloads found</td></tr>'; return; }
            payloads.forEach(p => {
                const tr = document.createElement('tr');
                const riskClass = (p.risk || 'medium').toLowerCase();
                tr.innerHTML = `
                    <td style="font-family:var(--mono);font-size:11px;color:var(--text-3)">${p.id}</td>
                    <td style="font-weight:500">${p.name}</td>
                    <td><span class="badge badge-${riskClass}">${p.risk || '—'}</span></td>
                    <td><button class="btn-ghost guide-btn" data-id="${p.id}">Details</button></td>
                `;
                tr.querySelector('.guide-btn').onclick = () => showPayloadDetails(p.id);
                tbody.appendChild(tr);
            });
        } catch (err) { tbody.innerHTML = '<tr><td colspan="4" class="empty-state" style="color:var(--red)">Failed to load</td></tr>'; }
    }

    function initPayloadCategories() {
        document.querySelectorAll('.payload-cats .cat-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.preventDefault();
                document.querySelectorAll('.payload-cats .cat-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                renderPayloads(btn.dataset.cat);
            };
        });
    }

    async function showPayloadDetails(pid) {
        try {
            const res = await fetch(`/api/payloads/${pid}/guide`);
            if (!res.ok) throw new Error('Not found');
            const data = await res.json();
            currentPayload = data;
            document.getElementById('pm-title').textContent = data.Title;
            document.getElementById('pm-payload').textContent = data.Payload;
            document.getElementById('pm-risk').textContent = (data.Risk || '').toUpperCase();
            document.getElementById('pm-risk').className = `badge badge-${(data.Risk || '').toLowerCase()}`;
            document.getElementById('pm-params').textContent = data['Target Params'];
            document.getElementById('pm-guide').textContent = data['Execution Guide'];
            document.getElementById('pm-evasion').textContent = data['Evasion Tips'];
            payloadModal.classList.remove('hidden');
        } catch (_) { showToast('Payload details not available.', 'Error', 'error'); }
    }

    document.getElementById('close-payload-modal')?.addEventListener('click', () => payloadModal?.classList.add('hidden'));
    document.getElementById('pm-copy-btn')?.addEventListener('click', () => {
        if (currentPayload) { navigator.clipboard.writeText(currentPayload.Payload); showToast('Copied.', 'Success', 'success', 2000); }
    });
    payloadModal?.addEventListener('click', (e) => { if (e.target.classList.contains('modal-backdrop')) payloadModal.classList.add('hidden'); });

    // ── Templates ───────────────────────────────────
    async function loadTemplates() {
        const grid = document.getElementById('templates-grid');
        if (!grid) return;
        try {
            const res = await fetch('/api/templates');
            const data = await res.json();
            const countEl = document.getElementById('template-count');
            if (countEl) countEl.textContent = `${data.count} templates`;
            grid.innerHTML = '';
            data.templates.forEach(t => {
                const card = document.createElement('div');
                card.className = 'template-card';
                card.innerHTML = `<h4>${t.name}</h4><p>${t.description}</p><div class="template-meta"><span class="template-tag">${t.module_count} modules</span><span class="template-tag">${t.estimated_time}</span><span class="template-tag intensity-${t.intensity}">${t.intensity}</span></div>`;
                card.onclick = () => startTemplateScan(t.id, t.name);
                grid.appendChild(card);
            });
        } catch (_) { grid.innerHTML = '<div class="empty-state">Failed to load templates</div>'; }
    }

    async function startTemplateScan(id, name) {
        let url = document.getElementById('template-target-url')?.value.trim();
        if (!url) return showToast('Enter a target URL first.', 'Warning', 'warning');
        if (!url.startsWith('http')) url = 'https://' + url;
        try {
            await fetch(`/api/scan/start/template/${id}?url=${encodeURIComponent(url)}`, { method: 'POST' });
            log('Template', `Started ${name} scan`, 'success');
            document.querySelector('[data-target="scan-view"]').click();
            resultsSection?.classList.remove('hidden');
        } catch (err) { log('Template', err.message, 'error'); }
    }

    // ── Settings ────────────────────────────────────
    async function loadSettings() {
        try {
            const res = await fetch('/api/settings');
            const s = await res.json();
            const el = (id) => document.getElementById(id);
            if (el('config-timeout')) el('config-timeout').value = s.timeout || 30;
            if (el('config-rate-limit')) el('config-rate-limit').value = s.rate_limit || 10;
            if (el('config-concurrent')) { el('config-concurrent').value = s.concurrent_requests || 10; if (el('concurrent-value')) el('concurrent-value').textContent = s.concurrent_requests || 10; }
            el('waf-toggle')?.classList.toggle('active', s.waf_evasion);
            el('ua-toggle')?.classList.toggle('active', s.ua_rotation);
            el('ssl-toggle')?.classList.toggle('active', s.ssl_verification);

            try {
                const aiRes = await fetch('/api/ai/status');
                const ai = await aiRes.json();
                const aiEl = el('ai-engine-status');
                if (aiEl) { aiEl.textContent = (ai.available || ai.enabled) ? `Active (${ai.provider || 'Gemini'})` : 'Disabled'; aiEl.style.color = (ai.available || ai.enabled) ? 'var(--green)' : 'var(--text-3)'; }
            } catch (_) { const aiEl = document.getElementById('ai-engine-status'); if (aiEl) { aiEl.textContent = 'Not configured'; aiEl.style.color = 'var(--text-3)'; } }
        } catch (_) {}
    }

    const concurrentSlider = document.getElementById('config-concurrent');
    const concurrentVal = document.getElementById('concurrent-value');
    if (concurrentSlider && concurrentVal) concurrentSlider.oninput = () => { concurrentVal.textContent = concurrentSlider.value; };

    ['waf-toggle', 'ua-toggle', 'ssl-toggle'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.onclick = () => el.classList.toggle('active');
    });

    document.getElementById('save-config-btn')?.addEventListener('click', async () => {
        const el = (id) => document.getElementById(id);
        try {
            const res = await fetch('/api/settings', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    timeout: parseInt(el('config-timeout')?.value) || 30,
                    rate_limit: parseInt(el('config-rate-limit')?.value) || 10,
                    concurrent_requests: parseInt(el('config-concurrent')?.value) || 10,
                    waf_evasion: el('waf-toggle')?.classList.contains('active'),
                    ua_rotation: el('ua-toggle')?.classList.contains('active'),
                    ssl_verification: el('ssl-toggle')?.classList.contains('active')
                })
            });
            if (res.ok) showToast('Settings saved.', 'Success', 'success');
        } catch (_) { showToast('Failed to save settings.', 'Error', 'error'); }
    });

    // ── Blue Team: IOC Checker ─────────────────────
    document.getElementById('ioc-check-btn')?.addEventListener('click', async () => {
        const input = document.getElementById('ioc-input')?.value.trim();
        if (!input) return;
        const resultDiv = document.getElementById('ioc-result');
        const contentDiv = document.getElementById('ioc-result-content');
        resultDiv.style.display = 'block';
        contentDiv.innerHTML = '<div class="loading-placeholder"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</div>';
        try {
            const res = await fetch('/api/v1/blueteam/ioc/check', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ indicator: input })
            });
            const data = await res.json();
            contentDiv.innerHTML = renderIOCResult(data);
        } catch (err) { contentDiv.innerHTML = `<div style="color:var(--red)">Check failed: ${err.message}</div>`; }
    });

    document.getElementById('ioc-bulk-btn')?.addEventListener('click', async () => {
        const text = document.getElementById('ioc-bulk-input')?.value.trim();
        if (!text) return;
        const indicators = text.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 50);
        const resultsDiv = document.getElementById('ioc-bulk-results');
        resultsDiv.innerHTML = '<div class="loading-placeholder"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</div>';
        try {
            const res = await fetch('/api/v1/blueteam/ioc/check/bulk', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(indicators)
            });
            const data = await res.json();
            resultsDiv.innerHTML = data.results.map(r => renderIOCResult(r)).join('');
        } catch (err) { resultsDiv.innerHTML = `<div style="color:var(--red)">Bulk check failed</div>`; }
    });

    function renderIOCResult(data) {
        const verdictColors = { malicious: 'var(--red)', suspicious: 'var(--orange)', low_risk: 'var(--yellow)', clean: 'var(--green)', unknown: 'var(--text-3)' };
        const color = verdictColors[data.verdict] || 'var(--text-3)';
        const tags = (data.tags || []).map(t => `<span class="badge badge-info">${t}</span>`).join(' ');
        const sources = (data.sources || []).map(s => {
            const details = Object.entries(s).filter(([k]) => k !== 'source').map(([k, v]) => `<span style="color:var(--text-3)">${k}:</span> ${v}`).join(' · ');
            return `<div style="font-size:11px;padding:4px 0"><strong>${s.source || '?'}</strong> — ${details}</div>`;
        }).join('');
        return `
            <div class="finding-card ${data.verdict === 'malicious' ? 'critical' : data.verdict === 'suspicious' ? 'high' : ''}" style="margin-bottom:8px">
                <div class="finding-header">
                    <div class="finding-title" style="font-family:var(--mono);font-size:13px">${data.indicator}</div>
                    <div class="finding-meta">
                        <span class="badge" style="background:${color}20;color:${color}">${data.verdict}</span>
                        <span style="font-size:11px;color:var(--text-3)">${data.confidence}% confidence</span>
                    </div>
                </div>
                ${tags ? `<div style="margin:6px 0;display:flex;gap:4px;flex-wrap:wrap">${tags}</div>` : ''}
                ${sources ? `<div style="margin-top:6px">${sources}</div>` : ''}
            </div>
        `;
    }

    // ── Blue Team: Hardening Analyzer ────────────────
    document.getElementById('hardening-btn')?.addEventListener('click', async () => {
        const url = document.getElementById('hardening-url')?.value.trim();
        if (!url) return;
        const resultDiv = document.getElementById('hardening-result');
        const scoreDiv = document.getElementById('hardening-score');
        const checksDiv = document.getElementById('hardening-checks');
        resultDiv.style.display = 'block';
        scoreDiv.innerHTML = '<div class="loading-placeholder"><i class="fa-solid fa-spinner fa-spin"></i> Analyzing...</div>';
        checksDiv.innerHTML = '';
        try {
            const res = await fetch('/api/v1/blueteam/hardening/analyze', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            const gradeColor = data.score >= 75 ? 'var(--green)' : data.score >= 50 ? 'var(--yellow)' : 'var(--red)';
            scoreDiv.innerHTML = `
                <div class="stat-card"><div class="stat-label">Score</div><div class="stat-value" style="color:${gradeColor}">${data.score}/100</div></div>
                <div class="stat-card"><div class="stat-label">Grade</div><div class="stat-value" style="color:${gradeColor}">${data.grade}</div></div>
                <div class="stat-card"><div class="stat-label">Checks</div><div class="stat-value">${data.checks.length}</div><div class="stat-sub" style="font-size:11px">Pass: ${data.summary.pass} · Warn: ${data.summary.warn} · Fail: ${data.summary.fail}</div></div>
            `;
            const categories = {};
            data.checks.forEach(c => { (categories[c.category] = categories[c.category] || []).push(c); });
            let html = '';
            for (const [cat, checks] of Object.entries(categories)) {
                html += `<div style="margin-bottom:16px"><h3 style="font-size:13px;text-transform:capitalize;margin-bottom:8px;color:var(--text-2)">${cat}</h3>`;
                checks.forEach(c => {
                    const icon = c.status === 'pass' ? '✓' : c.status === 'warn' ? '⚠' : c.status === 'fail' ? '✗' : '?';
                    const color = c.status === 'pass' ? 'var(--green)' : c.status === 'warn' ? 'var(--yellow)' : c.status === 'fail' ? 'var(--red)' : 'var(--text-3)';
                    html += `
                        <div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px">
                            <span style="color:${color};font-weight:700;width:20px;flex-shrink:0">${icon}</span>
                            <div style="flex:1">
                                <div style="font-weight:500">${c.name}</div>
                                ${c.current_value ? `<div style="color:var(--text-3);font-family:var(--mono);font-size:11px;margin-top:2px">${c.current_value}</div>` : ''}
                                ${c.remediation ? `<div style="color:var(--text-2);margin-top:4px">${c.remediation}</div>` : ''}
                            </div>
                            <span class="badge badge-${c.severity}" style="height:fit-content">${c.severity}</span>
                        </div>
                    `;
                });
                html += '</div>';
            }
            checksDiv.innerHTML = html;
        } catch (err) { scoreDiv.innerHTML = `<div style="color:var(--red)">Analysis failed: ${err.message}</div>`; checksDiv.innerHTML = ''; }
    });

    // ── Blue Team: Incident Tracker ─────────────────
    const incidentModal = document.getElementById('incident-modal');
    document.getElementById('incident-create-btn')?.addEventListener('click', () => incidentModal?.classList.remove('hidden'));
    document.getElementById('close-incident-modal')?.addEventListener('click', () => incidentModal?.classList.add('hidden'));
    incidentModal?.addEventListener('click', (e) => { if (e.target.classList.contains('modal-backdrop')) incidentModal.classList.add('hidden'); });

    document.getElementById('inc-submit')?.addEventListener('click', async () => {
        const title = document.getElementById('inc-title')?.value.trim();
        if (!title) return showToast('Title is required.', 'Error', 'error');
        try {
            await fetch('/api/v1/blueteam/incidents', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title,
                    description: document.getElementById('inc-desc')?.value || '',
                    severity: document.getElementById('inc-severity')?.value || 'medium',
                    category: document.getElementById('inc-category')?.value || 'vulnerability',
                    tags: (document.getElementById('inc-tags')?.value || '').split(',').map(t => t.trim()).filter(Boolean),
                })
            });
            incidentModal?.classList.add('hidden');
            showToast('Incident created.', 'Success', 'success');
            loadIncidents();
        } catch (_) { showToast('Failed to create incident.', 'Error', 'error'); }
    });

    async function loadIncidents() {
        const listDiv = document.getElementById('incident-list');
        const statsDiv = document.getElementById('incident-stats');
        if (!listDiv) return;
        try {
            const [incRes, statsRes] = await Promise.all([
                fetch('/api/v1/blueteam/incidents'),
                fetch('/api/v1/blueteam/incidents/stats')
            ]);
            const incData = await incRes.json();
            const stats = await statsRes.json();

            if (statsDiv) {
                statsDiv.innerHTML = `
                    <div style="display:flex;gap:16px;font-size:12px">
                        <span><strong>${stats.total}</strong> total</span>
                        <span style="color:var(--red)"><strong>${stats.open_count}</strong> open</span>
                        ${Object.entries(stats.by_severity || {}).map(([k, v]) => `<span>${k}: <strong>${v}</strong></span>`).join('')}
                    </div>
                `;
            }

            if (!incData.incidents?.length) {
                listDiv.innerHTML = '<div class="empty-state">No incidents yet.</div>';
                return;
            }

            listDiv.innerHTML = incData.incidents.map(inc => {
                const sevColor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)' }[inc.severity] || 'var(--text-3)';
                const statusMap = { open: 'Open', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved', closed: 'Closed' };
                return `
                    <div class="finding-card ${inc.severity}" style="margin-bottom:8px">
                        <div class="finding-header">
                            <div class="finding-title">${inc.title}</div>
                            <div class="finding-meta">
                                <span class="badge badge-${inc.severity}">${inc.severity}</span>
                                <span class="badge" style="background:var(--bg-3)">${statusMap[inc.status] || inc.status}</span>
                            </div>
                        </div>
                        ${inc.description ? `<div class="finding-desc">${inc.description}</div>` : ''}
                        <div style="display:flex;gap:6px;margin-top:8px">
                            ${inc.status === 'open' ? `<button class="btn-ghost" onclick="updateIncidentStatus('${inc.id}','investigating')">Investigate</button>` : ''}
                            ${inc.status === 'investigating' ? `<button class="btn-ghost" onclick="updateIncidentStatus('${inc.id}','contained')">Contain</button><button class="btn-ghost" onclick="updateIncidentStatus('${inc.id}','resolved')">Resolve</button>` : ''}
                            ${inc.status === 'contained' ? `<button class="btn-ghost" onclick="updateIncidentStatus('${inc.id}','resolved')">Resolve</button>` : ''}
                            ${inc.status === 'resolved' ? `<button class="btn-ghost" onclick="updateIncidentStatus('${inc.id}','closed')">Close</button>` : ''}
                        </div>
                        ${inc.timeline?.length > 1 ? `<details style="margin-top:8px"><summary style="font-size:11px;color:var(--text-3);cursor:pointer">Timeline (${inc.timeline.length} events)</summary><div style="margin-top:6px;font-size:11px">${inc.timeline.map(e => `<div style="padding:4px 0;border-left:2px solid var(--border);padding-left:8px;margin:4px 0"><span style="color:var(--text-3)">${new Date(e.timestamp).toLocaleString()}</span> · <strong>${e.action}</strong> ${e.detail}</div>`).join('')}</div></details>` : ''}
                    </div>
                `;
            }).join('');
        } catch (_) { listDiv.innerHTML = '<div class="empty-state" style="color:var(--red)">Failed to load incidents</div>'; }
    }

    // Global function for inline onclick handlers
    window.updateIncidentStatus = async (id, newStatus) => {
        try {
            await fetch(`/api/v1/blueteam/incidents/${id}/status`, {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });
            loadIncidents();
        } catch (_) { showToast('Failed to update status.', 'Error', 'error'); }
    };

    // ── Init ────────────────────────────────────────
    initializeMatrix();
    loadSettings();
    initPayloadCategories();

    // Load blue team data when navigating to it
    const origNavHandler = document.querySelectorAll('.nav-item');
    origNavHandler.forEach(link => {
        link.addEventListener('click', () => {
            if (link.dataset.target === 'blueteam-view') loadIncidents();
        });
    });
});
