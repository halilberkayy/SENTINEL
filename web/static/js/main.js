/**
 * SENTINEL ELITE - Assessment Orchestrator
 * High-performance tactical UI logic with AI Intelligence
 */

document.addEventListener('DOMContentLoaded', () => {
    // Platform State
    let selectedModules = new Set();
    let ws = null;
    let vulnCounter = 0;
    let currentScanId = null;
    let currentPocData = null;
    let scanHistory = JSON.parse(localStorage.getItem('sentinel_archives') || '[]');
    const launchTime = Date.now();

    // Elements - Navigation
    const navLinks = document.querySelectorAll('.nav-link');
    const pageViews = document.querySelectorAll('.page-view');
    const hudClock = document.getElementById('session-clock');

    // Elements - Core HUD
    const modulesGrid = document.getElementById('modules-grid');
    const startBtn = document.getElementById('start-scan-btn');
    const targetUrlInput = document.getElementById('target-url');
    const selectAllBtn = document.getElementById('select-all');
    const deselectAllBtn = document.getElementById('deselect-all');

    // Elements - Output Data
    const resultsSection = document.getElementById('results-section');
    const logViewer = document.getElementById('log-viewer');
    const progressPercent = document.getElementById('progress-percent');
    const progressLine = document.getElementById('progress-line');
    const vulnCountEl = document.getElementById('vuln-count');
    const activeModEl = document.getElementById('active-mod');
    const findingsGrid = document.getElementById('findings-grid');
    const archiveList = document.getElementById('history-list');

    // Elements - AI Intelligence
    const aiIntelSection = document.getElementById('ai-intel-section');
    const aiReportContainer = document.getElementById('ai-report-container');
    const aiReportContent = document.getElementById('ai-report-content');
    const aiLoading = document.getElementById('ai-loading');
    const aiLanguage = document.getElementById('ai-language');

    // Elements - PoC Modal
    const pocModal = document.getElementById('poc-modal');
    const pocCode = document.getElementById('poc-code');
    const closePocModal = document.getElementById('close-poc-modal');
    const copyPocBtn = document.getElementById('copy-poc');

    // 1. Tactical HUD Timer
    setInterval(() => {
        const diff = Date.now() - launchTime;
        const h = Math.floor(diff / 3600000).toString().padStart(2, '0');
        const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
        const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
        hudClock.innerText = `${h}:${m}:${s}`;
    }, 1000);

    // 2. Mission Control - View Switching
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = link.getAttribute('data-target');

            navLinks.forEach(l => l.classList.remove('active'));
            pageViews.forEach(v => v.classList.remove('active'));

            link.classList.add('active');
            const view = document.getElementById(target);
            view.classList.add('active');

            if (target === 'archive-view') renderArchives();
            if (target === 'payload-view') renderPayloads('all');
        });
    });

    // 3. Matrix Hybridization (Module Loading)
    async function initializeMatrix() {
        try {
            const response = await fetch('/api/modules');
            const modules = await response.json();

            modulesGrid.innerHTML = '';
            const iconMap = {
                'recon_scanner': 'fa-satellite-dish',
                'subdomain_scanner': 'fa-sitemap',
                'xss_scanner': 'fa-code',
                'sqli_scanner': 'fa-database',
                'lfi_scanner': 'fa-folder-open',
                'ssrf_scanner': 'fa-server',
                'cmd_injection': 'fa-terminal',
                'misconfig': 'fa-unlock-keyhole',
                'xxe_scanner': 'fa-file-code',
                'ssti_scanner': 'fa-file-lines',
                'deserialization': 'fa-box-open',
                'graphql_scanner': 'fa-project-diagram',
                'jwt_scanner': 'fa-fingerprint',
                'api_scanner': 'fa-network-wired',
                'auth_scanner': 'fa-user-shield',
                'cors_scanner': 'fa-arrow-right-arrow-left',
                'csrf_scanner': 'fa-shield-virus',
                'open_redirect': 'fa-diamond-turn-right',
                'proto_pollution': 'fa-dna',
                'webshell_scanner': 'fa-skull',
                'robots_scanner': 'fa-robot',
                'ssi_scanner': 'fa-gears',
                'js_secrets_scanner': 'fa-key',
                'port_scanner': 'fa-ethernet'
            };

            modules.forEach((mod, idx) => {
                const unit = document.createElement('div');
                unit.className = 'mod-unit active';
                unit.style.animation = `viewFade 0.4s ease forwards ${idx * 0.05}s`;
                unit.setAttribute('data-id', mod.id);
                selectedModules.add(mod.id);

                const iconClass = iconMap[mod.id] || 'fa-shield-halved';

                unit.innerHTML = `
                    <div class="mod-check"></div>
                    <div class="mod-icon">
                        <i class="fa-solid ${iconClass}"></i>
                    </div>
                    <div class="mod-body">
                        <h5>${mod.name}</h5>
                        <p>${mod.description}</p>
                    </div>
                    <div class="mod-status">READY</div>
                `;

                unit.onclick = () => {
                    const isActive = selectedModules.has(mod.id);
                    if (isActive) {
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
            log('PLATFORM', 'Core synchronization failure.', 'error');
        }
    }

    initializeMatrix();

    // 4. Multi-Select Protocols
    selectAllBtn.onclick = () => {
        document.querySelectorAll('.mod-unit').forEach(u => {
            selectedModules.add(u.getAttribute('data-id'));
            u.classList.add('active');
        });
    };

    deselectAllBtn.onclick = () => {
        document.querySelectorAll('.mod-unit').forEach(u => {
            selectedModules.delete(u.getAttribute('data-id'));
            u.classList.remove('active');
        });
    };

    // 5. Encrypted Comms (WebSocket)
    function establishLink() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

        ws.onmessage = (event) => processIntel(JSON.parse(event.data));
        ws.onclose = () => {
            log('SYSTEM', 'Mission link terminal. Re-engaging...', 'error');
            setTimeout(establishLink, 5000);
        };
    }

    establishLink();

    function log(service, message, status = 'none') {
        const line = document.createElement('div');
        line.className = `log-line ${status}`;
        const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
        line.innerHTML = `<span class="timestamp">[${time}]</span><span class="caller">${service}::</span> ${message}`;
        logViewer.appendChild(line);
        logViewer.scrollTop = logViewer.scrollHeight;
    }

    function processIntel(data) {
        if (data.type === 'progress') {
            activeModEl.innerText = data.module;
            progressPercent.innerText = `${Math.round(data.percentage)}%`;
            progressLine.style.width = `${data.percentage}%`;
            log(data.module, data.status, 'sys');
        } else if (data.type === 'complete') {
            log('COMMAND', 'Strategic objectives achieved. Reporting clear.', 'success');
            activeModEl.innerText = 'SECURED';
            progressLine.style.width = '100%';
            currentScanId = data.scan_id;
            renderIncidents(data.results);

            // Show AI panel always after scan completion
            if (aiIntelSection) {
                aiIntelSection.classList.remove('hidden');
                if (data.ai_available) {
                    log('AI', 'Intelligence Narrator ready for analysis.', 'success');
                } else {
                    log('AI', 'AI not configured. Add GOOGLE_AI_API_KEY to .env for AI reports.', 'error');
                }
            }

            archiveMission({
                url: targetUrlInput.value,
                timestamp: new Date().toLocaleString(),
                vulns: vulnCounter,
                scan_id: data.scan_id
            });
        } else if (data.type === 'error') {
            log('CRITICAL', data.message, 'error');
            activeModEl.innerText = 'ABORTED';
        } else if (data.type === 'ai_report') {
            handleAIReport(data);
        }
    }

    // ========================================
    // AI INTELLIGENCE FUNCTIONS
    // ========================================

    function handleAIReport(data) {
        if (aiLoading) aiLoading.style.display = 'none';

        if (data.status === 'error') {
            log('AI', `Report generation failed: ${data.message}`, 'error');
            if (aiReportContent) {
                aiReportContent.innerHTML = `
                    <div class="ai-section">
                        <div class="ai-section-header">
                            <div class="ai-section-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                            <span class="ai-section-title">Error Occurred</span>
                        </div>
                        <div class="ai-section-body">
                            <div class="ai-alert ai-alert-critical">
                                <i class="fa-solid fa-circle-xmark ai-alert-icon"></i>
                                <div class="ai-alert-content">
                                    <div class="ai-alert-title">Report Generation Failed</div>
                                    <div class="ai-alert-text">${data.message}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            return;
        }

        log('AI', `${data.report_type} report generated successfully.`, 'success');

        if (aiReportContent && data.data) {
            let html = '';
            const reportTypes = {
                'executive_summary': { icon: 'fa-chart-pie', title: 'Executive Summary', emoji: '📊' },
                'technical_report': { icon: 'fa-code', title: 'Technical Analysis', emoji: '🔧' },
                'risk_narrative': { icon: 'fa-shield-halved', title: 'Risk Assessment', emoji: '⚠️' },
                'remediation_plan': { icon: 'fa-screwdriver-wrench', title: 'Remediation Plan', emoji: '🛡️' },
                'attack_scenarios': { icon: 'fa-crosshairs', title: 'Attack Scenarios', emoji: '🎯' }
            };

            // Add report header
            html += `
                <div class="ai-report-header">
                    <div class="ai-report-meta">
                        <div class="ai-report-badge">
                            <i class="fa-solid fa-brain"></i>
                            <span>GEMINI AI</span>
                        </div>
                        <div class="ai-report-badge">
                            <i class="fa-solid fa-language"></i>
                            <span>${aiLanguage ? aiLanguage.value.toUpperCase() : 'EN'}</span>
                        </div>
                        <div class="ai-report-badge">
                            <i class="fa-solid fa-clock"></i>
                            <span>${new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>
                    </div>
                    <div class="ai-report-actions">
                        <button class="ai-action-btn" onclick="window.print()">
                            <i class="fa-solid fa-print"></i> Print
                        </button>
                        <button class="ai-action-btn" id="copy-report-btn">
                            <i class="fa-solid fa-copy"></i> Copy
                        </button>
                    </div>
                </div>
            `;

            // Generate sections
            Object.entries(reportTypes).forEach(([key, config]) => {
                if (data.data[key]) {
                    html += generateReportSection(config.icon, config.title, data.data[key]);
                }
            });

            // Add footer
            html += `
                <div class="ai-report-footer">
                    <div class="ai-report-branding">
                        <i class="fa-solid fa-robot"></i>
                        <span>POWERED BY SENTINEL AI ENGINE</span>
                    </div>
                    <div class="ai-report-timestamp">
                        Generated: ${new Date().toLocaleString('tr-TR')}
                    </div>
                </div>
            `;

            aiReportContent.innerHTML = html || '<p>No report data available.</p>';

            // Add copy functionality
            const copyBtn = document.getElementById('copy-report-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', async () => {
                    const reportText = aiReportContent.innerText;
                    try {
                        await navigator.clipboard.writeText(reportText);
                        copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                        setTimeout(() => {
                            copyBtn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy';
                        }, 2000);
                    } catch (err) {
                        log('AI', 'Failed to copy report', 'error');
                    }
                });
            }
        }
    }

    function generateReportSection(icon, title, content) {
        const formattedContent = formatAIText(content);
        return `
            <div class="ai-section">
                <div class="ai-section-header">
                    <div class="ai-section-icon"><i class="fa-solid ${icon}"></i></div>
                    <span class="ai-section-title">${title}</span>
                </div>
                <div class="ai-section-body">
                    ${formattedContent}
                </div>
            </div>
        `;
    }

    function formatAIText(text) {
        if (!text) return '';

        let html = text
            // Headers
            .replace(/^### (.+)$/gm, '<h4 class="ai-subsection-title">$1</h4>')
            .replace(/^## (.+)$/gm, '<h3 class="ai-subsection-title">$1</h3>')
            // Bold and italic
            .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.+?)\*/g, '<em>$1</em>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            // Risk indicators (CRITICAL, HIGH, MEDIUM, LOW)
            .replace(/\b(CRITICAL|KRİTİK)\b/gi, '<span style="color: var(--accent-danger); font-weight: 700;">$1</span>')
            .replace(/\b(HIGH|YÜKSEK)\b/gi, '<span style="color: #ff5e00; font-weight: 700;">$1</span>')
            .replace(/\b(MEDIUM|ORTA)\b/gi, '<span style="color: var(--accent-warning); font-weight: 700;">$1</span>')
            .replace(/\b(LOW|DÜŞÜK)\b/gi, '<span style="color: var(--accent-success); font-weight: 700;">$1</span>')
            // Convert numbered lists
            .replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>')
            // Convert bullet lists
            .replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>');

        // Wrap consecutive list items in ul
        html = html.replace(/(<li>.*?<\/li>\n?)+/gs, match => {
            return `<ul>${match}</ul>`;
        });

        // Paragraphs - split by double newlines
        const parts = html.split(/\n\n+/);
        html = parts.map(part => {
            // Don't wrap if already wrapped in html tags
            if (part.trim().startsWith('<')) return part;
            if (part.trim() === '') return '';
            return `<p>${part.replace(/\n/g, '<br>')}</p>`;
        }).join('');

        // Clean up extra breaks
        html = html
            .replace(/<p><br>/g, '<p>')
            .replace(/<br><\/p>/g, '</p>')
            .replace(/<p>\s*<\/p>/g, '')
            .replace(/<ul>\s*<\/ul>/g, '');

        return html;
    }

    async function generateAIReport(reportType) {
        if (!currentScanId) {
            log('AI', 'No scan results available for analysis.', 'error');
            return;
        }

        if (aiReportContainer) aiReportContainer.style.display = 'block';
        if (aiLoading) aiLoading.style.display = 'flex';
        if (aiReportContent) aiReportContent.innerHTML = '';

        const language = aiLanguage ? aiLanguage.value : 'en';

        log('AI', `Generating ${reportType} intelligence report...`, 'sys');

        try {
            const response = await fetch('/api/ai/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: currentScanId,
                    report_type: reportType,
                    language: language
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'AI generation failed');
            }

            log('AI', 'Report generation initiated. Awaiting neural response...', 'sys');
        } catch (err) {
            if (aiLoading) aiLoading.style.display = 'none';
            log('AI', err.message, 'error');
            if (aiReportContent) {
                aiReportContent.innerHTML = `
                    <div style="color: var(--accent-danger); text-align: center; padding: 2rem;">
                        <i class="fa-solid fa-triangle-exclamation" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                        <p>${err.message}</p>
                        <p style="font-size: 0.8rem; margin-top: 1rem; opacity: 0.7;">
                            Configure GOOGLE_AI_API_KEY in .env to enable AI reports.
                        </p>
                    </div>
                `;
                aiReportContainer.style.display = 'block';
            }
        }
    }

    // AI Button Event Listeners - Using event delegation for reliability
    document.addEventListener('click', async (e) => {
        const aiBtn = e.target.closest('.ai-btn');
        if (aiBtn) {
            e.preventDefault();
            const reportType = aiBtn.getAttribute('data-type');
            console.log('[AI] Button clicked:', reportType, 'ScanID:', currentScanId);

            if (!reportType) {
                log('AI', 'Invalid report type', 'error');
                return;
            }

            if (!currentScanId) {
                log('AI', 'No scan completed yet. Run a scan first!', 'error');
                showAIError('Please complete a scan first before generating AI reports.');
                return;
            }

            // Show loading state on button
            const originalHTML = aiBtn.innerHTML;
            aiBtn.disabled = true;
            aiBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating...';

            try {
                await generateAIReport(reportType);
            } finally {
                aiBtn.disabled = false;
                aiBtn.innerHTML = originalHTML;
            }
        }
    });

    function showAIError(message) {
        if (aiReportContainer) aiReportContainer.style.display = 'block';
        if (aiReportContent) {
            aiReportContent.innerHTML = `
                <div style="color: var(--accent-warning); text-align: center; padding: 2rem;">
                    <i class="fa-solid fa-info-circle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>${message}</p>
                </div>
            `;
        }
    }

    // ========================================
    // POC MODAL FUNCTIONS
    // ========================================

    async function showPoCModal(vulnIndex) {
        if (!currentScanId) return;

        try {
            const response = await fetch(`/api/poc/${currentScanId}/${vulnIndex}`);
            if (!response.ok) throw new Error('Failed to generate PoC');

            currentPocData = await response.json();

            // Show first available format - prioritize Nuclei/Python
            const formats = Object.keys(currentPocData.pocs).sort((a, b) => {
                const prio = { 'nuclei': 0, 'python': 1, 'curl': 2, 'burp_request': 3, 'html': 4 };
                return (prio[a] || 9) - (prio[b] || 9);
            });

            if (formats.length > 0) {
                showPoCFormat(formats[0]);
            }

            // Update tabs
            document.querySelectorAll('.poc-tab').forEach(tab => {
                const format = tab.getAttribute('data-format');
                if (currentPocData.pocs[format]) {
                    tab.style.display = 'block';
                    tab.classList.toggle('active', format === formats[0]);
                } else {
                    tab.style.display = 'none';
                }
            });

            pocModal.classList.remove('hidden');
        } catch (err) {
            log('POC', err.message, 'error');
        }
    }

    function showPoCFormat(format) {
        if (!currentPocData || !currentPocData.pocs[format]) return;

        if (pocCode) {
            pocCode.querySelector('code').textContent = currentPocData.pocs[format];
        }

        document.querySelectorAll('.poc-tab').forEach(tab => {
            tab.classList.toggle('active', tab.getAttribute('data-format') === format);
        });
    }

    // PoC Tab Click Handler
    document.querySelectorAll('.poc-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            showPoCFormat(tab.getAttribute('data-format'));
        });
    });

    // Close PoC Modal
    if (closePocModal) {
        closePocModal.addEventListener('click', () => {
            pocModal.classList.add('hidden');
        });
    }

    // Copy PoC
    if (copyPocBtn) {
        copyPocBtn.addEventListener('click', async () => {
            const code = pocCode.querySelector('code').textContent;
            try {
                await navigator.clipboard.writeText(code);
                copyPocBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                setTimeout(() => {
                    copyPocBtn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy to Clipboard';
                }, 2000);
            } catch (err) {
                log('POC', 'Failed to copy to clipboard', 'error');
            }
        });
    }

    // Close modal on outside click
    if (pocModal) {
        pocModal.addEventListener('click', (e) => {
            if (e.target === pocModal) {
                pocModal.classList.add('hidden');
            }
        });
    }

    // ========================================
    // INCIDENT RENDERING WITH CVSS & POC
    // ========================================

    // Chart.js Instance
    let vulnChart = null;

    function initChart() {
        if (typeof Chart === 'undefined') {
            log('SYSTEM', 'Chart.js library not loaded. Analytics visualization disabled.', 'error');
            const container = document.getElementById('vuln-chart').parentElement;
            container.innerHTML = '<div style="color:var(--text-dim); font-size:0.8rem">Visualization Unavailable (Offline)</div>';
            return;
        }

        const ctx = document.getElementById('vuln-chart').getContext('2d');
        vulnChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#ef4444', // Critical - Red
                        '#f97316', // High - Orange
                        '#eab308', // Medium - Yellow
                        '#22c55e', // Low - Green
                        '#3b82f6'  // Info - Blue
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 10, family: 'JetBrains Mono' } }
                    }
                },
                cutout: '70%'
            }
        });
    }

    // Call init after DOM load
    setTimeout(initChart, 500);

    function renderIncidents(results) {
        findingsGrid.innerHTML = '';
        vulnCounter = 0;
        let vulnIndex = 0;

        // Severity counters for Chart
        let sevCounts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        };

        results.forEach(res => {
            res.vulnerabilities.forEach((v) => {
                const currentIndex = vulnIndex++;
                vulnCounter++;
                const card = document.createElement('div');
                card.className = 'report-card';

                // normalize severity
                let s = (v.severity || 'info').toLowerCase();
                if (s === 'crit') s = 'critical';
                if (!sevCounts.hasOwnProperty(s)) s = 'info';
                sevCounts[s]++;

                // Chain Analyzer Special Rendering

                if (res.module === 'ChainAnalyzer') {
                    card.style.borderColor = 'var(--accent-danger)';
                    card.style.background = 'linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(0,0,0,0.4))';

                    card.innerHTML = `
                        <div class="r-head" style="border-bottom-color: rgba(239, 68, 68, 0.3)">
                            <span class="m-label" style="color: var(--accent-danger); font-weight: 800; letter-spacing: 1px;">
                                <i class="fa-solid fa-link"></i> ATTACK CHAIN DETECTED
                            </span>
                            <div class="r-sev critical">CRITICAL</div>
                        </div>
                        <div class="r-body">
                            <h4 style="font-family: 'Syncopate', sans-serif; color: #fff;">${v.title}</h4>
                            <p style="font-size: 1.1rem; color: #fff; margin-bottom: 1rem;">${v.description}</p>
                            
                            <div class="chain-steps" style="margin-top: 1rem; border-left: 2px solid var(--accent-danger); padding-left: 1rem;">
                                ${v.evidence && Array.isArray(v.evidence) ? v.evidence.map((step, i) => `
                                    <div style="margin-bottom: 0.5rem; font-size: 0.9rem;">
                                        <span style="color: var(--accent-danger); font-weight: bold;">STEP ${i + 1}:</span> 
                                        <span style="color: var(--text-dim);">${step.step || 'Action'}</span>
                                        <div style="font-family: monospace; opacity: 0.7; margin-left: 10px;">${typeof step.data === 'string' ? step.data : JSON.stringify(step.data)}</div>
                                    </div>
                                `).join('') : '<p>Detailed chain evidence available in technical report.</p>'}
                            </div>

                            <button class="poc-btn" style="background: var(--accent-danger); color: white; border: none; margin-top: 1rem;" data-index="${currentIndex}">
                                <i class="fa-solid fa-skull"></i> Generate Kill Chain PoC
                            </button>
                        </div>
                   `;
                } else {
                    // Standard Card
                    const sev = (v.severity || 'info').toLowerCase();
                    const cvssScore = v.cvss_score || 0;
                    const cvssClass = cvssScore >= 9 ? 'critical' : cvssScore >= 7 ? 'high' : cvssScore >= 4 ? 'medium' : 'low';

                    card.innerHTML = `
                        <div class="r-head">
                            <span class="m-label" style="font-size:0.6rem">SOURCE: ${res.module}</span>
                            <div style="display: flex; gap: 0.5rem; align-items: center;">
                                ${cvssScore > 0 ? `<span class="cvss-badge ${cvssClass}">CVSS: ${cvssScore.toFixed(1)}</span>` : ''}
                                <div class="r-sev ${sev}">${v.severity || 'INFO'}</div>
                            </div>
                        </div>
                        <div class="r-body">
                            <h4>${v.title || 'VULNERABILITY DETECTED'}</h4>
                            <p>${v.description}</p>
                            ${v.cwe_id ? `<p style="font-size:0.75rem; color:var(--accent-primary); margin-top:0.5rem;"><i class="fa-solid fa-tag"></i> ${v.cwe_id}</p>` : ''}
                            ${v.remediation ? `
                            <div class="r-fix">
                                <strong style="color:var(--accent-success); letter-spacing:1px; display:block; margin-bottom:5px">REMEDIATION PROTOCOL:</strong>
                                ${v.remediation}
                            </div>` : ''}
                            <button class="poc-btn" data-index="${currentIndex}">
                                <i class="fa-solid fa-code"></i> Generate PoC
                            </button>
                        </div>
                    `;
                }

                // Add PoC button event
                const pocBtn = card.querySelector('.poc-btn');
                pocBtn.addEventListener('click', () => {
                    showPoCModal(currentIndex);
                });

                findingsGrid.appendChild(card);
            });
        });

        vulnCountEl.innerText = vulnCounter;

        // Update Chart
        if (vulnChart) {
            vulnChart.data.datasets[0].data = [
                sevCounts.critical,
                sevCounts.high,
                sevCounts.medium,
                sevCounts.low,
                sevCounts.info
            ];
            vulnChart.update();
        }

        if (vulnCounter === 0) {
            findingsGrid.innerHTML = '<div class="report-card" style="padding:3rem; text-align:center; color:var(--text-dim); grid-column:1/-1">No anomalies detected in the target sector. Target is stable.</div>';
            // AI panel remains visible even with no vulnerabilities
        }
    }

    // 6. Archive Operations
    function archiveMission(mission) {
        scanHistory.unshift(mission);
        if (scanHistory.length > 50) scanHistory.pop();
        localStorage.setItem('sentinel_archives', JSON.stringify(scanHistory));
    }

    // Config Management Logic
    const wafToggle = document.getElementById('waf-evasion-toggle');
    const timeoutInput = document.getElementById('config-timeout');
    const concurrentInput = document.getElementById('config-concurrent');
    const saveConfigBtn = document.getElementById('save-config-btn');

    async function loadConfig() {
        try {
            const res = await fetch('/api/settings');
            const data = await res.json();
            if (timeoutInput) timeoutInput.value = data.timeout;
            if (concurrentInput) concurrentInput.value = data.concurrent_requests;

            // Check AI status
            const aiRes = await fetch('/api/ai/status');
            const aiData = await aiRes.json();
            const aiStatus = document.getElementById('ai-status');
            if (aiStatus) {
                if (aiData.available) {
                    aiStatus.innerHTML = `<span class="pulse-indicator" style="background: #8b5cf6;">READY - ${aiData.provider}</span>`;
                } else {
                    aiStatus.innerHTML = `<span class="pulse-indicator" style="background: var(--accent-danger);">NOT CONFIGURED</span>`;
                }
            }
        } catch (err) {
            log('SYSTEM', 'Failed to pull engine configuration.', 'error');
        }
    }

    if (saveConfigBtn) {
        saveConfigBtn.onclick = async () => {
            const payload = {
                timeout: parseInt(timeoutInput.value),
                concurrent_requests: parseInt(concurrentInput.value),
                rate_limit: 10
            };
            try {
                const res = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    log('SYSTEM', 'Engine parameters updated and locked.', 'success');
                    saveConfigBtn.innerHTML = 'CONFIGURATION SECURED';
                    setTimeout(() => saveConfigBtn.innerHTML = 'SAVE CONFIGURATION', 2000);
                }
            } catch (err) {
                log('CRITICAL', 'Failed to push configuration to engine.', 'error');
            }
        };
    }

    if (wafToggle) {
        wafToggle.onclick = () => {
            const label = wafToggle.querySelector('.m-label');
            const isActive = wafToggle.classList.contains('active');
            if (isActive) {
                wafToggle.classList.remove('active');
                label.innerText = 'DISABLED';
                log('SECURITY', 'WAF evasion protocols deactivated.', 'error');
            } else {
                wafToggle.classList.add('active');
                label.innerText = 'ENABLED';
                log('SECURITY', 'Enhanced WAF evasion protocols engaged.', 'success');
            }
        };
    }

    // Trigger config load when navigating to config view
    navLinks.forEach(link => {
        if (link.getAttribute('data-target') === 'config-view') {
            link.addEventListener('click', loadConfig);
        }
    });

    function renderArchives() {
        archiveList.innerHTML = '';
        if (scanHistory.length === 0) {
            archiveList.innerHTML = '<tr><td colspan="5" style="padding:3rem; text-align:center; color:var(--text-dim)">Archives are empty. No previous missions recorded.</td></tr>';
            return;
        }

        scanHistory.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding: 1.2rem; font-weight: 800; color: var(--accent-primary);">${item.url}</td>
                <td style="padding: 1.2rem; color: var(--text-muted);">${item.timestamp}</td>
                <td style="padding: 1.2rem;"><span class="r-sev ${item.vulns > 0 ? 'critical' : 'medium'}">${item.vulns} INCIDENTS</span></td>
                <td style="padding: 1.2rem; font-family:var(--font-mono); font-size:0.7rem; color:var(--accent-success); opacity:0.6">AES-256-GCM</td>
                <td style="padding: 1.2rem;"><button class="nav-link re-run-btn" data-url="${item.url}" style="padding:0.4rem 0.8rem; font-size:0.65rem">RE-ORCHESTRATE</button></td>
            `;

            const reRunBtn = tr.querySelector('.re-run-btn');
            reRunBtn.onclick = () => {
                targetUrlInput.value = item.url;
                document.querySelector('[data-target="ops-view"]').click();
                log('ARCHIVE', `Mission parameters for ${item.url} re-orchestrated.`, 'success');
            };

            archiveList.appendChild(tr);
        });
    }

    // Platform Initialization
    loadConfig();
    renderArchives();

    // 7. Tactical Launch Bridge
    startBtn.onclick = async () => {
        const url = targetUrlInput.value.trim();
        if (!url) return alert('MISSION BLOCKED: Target parameters missing.');
        if (selectedModules.size === 0) return alert('MISSION BLOCKED: No tactical resources allocated.');

        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-satellite-dish fa-spin"></i> ENGAGING...';

        resultsSection.classList.remove('hidden');
        // AI panel stays visible, just reset report container
        if (aiReportContainer) aiReportContainer.style.display = 'none';
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        logViewer.innerHTML = '';
        findingsGrid.innerHTML = '';
        vulnCounter = 0;
        vulnCountEl.innerText = '0';
        activeModEl.innerText = 'INITIALIZING';
        progressLine.style.width = '0%';

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: url,
                    modules: Array.from(selectedModules)
                })
            });
            const data = await response.json();
            currentScanId = data.scan_id;
            log('CENTCOM', 'Mission parameters verified. Tactical assessment launched.', 'success');
        } catch (err) {
            log('CRITICAL', 'Assessment engine connection dropped.', 'error');
        } finally {
            startBtn.disabled = false;
            startBtn.innerHTML = 'LAUNCH ASSESSMENT';
        }
    };
    // 8. Payload Database Logic
    const payloadTableBody = document.getElementById('payload-table-body');
    const payloadModal = document.getElementById('payload-modal');
    const closePayloadBtn = document.getElementById('close-payload-modal');
    const pmCopyBtn = document.getElementById('pm-copy-btn');
    let currentPayload = null;

    async function renderPayloads(category) {
        if (!payloadTableBody) return;
        payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;">Accessing Arsenal...</td></tr>';

        try {
            const url = category === 'all' ? '/api/payloads' : `/api/payloads?category=${category}`;
            const res = await fetch(url);
            const payloads = await res.json();

            payloadTableBody.innerHTML = '';
            if (payloads.length === 0) {
                payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;">No vectors found for this category.</td></tr>';
                return;
            }

            payloads.forEach(p => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="padding: 1rem; font-family:var(--font-mono); font-size:0.8rem; color:var(--text-dim);">${p.id}</td>
                    <td style="padding: 1rem; font-weight:600; color:#fff;">${p.name}</td>
                    <td style="padding: 1rem;"><div class="r-sev ${p.risk.toLowerCase()}">${p.risk}</div></td>
                    <td style="padding: 1rem;">
                        <button class="nav-link guide-btn" data-id="${p.id}" style="padding:0.4rem 0.8rem; font-size:0.7rem; background: var(--accent-primary); border:none;">
                            <i class="fa-solid fa-book"></i> GUIDE
                        </button>
                    </td>
                `;

                tr.querySelector('.guide-btn').onclick = () => showPayloadDetails(p.id);
                payloadTableBody.appendChild(tr);
            });

        } catch (err) {
            log('SYSTEM', 'Failed to load payload database.', 'error');
            payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;color:red;">Database Connection Failed</td></tr>';
        }
    }

    // Category Filter Buttons
    document.querySelectorAll('.cat-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderPayloads(btn.getAttribute('data-cat'));
        });
    });

    async function showPayloadDetails(pid) {
        try {
            const res = await fetch(`/api/payloads/${pid}/guide`);
            if (!res.ok) throw new Error('Guide unavailable');
            const data = await res.json();

            currentPayload = data; // Store for copy

            document.getElementById('pm-title').innerHTML = `<i class="fa-solid fa-crosshairs"></i> ${data.Title}`;
            document.getElementById('pm-payload').innerText = data.Payload;
            document.getElementById('pm-risk').innerText = data.Risk.toUpperCase();
            document.getElementById('pm-risk').className = `r-sev ${data.Risk.toLowerCase()}`;
            document.getElementById('pm-params').innerText = data['Target Params'];
            document.getElementById('pm-guide').innerText = data['Execution Guide'];
            document.getElementById('pm-evasion').innerText = data['Evasion Tips'];

            payloadModal.classList.remove('hidden');

        } catch (err) {
            alert('Could not retrieve mission guide.');
        }
    }

    if (closePayloadBtn) {
        closePayloadBtn.onclick = () => payloadModal.classList.add('hidden');
    }

    if (pmCopyBtn) {
        pmCopyBtn.onclick = () => {
            if (currentPayload) {
                navigator.clipboard.writeText(currentPayload.Payload);
                pmCopyBtn.innerText = 'COPIED!';
                setTimeout(() => pmCopyBtn.innerText = 'COPY PAYLOAD', 2000);
            }
        };
    }

    // Outside click closes payload modal
    if (payloadModal) {
        payloadModal.addEventListener('click', (e) => {
            if (e.target === payloadModal) payloadModal.classList.add('hidden');
        });
    }

});

