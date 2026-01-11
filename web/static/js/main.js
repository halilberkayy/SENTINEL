/**
 * SENTINEL ELITE - Assessment Orchestrator
 * High-performance tactical UI logic with AI Intelligence
 */

document.addEventListener('DOMContentLoaded', () => {
    // Platform State
    let selectedModules = new Set();
    let ws = null;
    let vulnCounter = 0;
    let currentScanId = localStorage.getItem('sentinel_latest_scan_id');
    let currentPocData = null;
    let currentScanResults = []; // Store real-time results
    let totalExpectedModules = 0;
    let completedModulesCount = 0;
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

    // 0. Notification System (Toasts)
    function showToast(message, title = 'SECURITY ALERT', type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            'success': 'fa-circle-check',
            'error': 'fa-triangle-exclamation',
            'warning': 'fa-circle-exclamation',
            'info': 'fa-circle-info'
        };

        toast.innerHTML = `
            <div class="toast-icon"><i class="fa-solid ${icons[type] || icons.info}"></i></div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-msg">${message}</div>
            </div>
            <div class="toast-close" style="cursor:pointer; opacity:0.5;">&times;</div>
        `;

        container.appendChild(toast);

        const closeToast = () => {
            toast.classList.add('closing');
            setTimeout(() => toast.remove(), 400);
        };

        toast.querySelector('.toast-close').onclick = closeToast;
        if (duration > 0) setTimeout(closeToast, duration);
    }

    // Replace window alert with our custom toast
    window.cyberAlert = (msg, title, type = 'warning') => showToast(msg, title, type);

    // 1. Tactical HUD Timer
    setInterval(() => {
        const diff = Date.now() - launchTime;
        const h = Math.floor(diff / 3600000).toString().padStart(2, '0');
        const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
        const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
        if (hudClock) hudClock.innerText = `${h}:${m}:${s}`;
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
            if (view) view.classList.add('active');

            // Load view-specific data
            if (target === 'archive-view') loadScanHistory();
            if (target === 'payload-view') {
                renderPayloads('all');
                setTimeout(initPayloadCategories, 100); // Reinitialize categories
            }
            if (target === 'templates-view') loadTemplates();
            if (target === 'config-view') loadSettings();
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
            log('PLATFORM', 'Çekirdek senkronizasyon hatası.', 'error');
            showToast('Modül matrisi yüklenemedi. Sunucu bağlantısını kontrol edin.', 'SİSTEM HATASI', 'error');
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

    // 5. Encrypted Comms (WebSocket) with Robust Reconnection
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT_ATTEMPTS = 10;
    const WS_BASE_DELAY = 1000; // 1 second
    const WS_MAX_DELAY = 30000; // 30 seconds max

    function establishLink() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';

        try {
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onopen = () => {
                wsReconnectAttempts = 0; // Reset on successful connection
                log('SYSTEM', 'Secure link established.', 'success');
            };

            ws.onmessage = (event) => {
                try {
                    processIntel(JSON.parse(event.data));
                } catch (e) {
                    log('SYSTEM', 'Sunucu mesajı ayrıştırılamadı.', 'error');
                }
            };

            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

            ws.onclose = (event) => {
                if (event.wasClean) {
                    log('SYSTEM', 'Connection closed cleanly.', 'sys');
                } else {
                    log('SYSTEM', 'Bağlantı kesildi. Yeniden bağlanılıyor...', 'error');
                }

                // Exponential backoff reconnection
                if (wsReconnectAttempts < WS_MAX_RECONNECT_ATTEMPTS) {
                    wsReconnectAttempts++;
                    const delay = Math.min(WS_BASE_DELAY * Math.pow(2, wsReconnectAttempts - 1), WS_MAX_DELAY);
                    log('SYSTEM', `Yeniden bağlanma denemesi ${wsReconnectAttempts}/${WS_MAX_RECONNECT_ATTEMPTS} - ${delay / 1000}s içinde...`, 'sys');
                    setTimeout(establishLink, delay);
                } else {
                    log('SYSTEM', 'Maksimum yeniden bağlanma denemesine ulaşıldı. Sayfayı yenileyin.', 'error');
                }
            };
        } catch (e) {
            log('SYSTEM', 'Failed to create WebSocket connection.', 'error');
            setTimeout(establishLink, WS_BASE_DELAY);
        }
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

            // Calculate global progress
            if (data.status === 'completed' || data.percentage === 100) {
                completedModulesCount++;
            }

            const globalPercentage = totalExpectedModules > 0
                ? (completedModulesCount / totalExpectedModules) * 100
                : data.percentage;

            progressPercent.innerText = `${Math.round(globalPercentage)}%`;
            progressLine.style.width = `${globalPercentage}%`;
            log(data.module, data.status, 'sys');
        } else if (data.type === 'module_result') {
            // Add to our real-time collection
            currentScanResults.push(data);
            renderIncidents(currentScanResults);

            // Log if vulnerabilities were found
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                log(data.module, `${data.vulnerabilities.length} adet zafiyet tespit edildi!`, 'error');
            }
        } else if (data.type === 'complete') {
            log('COMMAND', 'Stratejik hedeflere ulaşıldı. Raporlama temiz.', 'success');
            activeModEl.innerText = 'GÜVENLİ';
            progressLine.style.width = '100%';
            progressPercent.innerText = '100%';
            currentScanId = data.scan_id;
            localStorage.setItem('sentinel_latest_scan_id', data.scan_id);

            // Final render to ensure everything is in order (including chaining results)
            currentScanResults = data.results;
            renderIncidents(data.results);

            // Enable AI buttons after full completion
            document.querySelectorAll('.ai-btn').forEach(btn => {
                btn.disabled = false;
                btn.classList.remove('opacity-50', 'cursor-not-allowed');
            });

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

    // Trigger config load when navigating to config view - handled by loadSettings now

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
    renderArchives();

    // 7. Tactical Launch Bridge
    startBtn.onclick = async () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            showToast('Lütfen geçerli bir hedef URL girin.', 'HATA', 'error');
            return;
        }
        if (selectedModules.size === 0) return showToast('Taktiksel modül seçilmedi. Operasyon iptal edildi.', 'GÖREV ENGELLENDİ', 'error');

        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-satellite-dish fa-spin"></i> ENGAGING...';

        resultsSection.classList.remove('hidden');
        // AI panel stays visible, just reset report container
        if (aiReportContainer) aiReportContainer.style.display = 'none';
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        logViewer.innerHTML = '';
        // Reset state for new scan
        currentScanResults = [];
        completedModulesCount = 0;
        totalExpectedModules = selectedModules.size;

        // Disable AI buttons during scan
        document.querySelectorAll('.ai-btn').forEach(btn => {
            btn.disabled = true;
            btn.classList.add('opacity-50', 'cursor-not-allowed');
        });

        findingsGrid.innerHTML = '';
        vulnCounter = 0;
        vulnCountEl.innerText = '0';
        if (vulnChart) {
            vulnChart.data.datasets[0].data = [0, 0, 0, 0, 0];
            vulnChart.update();
        }
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
            log('CENTCOM', `Görev parametreleri doğrulandı. Tarama başlatıldı: ${url}`, 'success');
        } catch (err) {
            log('CRITICAL', 'Tarama motoru bağlantısı koptu.', 'error');
            showToast('Tarama motoru ile iletişim kurulamıyor.', 'KRİTİK HATA', 'error');
        } finally {
            startBtn.disabled = false;
            startBtn.innerHTML = 'LAUNCH ASSESSMENT';
        }
    };
    // 8. Payload Database Logic
    const payloadModal = document.getElementById('payload-modal');
    const closePayloadBtn = document.getElementById('close-payload-modal');
    const pmCopyBtn = document.getElementById('pm-copy-btn');
    let currentPayload = null;

    async function renderPayloads(category) {
        // Get element dynamically in case it wasn't available at init
        const payloadTableBody = document.getElementById('payload-table-body');
        if (!payloadTableBody) {
            console.error('Payload table body not found!');
            return;
        }

        console.log('Loading payloads for category:', category);
        payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;"><i class="fa-solid fa-spinner fa-spin"></i> Accessing Arsenal...</td></tr>';

        try {
            const url = category === 'all' ? '/api/payloads' : `/api/payloads?category=${category}`;
            console.log('Fetching from:', url);
            const res = await fetch(url);
            const payloads = await res.json();
            console.log('Received payloads:', payloads.length);

            payloadTableBody.innerHTML = '';
            if (payloads.length === 0) {
                payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;color:var(--text-tertiary);">No vectors found for this category.</td></tr>';
                return;
            }

            payloads.forEach(p => {
                const tr = document.createElement('tr');
                const riskClass = p.risk ? p.risk.toLowerCase() : 'medium';
                tr.innerHTML = `
                    <td style="padding: 1rem; font-family:var(--font-mono); font-size:0.8rem; color:var(--text-tertiary);">${p.id}</td>
                    <td style="padding: 1rem; font-weight:600; color:#fff;">${p.name}</td>
                    <td style="padding: 1rem;"><div class="r-sev ${riskClass}">${p.risk || 'Unknown'}</div></td>
                    <td style="padding: 1rem;">
                        <button class="guide-btn" data-id="${p.id}" style="padding:0.5rem 1rem; font-size:0.75rem; background: var(--holo-cyan); color: #000; border:none; border-radius: var(--radius-sm); cursor: pointer; font-weight: 600;">
                            <i class="fa-solid fa-book"></i> GUIDE
                        </button>
                    </td>
                `;

                tr.querySelector('.guide-btn').onclick = () => showPayloadDetails(p.id);
                payloadTableBody.appendChild(tr);
            });

            log('ARSENAL', `Loaded ${payloads.length} payloads`, 'success');

        } catch (err) {
            console.error('Payload loading error:', err);
            log('SYSTEM', 'Failed to load payload database.', 'error');
            payloadTableBody.innerHTML = '<tr><td colspan="4" style="padding:2rem;text-align:center;color:var(--signal-critical);">Database Connection Failed</td></tr>';
        }
    }

    // Category Filter Buttons - Initialize with event delegation
    function initPayloadCategories() {
        const catContainer = document.querySelector('.payload-cats');
        if (!catContainer) {
            console.warn('Payload categories container not found');
            return;
        }

        // Remove existing event listener by replacing the container
        const newContainer = catContainer.cloneNode(true);
        catContainer.parentNode.replaceChild(newContainer, catContainer);

        // Add click event listener to all category buttons
        newContainer.querySelectorAll('.cat-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                console.log('Category button clicked:', btn.getAttribute('data-cat'));

                // Update active state
                newContainer.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                // Fetch payloads for selected category
                const category = btn.getAttribute('data-cat');
                renderPayloads(category);
            });
        });

        console.log('Payload categories initialized');
    }

    // Initialize payload categories on page load
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(initPayloadCategories, 100);
    });

    // Also call now in case DOM is already ready
    initPayloadCategories();

    async function showPayloadDetails(pid) {
        console.log('[ARSENAL] Fetching guide for payload:', pid);
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
            console.error('Guide error:', err);
            showToast('Görev rehberine erişim reddedildi veya rehber bulunamadı.', 'GÖREV HATASI', 'error');
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

    // =====================================
    // SCAN TEMPLATES - Quick Deploy
    // =====================================
    async function loadTemplates() {
        const templatesGrid = document.getElementById('templates-grid');
        const templateCount = document.getElementById('template-count');

        if (!templatesGrid) return;

        try {
            const response = await fetch('/api/templates');
            const data = await response.json();

            if (templateCount) {
                templateCount.textContent = `${data.count} Templates`;
            }

            templatesGrid.innerHTML = '';

            data.templates.forEach((template, idx) => {
                const card = document.createElement('div');
                card.className = 'template-card';
                card.style.animationDelay = `${idx * 0.05}s`;

                const intensityClass = `intensity-${template.intensity}`;

                card.innerHTML = `
                    <h4>${template.name}</h4>
                    <p>${template.description}</p>
                    <div class="template-meta">
                        <span class="template-tag modules">${template.module_count} Modules</span>
                        <span class="template-tag time">${template.estimated_time}</span>
                        <span class="template-tag ${intensityClass}">${template.intensity.toUpperCase()}</span>
                    </div>
                `;

                card.onclick = () => startTemplateScan(template.id, template.name);
                templatesGrid.appendChild(card);
            });

        } catch (err) {
            log('SYSTEM', 'Failed to load scan templates.', 'error');
            templatesGrid.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--signal-critical); grid-column: 1/-1;">Failed to load templates</div>';
        }
    }

    async function startTemplateScan(templateId, templateName) {
        const targetInput = document.getElementById('template-target-url');
        let url = targetInput ? targetInput.value.trim() : '';

        if (!url) {
            showToast('Geçerli bir hedef URL giriniz.', 'HEDEF EKSİK', 'warning');
            return;
        }

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        try {
            const response = await fetch(`/api/scan/start/template/${templateId}?url=${encodeURIComponent(url)}`, {
                method: 'POST'
            });

            if (!response.ok) throw new Error('Failed to start template scan');

            const data = await response.json();
            log('TEMPLATE', `Started scan with template: ${templateName}`, 'success');

            // Switch to operations view
            document.querySelector('[data-target="ops-view"]').click();

            // Show results section
            if (resultsSection) resultsSection.classList.remove('hidden');

        } catch (err) {
            log('TEMPLATE', err.message, 'error');
        }
    }

    // =====================================
    // SCAN HISTORY - Archives
    // =====================================
    async function loadScanHistory() {
        const historyList = document.getElementById('history-list');
        if (!historyList) return;

        // First try to load from server API
        try {
            const response = await fetch('/api/scans/history?limit=50');
            const data = await response.json();

            if (data.scans && data.scans.length > 0) {
                renderHistoryTable(data.scans);
                return;
            }
        } catch (err) {
            console.log('Server history not available, using local storage');
        }

        // Fallback to localStorage
        if (scanHistory.length > 0) {
            renderHistoryTable(scanHistory);
        } else {
            historyList.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 3rem; color: var(--text-tertiary);">
                        <i class="fa-solid fa-folder-open" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                        No scan history available
                    </td>
                </tr>
            `;
        }
    }

    function renderHistoryTable(scans) {
        const historyList = document.getElementById('history-list');
        if (!historyList) return;

        historyList.innerHTML = '';

        scans.forEach(scan => {
            const tr = document.createElement('tr');
            const vulnCount = scan.vulnerability_count || scan.vulns || 0;
            const statusColor = vulnCount > 0 ? 'var(--signal-critical)' : 'var(--holo-electric)';
            const scanId = scan.scan_id || scan.id || Date.now();

            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 0.85rem;">${scan.url || scan.target || 'Unknown'}</td>
                <td>${scan.timestamp || scan.completed_at || (scan.saved_at ? new Date(scan.saved_at).toLocaleString() : 'N/A')}</td>
                <td><span style="color: ${statusColor}; font-weight: 700;">${vulnCount}</span></td>
                <td><span style="color: var(--holo-electric);">COMPLETED</span></td>
                <td style="display: flex; gap: 0.5rem;">
                    <button class="r-action-btn view-scan-btn" data-id="${scanId}" data-scan='${JSON.stringify(scan).replace(/'/g, "\\'")}'>
                        <i class="fa-solid fa-eye"></i> View
                    </button>
                    <button class="r-action-btn delete-scan-btn" data-id="${scanId}" style="color: var(--signal-critical);">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            `;

            historyList.appendChild(tr);
        });

        // View scan buttons
        document.querySelectorAll('.view-scan-btn').forEach(btn => {
            btn.onclick = () => {
                const scanId = btn.dataset.id;
                try {
                    // Try to get scan data from the button's data attribute
                    const scanData = btn.dataset.scan ? JSON.parse(btn.dataset.scan) : null;
                    if (scanData && scanData.results) {
                        // Switch to operations view
                        document.querySelector('[data-target="ops-view"]').click();

                        // Show results
                        if (resultsSection) resultsSection.classList.remove('hidden');

                        // Display the vulnerabilities
                        if (findingsGrid) {
                            findingsGrid.innerHTML = '';
                            const vulns = scanData.results || [];
                            vulns.forEach(v => {
                                if (v.vulnerabilities) {
                                    v.vulnerabilities.forEach(vuln => renderVulnCard(vuln));
                                }
                            });
                        }

                        log('ARCHIVE', `Loaded scan results for ${scanData.url || scanId}`, 'success');
                    } else {
                        // Fetch from API
                        fetchAndDisplayScan(scanId);
                    }
                } catch (err) {
                    console.error('Error viewing scan:', err);
                    fetchAndDisplayScan(scanId);
                }
            };
        });

        // Delete scan buttons
        document.querySelectorAll('.delete-scan-btn').forEach(btn => {
            btn.onclick = async () => {
                const scanId = btn.dataset.id;
                if (confirm('Delete this scan from history?')) {
                    // Remove from localStorage
                    scanHistory = scanHistory.filter(s => (s.scan_id || s.id) != scanId);
                    localStorage.setItem('sentinel_archives', JSON.stringify(scanHistory));

                    // Try to delete from server too
                    try {
                        await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
                    } catch (err) {
                        console.log('Server delete failed, local delete successful');
                    }

                    log('ARCHIVE', 'Scan deleted successfully', 'success');
                    loadScanHistory();
                }
            };
        });
    }

    // Fetch and display scan from API
    async function fetchAndDisplayScan(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}`);
            if (response.ok) {
                const data = await response.json();
                document.querySelector('[data-target="ops-view"]').click();
                if (resultsSection) resultsSection.classList.remove('hidden');
                log('ARCHIVE', `Loaded scan ${scanId} from server`, 'success');
            } else {
                showToast('Target mission parameters not found in deep storage.', 'MISSION NOT FOUND', 'warning');
            }
        } catch (err) {
            showToast('Protocol failure while retrieving mission data.', 'CRITICAL ERROR', 'error');
        }
    }

    // Clear history button
    const clearHistoryBtn = document.getElementById('clear-history');
    if (clearHistoryBtn) {
        clearHistoryBtn.onclick = async () => {
            if (confirm('Clear all scan history? This cannot be undone.')) {
                // Clear localStorage
                scanHistory = [];
                localStorage.setItem('sentinel_archives', JSON.stringify(scanHistory));

                // Try to clear server history too
                try {
                    const response = await fetch('/api/scans/history?limit=100');
                    const data = await response.json();
                    if (data.scans) {
                        for (const scan of data.scans) {
                            await fetch(`/api/scans/${scan.scan_id || scan.id}`, { method: 'DELETE' });
                        }
                    }
                } catch (err) {
                    console.log('Server clear failed, local clear successful');
                }

                log('ARCHIVE', 'All scan history cleared', 'success');
                loadScanHistory();
            }
        };
    }

    // =====================================
    // SETTINGS & CONFIG
    // =====================================
    async function loadSettings() {
        try {
            const response = await fetch('/api/settings');
            const settings = await response.json();

            const timeoutInput = document.getElementById('config-timeout');
            const rateLimitInput = document.getElementById('config-rate-limit');
            const concurrentInput = document.getElementById('config-concurrent');
            const concurrentValue = document.getElementById('concurrent-value');
            const aiEngineStatus = document.getElementById('ai-engine-status');

            if (timeoutInput) timeoutInput.value = settings.timeout || 30;
            if (rateLimitInput) rateLimitInput.value = settings.rate_limit || 10;
            if (concurrentInput) {
                concurrentInput.value = settings.concurrent_requests || 10;
                if (concurrentValue) concurrentValue.textContent = settings.concurrent_requests || 10;
            }

            // Load bypass toggles
            const wafToggle = document.getElementById('waf-toggle');
            const uaToggle = document.getElementById('ua-toggle');
            const sslToggle = document.getElementById('ssl-toggle');

            if (wafToggle) wafToggle.classList.toggle('active', settings.waf_evasion);
            if (uaToggle) uaToggle.classList.toggle('active', settings.ua_rotation);
            if (sslToggle) sslToggle.classList.toggle('active', settings.ssl_verification);

            // Check AI status from dedicated endpoint
            try {
                const aiResponse = await fetch('/api/ai/status');
                const aiStatus = await aiResponse.json();
                console.log('AI System Status:', aiStatus);

                if (aiEngineStatus) {
                    if (aiStatus.available || aiStatus.enabled) {
                        aiEngineStatus.textContent = `ACTIVE - ${aiStatus.provider || 'Gemini'}`;
                        aiEngineStatus.style.color = 'var(--holo-electric)';
                        aiEngineStatus.style.fontWeight = 'bold';
                        aiEngineStatus.style.cursor = 'default';
                        aiEngineStatus.onclick = null;

                        // If it's active, log it
                        log('SYSTEM', `AI Engine integrated: ${aiStatus.provider || 'Gemini'}`, 'success');
                    } else {
                        aiEngineStatus.textContent = 'DISABLED';
                        aiEngineStatus.style.color = 'var(--text-tertiary)';
                        aiEngineStatus.style.cursor = 'pointer';
                        aiEngineStatus.title = 'Click to configure AI';
                        aiEngineStatus.onclick = () => {
                            cyberAlert('To enable AI intelligence, ensure GOOGLE_AI_API_KEY is set in your .env and the AI server is running.', 'AI ENGINE CONFIGURATION');
                        };
                    }
                }
            } catch (aiErr) {
                if (aiEngineStatus) {
                    aiEngineStatus.textContent = 'NOT CONFIGURED';
                    aiEngineStatus.style.color = 'var(--signal-critical)';
                }
            }

        } catch (err) {
            log('CONFIG', 'Failed to load settings.', 'error');
        }
    }

    // Concurrent slider value update
    const concurrentSlider = document.getElementById('config-concurrent');
    const concurrentValueEl = document.getElementById('concurrent-value');
    if (concurrentSlider && concurrentValueEl) {
        concurrentSlider.oninput = () => {
            concurrentValueEl.textContent = concurrentSlider.value;
        };
    }

    // Initialize toggle switches with real functionality
    function initializeToggles() {
        const toggles = [
            document.getElementById('waf-toggle'),
            document.getElementById('ua-toggle'),
            document.getElementById('ssl-toggle')
        ];

        toggles.forEach(toggle => {
            if (toggle) {
                toggle.style.cursor = 'pointer';
                toggle.onclick = (e) => {
                    e.preventDefault();

                    const isActive = toggle.classList.toggle('active');
                    const label = toggle.id.replace('-toggle', '').toUpperCase();

                    if (isActive) {
                        log('CONFIG', `${label} güvenliği atlatma aktif`, 'success');
                    } else {
                        log('CONFIG', `${label} güvenliği atlatma pasif`, 'sys');
                    }
                };
            }
        });
    }

    // Call toggle initialization
    initializeToggles();

    // Save config button
    const saveConfigBtn = document.getElementById('save-config-btn');
    if (saveConfigBtn) {
        saveConfigBtn.onclick = async () => {
            const timeout = parseInt(document.getElementById('config-timeout')?.value) || 30;
            const rateLimit = parseInt(document.getElementById('config-rate-limit')?.value) || 10;
            const concurrent = parseInt(document.getElementById('config-concurrent')?.value) || 10;

            const wafEvasion = document.getElementById('waf-toggle')?.classList.contains('active');
            const uaRotation = document.getElementById('ua-toggle')?.classList.contains('active');
            const sslVerification = document.getElementById('ssl-toggle')?.classList.contains('active');

            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        timeout: timeout,
                        rate_limit: rateLimit,
                        concurrent_requests: concurrent,
                        waf_evasion: wafEvasion,
                        ua_rotation: uaRotation,
                        ssl_verification: sslVerification
                    })
                });

                if (response.ok) {
                    showToast('Küresel konfigürasyon güncellendi.', 'AYARLAR KAYDEDİLDİ', 'success');
                    saveConfigBtn.innerHTML = '<i class="fa-solid fa-check"></i> KAYDEDİLDİ!';
                    setTimeout(() => {
                        saveConfigBtn.innerHTML = '<i class="fa-solid fa-save"></i> KONFİGÜRASYONU KAYDET';
                    }, 2000);
                }
            } catch (err) {
                showToast('Yerel konfigürasyon komuta merkezi ile senkronize edilemedi.', 'KRİTİK HATA', 'error');
            }
        };
    }

    // =====================================
    // INITIALIZATION
    // =====================================
    initializeMatrix();
    loadSettings();

});
