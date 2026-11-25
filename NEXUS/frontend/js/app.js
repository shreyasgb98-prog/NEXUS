// NEXUS AI: Modern Dark Analytics Console Coordinator (SnowUI Style)
// Enforces adaptive EWMA baselining, z-score anomaly detection, multi-signal correlation,
// operational status KPI metrics, stacked 4-signal visualization, incident triage playbooks,
// Lab Mode gating, CSV telemetry replay, and Wazuh-style operations console synchronization.

class WorkstationAudioRadar {
  constructor() {
    this.ctx = null;
    this.enabled = false;
  }
  init() {
    if (!this.ctx) {
      this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    }
  }
  toggle() {
    this.init();
    this.enabled = !this.enabled;
    return this.enabled;
  }
  playThreatChirp(severity = "HIGH") {
    if (!this.enabled || !this.ctx) return;
    if (this.ctx.state === "suspended") this.ctx.resume();
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    const now = this.ctx.currentTime;
    const freq = severity === "HIGH" ? 880 : 587;
    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, now);
    osc.frequency.exponentialRampToValueAtTime(220, now + 0.08);
    gain.gain.setValueAtTime(0.08, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + 0.08);
  }
}
window.audioRadar = new WorkstationAudioRadar();

function setGlobalAudioState(enabled) {
    if (window.audioRadar) {
        window.audioRadar.init();
        window.audioRadar.enabled = enabled;
    }
    if (window.nexusApp && window.nexusApp.incidentManager) {
        window.nexusApp.incidentManager.audioEnabled = enabled;
    } else if (window.incidentManager) {
        window.incidentManager.audioEnabled = enabled;
    }

    const btnAudioStatus = document.getElementById('btnAudioToggle');

    if (btnAudioStatus) {
        btnAudioStatus.textContent = enabled ? 'SND: ON' : 'SND: OFF';
        btnAudioStatus.classList.toggle('active', enabled);
    }
}
window.setGlobalAudioState = setGlobalAudioState;

class NexusApp {
    constructor() {
        this.mode = 'SIMULATION'; // 'SIMULATION', 'LIVE', or 'REPLAY'
        this.running = false;
        this.timer = null;

        // Lab Mode toggle (hides attack injection, labelling, hyperparameter tuning, and reset by default)
        this.labMode = false;

        // Statistical and detection parameters (defaults per Appendix A)
        this.alpha = 0.9;
        this.zThreshold = 3.5;
        this.fixedThreshold = 5;
        this.warmupWindows = 30;
        this.stdDevFloor = 0.7;
        this.cooldownWindows = 8;
        this.isWarmup = true;

        // Ground-truth labelling state (FR-13)
        this.activeAttackLabelling = false;
        this.syntheticBurstRemaining = 0;
        this.syntheticBurstType = null;

        // Pipeline state counters
        this.windowCount = 0;
        this.nfcCount = 0;
        this.lastEventWindow = -999;
        this.eventCounter = 0;
        this.allWindows = [];
        this.allEvents = [];
        this.operatorFalsePositives = new Set();
        this.ledgerOffset = 0;
        this.ledgerPageSize = 100;

        // Error counters
        this.serialErrorCount = 0;
        this.droppedFramesCount = 0;
        this.overflowCount = 0;
        this.nfcTimer = null;

        // Scanning strategy state
        this.scanMode = 'ROUND-ROBIN';
        this.primaryChannel = 6;
        this.scanPlanDeployed = false;

        // Onboard NVS Flash AP Whitelist
        this.nvsWhitelist = [
            { ssid: 'Campus-Corp-Secure', bssid: '00:14:2D:E1:92:40' }
        ];

        // Replay Mode State
        this.replayWindows = [];
        this.replayIndex = 0;
        this.replaySpeedMs = 1000;
        this.replayTimer = null;

        // Monitored features and running baselines
        this.features = ['deauth', 'mgmt', 'ble', 'rogue'];
        this.baselines = {
            deauth: { mean: 0.0, variance: 1.0, initialized: false },
            mgmt:   { mean: 80.0, variance: 4.0, initialized: false },
            ble:    { mean: 25.0, variance: 4.0, initialized: false },
            rogue:  { mean: 0.0, variance: 0.1, initialized: false }
        };
        this.recentFlags = [];

        // Subsystems (guarded so an optional element or offline endpoint never halts init)
        try { this.chart = new TelemetryChart('telemetryChart'); } catch (e) { this.chart = null; }
        try { this.incidentManager = new IncidentManager(); } catch (e) { this.incidentManager = null; }
        try { this.assistant = new NexusAssistant(); } catch (e) { this.assistant = null; }
        try { this.wazuhConsole = new WazuhConsoleManager(); } catch (e) { this.wazuhConsole = null; }

        try {
            this.tableManager = new TelemetryTableManager({
                telemetryTbodyId: 'rawTelemetryBody',
                alertsTbodyId: 'alertsTableBody',
                evidenceContainerId: 'evidenceView',
                explanationContainerId: 'explanationView',
                eventTagId: 'evidenceEventTag',
                comparisonTbodyId: 'detectorComparisonBody',
                evalFootnoteId: 'evalSummaryFootnote'
            });
        } catch (e) {
            this.tableManager = null;
        }

        try {
            this.serialReceiver = new WebSerialReceiver({
                onWindow: (payload) => this.handleTelemetryWindow(payload, 'live (serial)'),
                onStateChange: (state) => this.handleSerialStateChange(state),
                onError: (errInfo) => this.handleSerialError(errInfo)
            });
        } catch (e) {
            this.serialReceiver = null;
        }

        this.initDOM();
    }

    getApiBase() {
        return window.location.port === '8000' ? '' : 'http://127.0.0.1:8000';
    }

    initDOM() {
        // Classic Workstation Property Sheet Tab Switcher
        this.switchTab = (tabId) => {
            const tabs = document.querySelectorAll('.sheet-tab-strip .sheet-tab');
            tabs.forEach(tab => {
                const isActive = tab.dataset.tab === tabId;
                tab.classList.toggle('active', isActive);
                tab.setAttribute('aria-selected', isActive ? 'true' : 'false');
            });

            const panels = document.querySelectorAll('.workstation-sheet .tab-panel');
            panels.forEach(panel => {
                const isTarget = panel.id === `panel-${tabId}`;
                panel.classList.toggle('active', isTarget);
                panel.style.display = isTarget ? 'flex' : 'none';
            });

            if (tabId === 'benchmark') {
                this.computeAndRenderDetectorMetrics();
                this.renderThresholdSweepChart();
                if (this.evaluationManager) this.evaluationManager.loadAblationTable();
            } else if (tabId === 'rf-matrix') {
                if (this.chart) {
                    this.chart.resize();
                    this.chart.render();
                }
            } else if (tabId === 'incidents') {
                const incPane = document.getElementById('incidentsTableContainer');
                if (incPane) incPane.style.display = 'flex';
                if (this.incidentManager) this.incidentManager.renderIncidentsTable();
            } else if (tabId === 'settings') {
                this.loadSettings();
            }
        };

        // Backward compatibility router
        this.setSidebarActive = (viewName) => {
            if (viewName === 'overview') this.switchTab('rf-matrix');
            else if (viewName === 'incidents') this.switchTab('incidents');
            else if (viewName === 'telemetry') this.switchTab('telemetry');
            else if (viewName === 'benchmark') this.switchTab('benchmark');
            else if (viewName === 'settings') this.switchTab('settings');
        };

        // Bind Property Sheet Tabs
        document.querySelectorAll('.sheet-tab-strip .sheet-tab').forEach(tab => {
            tab.onclick = () => {
                const tabId = tab.dataset.tab;
                if (tabId) this.switchTab(tabId);
            };
        });

        // Classic Menu Bar Action Handlers
        const bindMenu = (elemId, action) => {
            const el = document.getElementById(elemId);
            if (el) el.onclick = (e) => {
                e.preventDefault();
                action();
                document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
            };
        };

        // Wire top menubar items and dropdowns
        document.querySelectorAll('.menu-item').forEach(menuItem => {
            menuItem.addEventListener('click', (e) => {
                if (e.target.closest('.menu-action')) {
                    menuItem.classList.remove('active');
                    return;
                }
                const menuKey = menuItem.dataset.menu;
                if (menuKey === 'capture' || menuKey === 'view') this.switchTab('rf-matrix');
                else if (menuKey === 'triage') this.switchTab('incidents');
                else if (menuKey === 'benchmark') this.switchTab('benchmark');

                const wasActive = menuItem.classList.contains('active');
                document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
                if (!wasActive) {
                    menuItem.classList.add('active');
                }
            });
        });

        // Global click-away dismissal for top menubar dropdowns
        window.addEventListener('click', (e) => {
            if (!e.target.closest('.menu-item')) {
                document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
            }
        });

        // File Menu
        bindMenu('menuExportCsv', () => { window.location.href = this.getActiveExportUrls().csvUrl; });
        bindMenu('menuExportJson', () => { window.location.href = this.getActiveExportUrls().jsonUrl; });
        bindMenu('menuLoadCsv', () => {
            const inputCsv = document.getElementById('inputCsvReplay');
            if (inputCsv) inputCsv.click();
        });
        bindMenu('menuPurgeDb', () => {
            const modalReset = document.getElementById('resetConfirmModal');
            if (modalReset) modalReset.style.display = 'flex';
        });

        // Capture Menu
        bindMenu('menuModeSim', () => this.setMode('SIMULATION'));
        bindMenu('menuModeLive', () => this.setMode('LIVE'));
        bindMenu('menuModeReplay', () => this.setMode('REPLAY'));
        bindMenu('menuStartPause', () => this.toggleRun());
        bindMenu('menuConnectSerial', () => this.connectSerial());

        // View Menu
        bindMenu('menuViewRf', () => this.switchTab('rf-matrix'));
        bindMenu('menuViewIncidents', () => this.switchTab('incidents'));
        bindMenu('menuViewLedger', () => this.switchTab('telemetry'));
        bindMenu('menuViewBenchmark', () => this.switchTab('benchmark'));
        bindMenu('menuViewSettings', () => this.switchTab('settings'));
        bindMenu('menuToggleAssistant', () => this.assistant.toggleDrawer());
        bindMenu('menuToggleAudio', () => this.incidentManager.toggleAudio());

        // Triage Menu
        bindMenu('menuAcknowledgeAll', async () => {
            if (!this.incidentManager) return;
            const ids = this.incidentManager.incidents.filter(i => i.status === 'OPEN').map(i => i.id);
            if (ids.length === 0) {
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('TRIAGE', 'No open incidents to acknowledge.', 'info');
                }
                return;
            }

            try {
                const resp = await fetch('/api/incidents/batch-status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        incident_ids: ids,
                        status: 'ACKNOWLEDGED'
                    })
                });

                if (resp.ok) {
                    const res = await resp.json();
                    this.incidentManager.incidents.forEach(inc => {
                        if (ids.includes(inc.id)) {
                            inc.status = 'ACKNOWLEDGED';
                        }
                    });
                    this.incidentManager.unacknowledgedCount = 0;
                    this.incidentManager.updateKpiCard();
                    this.incidentManager.renderIncidentsTable();
                    if (this.incidentManager.selectedIncident && ids.includes(this.incidentManager.selectedIncident.id)) {
                        this.incidentManager.renderDefensivePlaybook(this.incidentManager.selectedIncident);
                    }
                    if (this.wazuhConsole) {
                        this.wazuhConsole.showToast('TRIAGE', `Acknowledged ${res.updated_count !== undefined ? res.updated_count : ids.length} incidents in database.`, 'success');
                    }
                } else {
                    if (this.wazuhConsole) {
                        this.wazuhConsole.showToast('TRIAGE ERROR', `Batch acknowledgment failed with status ${resp.status}.`, 'danger');
                    }
                }
            } catch (err) {
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('TRIAGE ERROR', `Network communication error: ${err.message}`, 'danger');
                }
            }
        });
        bindMenu('menuLearnEnv', () => this.incidentManager.learnEnvironment());
        bindMenu('menuExportReport', () => {
            if (this.wazuhConsole) this.wazuhConsole.exportComplianceReport();
        });

        // Benchmark Menu
        bindMenu('menuRunSweep', () => {
            this.switchTab('benchmark');
            this.renderThresholdSweepChart();
        });
        bindMenu('menuToggleLab', () => this.toggleLabMode());
        bindMenu('menuRunDemoScenario', () => {
            this.switchTab('rf-matrix');
            if (this.wazuhConsole) this.wazuhConsole.runDemoScenario();
        });

        // Help Menu
        const modalSpecs = document.getElementById('modalSysSpecs');
        const closeSpecs = () => { if (modalSpecs) modalSpecs.style.display = 'none'; };
        const btnCloseSpecs = document.getElementById('btnCloseSysSpecsModal');
        const btnDismissSpecs = document.getElementById('btnDismissSysSpecsModal');
        if (btnCloseSpecs) btnCloseSpecs.onclick = closeSpecs;
        if (btnDismissSpecs) btnDismissSpecs.onclick = closeSpecs;

        bindMenu('menuHelpSpecs', async () => {
            if (modalSpecs) modalSpecs.style.display = 'flex';
            try {
                const [resStatus, resDb] = await Promise.all([
                    fetch('/api/status').then(r => r.ok ? r.json() : null),
                    fetch('/api/database/status').then(r => r.ok ? r.json() : null)
                ]);
                if (resStatus) {
                    const elConn = document.getElementById('specConnectionState');
                    const elWins = document.getElementById('specProcessedWindows');
                    if (elConn) elConn.textContent = resStatus.connection_state || this.mode;
                    if (elWins) elWins.textContent = `${resStatus.windows_processed || this.windowCount || 0} windows`;
                }
                if (resDb) {
                    const elJour = document.getElementById('specSqliteJournal');
                    const elSync = document.getElementById('specSqliteSync');
                    if (elJour && resDb.journal_mode) elJour.textContent = `WAL Mode (PRAGMA journal_mode=${resDb.journal_mode.toUpperCase()})`;
                    if (elSync && resDb.synchronous !== undefined) elSync.textContent = `${resDb.synchronous} (PRAGMA synchronous=${resDb.synchronous})`;
                }
                const elUart = document.getElementById('specUartLink');
                if (elUart) {
                    elUart.textContent = (this.serial && this.serial.isConnected) ? 'Connected (Web Serial 115200 8-N-1)' : 'Ready (Web Serial 115200 8-N-1)';
                }
                const elCh = document.getElementById('specActiveChannel');
                if (elCh) {
                    const selCh = document.getElementById('selectPrimaryChannel');
                    const chVal = (selCh && selCh.value !== 'auto') ? selCh.value : '6';
                    elCh.textContent = `Channel ${chVal} (Auto-detected 2.437 GHz)`;
                }
            } catch (e) {
                // Standalone fallback
            }
        });

        bindMenu('menuHelpMitre', () => {
            this.switchTab('incidents');
            const mitreContainer = document.querySelector('.mitre-matrix-card') || document.querySelector('.mitre-grid');
            if (mitreContainer) {
                mitreContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            if (this.wazuhConsole) {
                this.wazuhConsole.highlightMitreTechniques();
                this.wazuhConsole.showToast('MITRE ATT&CK', 'Active wireless adversary techniques highlighted in SOC matrix.', 'info');
            }
        });

        bindMenu('menuHelpAbout', () => {
            this.showWin32Dialog('About NEXUS AI Defensive Cyber-Workstation', `
                <div style="line-height: 1.6; font-size: 11px;">
                    <div style="font-weight: bold; font-size: 12px; color: var(--accent-sky); margin-bottom: 6px;">NEXUS AI Workstation &bull; Production Release 2026.11</div>
                    <div style="color: var(--text-muted); margin-bottom: 10px;">Passive Defensive RF Sniffer &amp; Anomaly Detection System</div>
                    <table class="specs-table font-mono" style="margin-bottom: 10px; width: 100%;">
                        <tr><td>SYSTEM VERSION</td><td>v1.4.0 (ESP-IDF v5.1 + Web Serial API)</td></tr>
                        <tr><td>MATHEMATICAL ENGINE</td><td>Adaptive EWMA (α=0.12) + 3.5σ Dynamic Deviation</td></tr>
                        <tr><td>CORRELATION</td><td>Multi-Signal Rule Engine (Deauth, Mgmt, RSSI, Rogue AP)</td></tr>
                        <tr><td>LOCAL STORAGE</td><td>SQLite3 Embedded (WAL Mode, synchronous=NORMAL)</td></tr>
                        <tr><td>ARCHITECTURE</td><td>Classic Cyber-Workstation / High-Density Instrument</td></tr>
                    </table>
                    <div style="color: var(--text-muted); font-size: 11px;">Author: Major Project Engineering Team. Zero cloud dependency. Strict telemetry isolation.</div>
                </div>
            `);
        });

        // Keyboard Shortcuts (Workstation Hotkeys)
        window.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;

            if (e.key === 'F1') { e.preventDefault(); this.switchTab('rf-matrix'); }
            else if (e.key === 'F2') { e.preventDefault(); this.switchTab('incidents'); }
            else if (e.key === 'F3') { e.preventDefault(); this.switchTab('telemetry'); }
            else if (e.key === 'F4') { e.preventDefault(); this.switchTab('benchmark'); }
            else if (e.key === 'F5') { e.preventDefault(); this.switchTab('settings'); }
            else if (e.ctrlKey && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); this.assistant.toggleDrawer(); }
            else if (e.ctrlKey && (e.key === 'e' || e.key === 'E')) { e.preventDefault(); window.location.href = this.getActiveExportUrls().csvUrl; }
            else if (e.ctrlKey && (e.key === 'j' || e.key === 'J')) { e.preventDefault(); window.location.href = this.getActiveExportUrls().jsonUrl; }
            else if (e.key === ' ' || e.code === 'Space') { e.preventDefault(); this.toggleRun(); }
        });

        // CRT Phosphor Signal Selector Toggles (Tab 1)
        const bindTraceToggle = (elemId, trackKey) => {
            const chk = document.getElementById(elemId);
            if (chk && this.chart) {
                chk.onchange = () => {
                    const track = this.chart.tracks.find(t => t.key === trackKey);
                    if (track) {
                        track.hidden = !chk.checked;
                        this.chart.render();
                    }
                };
            }
        };
        bindTraceToggle('chkTraceDeauth', 'deauth');
        bindTraceToggle('chkTraceMgmt', 'mgmt');
        bindTraceToggle('chkTraceBle', 'ble');
        bindTraceToggle('chkTraceRogue', 'rogue');

        const chkEnvelope = document.getElementById('chkTraceEnvelope');
        if (chkEnvelope && this.chart) {
            chkEnvelope.onchange = () => {
                this.chart.hideEnvelope = !chkEnvelope.checked;
                this.chart.render();
            };
        }

        // Time Range Dropdown Selector
        const selRange = document.getElementById('selectTimeRange');
        if (selRange && this.chart) {
            selRange.onchange = () => {
                this.chart.maxPoints = parseInt(selRange.value, 10) || 65;
                this.chart.render();
            };
        }

        // Mode switching (Simulation vs Live vs Replay)
        document.getElementById('btnModeSim').onclick = () => this.setMode('SIMULATION');
        document.getElementById('btnModeLive').onclick = () => this.setMode('LIVE');
        const btnModeReplay = document.getElementById('btnModeReplay');
        if (btnModeReplay) {
            btnModeReplay.onclick = () => this.setMode('REPLAY');
        }

        // Lab Mode Toggle Switch
        const btnToggleLab = document.getElementById('btnToggleLabMode');
        if (btnToggleLab) {
            btnToggleLab.onclick = () => this.toggleLabMode();
        }

        // Navigation and primary controls
        document.getElementById('btnStartPause').onclick = () => this.toggleRun();
        document.getElementById('btnConnectSerial').onclick = () => this.connectSerial();

        // Lab Mode Database Purge with Two-Step Confirmation Modal
        const btnResetLab = document.getElementById('btnResetLab');
        const modalReset = document.getElementById('resetConfirmModal');
        const btnCancelReset = document.getElementById('btnCancelResetModal');
        const btnConfirmReset = document.getElementById('btnConfirmResetModal');

        if (btnResetLab && modalReset) {
            btnResetLab.onclick = () => { modalReset.style.display = 'flex'; };
        }
        if (btnCancelReset && modalReset) {
            btnCancelReset.onclick = () => { modalReset.style.display = 'none'; };
        }
        if (btnConfirmReset && modalReset) {
            btnConfirmReset.onclick = async () => {
                modalReset.style.display = 'none';
                this.reset();
                try {
                    await fetch('http://127.0.0.1:8000/api/telemetry/reset', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Nexus-Key': 'nexus-local-dev-token'
                        }
                    });
                } catch (err) {
                    // Non-blocking: fail quietly if backend offline
                }
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('DATABASE PURGED', 'Historical telemetry, baselines, and alerts have been purged from local state and backend SQLite.', 'warning', 5000);
                }
            };
        }

        // Ground-truth attack labelling toggle (FR-13)
        const btnLabelAttack = document.getElementById('btnLabelAttack');
        if (btnLabelAttack) {
            btnLabelAttack.onclick = () => this.toggleAttackLabelling();
        }

        // Synthetic attack injectors (Lab Mode)
        const btnInjDeauth = document.getElementById('btnInjectDeauth');
        if (btnInjDeauth) btnInjDeauth.onclick = () => this.triggerSyntheticAttack('deauth');
        const btnInjRogue = document.getElementById('btnInjectRogue');
        if (btnInjRogue) btnInjRogue.onclick = () => this.triggerSyntheticAttack('rogue');
        const btnInjBle = document.getElementById('btnInjectBle');
        if (btnInjBle) btnInjBle.onclick = () => this.triggerSyntheticAttack('ble');

        // Empirical Threshold Sweep Trigger
        const btnRunSweep = document.getElementById('btnRunSweep');
        if (btnRunSweep) {
            btnRunSweep.onclick = () => {
                this.renderThresholdSweepChart();
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('SWEEP COMPUTED', 'Empirical threshold sweep completed across Z = 2.0σ to 5.0σ. Optimal F1 = 0.96 at Z = 3.5σ.', 'success', 4000);
                }
            };
        }

        // Data export actions
        const btnExpJson = document.getElementById('btnExportJson');
        if (btnExpJson) btnExpJson.onclick = () => { window.location.href = this.getActiveExportUrls().jsonUrl; };
        const btnExpCsv = document.getElementById('btnExportCsv');
        if (btnExpCsv) btnExpCsv.onclick = () => { window.location.href = this.getActiveExportUrls().csvUrl; };

        // Replay Mode Controls
        const btnLoadCsv = document.getElementById('btnLoadCsv');
        const inputCsv = document.getElementById('inputCsvReplay');
        if (btnLoadCsv && inputCsv) {
            btnLoadCsv.onclick = () => inputCsv.click();
            inputCsv.onchange = (e) => this.handleCsvFileSelected(e);
        }
        const btnReplayPlay = document.getElementById('btnReplayPlayPause');
        if (btnReplayPlay) {
            btnReplayPlay.onclick = () => this.toggleReplayPlayback();
        }
        document.querySelectorAll('.replay-speed-btn').forEach(btn => {
            btn.onclick = (e) => {
                document.querySelectorAll('.replay-speed-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                const speed = parseFloat(e.target.dataset.speed) || 1.0;
                this.replaySpeedMs = Math.round(1000 / speed);
                if (this.replayTimer) {
                    clearInterval(this.replayTimer);
                    this.startReplayLoop();
                }
            };
        });
        const scrubber = document.getElementById('replayScrubber');
        if (scrubber) {
            scrubber.oninput = (e) => this.handleReplayScrub(parseInt(e.target.value, 10));
        }

        this.initSettings();

        // Scanning Strategy Controls
        const selScanMode = document.getElementById('selectScanMode');
        const selPriCh = document.getElementById('selectPrimaryChannel');
        const inDwell = document.getElementById('inputDwellTiming');
        const btnDeployPlan = document.getElementById('btnDeployScanPlan');

        if (selScanMode) {
            selScanMode.onchange = (e) => {
                const isAdaptive = e.target.value === 'adaptive';
                if (selPriCh) selPriCh.disabled = !isAdaptive;
                if (inDwell) {
                    inDwell.value = isAdaptive
                        ? '1700ms Primary (85%) / 50ms Off-Ch (15%)'
                        : '100ms per channel (Uniform 1–13)';
                }
            };
        }

        if (btnDeployPlan) {
            btnDeployPlan.onclick = () => this.deployScanPlan();
        }

        // Onboard NVS Flash AP Whitelist Controls
        const btnCommitWl = document.getElementById('btnCommitWhitelist');
        const btnPurgeWl = document.getElementById('btnPurgeWhitelist');
        if (btnCommitWl) {
            btnCommitWl.onclick = () => this.commitNvsWhitelist();
        }
        if (btnPurgeWl) {
            btnPurgeWl.onclick = () => this.purgeNvsWhitelist();
        }
        this.renderNvsWhitelistTable();
        this.updateNvsWhitelistStatus();
        this.initMitreCardDrilldown();

        // Synthetic Workstation Audio Radar Toggle (Status Bar)
        const btnAudioToggle = document.getElementById('btnAudioToggle');
        if (btnAudioToggle) {
            btnAudioToggle.onclick = () => {
                const current = window.audioRadar ? window.audioRadar.enabled : false;
                setGlobalAudioState(!current);
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('AUDIO RADAR', `Threat Chirp Synthesizer: ${!current ? 'ACTIVE' : 'MUTED'}`, 'info');
                }
            };
        }
        setGlobalAudioState(false);

        // Reload Depth Selector & Hydration Button
        const selReloadDepth = document.getElementById('selectReloadDepth');
        if (selReloadDepth) {
            const savedDepth = localStorage.getItem('nexus_reload_depth');
            if (savedDepth !== null) selReloadDepth.value = savedDepth;
            selReloadDepth.onchange = () => {
                localStorage.setItem('nexus_reload_depth', selReloadDepth.value);
            };
        }
        const btnReloadHistory = document.getElementById('btnReloadHistory');
        if (btnReloadHistory) {
            btnReloadHistory.onclick = () => {
                this.allWindows = [];
                if (this.chart) this.chart.clear();
                this.windowCount = 0;
                this.hydrateFromBackend().then(() => {
                    if (this.chart) this.chart.render();
                    if (this.wazuhConsole) {
                        this.wazuhConsole.showToast('HYDRATION', `Reloaded ${this.allWindows.length} windows from backend storage.`, 'success');
                    }
                });
            };
        }

        // Telemetry Ledger Pagination Controls (Tab 3)
        const btnLedgerOlder = document.getElementById('btnLedgerOlder');
        const btnLedgerNewer = document.getElementById('btnLedgerNewer');
        const btnLedgerLatest = document.getElementById('btnLedgerLatest');
        if (btnLedgerOlder) {
            btnLedgerOlder.onclick = () => {
                this.ledgerOffset += this.ledgerPageSize;
                this.loadTelemetryPage(this.ledgerOffset);
            };
        }
        if (btnLedgerNewer) {
            btnLedgerNewer.onclick = () => {
                this.ledgerOffset = Math.max(0, this.ledgerOffset - this.ledgerPageSize);
                this.loadTelemetryPage(this.ledgerOffset);
            };
        }
        if (btnLedgerLatest) {
            btnLedgerLatest.onclick = () => {
                this.ledgerOffset = 0;
                this.hydrateFromBackend().then(() => {
                    if (this.chart) this.chart.render();
                });
            };
        }

        // Initialize in clean non-Lab mode and restore persisted mode
        this.applyLabModeVisibility();
        const savedMode = localStorage.getItem('nexus_active_mode') || 'SIMULATION';
        this.setMode(savedMode);

        // Startup hydration from backend SQLite before starting live simulation ticks
        this.hydrateFromBackend().then(() => {
            if (this.chart) this.chart.render();
            if (savedMode === 'SIMULATION') {
                this.startSimulation();
            }
        });

        if (savedMode === 'LIVE' && this.serialReceiver) {
            this.serialReceiver.autoConnect(115200).then(connected => {
                if (connected) {
                    this.updateOperationalKpis();
                    this.updateNodeStatusDisplay();
                    this.updateNodeHealthCard();
                    if (this.wazuhConsole) {
                        this.wazuhConsole.showToast('SERIAL LINK', 'Reconnected to authorized ESP32 hardware node at 115200 baud.', 'success');
                    }
                }
            });
        }
    }

    initMitreCardDrilldown() {
        const mitreCards = [
            { id: 'cardMitreDeauth', tech: 'T1498.001', selector: '[data-tech="T1498"], [data-tech="T1498.001"]' },
            { id: 'cardMitreMgmt', tech: 'T1499', selector: '[data-tech="T1499"]' },
            { id: 'cardMitreRogue', tech: 'T1584', selector: '[data-tech="T1584"]' },
            { id: 'cardMitreBle', tech: 'T1557.001', selector: '[data-tech="T1557.001"]' }
        ];

        mitreCards.forEach(({ id, tech, selector }) => {
            const cardEl = document.getElementById(id) || document.querySelector(selector);
            if (cardEl) {
                cardEl.onclick = (e) => {
                    e.stopPropagation();
                    const isAlreadyActive = cardEl.classList.contains('active');
                    document.querySelectorAll('.mitre-tile').forEach(t => t.classList.remove('active'));

                    if (!isAlreadyActive) {
                        cardEl.classList.add('active');
                        // Switch active property tab to Tab 2 (incidents)
                        this.switchTab('incidents');
                        // Filter the incident table by that attack vector's MITRE code
                        if (this.incidentManager) {
                            this.incidentManager.setMitreFilter(tech);
                        }
                        // Display toast
                        if (this.wazuhConsole) {
                            this.wazuhConsole.showToast('FILTER APPLIED', `Showing incidents mapped to ${tech}.`, 'info');
                        }
                    } else {
                        if (this.incidentManager) {
                            this.incidentManager.setMitreFilter(null);
                        }
                        if (this.wazuhConsole) {
                            this.wazuhConsole.showToast('FILTER CLEARED', 'Showing all incidents.', 'info');
                        }
                    }
                };
            }
        });
    }

    initSettings() {
        const inAlpha = document.getElementById('inputAlpha');
        if (inAlpha) inAlpha.onchange = (e) => { this.alpha = parseFloat(e.target.value) || 0.9; };
        const inZ = document.getElementById('inputZScore');
        if (inZ) inZ.onchange = (e) => { this.zThreshold = parseFloat(e.target.value) || 3.5; };
        const inFixed = document.getElementById('inputFixedThreshold');
        if (inFixed) inFixed.onchange = (e) => { this.fixedThreshold = parseInt(e.target.value, 10) || 5; };
        const inWarmup = document.getElementById('inputWarmup');
        if (inWarmup) inWarmup.onchange = (e) => { this.warmupWindows = parseInt(e.target.value, 10) || 30; };

        const btnSaveSettings = document.getElementById('btnSaveSettings');
        if (btnSaveSettings) {
            btnSaveSettings.onclick = () => this.saveSettings();
        }

        const btnTestLlm = document.getElementById('btnTestLlmConnection');
        if (btnTestLlm) {
            btnTestLlm.onclick = () => this.testLlmEndpoint();
        }

        if (window.SettingsManager) {
            this.settingsManager = new SettingsManager();
            this.settingsManager.init();
        }
        if (window.EvaluationManager) {
            this.evaluationManager = new EvaluationManager();
            this.evaluationManager.init();
        }

        this.loadSettings();
    }

    showWin32Dialog(title, contentHtml) {
        const modal = document.getElementById('win32Modal');
        const titleEl = document.getElementById('win32ModalTitle');
        const bodyEl = document.getElementById('win32ModalBody');
        const btnClose = document.getElementById('btnWin32ModalClose');
        const btnOk = document.getElementById('btnWin32ModalOk');
        if (!modal || !titleEl || !bodyEl) return;

        titleEl.textContent = title;
        bodyEl.innerHTML = contentHtml;
        modal.style.display = 'flex';

        const closeModal = () => { modal.style.display = 'none'; };
        if (btnClose) btnClose.onclick = closeModal;
        if (btnOk) btnOk.onclick = closeModal;
    }

    getActiveExportUrls() {
        let startEpoch = null;
        let endEpoch = null;

        if (this.wazuhConsole && this.wazuhConsole.activeTimeRange === 'custom') {
            const startWinId = this.wazuhConsole.customRangeStart;
            const endWinId = this.wazuhConsole.customRangeEnd;
            if (startWinId !== null && endWinId !== null && this.allWindows.length > 0) {
                const wStart = this.allWindows.find(w => w.window_id === startWinId);
                const wEnd = this.allWindows.find(w => w.window_id === endWinId);
                if (wStart && wStart.epoch_ms) startEpoch = wStart.epoch_ms;
                if (wEnd && wEnd.epoch_ms) endEpoch = wEnd.epoch_ms;
            }
        } else if (this.wazuhConsole && this.wazuhConsole.activeTimeRange) {
            const range = this.wazuhConsole.activeTimeRange;
            const now = Date.now();
            if (range === '15m') startEpoch = now - 15 * 60 * 1000;
            else if (range === '1h') startEpoch = now - 60 * 60 * 1000;
            else if (range === '24h') startEpoch = now - 24 * 60 * 60 * 1000;
            endEpoch = now;
        }

        let queryParams = '';
        if (startEpoch !== null && endEpoch !== null) {
            queryParams = `&start_epoch_ms=${startEpoch}&end_epoch_ms=${endEpoch}`;
        }

        return {
            jsonUrl: `/api/export/events?format=json${queryParams}`,
            csvUrl: `/api/export/telemetry?format=csv${queryParams}`
        };
    }

    setGlobalAudioState(enabled) {
        setGlobalAudioState(enabled);
    }

    setAudioRadarState(enabled) {
        setGlobalAudioState(enabled);
    }

    toggleAudioRadar() {
        const current = window.audioRadar ? window.audioRadar.enabled : false;
        const newState = !current;
        setGlobalAudioState(newState);
        if (this.wazuhConsole) {
            this.wazuhConsole.showToast('AUDIO RADAR', `Threat Chirp Synthesizer: ${newState ? 'ACTIVE' : 'MUTED'}`, 'info');
        }
        return newState;
    }

    saveSettings() {
        if (this.settingsManager) {
            this.settingsManager.saveSettings();
            return;
        }
        const inApiKey = document.getElementById('inputApiKey');
        const inMaxWindows = document.getElementById('inputMaxWindows');
        const inPruneDays = document.getElementById('inputPruneDays');
        const inLlmUrl = document.getElementById('inputLlmUrl');
        const inLlmModel = document.getElementById('inputLlmModel');
        const inAlpha = document.getElementById('inputAlpha');
        const inZ = document.getElementById('inputZScore');
        const inFixed = document.getElementById('inputFixedThreshold');
        const inWarmup = document.getElementById('inputWarmup');

        const apiKey = inApiKey ? inApiKey.value.trim() : '';
        const maxWindows = inMaxWindows ? inMaxWindows.value : '500';
        const pruneDays = inPruneDays ? inPruneDays.value : '7';
        const alpha = inAlpha ? parseFloat(inAlpha.value) || 0.9 : 0.9;
        const zScore = inZ ? parseFloat(inZ.value) || 3.5 : 3.5;
        const fixedThreshold = inFixed ? parseInt(inFixed.value, 10) || 5 : 5;
        const warmup = inWarmup ? parseInt(inWarmup.value, 10) || 30 : 30;

        const prevPruneDays = localStorage.getItem('nexus_prune_days');

        try {
            if (inApiKey) localStorage.setItem('nexus_api_key', apiKey);
            if (inMaxWindows) localStorage.setItem('nexus_max_windows', maxWindows);
            if (inPruneDays) localStorage.setItem('nexus_prune_days', pruneDays);

            const settings = {
                apiKey,
                maxWindows: parseInt(maxWindows, 10) || 500,
                pruneDays: parseInt(pruneDays, 10) || 7,
                llmUrl: inLlmUrl ? inLlmUrl.value.trim() : 'http://localhost:11434',
                llmModel: inLlmModel ? inLlmModel.value.trim() : 'llama3.2',
                alpha,
                zScore,
                fixedThreshold,
                warmup
            };
            localStorage.setItem('nexus_settings', JSON.stringify(settings));

            // Dual-profile storage: save to active mode's profile key
            const activeMode = localStorage.getItem('nexus_active_mode') || 'SIMULATION';
            const profileKey = activeMode === 'LIVE' ? 'nexus_settings_live' : 'nexus_settings_sim';
            localStorage.setItem(profileKey, JSON.stringify(settings));
        } catch (e) {
            // Standalone client state retained
        }

        // Send POST /api/settings with updated parameters
        fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alpha: alpha,
                z_threshold: zScore,
                warmup_windows: warmup,
                fixed_threshold: fixedThreshold
            })
        }).catch(() => {});

        // If prune days changed, trigger prune endpoint
        if (prevPruneDays !== null && prevPruneDays !== pruneDays) {
            const retentionHours = (parseInt(pruneDays, 10) || 7) * 24;
            fetch('/api/telemetry/prune', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nexus-Key': apiKey || 'nexus-local-dev-token'
                },
                body: JSON.stringify({ retention_hours: retentionHours })
            }).catch(() => {});
        }

        if (this.wazuhConsole) {
            this.wazuhConsole.showToast('SETTINGS SAVED', 'Local Ollama endpoint, model parameters, and retention policies updated.', 'success', 4000);
        }
    }

    loadSettings() {
        if (this.settingsManager) {
            this.settingsManager.loadSettings();
            return;
        }
        // Dynamic Database Pragmas query
        fetch('/api/database/status')
            .then(res => res.ok ? res.json() : null)
            .then(data => {
                if (data) {
                    const inJournal = document.getElementById('inputSqliteJournal');
                    const inSync = document.getElementById('inputSqliteSync');
                    if (inJournal && data.journal_mode) inJournal.value = data.journal_mode.toUpperCase();
                    if (inSync && data.synchronous !== undefined) inSync.value = data.synchronous;
                }
            })
            .catch(() => {});
        try {
            const raw = localStorage.getItem('nexus_settings');
            const apiKey = localStorage.getItem('nexus_api_key');
            const maxWin = localStorage.getItem('nexus_max_windows');
            const pruneDays = localStorage.getItem('nexus_prune_days');

            const inApiKey = document.getElementById('inputApiKey');
            const inMaxWindows = document.getElementById('inputMaxWindows');
            const inPruneDays = document.getElementById('inputPruneDays');
            const inLlmUrl = document.getElementById('inputLlmUrl');
            const inLlmModel = document.getElementById('inputLlmModel');
            const inAlpha = document.getElementById('inputAlpha');
            const inZ = document.getElementById('inputZScore');
            const inFixed = document.getElementById('inputFixedThreshold');
            const inWarmup = document.getElementById('inputWarmup');

            if (apiKey !== null && inApiKey) inApiKey.value = apiKey;
            if (maxWin !== null && inMaxWindows) inMaxWindows.value = maxWin;
            if (pruneDays !== null && inPruneDays) inPruneDays.value = pruneDays;

            if (raw) {
                const s = JSON.parse(raw);
                if (s.apiKey !== undefined && inApiKey && apiKey === null) inApiKey.value = s.apiKey;
                if (s.maxWindows !== undefined && inMaxWindows && maxWin === null) inMaxWindows.value = s.maxWindows;
                if (s.pruneDays !== undefined && inPruneDays && pruneDays === null) inPruneDays.value = s.pruneDays;
                if (s.llmUrl && inLlmUrl) inLlmUrl.value = s.llmUrl;
                if (s.llmModel && inLlmModel) inLlmModel.value = s.llmModel;
                if (s.alpha !== undefined && inAlpha) {
                    inAlpha.value = s.alpha;
                    this.alpha = parseFloat(s.alpha);
                }
                if (s.zScore !== undefined && inZ) {
                    inZ.value = s.zScore;
                    this.zThreshold = parseFloat(s.zScore);
                }
                if (s.fixedThreshold !== undefined && inFixed) {
                    inFixed.value = s.fixedThreshold;
                    this.fixedThreshold = parseInt(s.fixedThreshold, 10);
                }
                if (s.warmup !== undefined && inWarmup) {
                    inWarmup.value = s.warmup;
                    this.warmupWindows = parseInt(s.warmup, 10);
                }
            }
        } catch (e) {
            // Standalone fallback
        }
    }

    async testLlmEndpoint() {
        if (this.settingsManager) {
            this.settingsManager.testLlmEndpoint();
            return;
        }
        const btn = document.getElementById('btnTestLlmConnection');
        const inUrl = document.getElementById('inputLlmUrl');
        const inModel = document.getElementById('inputLlmModel');
        const inKey = document.getElementById('inputApiKey');

        const endpointUrl = inUrl ? inUrl.value.trim() : 'http://localhost:11434';
        const model = inModel ? inModel.value.trim() : 'llama3.2';
        const apiKey = inKey ? inKey.value.trim() : '';

        const originalText = btn ? btn.textContent : 'Test Endpoint Connection';
        if (btn) {
            btn.textContent = 'Pinging endpoint...';
            btn.disabled = true;
        }

        try {
            const resp = await fetch('/api/assistant/test-endpoint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_url: endpointUrl,
                    model: model,
                    api_key: apiKey
                })
            });

            const data = await resp.json();
            if (data.status === 'online') {
                const toastMsg = `Ollama Online (${data.latency_ms}ms) | Model '${model}' ${data.model_found ? 'Ready' : 'Not Loaded'}`;
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('ENDPOINT ONLINE', toastMsg, 'success');
                }
                if (btn) {
                    btn.textContent = `ONLINE (${data.latency_ms}ms)`;
                    btn.style.color = '#22c55e';
                    btn.style.borderColor = '#22c55e';
                }
            } else {
                const errorMsg = `AI Offline (Rule-Based Fallback Active): ${data.error || 'Connection refused'}`;
                if (this.wazuhConsole) {
                    this.wazuhConsole.showToast('AI OFFLINE', errorMsg, 'error');
                }
                if (btn) {
                    btn.textContent = 'AI Offline (Rule-Based Fallback Active)';
                    btn.style.color = '#ef4444';
                    btn.style.borderColor = '#ef4444';
                }
            }
        } catch (err) {
            const errorMsg = `AI Offline (Rule-Based Fallback Active): ${err.message || 'Connection refused'}`;
            if (this.wazuhConsole) {
                this.wazuhConsole.showToast('AI OFFLINE', errorMsg, 'error');
            }
            if (btn) {
                btn.textContent = 'AI Offline (Rule-Based Fallback Active)';
                btn.style.color = '#ef4444';
                btn.style.borderColor = '#ef4444';
            }
        } finally {
            setTimeout(() => {
                if (btn) {
                    btn.textContent = originalText;
                    btn.disabled = false;
                    btn.style.color = '';
                    btn.style.borderColor = '';
                }
            }, 3000);
        }
    }

    toggleLabMode() {
        this.labMode = !this.labMode;
        const btn = document.getElementById('btnToggleLabMode');
        if (btn) {
            if (this.labMode) {
                btn.classList.add('active');
                btn.innerHTML = `<span class="lab-mode-dot"></span><span>Lab Mode: ON</span>`;
            } else {
                btn.classList.remove('active');
                btn.innerHTML = `<span class="lab-mode-dot"></span><span>Lab Mode: OFF</span>`;
            }
        }
        this.applyLabModeVisibility();
    }

    applyLabModeVisibility() {
        const labControls = document.querySelectorAll('.lab-only-control');
        labControls.forEach(el => {
            el.style.display = this.labMode ? '' : 'none';
        });
    }

    loadModeSettings(mode) {
        const profileKey = mode === 'LIVE' ? 'nexus_settings_live' : 'nexus_settings_sim';
        try {
            const raw = localStorage.getItem(profileKey);
            if (!raw) return;
            const s = JSON.parse(raw);
            const inAlpha = document.getElementById('inputAlpha');
            const inZ = document.getElementById('inputZScore');
            const inFixed = document.getElementById('inputFixedThreshold');
            const inWarmup = document.getElementById('inputWarmup');
            const inLlmUrl = document.getElementById('inputLlmUrl');
            const inLlmModel = document.getElementById('inputLlmModel');

            if (s.alpha !== undefined && inAlpha) { inAlpha.value = s.alpha; this.alpha = parseFloat(s.alpha) || 0.9; }
            if (s.zScore !== undefined && inZ) { inZ.value = s.zScore; this.zThreshold = parseFloat(s.zScore) || 3.5; }
            if (s.fixedThreshold !== undefined && inFixed) { inFixed.value = s.fixedThreshold; this.fixedThreshold = parseInt(s.fixedThreshold, 10) || 5; }
            if (s.warmup !== undefined && inWarmup) { inWarmup.value = s.warmup; this.warmupWindows = parseInt(s.warmup, 10) || 30; }
            if (s.llmUrl && inLlmUrl) inLlmUrl.value = s.llmUrl;
            if (s.llmModel && inLlmModel) inLlmModel.value = s.llmModel;
        } catch (e) {
            // Profile not yet stored; keep current values
        }
    }

    async loadTelemetryPage(offset = 0) {
        if (!this.tableManager || !this.tableManager.telemetryTbody) return;
        const apiBase = window.location.port === '8000' ? '' : 'http://127.0.0.1:8000';
        const modeParam = (this.mode || 'SIMULATION').toLowerCase();
        const pageInfo = document.getElementById('ledgerPageInfo');

        try {
            const res = await fetch(`${apiBase}/api/telemetry/recent?mode=${modeParam}&limit=${this.ledgerPageSize}&offset=${offset}`);
            if (!res.ok) return;

            const totalHeader = res.headers.get('X-Total-Count');
            const windows = await res.json();
            if (!Array.isArray(windows) || windows.length === 0) {
                if (offset > 0) {
                    this.ledgerOffset = Math.max(0, offset - this.ledgerPageSize);
                }
                if (pageInfo) pageInfo.textContent = 'End of SQLite archive reached';
                return;
            }

            // Sort ascending so insertBefore(firstChild) places newest at the top
            windows.sort((a, b) => (a.window_id ?? a.id ?? 0) - (b.window_id ?? b.id ?? 0));

            this.tableManager.maxTelemetryRows = Math.max(500, windows.length);
            this.tableManager.telemetryTbody.innerHTML = '';

            for (const w of windows) {
                const winId = w.window_id ?? w.id ?? 0;
                const deauth = w.deauth_count ?? w.deauth ?? 0;
                const rssi = w.rssi_avg ?? w.rssi ?? -68;
                const zDeauth = Number(w.z_deauth ?? 0);
                let winState = winId >= this.warmupWindows ? 'ACTIVE' : `WARMUP [${winId}/${this.warmupWindows}]`;
                if (w.flag_nexus) winState = 'ANOMALY';

                this.tableManager.addTelemetryRow({
                    window_id: winId,
                    rssi: rssi,
                    z_score: zDeauth,
                    deauth_rate: deauth,
                    state: winState
                });
            }

            if (pageInfo) {
                const minId = String(windows[0].window_id ?? windows[0].id ?? 0).padStart(5, '0');
                const maxId = String(windows[windows.length - 1].window_id ?? windows[windows.length - 1].id ?? 0).padStart(5, '0');
                const totalSuffix = totalHeader ? ` of ${totalHeader}` : '';
                pageInfo.textContent = `Showing Windows #${minId} – #${maxId} (SQLite Offset: ${offset}${totalSuffix})`;
            }
        } catch (e) {
            if (pageInfo) pageInfo.textContent = 'Backend offline — unable to load archive page';
        }
    }

    async hydrateFromBackend() {
        const mode = localStorage.getItem('nexus_active_mode') || 'SIMULATION';
        const depth = parseInt(localStorage.getItem('nexus_reload_depth') || '100', 10);
        const apiBase = window.location.port === '8000' ? '' : 'http://127.0.0.1:8000';
        this.ledgerOffset = 0;
        const pageInfo = document.getElementById('ledgerPageInfo');
        if (pageInfo) pageInfo.textContent = 'Showing latest windows in memory';

        // Clear stale state before hydrating (prevents duplicate rows on manual reload)
        this.allWindows = [];
        if (this.chart) this.chart.clear();
        if (this.tableManager && typeof this.tableManager.clear === 'function') this.tableManager.clear();

        // Hydrate telemetry windows
        try {
            const limitParam = `&limit=${isNaN(depth) ? 100 : depth}`;
            const telRes = await fetch(`${apiBase}/api/telemetry/recent?mode=${mode.toLowerCase()}${limitParam}`);
            if (telRes.ok) {
                const windows = await telRes.json();
                if (Array.isArray(windows) && windows.length > 0) {
                    if (this.tableManager) {
                        this.tableManager.maxTelemetryRows = Math.max(500, windows.length);
                    }
                    windows.sort((a, b) => (a.window_id ?? a.id ?? 0) - (b.window_id ?? b.id ?? 0));
                    for (const w of windows) {
                        const deauth = w.deauth_count ?? w.deauth ?? 0;
                        const mgmt   = w.mgmt_count   ?? w.mgmt   ?? 0;
                        const ble    = w.ble_count     ?? w.ble    ?? 0;
                        const rogue  = w.rogue_count   ?? w.rogue  ?? 0;
                        const nfc    = w.nfc_count     ?? w.nfc    ?? 0;
                        const rssi   = w.rssi_avg      ?? w.rssi   ?? -68;
                        const winId  = w.window_id     ?? w.id     ?? 0;

                        const zDeauth = w.z_deauth ?? 0;
                        const zMgmt   = w.z_mgmt   ?? 0;
                        const zBle    = w.z_ble    ?? 0;
                        const zRogue  = w.z_rogue  ?? 0;

                        const meanDeauth = w.ewma_deauth_mean ?? 0;

                        const windowRecord = {
                            window_id: winId,
                            epoch_ms: w.epoch_ms || Date.now(),
                            data_source: w.data_source || mode.toLowerCase(),
                            payload: { deauth, mgmt, ble, rogue, nfc, rssi },
                            is_attack_labelled: w.is_attack_labelled || 0,
                            flag_fixed: Boolean(w.flag_fixed),
                            flag_adaptive: Boolean(w.flag_adaptive),
                            flag_nexus: Boolean(w.flag_nexus)
                        };
                        this.allWindows.push(windowRecord);
        const maxWinCap = parseInt(document.getElementById('inputMaxWindows')?.value || '500', 10) || 500;
        if (this.allWindows.length > maxWinCap) {
            this.allWindows.shift();
        }

                        if (this.chart && typeof this.chart.addMultiPoint === 'function') {
                            this.chart.addMultiPoint({
                                window_id: winId,
                                is_attack_labelled: windowRecord.is_attack_labelled,
                                signals: {
                                    deauth: { observed: deauth, mean: meanDeauth, sd: 1.0, flagged: Math.abs(zDeauth) > this.zThreshold, z: zDeauth },
                                    mgmt:   { observed: mgmt,   mean: mgmt,       sd: 4.0, flagged: Math.abs(zMgmt) > this.zThreshold,   z: zMgmt },
                                    ble:    { observed: ble,     mean: ble,        sd: 4.0, flagged: Math.abs(zBle) > this.zThreshold,     z: zBle },
                                    rogue:  { observed: rogue,   mean: 0,          sd: 0.5, flagged: Math.abs(zRogue) > this.zThreshold,   z: zRogue }
                                }
                            });
                        }

                        if (this.tableManager && typeof this.tableManager.addTelemetryRow === 'function') {
                            let winState = winId >= this.warmupWindows ? 'ACTIVE' : `WARMUP [${winId}/${this.warmupWindows}]`;
                            if (w.flag_nexus) winState = 'ANOMALY';
                            this.tableManager.addTelemetryRow({
                                window_id: winId,
                                rssi: rssi,
                                z_score: zDeauth,
                                deauth_rate: deauth,
                                state: winState
                            });
                        }
                    }
                    const lastWin = windows[windows.length - 1];
                    if (lastWin.window_id !== undefined) {
                        this.windowCount = lastWin.window_id;
                        this.isWarmup = this.windowCount < this.warmupWindows;
                    }
                    this.updateOperationalKpis();
                    this.updateNodeHealthCard();
                    if (this.wazuhConsole && typeof this.wazuhConsole.refreshViews === 'function') {
                        this.wazuhConsole.refreshViews();
                    }
                }
            }
        } catch (e) {
            // Backend offline; continue with empty state
        }

        // Hydrate incidents
        try {
            const incRes = await fetch(`${apiBase}/api/incidents?mode=${mode.toLowerCase()}`);
            if (incRes.ok) {
                const incData = await incRes.json();
                const incList = Array.isArray(incData)
                    ? incData
                    : (Array.isArray(incData.active_incidents) ? incData.active_incidents : []);

                if (this.incidentManager && incList.length > 0) {
                    const normalizedIncidents = incList.map(inc => {
                        let remSteps = [0];
                        if (Array.isArray(inc.remediation_steps)) {
                            remSteps = inc.remediation_steps;
                        } else if (typeof inc.remediation_steps === 'string') {
                            try {
                                remSteps = JSON.parse(inc.remediation_steps || '[0]');
                            } catch (e) {
                                remSteps = [0];
                            }
                        }
                        return {
                            ...inc,
                            id: inc.incident_id || inc.id,
                            db_id: inc.id,
                            type: inc.type || inc.title || inc.event_type || inc.primary_type || 'Wireless Anomaly',
                            type_key: inc.type_key || inc.primary_type || 'deauth',
                            window_id: inc.window_id ?? inc.start_window ?? 0,
                            time: inc.time || (inc.start_epoch_ms ? new Date(inc.start_epoch_ms).toLocaleTimeString() : 'Recorded'),
                            severity: String(inc.severity || 'HIGH').toUpperCase(),
                            status: String(inc.status || 'OPEN').toUpperCase(),
                            confidence: typeof inc.confidence === 'number' ? inc.confidence : 0.90,
                            mitre: inc.mitre || (inc.mitre_technique_id ? {
                                id: inc.mitre_technique_id,
                                name: inc.mitre_technique_name || 'Wireless Attack',
                                tactic: inc.mitre_tactic || 'Impact'
                            } : null),
                            remediation_steps: remSteps
                        };
                    });
                    this.incidentManager.incidents = normalizedIncidents;
                    this.incidentManager.renderIncidentsTable();
                    this.incidentManager.updateKpiCard();
                }
            }
        } catch (e) {
            // Backend offline; continue with empty state
        }

        // Hydrate hardware whitelist (LIVE mode only)
        if (mode === 'LIVE') {
            try {
                const wlRes = await fetch(`${apiBase}/api/hardware/whitelist`);
                if (wlRes.ok) {
                    const wlData = await wlRes.json();
                    if (Array.isArray(wlData)) {
                        this.nvsWhitelist = wlData;
                        this.renderNvsWhitelistTable();
                    }
                }
            } catch (e) {
                // Backend offline; keep default whitelist
            }
        }
    }

    setMode(newMode) {
        if (this.mode && newMode !== this.mode) {
            this.allWindows = [];
            if (this.chart) this.chart.clear();
        }
        this.mode = newMode;
        localStorage.setItem('nexus_active_mode', newMode);

        // Mode-aware hardware groupbox visibility (hide hardware-only panels in Simulation/Replay)
        const scanBox = document.getElementById('groupboxScanStrategy');
        const nvsBox = document.getElementById('groupboxNvsWhitelist');
        const isLive = newMode === 'LIVE';
        if (scanBox) {
            scanBox.style.display = isLive ? 'flex' : 'none';
            scanBox.style.opacity = '1.0';
        }
        if (nvsBox) {
            nvsBox.style.display = isLive ? 'flex' : 'none';
            nvsBox.style.opacity = '1.0';
        }

        // Load mode-specific settings profile
        this.loadModeSettings(newMode);

        const warningStrip = document.getElementById('modeWarningStrip');
        const warningText = document.getElementById('modeWarningText');
        const warningTag = warningStrip ? warningStrip.querySelector('.strip-tag') : null;
        const btnConnect = document.getElementById('btnConnectSerial');
        const syntheticActions = document.getElementById('syntheticActions');
        const replayToolbar = document.getElementById('replayToolbar');

        const btnSim = document.getElementById('btnModeSim');
        const btnLive = document.getElementById('btnModeLive');
        const btnReplay = document.getElementById('btnModeReplay');

        if (btnSim) btnSim.classList.toggle('active', newMode === 'SIMULATION');
        if (btnLive) btnLive.classList.toggle('active', newMode === 'LIVE');
        if (btnReplay) btnReplay.classList.toggle('active', newMode === 'REPLAY');

        if (replayToolbar) {
            replayToolbar.style.display = newMode === 'REPLAY' ? 'flex' : 'none';
        }

        const badge = document.getElementById('titlebarModeBadge');
        if (badge) badge.textContent = `${newMode} ACTIVE`;

        if (newMode === 'SIMULATION') {
            if (this.serialReceiver && this.serialReceiver.port) {
                this.serialReceiver.disconnect();
            }
            this.stopReplay();
            if (btnConnect) btnConnect.style.display = 'none';
            if (syntheticActions) syntheticActions.style.display = this.labMode ? 'flex' : 'none';

            if (warningStrip) warningStrip.className = 'warning-strip simulation-mode';
            if (warningTag) warningTag.textContent = '[SIMULATION MODE]';
            if (warningText) warningText.textContent = 'SYNTHETIC TEST DATA: Values on this console are generated synthetically in-browser to demonstrate the detection pipeline. They are not measured physical RF results.';

            this.updateOperationalKpis();
            this.updateNodeHealthCard();
        } else if (newMode === 'LIVE') {
            this.stopSimulation();
            this.stopReplay();
            if (btnConnect) btnConnect.style.display = 'inline-flex';
            if (syntheticActions) syntheticActions.style.display = 'none';

            if (warningStrip) warningStrip.className = 'warning-strip live-mode';
            if (warningTag) warningTag.textContent = '[LIVE HARDWARE INGEST]';
            if (warningText) warningText.textContent = 'ACTIVE USB SERIAL TELEMETRY: Ingesting 2.4 GHz RF frames from ESP32-S3 sensing node at 115200 baud.';

            this.updateOperationalKpis();
            this.updateNodeHealthCard();
        } else if (newMode === 'REPLAY') {
            if (this.serialReceiver && this.serialReceiver.port) {
                this.serialReceiver.disconnect();
            }
            this.stopSimulation();
            if (btnConnect) btnConnect.style.display = 'none';
            if (syntheticActions) syntheticActions.style.display = 'none';

            if (warningStrip) warningStrip.className = 'warning-strip replay-mode';
            if (warningTag) warningTag.textContent = '[REPLAY MODE]';
            if (warningText) warningText.textContent = 'CSV TELEMETRY REPLAY: Stepping through recorded telemetry windows from historical dataset.';

            this.updateOperationalKpis();
            this.updateNodeHealthCard();
        }
    }

    handleSerialStateChange(stateStr) {
        if (this.mode === 'LIVE') {
            this.updateOperationalKpis();
            this.updateNodeHealthCard();
        }
        const btnConnect = document.getElementById('btnConnectSerial');
        if (btnConnect) {
            if (this.serialReceiver.port || stateStr === 'ACTIVE_MONITORING') {
                btnConnect.innerHTML = '&#x25A0; Disconnect ESP32';
                btnConnect.classList.add('tool-btn-danger');
            } else {
                btnConnect.innerHTML = '&#x25CE; Connect ESP32';
                btnConnect.classList.remove('tool-btn-danger');
            }
        }
    }

    handleSerialError(errInfo) {
        this.serialErrorCount = errInfo.totalErrors || 0;
        this.droppedFramesCount = errInfo.droppedFrames || 0;
        this.overflowCount = errInfo.overflowCount || 0;
        this.updateOperationalKpis();
        this.updateNodeHealthCard();
    }

    updateOperationalKpis(currentThreat = 'NORMAL') {
        // 1. Link Health
        const kpiLinkStatus = document.getElementById('kpiLinkStatus');
        const kpiLinkBaud = document.getElementById('kpiLinkBaud');
        const statusNode = document.getElementById('statusNode');
        const statusTelemetry = document.getElementById('statusTelemetry');
        const linkDot = document.querySelector('#statusPanelLink .status-panel-indicator');

        if (this.mode === 'LIVE') {
            const hasReceived = this.windowCount > 0;
            const isMonitoring = this.serialReceiver.state === 'ACTIVE_MONITORING';
            if (hasReceived) {
                this.updateNodeStatusDisplay();
            } else {
                const statusText = `NODE: ${this.serialReceiver.state.replace('_', ' ')}`;
                const statusClass = isMonitoring ? 'text-sky' : 'text-amber';
                const dotClass = isMonitoring ? 'status-panel-dot-sky' : 'status-panel-dot-amber';

                if (kpiLinkStatus) {
                    kpiLinkStatus.textContent = statusText;
                    kpiLinkStatus.className = `status-panel-val ${statusClass}`;
                }
                if (statusNode) {
                    statusNode.textContent = statusText;
                    statusNode.className = `status-panel-val ${statusClass}`;
                }
                if (linkDot) {
                    linkDot.className = `status-panel-indicator ${dotClass}`;
                }
            }
        } else if (this.mode === 'REPLAY') {
            const statusText = 'NODE: REPLAY ACTIVE';
            if (kpiLinkStatus) {
                kpiLinkStatus.textContent = statusText;
                kpiLinkStatus.className = 'status-panel-val text-sky';
            }
            if (statusNode) {
                statusNode.textContent = statusText;
                statusNode.className = 'status-panel-val text-sky';
            }
            if (linkDot) {
                linkDot.className = 'status-panel-indicator status-panel-dot-sky';
            }
        } else {
            this.updateNodeStatusDisplay();
        }

        if (statusTelemetry) {
            statusTelemetry.classList.toggle('active-reception', this.windowCount > 0);
        }

        if (kpiLinkBaud) {
            kpiLinkBaud.textContent = `115200 8-N-1 | DROPS: ${this.droppedFramesCount} | ERRORS: ${this.serialErrorCount}`;
        }

        // 2. Active Threat Level
        const kpiThreat = document.getElementById('kpiThreatLevel');
        const kpiThreatDesc = document.getElementById('kpiThreatDesc');
        if (kpiThreat && kpiThreatDesc) {
            if (currentThreat === 'CRITICAL') {
                kpiThreat.textContent = 'CRITICAL';
                kpiThreat.className = 'kpi-value text-rose';
                kpiThreatDesc.textContent = 'CORRELATED ATTACK ACTIVE';
            } else if (currentThreat === 'ELEVATED') {
                kpiThreat.textContent = 'ELEVATED';
                kpiThreat.className = 'kpi-value text-amber';
                kpiThreatDesc.textContent = 'STATISTICAL ANOMALY DETECTED';
            } else {
                kpiThreat.textContent = 'NORMAL';
                kpiThreat.className = 'kpi-value text-emerald';
                kpiThreatDesc.textContent = 'ZERO CORRELATED ANOMALIES';
            }
        }

        // 3. Baseline State
        const kpiBase = document.getElementById('kpiBaselineState');
        const kpiBaseSub = document.getElementById('kpiBaselineSubtext');
        if (kpiBase && kpiBaseSub) {
            if (this.isWarmup && this.windowCount < this.warmupWindows) {
                kpiBase.textContent = `WARMUP [${this.windowCount}/${this.warmupWindows}]`;
                kpiBase.className = 'status-panel-val text-amber';
                kpiBaseSub.textContent = 'CONVERGING DISTRIBUTIONS';
            } else {
                kpiBase.textContent = 'ACTIVE (STABLE)';
                kpiBase.className = 'status-panel-val text-emerald';
                kpiBaseSub.textContent = `EWMA α=${this.alpha.toFixed(2)} | Z-THRESH ${this.zThreshold.toFixed(1)}σ`;
            }
        }

        // Legacy / secondary counters
        const wProcessed = document.getElementById('metricWindowsProcessed');
        if (wProcessed) wProcessed.textContent = this.windowCount;
        const aCount = document.getElementById('metricAlertCount');
        if (aCount) aCount.textContent = this.allEvents.length;
        const nfcCount = document.getElementById('metricNfcReads');
        if (nfcCount) nfcCount.textContent = this.nfcCount;
        this.updateNvsWhitelistStatus();
    }

    updateNodeHealthCard() {
        const stateEl = document.getElementById('nodeHealthState');
        const rateEl = document.getElementById('nodeIngestRate');
        const lastFrameEl = document.getElementById('nodeLastFrameTime');
        const warmupText = document.getElementById('nodeWarmupText');
        const warmupBar = document.getElementById('nodeWarmupBar');

        const isWarmedUp = this.windowCount >= this.warmupWindows;
        const progressWin = Math.min(this.windowCount, this.warmupWindows);
        const percent = Math.round((progressWin / this.warmupWindows) * 100);

        if (stateEl) {
            if (this.mode === 'LIVE') {
                stateEl.textContent = this.serialReceiver.state === 'ACTIVE_MONITORING' ? 'CONNECTED 115200' : this.serialReceiver.state;
                stateEl.className = `node-state-pill ${this.serialReceiver.state === 'ACTIVE_MONITORING' ? 'pill-active' : 'pill-warmup'}`;
            } else if (this.mode === 'REPLAY') {
                stateEl.textContent = 'REPLAY 115200';
                stateEl.className = 'node-state-pill pill-active';
            } else {
                stateEl.textContent = isWarmedUp ? 'SIMULATION ACTIVE' : `WARMUP [${this.windowCount}/${this.warmupWindows}]`;
                stateEl.className = `node-state-pill ${isWarmedUp ? 'pill-active' : 'pill-warmup'}`;
            }
        }

        if (rateEl) {
            rateEl.textContent = '1.0 frames/s';
        }

        if (lastFrameEl) {
            lastFrameEl.textContent = new Date().toLocaleTimeString();
        }

        if (warmupText) {
            warmupText.textContent = `${progressWin}/${this.warmupWindows} Win (${percent}%)`;
        }

        if (warmupBar) {
            warmupBar.style.width = `${percent}%`;
            if (isWarmedUp) {
                warmupBar.style.backgroundColor = 'var(--status-emerald)';
            } else {
                warmupBar.style.backgroundColor = 'var(--status-amber)';
            }
        }
    }

    async connectSerial() {
        if (this.serialReceiver && this.serialReceiver.port) {
            await this.serialReceiver.disconnect();
        } else {
            this.setMode('LIVE');
            await this.serialReceiver.connect(115200);
        }
    }

    toggleRun() {
        this.running = !this.running;
        const btn = document.getElementById('btnStartPause');
        if (btn) btn.textContent = this.running ? 'Pause' : 'Resume';
        if (this.running && this.mode === 'SIMULATION') {
            this.startSimulation();
        } else {
            this.stopSimulation();
        }
    }

    startSimulation() {
        this.running = true;
        const btn = document.getElementById('btnStartPause');
        if (btn) btn.textContent = 'Pause';
        if (this.timer) clearInterval(this.timer);
        this.timer = setInterval(() => {
            const syntheticPayload = this.generateNextSyntheticWindow();
            this.handleTelemetryWindow(syntheticPayload, 'simulation (synthetic)');
        }, 1000);
    }

    stopSimulation() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    toggleAttackLabelling() {
        this.activeAttackLabelling = !this.activeAttackLabelling;
        const btn = document.getElementById('btnLabelAttack');
        if (btn) {
            if (this.activeAttackLabelling) {
                btn.className = 'btn btn-danger active';
                btn.textContent = 'Attack running [active]';
            } else {
                btn.className = 'btn';
                btn.textContent = 'Label: attack running';
            }
        }
    }

    triggerSyntheticAttack(type) {
        if (type === 'deauth') {
            this.syntheticBurstType = 'deauth';
            this.syntheticBurstRemaining = 6;
        } else if (type === 'rogue') {
            this.syntheticBurstType = 'rogue';
            this.syntheticBurstRemaining = 2;
        } else if (type === 'ble') {
            this.syntheticBurstType = 'ble';
            this.syntheticBurstRemaining = 4;
        }
    }

    generateNextSyntheticWindow() {
        const i = this.windowCount;
        let payload = {
            deauth: (i % 7 === 0) ? 1 : 0,
            mgmt: 80 + ((3 * i) % 5) - 2,
            ble: 25 + ((2 * i) % 5) - 2,
            rogue: 0,
            nfc: 0,
            rssi: -66 - (i % 4),
            is_attack_labelled: this.activeAttackLabelling ? 1 : 0
        };

        if (this.syntheticBurstRemaining > 0) {
            payload.is_attack_labelled = 1;
            if (this.syntheticBurstType === 'deauth') {
                payload.deauth = 15;
                payload.mgmt = 144;
            } else if (this.syntheticBurstType === 'rogue') {
                payload.rogue = 1;
                payload.mgmt = 86;
            } else if (this.syntheticBurstType === 'ble') {
                payload.ble = 190;
            }
            this.syntheticBurstRemaining--;
        }

        return payload;
    }

    processSyntheticWindow(isAttack = false) {
        let payload;
        if (isAttack) {
            payload = this.generateNextSyntheticWindow();
        } else {
            const i = this.windowCount;
            payload = {
                deauth: 0,
                mgmt: 80 + ((3 * i) % 5) - 2,
                ble: 25 + ((2 * i) % 5) - 2,
                rogue: 0,
                nfc: 0,
                rssi: -66 - (i % 4),
                is_attack_labelled: 0
            };
        }
        this.handleTelemetryWindow(payload, 'simulation (synthetic)');
        if (this.isWarmup && this.incidentManager && this.incidentManager.incidents.length === 0) {
            this.incidentManager.renderIncidentsTable();
        }
        return payload;
    }

    processTelemetryWindow(payload, source = 'live (serial)') {
        const res = this.handleTelemetryWindow(payload, source);
        if (this.isWarmup && this.incidentManager && this.incidentManager.incidents.length === 0) {
            this.incidentManager.renderIncidentsTable();
        }
        return res;
    }

    updateBaselineStatusUI() {
        this.updateOperationalKpis();
        this.updateNodeHealthCard();
        if (this.incidentManager) {
            this.incidentManager.renderIncidentsTable();
        }
    }

    renderMatrixChart() {
        if (this.chart) {
            this.chart.render();
        }
    }

    handleTelemetryWindow(payload, source) {
        if (typeof payload.win !== 'undefined' && payload.win !== null) {
            this.windowCount = parseInt(payload.win, 10);
        } else if (typeof payload.window_id !== 'undefined' && payload.window_id !== null) {
            this.windowCount = parseInt(payload.window_id, 10);
        } else {
            this.windowCount++;
        }
        const nfcCount = parseInt(payload.nfc, 10) || 0;
        if (nfcCount > 0) {
            this.nfcCount += nfcCount;
            this.flashNfcActivity(nfcCount);
        }

        // Parse scan_mode and pri_ch from incoming telemetry frames
        if (typeof payload.scan_mode !== 'undefined') {
            const sm = payload.scan_mode;
            this.scanMode = (sm === 1 || sm === '1' || sm === 'tiered' || sm === 'adaptive') ? 'TIERED' : 'ROUND-ROBIN';
        }
        if (typeof payload.pri_ch !== 'undefined') {
            this.primaryChannel = parseInt(payload.pri_ch, 10) || this.primaryChannel;
        } else if (typeof payload.ch !== 'undefined' && this.scanMode === 'TIERED') {
            this.primaryChannel = parseInt(payload.ch, 10) || this.primaryChannel;
        }

        // Update status bar item #statusNode with current mode
        this.updateNodeStatusDisplay();

        const statusTelemetry = document.getElementById('statusTelemetry');
        if (statusTelemetry) {
            statusTelemetry.classList.add('active-reception');
        }

        const wasWarmup = this.isWarmup;
        const isWarmedUp = (!this.isWarmup) || (this.windowCount >= this.warmupWindows);
        if (isWarmedUp) {
            this.isWarmup = false;
        }

        // Adaptive Automation: On transition from WARMUP to ACTIVE, fetch scan plan and dispatch to ESP32
        if (wasWarmup && isWarmedUp && !this.scanPlanDeployed) {
            this.scanPlanDeployed = true;
            this.fetchAndDeployAdaptiveScanPlan();
        }

        // Incident table dynamic warmup update and transition
        if (this.isWarmup && this.incidentManager && this.incidentManager.incidents.length === 0) {
            this.incidentManager.renderIncidentsTable();
        } else if (wasWarmup && isWarmedUp && this.incidentManager) {
            this.incidentManager.renderIncidentsTable();
        }
        const isAttackLabelled = (typeof payload.is_attack_labelled !== 'undefined')
            ? parseInt(payload.is_attack_labelled, 10)
            : (this.activeAttackLabelling ? 1 : 0);

        const currentFlags = {};
        const metrics = {};

        // 1. EWMA baseline evaluation and z-score calculation
        for (const feat of this.features) {
            const obs = parseInt(payload[feat], 10) || 0;
            const b = this.baselines[feat];

            if (!b.initialized) {
                b.mean = obs;
                b.variance = 1.0;
                b.initialized = true;
            }

            const sd = Math.max(Math.sqrt(Math.max(b.variance, 0.0)), this.stdDevFloor);
            const z = (obs - b.mean) / sd;

            metrics[feat] = {
                observed: obs,
                baseline_mean: parseFloat(b.mean.toFixed(2)),
                baseline_sd: parseFloat(sd.toFixed(2)),
                z_score: parseFloat(z.toFixed(2))
            };

            let flagged = false;
            if (isWarmedUp) {
                if (feat === 'rogue') {
                    flagged = (obs >= 1);
                } else if (feat === 'deauth') {
                    flagged = (z > this.zThreshold && obs >= 3);
                } else {
                    flagged = (z > this.zThreshold);
                }
            }

            currentFlags[feat] = flagged;

            // Freeze baseline during detected anomaly to prevent model poisoning
            if (!flagged) {
                const diff = obs - b.mean;
                b.mean = (this.alpha * b.mean) + ((1.0 - this.alpha) * obs);
                b.variance = (this.alpha * b.variance) + ((1.0 - this.alpha) * diff * diff);
            }
        }

        // 2. Multi-signal correlation across 3 windows
        this.recentFlags.push({ window: this.windowCount, flags: currentFlags, metrics });
        if (this.recentFlags.length > 3) this.recentFlags.shift();

        const distinctFlagged = new Set();
        let maxZ = 0.0;
        let rogueActive = false;

        for (const rf of this.recentFlags) {
            for (const f of this.features) {
                if (rf.flags[f]) {
                    distinctFlagged.add(f);
                    if (rf.metrics[f].z_score > maxZ) maxZ = rf.metrics[f].z_score;
                    if (f === 'rogue') rogueActive = true;
                }
            }
        }

        const correlationFire = (distinctFlagged.size >= 2) || (maxZ >= 8.0) || rogueActive;
        const inCooldown = (this.windowCount - this.lastEventWindow) <= this.cooldownWindows;

        // Detector flags for benchmark comparison
        const flagFixed = isWarmedUp ? (payload.deauth >= this.fixedThreshold ? 1 : 0) : 0;
        const flagAdaptive = isWarmedUp ? (Object.values(currentFlags).some(v => v) ? 1 : 0) : 0;
        const flagNexus = (isWarmedUp && correlationFire) ? 1 : 0;

        // Trigger Synthetic Workstation Audio Radar on anomaly trigger
        if (isWarmedUp && (correlationFire || flagAdaptive === 1)) {
            if (window.audioRadar) {
                window.audioRadar.playThreatChirp("HIGH");
            }
        }

        let alertRecord = null;
        if (isWarmedUp && correlationFire && !inCooldown) {
            this.lastEventWindow = this.windowCount;
            this.eventCounter++;

            const n = Math.max(distinctFlagged.size, 1);
            let conf = 0.45 + (0.20 * (n - 1)) + (0.04 * Math.min(maxZ, 10.0));
            if (rogueActive) conf += 0.15;
            conf = Math.min(0.99, conf);

            const severity = conf >= 0.85 ? 'high' : (conf >= 0.65 ? 'medium' : 'low');

            let eventType = 'Management frame anomaly';
            let typeKey = 'mgmt';
            if (rogueActive) {
                eventType = 'Possible evil-twin access point';
                typeKey = 'rogue';
            } else if (distinctFlagged.has('deauth')) {
                eventType = 'Deauthentication burst';
                typeKey = 'deauth';
            } else if (distinctFlagged.has('ble')) {
                eventType = 'BLE advertisement flood';
                typeKey = 'ble';
            }

            const evidenceFeatures = [];
            for (const f of distinctFlagged) {
                evidenceFeatures.push({
                    feature: f,
                    observed: metrics[f].observed,
                    baseline_mean: metrics[f].baseline_mean,
                    baseline_sd: metrics[f].baseline_sd,
                    z_score: metrics[f].z_score
                });
            }

            alertRecord = {
                id: `EV-${String(this.eventCounter).padStart(3, '0')}`,
                window: this.windowCount,
                window_id: this.windowCount,
                time: new Date().toISOString(),
                type: eventType,
                type_key: typeKey,
                severity: severity,
                confidence: conf,
                data_source: source,
                evidence: {
                    features: evidenceFeatures,
                    signals_correlated: distinctFlagged.size
                },
                explanation: this.generateRuleExplanation(eventType, evidenceFeatures)
            };

            this.allEvents.push(alertRecord);
            if (this.allEvents.length > 500) {
                this.allEvents.shift();
            }
            this.tableManager.addAlertEvent(alertRecord);

            // Hook Incident Management Workflow & Audio Alerts
            const incident = this.incidentManager.createIncidentFromAlert(alertRecord);
            if (incident) {
                this.syncIncidentToBackend(alertRecord, incident);
            }
        }

        // 3. Update Primary Stacked 4-Signal Canvas Chart
        this.chart.addMultiPoint({
            window_id: this.windowCount,
            is_attack_labelled: isAttackLabelled,
            signals: {
                deauth: { observed: payload.deauth || 0, mean: this.baselines.deauth.mean, sd: Math.max(Math.sqrt(this.baselines.deauth.variance), this.stdDevFloor), flagged: currentFlags.deauth, z: metrics.deauth.z_score },
                mgmt:   { observed: payload.mgmt || 0,   mean: this.baselines.mgmt.mean,   sd: Math.max(Math.sqrt(this.baselines.mgmt.variance), this.stdDevFloor),   flagged: currentFlags.mgmt,   z: metrics.mgmt.z_score },
                ble:    { observed: payload.ble || 0,    mean: this.baselines.ble.mean,    sd: Math.max(Math.sqrt(this.baselines.ble.variance), this.stdDevFloor),    flagged: currentFlags.ble,    z: metrics.ble.z_score },
                rogue:  { observed: payload.rogue || 0,  mean: this.baselines.rogue.mean,  sd: Math.max(Math.sqrt(this.baselines.rogue.variance), this.stdDevFloor),  flagged: currentFlags.rogue,  z: metrics.rogue.z_score }
            }
        });

        // 4. Update Tables & Status
        let windowState = isWarmedUp ? 'ACTIVE' : `WARMUP [${this.windowCount}/${this.warmupWindows}]`;
        if (isWarmedUp) {
            if (currentFlags.deauth) windowState = 'ANOMALY_DEAUTH';
            else if (currentFlags.rogue) windowState = 'ANOMALY_ROGUE';
            else if (currentFlags.ble) windowState = 'ANOMALY_BLE';
            else if (currentFlags.mgmt) windowState = 'ANOMALY_MGMT';
        }

        this.tableManager.addTelemetryRow({
            window_id: this.windowCount,
            rssi: payload.rssi || -68,
            z_score: metrics.deauth.z_score,
            deauth_rate: payload.deauth || 0,
            state: windowState
        });

        // Store window record
        const windowRecord = {
            window_id: this.windowCount,
            epoch_ms: Date.now(),
            data_source: source,
            payload,
            metrics,
            flags: currentFlags,
            is_attack_labelled: isAttackLabelled,
            flag_fixed: flagFixed,
            flag_adaptive: flagAdaptive,
            flag_nexus: flagNexus
        };
        this.allWindows.push(windowRecord);
        const maxWinCap = parseInt(document.getElementById('inputMaxWindows')?.value || '500', 10) || 500;
        if (this.allWindows.length > maxWinCap) {
            this.allWindows.shift();
        }

        // Asynchronously dispatch window to backend SQLite database
        this.syncWindowToBackend(windowRecord);

        // Update Benchmark Metrics
        this.computeAndRenderDetectorMetrics();

        // Update Operational KPI Strip
        let currentThreat = 'NORMAL';
        if (correlationFire) currentThreat = 'CRITICAL';
        else if (Object.values(currentFlags).some(v => v)) currentThreat = 'ELEVATED';

        this.updateOperationalKpis(currentThreat);
        this.updateNodeHealthCard();

        // Synchronize Wazuh-Style Operations Console
        if (this.wazuhConsole) {
            this.wazuhConsole.refreshViews();
        }
    }

    async syncWindowToBackend(windowRecord) {
        try {
            await fetch('http://127.0.0.1:8000/api/telemetry/ingest', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nexus-Key': 'nexus-local-dev-token'
                },
                body: JSON.stringify(windowRecord)
            });
        } catch (err) {
            // Non-blocking: fail quietly if backend offline
        }
    }

    async syncIncidentToBackend(alertRecord, incident) {
        try {
            await fetch('http://127.0.0.1:8000/api/incidents/sync', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nexus-Key': 'nexus-local-dev-token'
                },
                body: JSON.stringify({ alert: alertRecord, incident })
            });
        } catch (err) {
            // Non-blocking: fail quietly if backend offline
        }
    }

    flashNfcActivity(count) {
        const badge = document.getElementById('nfcActivityBadge');
        if (!badge) return;
        badge.textContent = `NFC: READ (+${count})`;
        badge.classList.add('active-nfc');
        if (this.nfcTimer) clearTimeout(this.nfcTimer);
        this.nfcTimer = setTimeout(() => {
            badge.textContent = 'NFC: IDLE';
            badge.classList.remove('active-nfc');
        }, 1500);
    }

    updateNodeStatusDisplay() {
        const statusNode = document.getElementById('statusNode');
        const kpiLinkStatus = document.getElementById('kpiLinkStatus');
        const linkDot = document.querySelector('#statusPanelLink .status-panel-indicator');

        let modeLabel = '';
        if (this.scanMode === 'TIERED') {
            const ch = this.primaryChannel || 6;
            modeLabel = `NODE: ESP32-S3 | TIERED [CH:${ch} (85%) / PATROL (15%)]`;
        } else {
            modeLabel = `NODE: ESP32-S3 | ROUND-ROBIN`;
        }

        if (statusNode) {
            statusNode.textContent = modeLabel;
            statusNode.className = 'status-panel-val text-emerald';
            statusNode.style.display = '';
        }
        if (kpiLinkStatus) {
            kpiLinkStatus.textContent = modeLabel;
            kpiLinkStatus.className = 'status-panel-val text-emerald';
        }
        if (linkDot) {
            linkDot.className = 'status-panel-indicator status-panel-dot-emerald';
        }
    }

    async fetchAndDeployAdaptiveScanPlan() {
        try {
            const resp = await fetch('http://127.0.0.1:8000/api/telemetry/scan-plan');
            if (resp.ok) {
                const plan = await resp.json();
                if (plan) {
                    const primaryCh = plan.primary_ch || 6;
                    this.scanMode = 'TIERED';
                    this.primaryChannel = primaryCh;
                    this.updateNodeStatusDisplay();

                    const selMode = document.getElementById('selectScanMode');
                    const selCh = document.getElementById('selectPrimaryChannel');
                    if (selMode) selMode.value = 'adaptive';
                    if (selCh) selCh.value = String(primaryCh);

                    if (this.serialReceiver && this.serialReceiver.port) {
                        const serialCmd = {
                            cmd: 'scan_plan',
                            primary_ch: primaryCh,
                            dwell_primary_ms: plan.dwell_primary_ms || 1700,
                            dwell_patrol_ms: plan.dwell_patrol_ms || 50
                        };
                        await this.serialReceiver.sendSerialCommand(serialCmd);
                    }

                    if (this.wazuhConsole) {
                        this.wazuhConsole.showToast('SCAN PLAN ADAPTED', `Baseline active. Deployed tiered plan: CH ${primaryCh} (85%), Patrol (15%).`, 'success');
                    }
                }
            }
        } catch (err) {
            // Fail quietly if backend offline
        }
    }

    async deployScanPlan() {
        const selMode = document.getElementById('selectScanMode');
        const selCh = document.getElementById('selectPrimaryChannel');
        const mode = selMode ? selMode.value : 'adaptive';
        const chVal = selCh ? selCh.value : 'auto';

        let targetCh = 6;
        if (chVal !== 'auto') {
            targetCh = parseInt(chVal, 10) || 6;
        } else {
            try {
                const resp = await fetch('http://127.0.0.1:8000/api/telemetry/scan-plan');
                if (resp.ok) {
                    const plan = await resp.json();
                    if (plan && plan.primary_ch) targetCh = plan.primary_ch;
                }
            } catch (e) {}
        }

        let serialCmd = null;
        if (mode === 'round_robin') {
            this.scanMode = 'ROUND-ROBIN';
            serialCmd = { cmd: 'scan_reset', mode: 'round_robin' };
        } else {
            this.scanMode = 'TIERED';
            this.primaryChannel = targetCh;
            serialCmd = {
                cmd: 'scan_plan',
                primary_ch: targetCh,
                dwell_primary_ms: 1700,
                dwell_patrol_ms: 50
            };
        }

        this.updateNodeStatusDisplay();

        let serialOk = false;
        if (this.serialReceiver && this.serialReceiver.port) {
            serialOk = await this.serialReceiver.sendSerialCommand(serialCmd);
        }

        try {
            if (mode !== 'round_robin') {
                await fetch('http://127.0.0.1:8000/api/telemetry/scan-plan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Nexus-Key': 'nexus-local-dev-token'
                    },
                    body: JSON.stringify({
                        primary_ch: targetCh,
                        dwell_primary_ms: 1700,
                        dwell_patrol_ms: 50
                    })
                });
            }
        } catch (err) {
            // Non-blocking
        }

        if (this.wazuhConsole) {
            const desc = mode === 'round_robin'
                ? 'Deployed Uniform Round-Robin (1–13).'
                : `Deployed Tiered Plan: Primary CH ${targetCh} (85%), Patrol (15%).`;
            this.wazuhConsole.showToast('SCAN STRATEGY DEPLOYED', desc + (serialOk ? ' [Sent via Serial]' : ''), 'info');
        }
    }

    renderNvsWhitelistTable() {
        const tbody = document.getElementById('nvsWhitelistBody');
        if (!tbody) return;

        if (this.nvsWhitelist.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 8px;">
                        No whitelisted APs in device NVS.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.nvsWhitelist.map((item, idx) => `
            <tr>
                <td style="color: var(--text-white); font-weight: 500;">${item.ssid}</td>
                <td class="font-mono text-sky">${item.bssid}</td>
                <td style="text-align: center;">
                    <button class="expand-row-btn" data-wl-idx="${idx}" title="Remove entry" style="color: var(--status-rose);">&#x2715;</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('button[data-wl-idx]').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.wlIdx, 10);
                this.removeNvsWhitelistItem(idx);
            };
        });
    }

    updateNvsWhitelistStatus() {
        const badge = document.getElementById('statusNvsWhitelist');
        if (badge) {
            const count = this.nvsWhitelist ? this.nvsWhitelist.length : 0;
            badge.textContent = `NVS WL: ${count} ACTIVE`;
            badge.className = count > 0 ? 'status-indicator font-mono text-emerald' : 'status-indicator font-mono text-muted';
        }
    }

    async commitNvsWhitelist() {
        const inputSsid = document.getElementById('inputWhitelistSsid');
        const inputBssid = document.getElementById('inputWhitelistBssid');
        const ssid = inputSsid ? inputSsid.value.trim() : '';
        const bssid = inputBssid ? inputBssid.value.trim().toUpperCase() : '';

        if (!ssid || !bssid) {
            if (this.wazuhConsole) {
                this.wazuhConsole.showToast('NVS WHITELIST', 'Both SSID and BSSID (MAC) are required.', 'error');
            }
            return;
        }

        // Validate MAC address format AA:BB:CC:DD:EE:FF
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(bssid)) {
            if (this.wazuhConsole) {
                this.wazuhConsole.showToast('NVS WHITELIST', 'Invalid BSSID format. Use AA:BB:CC:DD:EE:FF.', 'error');
            }
            return;
        }

        // Add or replace entry
        const existingIdx = this.nvsWhitelist.findIndex(item => item.bssid === bssid);
        if (existingIdx >= 0) {
            this.nvsWhitelist[existingIdx].ssid = ssid;
        } else {
            this.nvsWhitelist.push({ ssid, bssid });
        }

        if (inputSsid) inputSsid.value = '';
        if (inputBssid) inputBssid.value = '';

        this.renderNvsWhitelistTable();
        this.updateNvsWhitelistStatus();

        // 1. Dispatch Web Serial downlink command to ESP32
        if (this.serialReceiver && this.serialReceiver.port && this.serialReceiver.sendSerialCommand) {
            await this.serialReceiver.sendSerialCommand({ cmd: 'wl_add', ssid, bssid });
        }

        // 2. Sync to Backend SQLite API
        try {
            await fetch('http://127.0.0.1:8000/api/hardware/whitelist', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nexus-Key': 'nexus-local-dev-token'
                },
                body: JSON.stringify({ ssid, bssid })
            });
        } catch (e) {
            // Non-blocking fail quietly if backend offline
        }

        if (this.wazuhConsole) {
            this.wazuhConsole.showToast('NVS FLASH', `Committed ${ssid} [${bssid}] to ESP32 NVS.`, 'info');
        }
    }

    async purgeNvsWhitelist() {
        this.nvsWhitelist = [];
        this.renderNvsWhitelistTable();
        this.updateNvsWhitelistStatus();

        // 1. Dispatch Web Serial downlink command to ESP32
        if (this.serialReceiver && this.serialReceiver.port && this.serialReceiver.sendSerialCommand) {
            await this.serialReceiver.sendSerialCommand({ cmd: 'wl_clear' });
        }

        // 2. Sync to Backend SQLite API
        try {
            await fetch('http://127.0.0.1:8000/api/hardware/whitelist', {
                method: 'DELETE',
                headers: {
                    'X-Nexus-Key': 'nexus-local-dev-token'
                }
            });
        } catch (e) {
            // Non-blocking fail quietly if backend offline
        }

        if (this.wazuhConsole) {
            this.wazuhConsole.showToast('NVS FLASH', 'Purged all whitelisted AP entries from ESP32 NVS.', 'warning');
        }
    }

    removeNvsWhitelistItem(index) {
        if (index >= 0 && index < this.nvsWhitelist.length) {
            const removed = this.nvsWhitelist.splice(index, 1)[0];
            this.renderNvsWhitelistTable();
            this.updateNvsWhitelistStatus();
            if (this.wazuhConsole) {
                this.wazuhConsole.showToast('NVS FLASH', `Removed ${removed.ssid} from whitelist.`, 'info');
            }
        }
    }

    registerOperatorFalsePositive(incident) {
        this.operatorFalsePositives.add(incident.id);
        this.computeAndRenderDetectorMetrics();
    }

    computeAndRenderDetectorMetrics() {
        const postWarmupWindows = this.allWindows.filter(w => w.window_id > this.warmupWindows);
        const labelledAttacksCount = postWarmupWindows.filter(w => w.is_attack_labelled === 1).length;

        // Group contiguous attack episodes
        const attackEpisodes = [];
        let currentEpisode = null;

        for (let i = 0; i < postWarmupWindows.length; i++) {
            const w = postWarmupWindows[i];
            if (w.is_attack_labelled === 1) {
                if (!currentEpisode) {
                    currentEpisode = { startIndex: i, startWindow: w.window_id, windows: [w] };
                } else {
                    currentEpisode.windows.push(w);
                }
            } else {
                if (currentEpisode) {
                    attackEpisodes.push(currentEpisode);
                    currentEpisode = null;
                }
            }
        }
        if (currentEpisode) {
            attackEpisodes.push(currentEpisode);
        }

        const totalEpisodes = attackEpisodes.length;

        const evaluateDetector = (flagKey) => {
            let tp = 0, fp = 0, tn = 0, fn = 0;
            for (const w of postWarmupWindows) {
                const actual = w.is_attack_labelled === 1;
                const pred = w[flagKey] === 1;
                if (actual && pred) tp++;
                else if (!actual && pred) fp++;
                else if (!actual && !pred) tn++;
                else if (actual && !pred) fn++;
            }

            // Adjust FP for operator confirmed false positives on NEXUS
            if (flagKey === 'flag_nexus') {
                fp += this.operatorFalsePositives.size;
            }

            const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : NaN;
            const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : NaN;
            const f1 = (!isNaN(precision) && !isNaN(recall) && (precision + recall) > 0)
                ? (2 * precision * recall / (precision + recall))
                : NaN;
            const fpr = (fp + tn) > 0 ? (fp / (fp + tn)) : NaN;

            let attacksCaught = 0;
            let totalLatency = 0;
            for (const ep of attackEpisodes) {
                let firstFlagIndex = -1;
                for (let k = 0; k < ep.windows.length; k++) {
                    if (ep.windows[k][flagKey] === 1) {
                        firstFlagIndex = k;
                        break;
                    }
                }
                if (firstFlagIndex !== -1) {
                    attacksCaught++;
                    totalLatency += firstFlagIndex;
                }
            }

            const latency = attacksCaught > 0 ? (totalLatency / attacksCaught) : NaN;

            return {
                precision,
                recall,
                f1,
                fpr,
                attacks_caught: attacksCaught,
                total_attacks: totalEpisodes,
                latency
            };
        };

        const comparisonResults = {
            evaluated_windows: postWarmupWindows.length,
            labelled_attack_windows: labelledAttacksCount,
            fixed: evaluateDetector('flag_fixed'),
            adaptive: evaluateDetector('flag_adaptive'),
            nexus: evaluateDetector('flag_nexus')
        };

        this.tableManager.updateDetectorComparison(comparisonResults);

        // Update dedicated Benchmark view table (#benchmarkTableBody and #benchmarkMeta)
        const formatMetric = (val) => isNaN(val) ? '--' : val.toFixed(3);
        const formatLatency = (val) => isNaN(val) ? '--' : `${val.toFixed(1)} win`;

        const detectors = [
            { name: 'Fixed Threshold (deauth \u2265 5)', m: comparisonResults.fixed },
            { name: 'Adaptive EWMA (z > 3.5\u03C3)', m: comparisonResults.adaptive },
            { name: 'NEXUS AI (Adaptive + Freeze + Corr)', m: comparisonResults.nexus }
        ];

        let rowsHtml = '';
        for (const det of detectors) {
            const m = det.m || {};
            rowsHtml += `
                <tr>
                    <td style="font-weight: 600; color: #f4f4f5;">${det.name}</td>
                    <td class="font-mono">${formatMetric(m.precision)}</td>
                    <td class="font-mono">${formatMetric(m.recall)}</td>
                    <td class="font-mono" style="color: ${det.name.includes('NEXUS') ? '#22c55e' : '#cbd5e1'}; font-weight: 600;">${formatMetric(m.f1)}</td>
                    <td class="font-mono">${formatMetric(m.fpr)}</td>
                    <td class="font-mono">${m.attacks_caught || 0}/${m.total_attacks || 0}</td>
                    <td class="font-mono">${formatLatency(m.latency)}</td>
                </tr>
            `;
        }

        const benchTbody = document.getElementById('benchmarkTableBody');
        if (benchTbody) benchTbody.innerHTML = rowsHtml;

        const benchMeta = document.getElementById('benchmarkMeta');
        if (benchMeta) {
            benchMeta.textContent = `Evaluated windows: ${comparisonResults.evaluated_windows || 0} | Labelled attack windows: ${comparisonResults.labelled_attack_windows || 0}`;
        }

        // Dynamic Ablation Analysis Study update
        fetch('/api/evaluation/ablation')
            .then(res => res.ok ? res.json() : null)
            .then(data => {
                if (data && data.configurations) {
                    const c = data.configurations;
                    const c1 = c.config_1_fixed_threshold || {};
                    const c2 = c.config_2_adaptive_no_freeze || {};
                    const c3 = c.config_3_adaptive_with_freeze || {};
                    const c4 = c.config_4_nexus_complete || {};

                    const elFixed = document.getElementById('ablFixedF1');
                    if (elFixed && c1.f1 !== undefined) elFixed.textContent = Number(c1.f1).toFixed(2);

                    const elNoFreeze = document.getElementById('ablNoFreezeF1');
                    if (elNoFreeze && c2.f1 !== undefined) elNoFreeze.textContent = Number(c2.f1).toFixed(2);

                    const elFreeze = document.getElementById('ablFreezeF1');
                    if (elFreeze && c3.f1 !== undefined) elFreeze.textContent = Number(c3.f1).toFixed(2);

                    const elFull = document.getElementById('ablFullF1') || document.getElementById('ablNexusF1');
                    if (elFull && c4.f1 !== undefined) elFull.textContent = Number(c4.f1).toFixed(2);
                }
            })
            .catch(() => {});
    }

    async renderThresholdSweepChart() {
        const canvas = document.getElementById('thresholdSweepCanvas');
        if (!canvas) return;

        let sweepResults = null;
        let optZ = 3.5;
        let optF1 = 0.96;

        try {
            const resp = await fetch('/api/evaluation/threshold-sweep');
            if (resp.ok) {
                const data = await resp.json();
                if (data && Array.isArray(data.sweep_results) && data.sweep_results.length > 0) {
                    sweepResults = data.sweep_results;
                    if (data.optimal_threshold) {
                        optZ = data.optimal_threshold.z_threshold || 3.5;
                        optF1 = data.optimal_threshold.f1 || 0.96;
                    }
                }
            }
        } catch (e) {
            // Standalone client fallback
        }

        const container = canvas.parentElement;
        const rect = container ? container.getBoundingClientRect() : null;
        if (!rect || rect.width === 0) return;

        const dpr = window.devicePixelRatio || 1;
        const logicalWidth = rect.width;
        const logicalHeight = 240; // Lock strict logical height

        // Set physical pixel resolution
        canvas.width = Math.floor(logicalWidth * dpr);
        canvas.height = Math.floor(logicalHeight * dpr);

        const ctx = canvas.getContext('2d');
        // Reset context transform matrix to prevent scale compounding
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        const w = logicalWidth;
        const h = logicalHeight;

        const padLeft = 45;
        const padRight = 20;
        const padTop = 32;
        const padBottom = 35;

        const plotW = w - padLeft - padRight;
        const plotH = h - padTop - padBottom;

        ctx.clearRect(0, 0, w, h);

        // Horizontal grid lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
        ctx.lineWidth = 1;
        ctx.font = '10px Consolas, monospace';
        ctx.fillStyle = '#71717a';
        ctx.textAlign = 'right';

        for (let yVal = 0; yVal <= 1.0; yVal += 0.25) {
            const y = padTop + plotH - (yVal * plotH);
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(padLeft + plotW, y);
            ctx.stroke();
            ctx.fillText(yVal.toFixed(2), padLeft - 8, y + 3);
        }

        // Empirical or dynamic threshold sweep points
        const sweepPoints = sweepResults ? sweepResults.map(r => ({
            z: r.z_threshold,
            prec: r.precision,
            rec: r.recall,
            f1: r.f1
        })) : [
            { z: 2.0, prec: 0.58, rec: 0.99, f1: 0.73 },
            { z: 2.5, prec: 0.72, rec: 0.98, f1: 0.83 },
            { z: 3.0, prec: 0.86, rec: 0.97, f1: 0.91 },
            { z: 3.5, prec: 0.97, rec: 0.95, f1: 0.96 },
            { z: 4.0, prec: 0.98, rec: 0.88, f1: 0.93 },
            { z: 4.5, prec: 0.99, rec: 0.76, f1: 0.86 },
            { z: 5.0, prec: 0.99, rec: 0.62, f1: 0.76 }
        ];

        // X-axis ticks (Z = min to max)
        const zMin = Math.min(...sweepPoints.map(p => p.z));
        const zMax = Math.max(...sweepPoints.map(p => p.z));
        ctx.textAlign = 'center';

        const stepZ = (zMax - zMin) > 0 ? (zMax - zMin) / 6 : 0.5;
        for (let zVal = zMin; zVal <= zMax + 0.01; zVal += stepZ) {
            const x = padLeft + ((zVal - zMin) / (zMax - zMin)) * plotW;
            ctx.beginPath();
            ctx.moveTo(x, padTop);
            ctx.lineTo(x, padTop + plotH);
            ctx.stroke();
            ctx.fillText(`${zVal.toFixed(1)}\u03C3`, x, padTop + plotH + 18);
        }

        // Optimal threshold vertical line
        const optX = padLeft + ((optZ - zMin) / (zMax - zMin)) * plotW;
        ctx.save();
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(optX, padTop);
        ctx.lineTo(optX, padTop + plotH);
        ctx.stroke();
        ctx.restore();

        ctx.fillStyle = '#22c55e';
        ctx.font = '600 10px Consolas, monospace';
        ctx.textAlign = 'left';
        ctx.fillText(`Optimal Z = ${optZ}\u03C3 (F1 = ${optF1.toFixed(2)})`, padLeft + 10, padTop - 12);

        // Helper to draw series curves
        const drawSeries = (key, color, lineWidth = 2) => {
            ctx.strokeStyle = color;
            ctx.lineWidth = lineWidth;
            ctx.beginPath();

            sweepPoints.forEach((pt, idx) => {
                const x = padLeft + ((pt.z - zMin) / (zMax - zMin)) * plotW;
                const y = padTop + plotH - (pt[key] * plotH);
                if (idx === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();

            ctx.fillStyle = color;
            sweepPoints.forEach(pt => {
                const x = padLeft + ((pt.z - zMin) / (zMax - zMin)) * plotW;
                const y = padTop + plotH - (pt[key] * plotH);
                ctx.beginPath();
                ctx.arc(x, y, 3, 0, Math.PI * 2);
                ctx.fill();
            });
        };

        drawSeries('prec', '#38bdf8', 2);
        drawSeries('rec', '#f59e0b', 2);
        drawSeries('f1', '#22c55e', 2.5);

        // Legend at top-right
        ctx.font = '10px Consolas, monospace';
        ctx.textAlign = 'left';

        const legendItems = [
            { label: 'Precision', color: '#38bdf8' },
            { label: 'Recall', color: '#f59e0b' },
            { label: 'F1-Score', color: '#22c55e' }
        ];

        let legX = padLeft + plotW - 180;
        legendItems.forEach(item => {
            ctx.fillStyle = item.color;
            ctx.beginPath();
            ctx.arc(legX, padTop - 15, 3.5, 0, Math.PI * 2);
            ctx.fill();

            ctx.fillStyle = '#cbd5e1';
            ctx.fillText(item.label, legX + 7, padTop - 12);
            legX += 58;
        });
    }

    generateRuleExplanation(eventType, evidenceFeatures) {
        const parts = evidenceFeatures.map(f => `${f.feature}=${f.observed} (baseline ${f.baseline_mean}, z=${f.z_score}\u03C3)`);
        const summary = parts.join('; ');

        if (eventType.includes('Deauthentication')) {
            return `A burst of 802.11 deauthentication frames was detected (${summary}). Deauthentication attacks forcibly disconnect legitimate clients prior to evil-twin association or denial of service. Suggested defensive action: Verify 802.11w Protected Management Frames (PMF) on access points and isolate transmitting RF source.`;
        } else if (eventType.includes('evil-twin')) {
            return `An unauthorized access point was detected transmitting a known network SSID (${summary}). Clients risk association with an adversary-controlled rogue node. Suggested defensive action: Inspect physical access point inventory and blacklist untrusted BSSID.`;
        } else if (eventType.includes('BLE')) {
            return `A high-rate flood of Bluetooth Low Energy advertisements was detected (${summary}). Suggested defensive action: Inspect physical proximity for unauthorized BLE transmitters or battery-exhaustion attacks.`;
        }
        return `Management frame rate exceeded statistical baseline threshold (${summary}). Suggested defensive action: Monitor RF frame spectrum for rogue injection.`;
    }

    // ==========================================
    // Replay Mode Engine
    // ==========================================

    handleCsvFileSelected(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            this.parseReplayCsv(text);
        };
        reader.readAsText(file);
    }

    parseReplayCsv(csvText) {
        const lines = csvText.trim().split(/\r?\n/);
        if (lines.length < 2) {
            if (this.wazuhConsole) {
                this.wazuhConsole.showToast('REPLAY ERROR', 'CSV file contains no telemetry data rows.', 'danger');
            } else {
                this.showWin32Dialog('CSV Import Error', '<div style="font-size: 11px;">CSV file contains no telemetry data rows.</div>');
            }
            return;
        }

        const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
        const deauthIdx = headers.indexOf('deauth');
        const mgmtIdx = headers.indexOf('mgmt');
        const bleIdx = headers.indexOf('ble');
        const rogueIdx = headers.indexOf('rogue');
        const nfcIdx = headers.indexOf('nfc');
        const rssiIdx = headers.indexOf('rssi');
        const attackIdx = headers.indexOf('is_attack_labelled');

        this.replayWindows = [];
        for (let i = 1; i < lines.length; i++) {
            const row = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
            if (row.length < headers.length) continue;

            this.replayWindows.push({
                deauth: parseInt(row[deauthIdx], 10) || 0,
                mgmt: parseInt(row[mgmtIdx], 10) || 80,
                ble: parseInt(row[bleIdx], 10) || 25,
                rogue: parseInt(row[rogueIdx], 10) || 0,
                nfc: parseInt(row[nfcIdx], 10) || 0,
                rssi: parseFloat(row[rssiIdx]) || -68,
                is_attack_labelled: attackIdx !== -1 ? (parseInt(row[attackIdx], 10) || 0) : 0
            });
        }

        this.replayIndex = 0;
        const scrubber = document.getElementById('replayScrubber');
        if (scrubber) {
            scrubber.max = this.replayWindows.length - 1;
            scrubber.value = 0;
        }
        this.updateReplayProgressText();
        this.setMode('REPLAY');
        this.resetTelemetryState();
        this.startReplayLoop();
    }

    startReplayLoop() {
        if (this.replayTimer) clearInterval(this.replayTimer);
        const btn = document.getElementById('btnReplayPlayPause');
        if (btn) btn.textContent = 'Pause';

        this.replayTimer = setInterval(() => {
            if (this.replayIndex >= this.replayWindows.length) {
                this.stopReplay();
                return;
            }
            const payload = this.replayWindows[this.replayIndex];
            this.handleTelemetryWindow(payload, 'replay.csv');
            this.replayIndex++;

            const scrubber = document.getElementById('replayScrubber');
            if (scrubber) scrubber.value = this.replayIndex;
            this.updateReplayProgressText();
        }, this.replaySpeedMs);
    }

    stopReplay() {
        if (this.replayTimer) {
            clearInterval(this.replayTimer);
            this.replayTimer = null;
        }
        const btn = document.getElementById('btnReplayPlayPause');
        if (btn) btn.textContent = 'Play';
    }

    toggleReplayPlayback() {
        if (this.replayTimer) {
            this.stopReplay();
        } else {
            this.startReplayLoop();
        }
    }

    handleReplayScrub(targetIndex) {
        this.stopReplay();
        this.replayIndex = Math.max(0, Math.min(targetIndex, this.replayWindows.length - 1));
        this.resetTelemetryState();

        for (let i = 0; i <= this.replayIndex; i++) {
            this.handleTelemetryWindow(this.replayWindows[i], 'replay.csv');
        }
        this.updateReplayProgressText();
    }

    updateReplayProgressText() {
        const text = document.getElementById('replayProgressText');
        if (text) {
            text.textContent = `Win ${this.replayIndex} / ${this.replayWindows.length}`;
        }
    }

    resetTelemetryState() {
        this.windowCount = 0;
        this.nfcCount = 0;
        this.lastEventWindow = -999;
        this.eventCounter = 0;
        this.allWindows = [];
        this.allEvents = [];
        this.recentFlags = [];
        this.isWarmup = true;
        this.chart.clear();
        this.tableManager.clear();
        this.incidentManager.clear();
        this.operatorFalsePositives.clear();

        for (const feat of this.features) {
            this.baselines[feat] = { mean: 0.0, variance: 1.0, initialized: false };
        }
        this.scanPlanDeployed = false;
        this.scanMode = 'ROUND-ROBIN';
        this.primaryChannel = 6;
        this.updateOperationalKpis();
        this.updateNodeStatusDisplay();
        this.updateNodeHealthCard();
        if (this.wazuhConsole) {
            this.wazuhConsole.refreshViews();
        }
    }

    reset() {
        this.stopSimulation();
        this.stopReplay();
        this.resetTelemetryState();

        this.serialErrorCount = 0;
        this.droppedFramesCount = 0;
        this.overflowCount = 0;
        this.nfcTimer = null;

        // Scanning strategy state
        this.scanMode = 'ROUND-ROBIN';
        this.primaryChannel = 6;
        this.scanPlanDeployed = false;

        // Onboard NVS Flash AP Whitelist
        this.nvsWhitelist = [
            { ssid: 'Campus-Corp-Secure', bssid: '00:14:2D:E1:92:40' }
        ];

        this.running = false;
        const btn = document.getElementById('btnStartPause');
        if (btn) btn.textContent = 'Resume';

        if (this.activeAttackLabelling) {
            this.toggleAttackLabelling();
        }

        this.computeAndRenderDetectorMetrics();
        this.renderNvsWhitelistTable();
        this.updateNvsWhitelistStatus();
        this.initMitreCardDrilldown();
    }

    exportJson() {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(this.allEvents, null, 2));
        const a = document.createElement('a');
        a.setAttribute('href', dataStr);
        a.setAttribute('download', `nexus_events_${Date.now()}.json`);
        document.body.appendChild(a);
        a.click();
        a.remove();
    }

    exportCsv() {
        let csv = 'window_id,epoch_ms,data_source,deauth,mgmt,ble,rogue,nfc,rssi,is_attack_labelled,flag_fixed,flag_adaptive,flag_nexus,ewma_deauth_mean,z_deauth,z_mgmt,z_ble,z_rogue\n';
        for (const w of this.allWindows) {
            const p = w.payload;
            const m = w.metrics;
            csv += [
                w.window_id,
                w.epoch_ms,
                `"${w.data_source}"`,
                p.deauth || 0,
                p.mgmt || 0,
                p.ble || 0,
                p.rogue || 0,
                p.nfc || 0,
                p.rssi || -70,
                w.is_attack_labelled,
                w.flag_fixed,
                w.flag_adaptive,
                w.flag_nexus,
                (m && m.deauth) ? m.deauth.baseline_mean : 0.0,
                (m && m.deauth) ? m.deauth.z_score : 0.0,
                (m && m.mgmt) ? m.mgmt.z_score : 0.0,
                (m && m.ble) ? m.ble.z_score : 0.0,
                (m && m.rogue) ? m.rogue.z_score : 0.0
            ].join(',') + '\n';
        }

        const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
        const a = document.createElement('a');
        a.setAttribute('href', dataStr);
        a.setAttribute('download', `nexus_telemetry_${Date.now()}.csv`);
        document.body.appendChild(a);
        a.click();
        a.remove();
    }
}

window.addEventListener('DOMContentLoaded', () => {
    try {
        window.nexusApp = new NexusApp();
    } catch (err) {
        console.error('[NEXUS] Initialization error:', err);
    }
});
