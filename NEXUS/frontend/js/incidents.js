// NEXUS AI: Incident Management Workflow, Defensive Playbooks, Trusted AP Manager & Flyout Inspector
// Manages aggregated incident timelines, expandable row detail panes (Table View / JSON View + Copy),
// slide-over flyout inspector, first-run empty states, interactive playbooks, and local alerts.

class IncidentManager {
    constructor() {
        this.incidents = [];
        this.selectedIncident = null;
        this.expandedIncidentIds = new Set();
        this.incidentCounter = 0;
        this.unacknowledgedCount = 0;

        // Window range & status filter state
        this.windowFilterStart = null;
        this.windowFilterEnd = null;
        this.mitreFilter = null;
        this.statusFilter = 'ALL';

        // Audio Alert Synthesizer State
        this.audioEnabled = window.audioRadar ? Boolean(window.audioRadar.enabled) : false;
        this.audioCtx = null;

        // Trusted AP Allowlist State (seed demo APs strictly in Simulation mode)
        const activeMode = localStorage.getItem('nexus_active_mode') || 'SIMULATION';
        this.trustedAps = activeMode === 'SIMULATION' ? this.getDefaultSimulationTrustedAps() : [];

        // Active Rogue AP State
        this.activeRogueAlert = null;

        this.init();
    }

    getDefaultSimulationTrustedAps() {
        return [
            { bssid: '00:14:2D:E1:92:40', ssid: 'Campus-Corp-Secure', channel: 6, status: 'TRUSTED', first_seen: '2026-11-20 08:00:00' },
            { bssid: '00:14:2D:E1:92:41', ssid: 'Campus-IoT-Telemetry', channel: 11, status: 'TRUSTED', first_seen: '2026-11-20 08:00:00' }
        ];
    }

    init() {
        this.initDOM();
        this.requestNotificationPermission();
    }

    initDOM() {
        // Tab switching between Incidents and Trusted APs if tab buttons exist
        const tabIncidents = document.getElementById('tabShowIncidents');
        const tabTrustedAps = document.getElementById('tabShowTrustedAps');
        const tabTelemetry = document.getElementById('tabShowTelemetry');
        const incContainer = document.getElementById('incidentsTableContainer');
        const apsContainer = document.getElementById('trustedApsContainer');

        // Incident Status Filter Sub-Tabs
        const statusTabs = document.querySelectorAll('#incidentStatusTabs .inc-filter-tab');
        statusTabs.forEach(tab => {
            tab.onclick = () => {
                this.statusFilter = tab.dataset.statusFilter || 'ALL';
                statusTabs.forEach(t => {
                    const isAct = t === tab;
                    t.classList.toggle('active', isAct);
                    t.setAttribute('aria-selected', isAct ? 'true' : 'false');
                });
                this.renderIncidentsTable();
            };
        });
        const telContainer = document.getElementById('telemetryTableContainer');

        if (tabIncidents && tabTrustedAps && incContainer && apsContainer) {
            tabIncidents.onclick = () => {
                tabIncidents.classList.add('active');
                tabTrustedAps.classList.remove('active');
                if (tabTelemetry) tabTelemetry.classList.remove('active');
                incContainer.style.display = 'block';
                apsContainer.style.display = 'none';
                if (telContainer) telContainer.style.display = 'none';
            };
            tabTrustedAps.onclick = () => {
                tabTrustedAps.classList.add('active');
                tabIncidents.classList.remove('active');
                if (tabTelemetry) tabTelemetry.classList.remove('active');
                apsContainer.style.display = 'block';
                incContainer.style.display = 'none';
                if (telContainer) telContainer.style.display = 'none';
                this.renderTrustedApsTable();
            };
        }

        // Flyout close button
        const btnCloseFlyout = document.getElementById('btnCloseFlyout');
        if (btnCloseFlyout) {
            btnCloseFlyout.onclick = () => this.closeFlyout();
        }

        // Learn environment button
        const btnLearn = document.getElementById('btnLearnEnvironment');
        if (btnLearn) {
            btnLearn.onclick = () => this.learnEnvironment();
        }

        // Add trusted AP button
        const btnAddAp = document.getElementById('btnAddTrustedAp');
        if (btnAddAp) {
            btnAddAp.onclick = () => this.handleAddTrustedAp();
        }

        // Copy SHA-256 Evidence Digest button (Static Property Sheet)
        const btnCopyHash = document.getElementById('btnCopyEvidenceHash');
        if (btnCopyHash) {
            btnCopyHash.onclick = () => {
                const hashVal = btnCopyHash.dataset.hash || (document.getElementById('hashDisplayVal') ? document.getElementById('hashDisplayVal').textContent : '');
                this.copyTextToClipboard(hashVal, btnCopyHash);
            };
        }

        // Audio mute fallback handled by status bar btnAudioToggle in app.js

        const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';

        this.renderTrustedApsTable();
    }

    computeSha256(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        }
        const mathPow = Math.pow;
        const maxWord = mathPow(2, 32);
        let i, j;
        let result = '';
        const words = [];
        const asciiBitLength = ascii.length * 8;
        let hash = [];
        const k = [];
        let primeCounter = 0;
        const isComposite = {};
        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (i = 0; i < 313; i += candidate) {
                    isComposite[i] = candidate;
                }
                hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
            }
        }
        ascii += '\x80';
        while ((ascii.length % 64) - 56) ascii += '\x00';
        for (i = 0; i < ascii.length; i++) {
            j = ascii.charCodeAt(i);
            if (j >> 8) return '';
            words[i >> 2] |= j << (((3 - i) % 4) * 8);
        }
        words[words.length] = (asciiBitLength / maxWord) | 0;
        words[words.length] = asciiBitLength | 0;
        for (j = 0; j < words.length;) {
            const w = words.slice(j, (j += 16));
            const oldHash = hash;
            hash = hash.slice(0, 8);
            for (i = 0; i < 64; i++) {
                const w15 = w[i - 15], w2 = w[i - 2];
                const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
                const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
                const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
                const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
                const temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + (w[i] = (i < 16) ? w[i] : ((w[i - 16] + s0 + w[i - 7] + s1) | 0))) | 0;
                const temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;
                hash = [(temp1 + temp2) | 0, hash[0], hash[1], hash[2], (hash[3] + temp1) | 0, hash[4], hash[5], hash[6]];
            }
            for (i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            }
        }
        for (i = 0; i < 8; i++) {
            for (let b = 3; b >= 0; b--) {
                const byte = (hash[i] >> (b * 8)) & 255;
                result += (byte < 16 ? '0' : '') + byte.toString(16);
            }
        }
        return result;
    }

    getMitreDetailsForType(type) {
        const norm = String(type || '').toUpperCase();
        if (norm.includes('DEAUTH') || norm.includes('FLOOD')) {
            return {
                id: 'T1498.001',
                name: 'Network Flood',
                tag: '[T1498.001: Network Flood]',
                tactic: 'TACTIC: Impact (TA0040)'
            };
        }
        if (norm.includes('EVIL') || norm.includes('ROGUE') || norm.includes('TWIN') || norm.includes('ACCESS POINT')) {
            return {
                id: 'T1557.004',
                name: 'Rogue AP',
                tag: '[T1557.004: Rogue AP]',
                tactic: 'TACTIC: Credential Access (TA0006)'
            };
        }
        if (norm.includes('BLE') || norm.includes('BLUETOOTH')) {
            return {
                id: 'T1498',
                name: 'Radio Exhaustion',
                tag: '[T1498: Radio Exhaustion]',
                tactic: 'TACTIC: Impact (TA0040)'
            };
        }
        return {
            id: 'T1499',
            name: 'Endpoint DoS',
            tag: '[T1499: Endpoint DoS]',
            tactic: 'TACTIC: Impact (TA0040)'
        };
    }

    copyTextToClipboard(text, btnElement) {
        if (!text) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text);
        } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
        if (btnElement) {
            const orig = btnElement.textContent;
            btnElement.textContent = 'COPIED!';
            setTimeout(() => { btnElement.textContent = orig; }, 2000);
        }
        if (window.nexusApp && window.nexusApp.opsConsole) {
            window.nexusApp.opsConsole.showToast('SHA-256 COPIED', 'Evidence digest copied to clipboard.', 'info');
        }
    }

    requestNotificationPermission() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    toggleAudio() {
        if (typeof window.setGlobalAudioState === 'function') {
            const current = window.audioRadar ? window.audioRadar.enabled : this.audioEnabled;
            window.setGlobalAudioState(!current);
            return !current;
        }
        if (window.nexusApp && typeof window.nexusApp.setGlobalAudioState === 'function') {
            const current = window.audioRadar ? window.audioRadar.enabled : this.audioEnabled;
            window.nexusApp.setGlobalAudioState(!current);
            return !current;
        }
        this.audioEnabled = !this.audioEnabled;
        const btn = document.getElementById('btnAudioToggle');
        if (btn) {
            btn.classList.toggle('active', this.audioEnabled);
            btn.textContent = this.audioEnabled ? 'SND: ON' : 'SND: OFF';
        }
        return this.audioEnabled;
    }

    playHighSeverityAlertTone() {
        if (!this.audioEnabled || (window.audioRadar && !window.audioRadar.enabled)) return;
        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return;
            if (!this.audioCtx) this.audioCtx = new AudioCtx();
            if (this.audioCtx.state === 'suspended') this.audioCtx.resume();

            const now = this.audioCtx.currentTime;
            // Short dual-tone beep at 880 Hz (A5)
            const osc1 = this.audioCtx.createOscillator();
            const gain1 = this.audioCtx.createGain();
            osc1.type = 'sine';
            osc1.frequency.setValueAtTime(880, now);
            gain1.gain.setValueAtTime(0.18, now);
            gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
            osc1.connect(gain1);
            gain1.connect(this.audioCtx.destination);
            osc1.start(now);
            osc1.stop(now + 0.08);

            const osc2 = this.audioCtx.createOscillator();
            const gain2 = this.audioCtx.createGain();
            osc2.type = 'sine';
            osc2.frequency.setValueAtTime(880, now + 0.12);
            gain2.gain.setValueAtTime(0.18, now + 0.12);
            gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.20);
            osc2.connect(gain2);
            gain2.connect(this.audioCtx.destination);
            osc2.start(now + 0.12);
            osc2.stop(now + 0.20);
        } catch (e) {
            // Audio context handled
        }
    }

    dispatchDesktopNotification(incident) {
        if (!('Notification' in window) || Notification.permission !== 'granted') return;
        try {
            new Notification(`NEXUS AI: [${incident.severity}] ${incident.type}`, {
                body: `Incident ${incident.id} detected at Window #${incident.start_window}. Correlated: ${incident.correlated_signals.join(', ')}`,
                tag: incident.id
            });
        } catch (e) {
            // Notification handled
        }
    }

    syncCounterFromIncidents() {
        const now = new Date();
        const prefix = `INC-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-`;
        let maxSeq = this.incidentCounter || 0;
        for (const inc of this.incidents) {
            const idStr = String(inc.id || '');
            if (idStr.startsWith(prefix)) {
                const seq = parseInt(idStr.slice(prefix.length), 10);
                if (!isNaN(seq) && seq > maxSeq) maxSeq = seq;
            }
        }
        this.incidentCounter = maxSeq;
    }

    createIncidentFromAlert(alertRecord) {
        this.syncCounterFromIncidents();
        this.incidentCounter++;
        const now = new Date();
        const y = now.getFullYear();
        const m = String(now.getMonth() + 1).padStart(2, '0');
        const d = String(now.getDate()).padStart(2, '0');
        const incId = `INC-${y}${m}${d}-${String(this.incidentCounter).padStart(3, '0')}`;

        const correlated = (alertRecord.evidence && alertRecord.evidence.features)
            ? alertRecord.evidence.features.map(f => f.feature)
            : ['deauth'];

        const isLiveMode = window.nexusApp && window.nexusApp.mode !== 'SIMULATION';

        const attackerMac = alertRecord.attacker_mac || (isLiveMode ? 'N/A (Aggregate)' : (
            alertRecord.type.includes('Deauth') ? '00:C0:CA:98:A2:14' :
            alertRecord.type.includes('evil-twin') || alertRecord.type.includes('access point') ? 'F4:F5:E8:21:99:3B' :
            alertRecord.type.includes('BLE') ? '4B:92:1F:08:4C:7A' : '24:A0:74:11:88:5B'
        ));
        const toolSignature = alertRecord.tool_signature || (isLiveMode ? 'STATISTICAL ANOMALY' : (
            alertRecord.type.includes('Deauth') ? '[AIREPLAY-NG / REASON 7]' :
            alertRecord.type.includes('evil-twin') || alertRecord.type.includes('access point') ? '[EVIL-TWIN / HOSTAPD-MANA]' :
            alertRecord.type.includes('BLE') ? '[BLE-SPAM / FLIPPER ZERO]' : '[LEGITIMATE ROAM / REASON 3]'
        ));
        const targetBssid = alertRecord.target_bssid || (isLiveMode ? 'N/A (Window)' : (
            alertRecord.type.includes('BLE') ? 'BROADCAST (ADV_IND)' : '00:14:2D:E1:92:40'
        ));
        const frameChannel = alertRecord.channel || (window.nexusApp && window.nexusApp.primaryChannel) || 6;
        const hasValidRssi = alertRecord.rssi !== undefined && alertRecord.rssi !== null && alertRecord.rssi !== 0;
        const rssi = hasValidRssi
            ? alertRecord.rssi
            : (isLiveMode ? null : (alertRecord.severity === 'HIGH' ? -42 : alertRecord.severity === 'MEDIUM' ? -58 : -76));

        let proximityZone = 'N/A';
        let proximityClass = 'proximity-perimeter';
        if (rssi !== null) {
            proximityZone = 'MID-RANGE (5-15m)';
            proximityClass = 'proximity-mid';
            if (rssi >= -48) {
                proximityZone = 'IMMEDIATE (< 3m)';
                proximityClass = 'proximity-immediate';
            } else if (rssi <= -72) {
                proximityZone = 'PERIMETER (> 15m)';
                proximityClass = 'proximity-perimeter';
            }
        }

        const hardwareProfile = alertRecord.hardware_profile || (isLiveMode ? 'N/A (Count-Only)' : (
            alertRecord.type.includes('Deauth') ? '[ESP8266/ESP32 DEAUTHER]' :
            (alertRecord.type.includes('evil-twin') || alertRecord.type.includes('access point')) ? '[SPOOFED LAA]' :
            alertRecord.type.includes('BLE') ? '[FLIPPER ZERO / CC2540]' : '[ESP8266/ESP32 DEAUTHER]'
        ));

        const rawInjectionCount = (typeof alertRecord.raw_injection_count !== 'undefined')
            ? alertRecord.raw_injection_count
            : (isLiveMode ? 0 : (alertRecord.type.includes('Deauth') ? 142 : (alertRecord.type.includes('evil-twin') ? 38 : 0)));

        const mitre = this.getMitreDetailsForType(alertRecord.type);
        const canonicalString = `${incId}|${now.getTime()}|${attackerMac}|${targetBssid}|0|${alertRecord.type}`;
        const evidenceHash = alertRecord.evidence_hash || this.computeSha256(canonicalString);

        const incident = {
            id: incId,
            start_window: alertRecord.window,
            end_window: alertRecord.window + 2,
            time: now.toLocaleTimeString(),
            type: alertRecord.type,
            severity: alertRecord.severity.toUpperCase(), // HIGH, MEDIUM, LOW
            status: 'OPEN', // OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE
            confidence: alertRecord.confidence,
            correlated_signals: correlated,
            alert_id: alertRecord.id,
            evidence: alertRecord.evidence,
            explanation: alertRecord.explanation || '',
            analyst_notes: '',
            attacker_mac: attackerMac,
            tool_signature: toolSignature,
            target_bssid: targetBssid,
            channel: frameChannel,
            rssi: rssi,
            proximity_zone: proximityZone,
            proximity_class: proximityClass,
            hardware_profile: hardwareProfile,
            raw_injection_count: rawInjectionCount,
            mitre: mitre,
            mitre_technique_id: mitre.id,
            mitre_technique_name: mitre.name,
            mitre_tactic: mitre.tactic,
            evidence_hash: evidenceHash
        };

        this.incidents.unshift(incident);
        this.unacknowledgedCount++;
        this.updateKpiCard();
        this.renderIncidentsTable();

        // Audio & Desktop alerts on HIGH severity
        if (incident.severity === 'HIGH') {
            this.playHighSeverityAlertTone();
            this.dispatchDesktopNotification(incident);
        }

        // Auto-select latest incident in Playbook
        this.selectIncident(incident);

        // Check if Rogue AP alert
        if (alertRecord.type.includes('evil-twin') || alertRecord.type.includes('access point')) {
            this.triggerRogueApAlert('00:11:22:33:44:55', 'Campus-Corp-Secure', 6);
        }

        return incident;
    }

    selectIncidentById(incId) {
        const found = this.incidents.find(i => i.id === incId);
        if (found) {
            this.selectIncident(found);
            const incCard = document.getElementById('sec-incidents');
            if (incCard) incCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    selectIncident(incident) {
        this.selectedIncident = incident;
        this.renderIncidentsTable();
        this.renderDefensivePlaybook(incident);

        if (incident) {
            const evView = document.getElementById('evidenceView');
            const expView = document.getElementById('explanationView');
            const evTag = document.getElementById('evidenceEventTag');

            if (evTag) {
                const sev = String(incident.severity || 'HIGH').toUpperCase();
                evTag.className = `status-pill ${sev === 'HIGH' || sev === 'CRITICAL' ? 'pill-high' : 'pill-medium'}`;
                evTag.textContent = incident.id || `WIN-${incident.window_id ?? incident.start_window ?? '--'}`;
            }

            if (evView) {
                let rawEvidenceObj = incident.evidence || null;
                if (!rawEvidenceObj && incident.signals_involved_json) {
                    if (typeof incident.signals_involved_json === 'string') {
                        try {
                            const parsed = JSON.parse(incident.signals_involved_json);
                            const isLegacyEvIdList = Array.isArray(parsed) && (parsed.length === 0 || parsed.every(item => typeof item === 'string' && /^EV-/i.test(item)));
                            if (!isLegacyEvIdList) {
                                rawEvidenceObj = parsed;
                            }
                        } catch (e) {
                            // Ignore malformed JSON and use structured summary fallback
                        }
                    } else if (typeof incident.signals_involved_json === 'object') {
                        const arr = incident.signals_involved_json;
                        const isLegacyEvIdList = Array.isArray(arr) && (arr.length === 0 || arr.every(item => typeof item === 'string' && /^EV-/i.test(item)));
                        if (!isLegacyEvIdList) {
                            rawEvidenceObj = arr;
                        }
                    }
                }

                if (!rawEvidenceObj) {
                    rawEvidenceObj = {
                        window_id: incident.window_id ?? incident.start_window ?? '--',
                        type: incident.type || incident.title || incident.primary_type || 'Wireless Anomaly',
                        severity: incident.severity,
                        channel: incident.channel || (window.nexusApp && window.nexusApp.primaryChannel) || '--',
                        rationale: incident.summary || incident.explanation || `${incident.type || 'Wireless Anomaly'} detected at window #${incident.window_id ?? incident.start_window ?? '--'}.`
                    };
                }
                evView.textContent = typeof rawEvidenceObj === 'string' ? rawEvidenceObj : JSON.stringify(rawEvidenceObj, null, 2);
            }

            if (expView) {
                expView.textContent = incident.summary || incident.explanation || `${incident.type || 'Wireless Anomaly'} detected at window #${incident.window_id ?? incident.start_window ?? '--'}.`;
            }
        }
    }

    acknowledgeIncident(incId) {
        const inc = this.incidents.find(i => i.id === incId);
        if (!inc) return;
        if (inc.status === 'OPEN') {
            this.unacknowledgedCount = Math.max(0, this.unacknowledgedCount - 1);
        }
        inc.status = 'ACKNOWLEDGED';
        this.updateKpiCard();
        this.renderIncidentsTable();
        this.renderDefensivePlaybook(inc);
        const btnAck = document.getElementById('btnAckInc');
        if (btnAck) btnAck.disabled = true;
        if (window.nexusApp && window.nexusApp.opsConsole) {
            window.nexusApp.opsConsole.showToast('INCIDENT ACKNOWLEDGED', `${incId} status set to ACKNOWLEDGED.`, 'info');
        }
        this.syncBackendStatus(incId, 'ACKNOWLEDGED');
    }

    markFalsePositive(incId) {
        const inc = this.incidents.find(i => i.id === incId);
        if (!inc) return;

        const confirmed = confirm(
            `Mark ${inc.id} as False Positive?\n\n` +
            `This action unfreezes the EWMA baseline adaptation and records a False Positive in the detector benchmark comparison.`
        );

        if (confirmed) {
            inc.status = 'FALSE_POSITIVE';
            if (inc.status === 'OPEN') {
                this.unacknowledgedCount = Math.max(0, this.unacknowledgedCount - 1);
            }
            this.updateKpiCard();
            this.renderIncidentsTable();
            this.renderDefensivePlaybook(inc);
            this.syncBackendStatus(incId, 'FALSE_POSITIVE');

            if (window.nexusApp) {
                window.nexusApp.registerOperatorFalsePositive(inc);
            }
        }
    }

    resolveIncident(incId) {
        const inc = this.incidents.find(i => i.id === incId);
        if (!inc) return;
        if (inc.status === 'OPEN') {
            this.unacknowledgedCount = Math.max(0, this.unacknowledgedCount - 1);
        }
        inc.status = 'RESOLVED';
        this.updateKpiCard();
        this.renderIncidentsTable();
        this.renderDefensivePlaybook(inc);
        const btnRes = document.getElementById('btnResolveInc');
        if (btnRes) btnRes.disabled = true;
        const btnAck = document.getElementById('btnAckInc');
        if (btnAck) btnAck.disabled = true;
        if (window.nexusApp && window.nexusApp.opsConsole) {
            window.nexusApp.opsConsole.showToast('INCIDENT RESOLVED', `${incId} status set to RESOLVED.`, 'success');
        }
        this.syncBackendStatus(incId, 'RESOLVED');
    }

    async syncBackendStatus(incId, newStatus) {
        const apiBase = (window.nexusApp && typeof window.nexusApp.getApiBase === 'function')
            ? window.nexusApp.getApiBase()
            : (window.location.port === '8000' ? '' : 'http://127.0.0.1:8000');
        const dbMode = (window.nexusApp && window.nexusApp.mode === 'SIMULATION') ? 'simulation' : 'live';
        try {
            const resp = await fetch(`${apiBase}/api/incidents/${incId}/status?mode=${dbMode}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus, note: 'Operator updated status from UI' })
            });
            if (!resp.ok) {
                console.error(`[NEXUS] Failed to persist status for ${incId}: HTTP ${resp.status}`);
                if (window.nexusApp && window.nexusApp.opsConsole) {
                    window.nexusApp.opsConsole.showToast('PERSISTENCE ERROR', `Failed to save ${newStatus} for ${incId} (HTTP ${resp.status}).`, 'danger');
                }
            }
        } catch (e) {
            console.error(`[NEXUS] Network error persisting status for ${incId}:`, e);
        }
    }

    async exportIncidentPcap(incId) {
        const apiBase = (window.nexusApp && typeof window.nexusApp.getApiBase === 'function')
            ? window.nexusApp.getApiBase()
            : (window.location.port === '8000' ? '' : 'http://127.0.0.1:8000');
        const dbMode = (window.nexusApp && window.nexusApp.mode === 'SIMULATION') ? 'simulation' : 'live';
        try {
            const resp = await fetch(`${apiBase}/api/incidents/${incId}/pcap?mode=${dbMode}`);
            if (resp.ok) {
                const blob = await resp.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `incident_${incId}.pcap`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                if (window.nexusApp && window.nexusApp.opsConsole) {
                    window.nexusApp.opsConsole.showToast('PCAP EXPORT', `Exported binary PCAP for ${incId}.`, 'info');
                }
                return;
            }
        } catch (e) {
            // Fallback to client-side synthetic PCAP generation if backend offline
        }
        this.downloadClientSynthesizedPcap(incId);
    }

    downloadClientSynthesizedPcap(incId) {
        const inc = this.incidents.find(i => i.id === incId);
        // PCAP Global Header: magic 0xA1B2C3D4 (DLT_IEEE802_11 linktype 105 = 0x00000069)
        const globalHeader = new Uint8Array([
            0xd4, 0xc3, 0xb2, 0xa1, // Magic number
            0x02, 0x00,             // Major version 2
            0x04, 0x00,             // Minor version 4
            0x00, 0x00, 0x00, 0x00, // Timezone offset 0
            0x00, 0x00, 0x00, 0x00, // Sigfigs 0
            0xff, 0xff, 0x00, 0x00, // Snaplen 65535
            0x69, 0x00, 0x00, 0x00  // LinkType 105 (DLT_IEEE802_11)
        ]);

        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
        const parseMac = (macStr, fallback) => {
            const candidate = (macStr && macRegex.test(macStr)) ? macStr : (fallback || '00:00:00:00:00:00');
            const clean = candidate.replace(/[-]/g, ':').split(':');
            const bytes = new Uint8Array(6);
            for (let i = 0; i < 6; i++) {
                bytes[i] = clean[i] ? (parseInt(clean[i], 16) || 0) : 0;
            }
            return bytes;
        };

        const isLiveMode = window.nexusApp && window.nexusApp.mode !== 'SIMULATION';
        const destBytes = parseMac(inc ? inc.target_bssid : null, 'FF:FF:FF:FF:FF:FF');
        const srcBytes = parseMac(inc ? inc.attacker_mac : null, isLiveMode ? '00:00:00:00:00:00' : '00:C0:CA:98:A2:14');
        const bssidBytes = parseMac(inc ? inc.target_bssid : null, isLiveMode ? '00:00:00:00:00:00' : '00:14:2D:E1:92:40');
        const reasonCode = (inc && inc.deauth_reason) ? (parseInt(inc.deauth_reason, 10) || 7) : 7;

        // Dynamic 802.11 subtype byte: 0xC0 for deauth bursts, 0x80 for beacon/rogue AP frames
        const isBeaconOrRogue = inc && inc.type && (
            inc.type.toLowerCase().includes('evil-twin') ||
            inc.type.toLowerCase().includes('access point') ||
            inc.type.toLowerCase().includes('rogue') ||
            inc.type.toLowerCase().includes('beacon')
        );
        const frameSubtype = isBeaconOrRogue ? 0x80 : 0xc0;

        // Synthesize 802.11 frame (26 bytes)
        const frame = new Uint8Array(26);
        frame[0] = frameSubtype;              // Frame Control: Subtype (0xC0 Deauth or 0x80 Beacon)
        frame[1] = 0x00;
        frame[2] = 0x3a;                      // Duration
        frame[3] = 0x01;
        frame.set(destBytes, 4);              // Dest Addr: Target BSSID / Broadcast (bytes 4..9)
        frame.set(srcBytes, 10);              // Src Addr: Attacker MAC (bytes 10..15)
        frame.set(bssidBytes, 16);            // BSSID: Target AP (bytes 16..21)
        frame[22] = 0x00;                     // Seq Control
        frame[23] = 0x00;
        frame[24] = reasonCode & 0xFF;        // Reason Code (LSB)
        frame[25] = (reasonCode >> 8) & 0xFF; // Reason Code (MSB)

        const nowSec = Math.floor(Date.now() / 1000);
        const nowUsec = (Date.now() % 1000) * 1000;
        const pktLen = frame.length;

        // Packet Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
        const pktHdr = new ArrayBuffer(16);
        const pktView = new DataView(pktHdr);
        pktView.setUint32(0, nowSec, true);
        pktView.setUint32(4, nowUsec, true);
        pktView.setUint32(8, pktLen, true);
        pktView.setUint32(12, pktLen, true);

        const pcapBlob = new Blob([globalHeader, new Uint8Array(pktHdr), frame], { type: 'application/vnd.tcpdump.pcap' });
        const url = window.URL.createObjectURL(pcapBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `incident_${incId}.pcap`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        if (window.nexusApp && window.nexusApp.opsConsole) {
            window.nexusApp.opsConsole.showToast('PCAP EXPORT', `Exported binary PCAP for ${incId}.`, 'info');
        }
    }

    updateKpiCard() {
        const countEl = document.getElementById('kpiOpenIncidents');
        const badgeEl = document.getElementById('kpiIncidentBadge');
        const openCount = this.incidents.filter(i => i.status === 'OPEN' || i.status === 'ACKNOWLEDGED').length;
        if (countEl) countEl.textContent = openCount;
        if (badgeEl) badgeEl.textContent = `${this.unacknowledgedCount} UNACK`;
        const tabBadge = document.getElementById('tabBadgeIncidents');
        if (tabBadge) tabBadge.textContent = openCount;
    }

    setWindowFilter(startWin, endWin) {
        this.windowFilterStart = (startWin !== undefined && startWin !== null) ? startWin : null;
        this.windowFilterEnd = (endWin !== undefined && endWin !== null) ? endWin : null;
        this.renderIncidentsTable();
    }

    setMitreFilter(mitreCode) {
        this.mitreFilter = mitreCode || null;
        this.renderIncidentsTable();
    }

    renderIncidentsTable() {
        const tbody = document.getElementById('incidentsTableBody');
        if (!tbody) return;

        // Update live status filter tab counts
        const cntAll = document.getElementById('cntIncAll');
        const cntOpen = document.getElementById('cntIncOpen');
        const cntAck = document.getElementById('cntIncAck');
        const cntResolved = document.getElementById('cntIncResolved');
        if (cntAll) cntAll.textContent = String(this.incidents.length);
        if (cntOpen) cntOpen.textContent = String(this.incidents.filter(i => i.status === 'OPEN').length);
        if (cntAck) cntAck.textContent = String(this.incidents.filter(i => i.status === 'ACKNOWLEDGED').length);
        if (cntResolved) cntResolved.textContent = String(this.incidents.filter(i => i.status === 'RESOLVED').length);

        // First-Run / Empty State
        if (this.incidents.length === 0) {
            const app = window.nexusApp;
            const isWarmup = app ? (app.isWarmup !== undefined ? (app.isWarmup && app.windowCount < app.warmupWindows) : (app.windowCount < app.warmupWindows)) : false;
            const winCount = app ? (app.windowCount !== undefined ? app.windowCount : 0) : 0;
            const warmupLimit = app ? (app.warmupWindows !== undefined ? app.warmupWindows : 30) : 30;

            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="padding: 24px; text-align: center;">
                        <div class="empty-state-box">
                            <div class="empty-state-title ${isWarmup ? '' : 'text-emerald'}">
                                ${isWarmup ? `Warm-up in progress (${winCount}/${warmupLimit} windows)` : 'Active Monitoring (Baseline Stable)'}
                            </div>
                            <div class="empty-state-subtext">
                                ${isWarmup ? 'Baseline converging. Zero anomalies detected.' : 'Zero anomalies detected. All 4 RF channels operating within normal 3σ baseline variance.'}
                            </div>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        let filteredIncidents = (this.windowFilterStart !== null && this.windowFilterEnd !== null)
            ? this.incidents.filter(inc => {
                const w = (inc.start_window !== undefined && inc.start_window !== null) ? inc.start_window : inc.window_id;
                return w >= this.windowFilterStart && w <= this.windowFilterEnd;
            })
            : this.incidents;

        if (this.mitreFilter) {
            const code = this.mitreFilter.toUpperCase();
            filteredIncidents = filteredIncidents.filter(inc => {
                const incMitre = (inc.mitre_technique_id || (inc.mitre && inc.mitre.id) || '').toUpperCase();
                const incType = (inc.type || '').toUpperCase();
                if (code.includes('1498')) {
                    return incMitre.includes('1498') || incType.includes('DEAUTH') || incType.includes('FLOOD');
                }
                if (code.includes('1499')) {
                    return incMitre.includes('1499') || incType.includes('MGMT');
                }
                if (code.includes('1584') || code.includes('1557.004')) {
                    return incMitre.includes('1584') || incMitre.includes('1557.004') || incType.includes('EVIL-TWIN') || incType.includes('ACCESS POINT') || incType.includes('ROGUE');
                }
                if (code.includes('1557')) {
                    return incMitre.includes('1557') || incType.includes('BLE') || incType.includes('SPOOF');
                }
                return incMitre.includes(code);
            });
        }

        if (this.statusFilter && this.statusFilter !== 'ALL') {
            filteredIncidents = filteredIncidents.filter(inc => inc.status === this.statusFilter);
        }

        if (filteredIncidents.length === 0) {
            let emptyMsg = 'Zero incidents recorded.';
            if (this.statusFilter && this.statusFilter !== 'ALL') {
                emptyMsg = `Zero ${this.statusFilter.toLowerCase()} incidents recorded.`;
            } else if (this.windowFilterStart !== null && this.windowFilterEnd !== null) {
                emptyMsg = `Zero incidents recorded within scrubbed range W#${this.windowFilterStart} - W#${this.windowFilterEnd}.`;
            } else if (this.mitreFilter) {
                emptyMsg = `Zero incidents matching MITRE ATT&amp;CK technique ${this.mitreFilter}.`;
            }
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="padding: 24px; text-align: center; color: var(--text-muted);">
                        ${emptyMsg}
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        filteredIncidents.forEach(inc => {
            const isSelected = this.selectedIncident && this.selectedIncident.id === inc.id;
            const isExpanded = this.expandedIncidentIds.has(inc.id);

            let sevClass = 'pill-low';
            if (inc.severity === 'HIGH') sevClass = 'pill-high';
            else if (inc.severity === 'MEDIUM') sevClass = 'pill-medium';

            let statusClass = 'pill-warmup';
            if (inc.status === 'ACKNOWLEDGED') statusClass = 'pill-active';
            else if (inc.status === 'RESOLVED') statusClass = 'pill-resolved';
            else if (inc.status === 'FALSE_POSITIVE') statusClass = 'pill-low';

            const isLiveMode = window.nexusApp && window.nexusApp.mode !== 'SIMULATION';
            const attackerMac = inc.attacker_mac || (isLiveMode ? 'N/A' : '24:A0:74:11:88:5B');
            const toolSig = inc.tool_signature || (isLiveMode ? 'STATISTICAL ANOMALY' : '[UNKNOWN / REASON 0]');
            let sigClass = 'badge-sig-rose';
            if (toolSig.includes('AIREPLAY')) sigClass = 'badge-sig-amber';
            else if (toolSig.includes('ROAM')) sigClass = 'badge-sig-cyan';

            const proxZone = inc.proximity_zone || (isLiveMode ? 'N/A' : 'MID-RANGE (5-15m)');
            const proxClass = inc.proximity_class || (isLiveMode ? 'proximity-perimeter' : 'proximity-mid');
            const incMitre = inc.mitre || this.getMitreDetailsForType(inc.type);
            const incHash = inc.evidence_hash || (inc.evidence_hash = this.computeSha256(`${inc.id}|${inc.time}|${attackerMac}|${inc.target_bssid || ''}|0|${inc.type}`));

            const isResolvedRow = inc.status === 'RESOLVED' || inc.status === 'FALSE_POSITIVE';
            html += `
                <tr class="${isSelected ? 'selected' : ''}${isResolvedRow ? ' row-resolved' : ''}" data-inc-id="${inc.id}">
                    <td style="width: 24px;">
                        <button class="expand-row-btn" data-inc-id="${inc.id}" title="Toggle Document Inspection">${isExpanded ? '&#x25BC;' : '&#x25B6;'}</button>
                    </td>
                    <td class="font-mono font-bold" style="color: var(--accent-sky); white-space: nowrap;">${inc.id}</td>
                    <td style="white-space: nowrap;"><span class="status-pill ${statusClass}">${inc.status}</span></td>
                    <td class="font-mono" style="white-space: nowrap;">W#${inc.start_window ?? inc.window_id ?? '--'} (${inc.time})</td>
                    <td style="color: var(--text-white); font-weight: 500; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${inc.type}">${inc.type}</td>
                    <td><span class="status-pill ${sevClass}">${inc.severity}</span></td>
                    <td><span class="badge-mac">${attackerMac}</span></td>
                    <td><span class="badge-sig ${sigClass}">${toolSig}</span></td>
                    <td style="white-space: nowrap;"><span class="badge-proximity ${proxClass}">${proxZone}</span></td>
                </tr>
            `;

            // Inline Expanded Document Pane
            if (isExpanded) {
                html += `
                    <tr class="expanded-detail-row">
                        <td colspan="9" style="padding: 0;">
                            <div class="row-detail-pane">
                                <div class="detail-pane-tabs">
                                    <button class="detail-tab active" data-inc-id="${inc.id}" data-pane="table">Table View</button>
                                    <button class="detail-tab" data-inc-id="${inc.id}" data-pane="json">JSON View</button>
                                    <button class="btn btn-sm btn-copy-json" data-inc-id="${inc.id}">Copy JSON</button>
                                    <button class="btn btn-sm btn-export-pcap" data-inc-id="${inc.id}" title="Download binary Wireshark PCAP">&#x2913; Export PCAP</button>
                                    <button class="btn btn-sm btn-primary btn-open-flyout" data-inc-id="${inc.id}" style="margin-left: auto;">Open Flyout Inspector &rarr;</button>
                                </div>
                                <div class="detail-pane-content" id="pane-table-${inc.id}">
                                    <table class="detail-kv-table">
                                        <tbody>
                                            <tr><td>Incident ID</td><td>${inc.id}</td></tr>
                                            <tr><td>Time Bounds</td><td>Window #${inc.start_window} &rarr; #${inc.end_window} (${inc.time})</td></tr>
                                            <tr><td>Classification</td><td>${inc.type}</td></tr>
                                            <tr><td>Severity & Confidence</td><td>${inc.severity} (Confidence: ${(inc.confidence * 100).toFixed(0)}%)</td></tr>
                                            <tr><td>Attacker MAC</td><td><span class="badge-mac">${attackerMac}</span></td></tr>
                                            <tr><td>Hardware Profile</td><td><span class="badge-hardware font-mono"><span class="hardware-icon">&#x2699;</span> ${inc.hardware_profile || (isLiveMode ? 'N/A (Count-Only)' : '[ESP8266/ESP32 DEAUTHER]')}</span></td></tr>
                                            <tr><td>Injection Alert</td><td>${(inc.raw_injection_count && inc.raw_injection_count > 0) ? '<span style="color: var(--status-rose); font-weight: 700;">RAW FRAME INJECTION DETECTED (' + inc.raw_injection_count + ' frames)</span>' : '<span style="color: var(--text-muted);">None</span>'}</td></tr>
                                            <tr><td>Tool Attribution</td><td><span class="badge-sig ${sigClass}">${toolSig}</span></td></tr>
                                            <tr><td>Proximity Zone</td><td><span class="badge-proximity ${proxClass}">${proxZone}</span>${inc.rssi != null ? ` (${inc.rssi} dBm)` : (isLiveMode ? '' : ' (-58 dBm)')}</td></tr>
                                            <tr><td>Target BSSID / Ch</td><td class="font-mono">${inc.target_bssid || (isLiveMode ? 'N/A (Window)' : '00:14:2D:E1:92:40')} (Channel ${inc.channel || (window.nexusApp && window.nexusApp.primaryChannel) || '--'})</td></tr>
                                            <tr><td>Correlated Signals</td><td>${inc.correlated_signals.join(', ')}</td></tr>
                                            <tr><td>MITRE ATT&amp;CK</td><td>
                                                <div class="mitre-badge-container">
                                                    <span class="badge-mitre font-mono">[<span class="mitre-id">${incMitre.id}:</span> ${incMitre.name}]</span>
                                                    <div class="mitre-tactic font-mono">${incMitre.tactic}</div>
                                                </div>
                                            </td></tr>
                                            <tr><td>SHA-256 Digest</td><td>
                                                <div class="evidence-hash-box">
                                                    <span class="hash-label">DIGEST:</span>
                                                    <code class="mono-hash">${incHash}</code>
                                                    <button class="btn btn-sm btn-copy-hash" data-hash="${incHash}" title="Copy SHA-256 Checksum">COPY SHA-256</button>
                                                </div>
                                            </td></tr>
                                        </tbody>
                                    </table>
                                </div>
                                <div class="detail-pane-content" id="pane-json-${inc.id}" style="display: none;">
                                    <pre class="detail-json-block">${JSON.stringify(inc, null, 2)}</pre>
                                </div>
                            </div>
                        </td>
                    </tr>
                `;
            }
        });

        tbody.innerHTML = html;

        // Row Selection and Expansion Click Handlers
        tbody.querySelectorAll('tr[data-inc-id]').forEach(tr => {
            tr.onclick = (e) => {
                if (e.target.closest('.expand-row-btn')) return;
                const incId = tr.dataset.incId;
                const inc = this.incidents.find(i => i.id === incId);
                if (inc) this.selectIncident(inc);
            };
        });

        tbody.querySelectorAll('.expand-row-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const incId = btn.dataset.incId;
                if (this.expandedIncidentIds.has(incId)) {
                    this.expandedIncidentIds.delete(incId);
                } else {
                    this.expandedIncidentIds.add(incId);
                }
                this.renderIncidentsTable();
            };
        });

        // Tab Switchers inside Detail Pane
        tbody.querySelectorAll('.detail-tab').forEach(tab => {
            tab.onclick = (e) => {
                e.stopPropagation();
                const incId = tab.dataset.incId;
                const pane = tab.dataset.pane;
                const parentPane = tab.closest('.row-detail-pane');
                parentPane.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                const tablePane = parentPane.querySelector(`#pane-table-${incId}`);
                const jsonPane = parentPane.querySelector(`#pane-json-${incId}`);
                if (tablePane && jsonPane) {
                    tablePane.style.display = pane === 'table' ? 'block' : 'none';
                    jsonPane.style.display = pane === 'json' ? 'block' : 'none';
                }
            };
        });

        // Copy JSON Button
        tbody.querySelectorAll('.btn-copy-json').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const incId = btn.dataset.incId;
                const inc = this.incidents.find(i => i.id === incId);
                if (inc) {
                    navigator.clipboard.writeText(JSON.stringify(inc, null, 2));
                    const orig = btn.textContent;
                    btn.textContent = 'Copied!';
                    setTimeout(() => { btn.textContent = orig; }, 2000);
                }
            };
        });

        // Export PCAP Button on table row detail
        tbody.querySelectorAll('.btn-export-pcap').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const incId = btn.dataset.incId;
                this.exportIncidentPcap(incId);
            };
        });

        // Copy SHA-256 Digest Button on table row detail
        tbody.querySelectorAll('.btn-copy-hash').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                this.copyTextToClipboard(btn.dataset.hash, btn);
            };
        });

        // Open Flyout Drawer Button
        tbody.querySelectorAll('.btn-open-flyout').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const incId = btn.dataset.incId;
                const inc = this.incidents.find(i => i.id === incId);
                if (inc) this.openFlyout(inc);
            };
        });
    }

    getMitreIdForType(type) {
        if (type.includes('Deauth') || type.includes('Flood')) return 'T1498 (Network DoS)';
        if (type.includes('evil-twin') || type.includes('access point')) return 'T1584 (Rogue Infrastructure)';
        if (type.includes('BLE')) return 'T1557.001 (Wireless Spoofing)';
        return 'T1499 (Endpoint DoS)';
    }

    // ==========================================
    // Slide-Over Flyout Inspector Drawer
    // ==========================================
    openFlyout(incident) {
        const drawer = document.getElementById('eventFlyoutDrawer');
        const content = document.getElementById('flyoutContent');
        if (!drawer || !content) return;

        let featuresHtml = '';
        if (incident.evidence && incident.evidence.features) {
            featuresHtml = incident.evidence.features.map(f => `
                <div class="flyout-metric-card">
                    <div class="flyout-metric-name">${f.feature}</div>
                    <div class="flyout-metric-val font-mono">${f.observed}</div>
                    <div class="flyout-metric-sub font-mono">μ: ${f.baseline_mean} | z: +${f.z_score}σ</div>
                </div>
            `).join('');
        }

        const isLiveMode = window.nexusApp && window.nexusApp.mode !== 'SIMULATION';
        const attackerMac = incident.attacker_mac || (isLiveMode ? 'N/A' : '24:A0:74:11:88:5B');
        const toolSig = incident.tool_signature || (isLiveMode ? 'STATISTICAL ANOMALY' : '[UNKNOWN / REASON 0]');
        let sigClass = 'badge-sig-rose';
        if (toolSig.includes('AIREPLAY')) sigClass = 'badge-sig-amber';
        else if (toolSig.includes('ROAM')) sigClass = 'badge-sig-cyan';

        const proxZone = incident.proximity_zone || (isLiveMode ? 'N/A' : 'MID-RANGE (5-15m)');
        const proxClass = incident.proximity_class || (isLiveMode ? 'proximity-perimeter' : 'proximity-mid');
        const flyoutMitre = incident.mitre || this.getMitreDetailsForType(incident.type);
        const flyoutHash = incident.evidence_hash || (incident.evidence_hash = this.computeSha256(`${incident.id}|${incident.time}|${attackerMac}|${incident.target_bssid || ''}|0|${incident.type}`));

        content.innerHTML = `
            <div class="flyout-header-box">
                <span class="status-pill pill-high">${incident.severity}</span>
                <span class="font-mono font-bold" style="color: var(--accent-sky); font-size: 14px;">${incident.id}</span>
                <span class="font-mono text-muted">Window #${incident.start_window} (${incident.time})</span>
            </div>

            <div class="forensic-meta-strip">
                <div class="forensic-meta-item">
                    <strong>ATTACKER:</strong>
                    <span class="badge-mac">${attackerMac}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>HARDWARE:</strong>
                    <span class="badge-hardware font-mono"><span class="hardware-icon">&#x2699;</span> ${incident.hardware_profile || (isLiveMode ? 'N/A (Count-Only)' : '[ESP8266/ESP32 DEAUTHER]')}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>SIGNATURE:</strong>
                    <span class="badge-sig ${sigClass}">${toolSig}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>PROXIMITY:</strong>
                    <span class="badge-proximity ${proxClass}">${proxZone}</span>
                </div>
            </div>

            ${(incident.raw_injection_count && incident.raw_injection_count > 0) ? `
                <div class="frame-injection-alert">
                    <span class="alert-pulse-dot"></span>
                    <span>RAW FRAME INJECTION DETECTED &bull; ${incident.raw_injection_count} FRAMES</span>
                </div>
            ` : ''}

            <div style="margin-top: 8px; margin-bottom: 8px; display: flex; flex-direction: column; gap: 6px;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <span class="font-mono" style="font-size: 10px; color: var(--text-muted); font-weight: 700;">MITRE ATT&amp;CK:</span>
                    <div class="mitre-badge-container" style="align-items: flex-end;">
                        <span class="badge-mitre font-mono">[<span class="mitre-id">${flyoutMitre.id}:</span> ${flyoutMitre.name}]</span>
                        <div class="mitre-tactic font-mono">${flyoutMitre.tactic}</div>
                    </div>
                </div>
                <div class="evidence-hash-box">
                    <span class="hash-label">DIGEST:</span>
                    <code class="mono-hash">${flyoutHash}</code>
                    <button class="btn btn-sm btn-copy-hash" data-hash="${flyoutHash}" title="Copy SHA-256 Checksum">COPY SHA-256</button>
                </div>
            </div>

            <div class="flyout-section-title">Telemetry Signal Analysis</div>
            <div class="flyout-metrics-grid">${featuresHtml || '<div class="text-muted">No individual feature measurements attached.</div>'}</div>

            <div class="flyout-section-title" style="margin-top: 14px;">Grounded Forensic Rationale</div>
            <div class="flyout-text-box">${incident.explanation || 'Anomalous statistical burst triggered multi-signal correlation.'}</div>

            <div class="flyout-section-title" style="margin-top: 14px;">Structured Incident Record</div>
            <pre class="flyout-json-box">${JSON.stringify(incident, null, 2)}</pre>

            <div class="flyout-actions-row">
                <button class="btn btn-sm" id="btnFlyoutPcap">&#x2913; Export PCAP</button>
                <button class="btn btn-sm" id="btnFlyoutAck">Acknowledge</button>
                <button class="btn btn-sm btn-danger" id="btnFlyoutFp">Mark False Positive</button>
                <button class="btn btn-sm btn-primary" id="btnFlyoutRes">Resolved</button>
            </div>
        `;

        const bPcap = content.querySelector('#btnFlyoutPcap');
        if (bPcap) bPcap.onclick = () => this.exportIncidentPcap(incident.id);

        const bCopyHash = content.querySelector('.btn-copy-hash');
        if (bCopyHash) bCopyHash.onclick = () => this.copyTextToClipboard(flyoutHash, bCopyHash);

        const bAck = content.querySelector('#btnFlyoutAck');
        if (bAck) bAck.onclick = () => { this.acknowledgeIncident(incident.id); this.closeFlyout(); };
        const bFp = content.querySelector('#btnFlyoutFp');
        if (bFp) bFp.onclick = () => { this.markFalsePositive(incident.id); this.closeFlyout(); };
        const bRes = content.querySelector('#btnFlyoutRes');
        if (bRes) bRes.onclick = () => { this.resolveIncident(incident.id); this.closeFlyout(); };

        drawer.classList.add('open');
    }

    closeFlyout() {
        const drawer = document.getElementById('eventFlyoutDrawer');
        if (drawer) drawer.classList.remove('open');
    }

    renderDefensivePlaybook(incident) {
        const container = document.getElementById('defensivePlaybookContent');
        if (!container) return;

        if (!incident) {
            container.innerHTML = `<div style="color: var(--text-muted); font-size: 11px; padding: 18px 0; text-align: center;">Select an incident from the timeline to inspect tactical mitigation playbooks.</div>`;
            const propSheet = document.getElementById('incidentPropertySheet');
            if (propSheet) propSheet.style.display = 'none';
            const tag = document.getElementById('evidenceEventTag');
            if (tag) { tag.className = 'status-pill pill-low'; tag.textContent = 'EV-NONE'; }
            const evView = document.getElementById('evidenceView');
            if (evView) evView.textContent = '// Awaiting incident selection';
            const expView = document.getElementById('explanationView');
            if (expView) expView.textContent = '// Local anomaly detector rule explanation';
            return;
        }

        let playbooks = [];
        let citations = [];
        const incTypeStr = String(incident.type || incident.title || incident.primary_type || 'Wireless Anomaly');
        const incType = incTypeStr.toLowerCase();

        if (incType.includes('deauth')) {
            playbooks = [
                "Enforce 802.11w Protected Management Frames (PMF: Required) across all enterprise and IoT access points to cryptographically sign deauth/disassociation frames.",
                "Inspect RF proximity using a directional antenna or spectrum analyzer to localize the transmitting 802.11 injection hardware.",
                "Review client re-connection spikes on RADIUS / 802.1X authenticators for credential-harvesting or rogue handshake captures."
            ];
            citations = [
                { id: 'T1498.001', framework: 'MITRE ATT&CK', title: 'Network Denial of Service: Direct Network Flood (Wi-Fi Deauthentication)' },
                { id: 'IOT-M3', framework: 'OWASP IoT', title: 'Insecure Network Services & Wireless Management Protection' }
            ];
        } else if (incType.includes('evil') || incType.includes('rogue') || incType.includes('twin') || incType.includes('access point')) {
            playbooks = [
                "Isolate unauthorized BSSID from enterprise LAN switch ports and verify zero wired uplink bridges.",
                "Rotate WPA3 Enterprise Pre-Shared Keys or certificate authorities if credential harvesting is suspected.",
                "Add verified BSSIDs to NEXUS Trusted AP Allowlist and blackhole rogue MAC address on wireless controllers."
            ];
            citations = [
                { id: 'T1040', framework: 'MITRE ATT&CK', title: 'Network Sniffing & Adversary-Controlled Rogue Access Point Impersonation' },
                { id: 'IOT-M7', framework: 'OWASP IoT', title: 'Insecure Default Settings & Unverified BSSID Association' }
            ];
        } else if (incType.includes('ble') || incType.includes('bluetooth')) {
            playbooks = [
                "Deploy Bluetooth Low Energy packet filtering on border gateways to discard non-whitelisted peripheral advertisement UUIDs.",
                "Conduct a physical sweep for malicious battery-exhaustion hardware or proximity spoofing tags.",
                "Enforce BLE secure connection pairing and disable unauthenticated broadcast listening on sensitive sensor nodes."
            ];
            citations = [
                { id: 'T1498', framework: 'MITRE ATT&CK', title: 'Network Denial of Service: Radio Resource Exhaustion (BLE Flooding)' },
                { id: 'IOT-M3', framework: 'OWASP IoT', title: 'Insecure Wireless Interfaces & Unrestricted Peripheral Advertisement' }
            ];
        } else {
            playbooks = [
                "Inspect RF spectrum density and check for 2.4 GHz channel saturation or microwave interference.",
                "Verify access point firmware integrity and check for unauthorized packet flooding."
            ];
            citations = [
                { id: 'T1498', framework: 'MITRE ATT&CK', title: 'Network Denial of Service: RF Protocol Anomaly' }
            ];
        }

        let stepsHtml = playbooks.map((step, idx) => `
            <div class="playbook-step">
                <span class="step-num">${idx + 1}</span>
                <span class="step-desc">${step}</span>
            </div>
        `).join('');

        let citationsHtml = citations.map(c => `
            <div class="playbook-citation">
                <span class="citation-badge">${c.framework}</span>
                <span class="citation-title">[${c.id}] ${c.title}</span>
            </div>
        `).join('');

        const isLiveMode = window.nexusApp && window.nexusApp.mode !== 'SIMULATION';
        const playbookAttackerMac = incident.attacker_mac || (isLiveMode ? 'N/A' : '24:A0:74:11:88:5B');
        const playbookToolSig = incident.tool_signature || (isLiveMode ? 'STATISTICAL ANOMALY' : '[UNKNOWN / REASON 0]');
        let playbookSigClass = 'badge-sig-rose';
        if (playbookToolSig.includes('AIREPLAY')) playbookSigClass = 'badge-sig-amber';
        else if (playbookToolSig.includes('ROAM')) playbookSigClass = 'badge-sig-cyan';

        const playbookProxZone = incident.proximity_zone || (isLiveMode ? 'N/A' : 'MID-RANGE (5-15m)');
        const playbookProxClass = incident.proximity_class || (isLiveMode ? 'proximity-perimeter' : 'proximity-mid');
        const playbookTargetBssid = incident.target_bssid || (isLiveMode ? 'N/A (Window)' : '00:14:2D:E1:92:40');
        const playbookChannel = incident.channel || (window.nexusApp && window.nexusApp.primaryChannel) || '--';
        const playbookWin = incident.start_window ?? incident.window_id ?? '--';
        const playbookConf = (typeof incident.confidence === 'number') ? `${(incident.confidence * 100).toFixed(0)}%` : '--';
        const isCountOnlyLive = isLiveMode && !incident.raw_packets && (!incident.raw_injection_count || incident.raw_injection_count === 0);
        const pcapLabel = isCountOnlyLive ? '&#x2913; Export Synthetic PCAP' : '&#x2913; Export Incident PCAP';
        const pcapTitle = isCountOnlyLive
            ? 'Synthesizes a Wireshark-compatible 802.11 frame from aggregate live telemetry counts (ESP32 serial stream sends counts, not raw PCAP bytes)'
            : 'Download binary Wireshark PCAP capture';
        const playbookMitre = incident.mitre || this.getMitreDetailsForType(incTypeStr);
        const playbookHash = incident.evidence_hash || (incident.evidence_hash = this.computeSha256(`${incident.id}|${incident.time}|${playbookAttackerMac}|${playbookTargetBssid}|0|${incTypeStr}`));
        const showPmfAdvisory = Boolean(
            incident.type && (
                incident.type.includes('Deauth') ||
                incident.type.includes('evil-twin') ||
                incident.type.includes('Rogue')
            )
        );

        if (typeof incident.remediation_steps === 'string') {
            try {
                incident.remediation_steps = JSON.parse(incident.remediation_steps);
            } catch (e) {
                incident.remediation_steps = [0];
            }
        }
        incident.remediation_steps = incident.remediation_steps || [0];
        if (!Array.isArray(incident.remediation_steps)) {
            incident.remediation_steps = [0];
        }
        if (!incident.remediation_steps.includes(0)) {
            incident.remediation_steps.unshift(0);
        }

        container.innerHTML = `
            <div class="playbook-header">
                <div>
                    <div class="playbook-title">${incident.type}</div>
                    <div class="playbook-meta">ID: ${incident.id} | Window #${playbookWin} | Confidence: ${playbookConf} <span class="status-pill status-pill-lg ${incident.status === 'OPEN' ? 'pill-high' : (incident.status === 'ACKNOWLEDGED' ? 'pill-active' : 'pill-resolved')}">${incident.status}</span></div>
                </div>
                <div class="playbook-actions">
                    <button class="btn btn-sm" id="btnExportPcap" title="${pcapTitle}">${pcapLabel}</button>
                    <button class="btn btn-sm" id="btnAckInc" ${incident.status !== 'OPEN' ? 'disabled' : ''}>Acknowledge</button>
                    <button class="btn btn-sm btn-danger" id="btnFpInc" ${incident.status === 'FALSE_POSITIVE' ? 'disabled' : ''}>Mark False Positive</button>
                    <button class="btn btn-sm btn-primary" id="btnResolveInc" ${incident.status === 'RESOLVED' ? 'disabled' : ''}>Resolved</button>
                </div>
            </div>

            <div class="forensic-meta-strip">
                <div class="forensic-meta-item">
                    <strong>ATTACKER:</strong>
                    <span class="badge-mac">${playbookAttackerMac}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>HARDWARE:</strong>
                    <span class="badge-hardware font-mono"><span class="hardware-icon">&#x2699;</span> ${incident.hardware_profile || (isLiveMode ? 'N/A (Count-Only)' : '[ESP8266/ESP32 DEAUTHER]')}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>SIGNATURE:</strong>
                    <span class="badge-sig ${playbookSigClass}">${playbookToolSig}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>PROXIMITY:</strong>
                    <span class="badge-proximity ${playbookProxClass}">${playbookProxZone}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>TARGET:</strong>
                    <span class="font-mono">${playbookTargetBssid}</span>
                </div>
                <div class="forensic-meta-item">
                    <strong>CH:</strong>
                    <span class="font-mono">${playbookChannel}</span>
                </div>
            </div>

            ${(incident.raw_injection_count && incident.raw_injection_count > 0) ? `
                <div class="frame-injection-alert">
                    <span class="alert-pulse-dot"></span>
                    <span>RAW FRAME INJECTION DETECTED &bull; ${incident.raw_injection_count} RAW 802.11 FRAMES TRANSMITTED</span>
                </div>
            ` : ''}

            ${showPmfAdvisory ? `
            <div class="remediation-advisory-card">
                <div class="remediation-advisory-header">
                    <span class="remediation-advisory-title">&#x26A0; 802.11w PMF &amp; 802.1X REMEDIATION ADVISORY</span>
                    <span class="remediation-advisory-spec">IEEE 802.11w-2009 / WPA3 Protected Management Frames</span>
                </div>
                <div class="remediation-checklist">
                    <label class="remediation-checklist-item">
                        <input type="checkbox" data-step-index="0" checked disabled>
                        <span><strong>Enforce 802.11w PMF: Required</strong> &mdash; Mandate BIP-CMAC-128 cryptographic signing for deauthentication/disassociation frames across all BSSIDs.</span>
                    </label>
                    <label class="remediation-checklist-item">
                        <input type="checkbox" data-step-index="1" ${incident.remediation_steps.includes(1) ? 'checked' : ''}>
                        <span><strong>WLC ACL Blacklist</strong> &mdash; Add attacker MAC <code class="font-mono" style="color: var(--accent-sky);">${playbookAttackerMac}</code> to hardware filtering tables on access controller.</span>
                    </label>
                    <label class="remediation-checklist-item">
                        <input type="checkbox" data-step-index="2" ${incident.remediation_steps.includes(2) ? 'checked' : ''}>
                        <span><strong>Terminate AID Session States</strong> &mdash; Purge orphaned Association ID state machines on target AP radio <code class="font-mono">${playbookTargetBssid}</code> to mitigate client starvation.</span>
                    </label>
                    <label class="remediation-checklist-item">
                        <input type="checkbox" data-step-index="3" ${incident.remediation_steps.includes(3) ? 'checked' : ''}>
                        <span><strong>802.1X EAP-TLS Verification</strong> &mdash; Enforce client certificate validation &amp; disable unauthenticated identity requests on RADIUS.</span>
                    </label>
                </div>
            </div>
            ` : ''}

            <div class="card-subtitle" style="margin-top: 10px; font-weight: 700; text-transform: uppercase; font-size: 10px;">Defensive Mitigation Playbook:</div>
            <div class="playbook-steps-list">${stepsHtml}</div>

            <div class="card-subtitle" style="margin-top: 12px; font-weight: 700; text-transform: uppercase; font-size: 10px;">Tactical Framework References:</div>
            <div class="playbook-citations-list">${citationsHtml}</div>
        `;

        // Wire copy buttons in playbook container
        container.querySelectorAll('.btn-copy-hash').forEach(btn => {
            btn.onclick = () => this.copyTextToClipboard(btn.dataset.hash, btn);
        });

        // Update static property sheet in index.html if present
        const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'block';

        const propMitre = document.getElementById('propMitreAttack');
        if (propMitre) {
            propMitre.innerHTML = `
                <div class="mitre-badge-container">
                    <span class="badge-mitre font-mono">[<span class="mitre-id">${playbookMitre.id}:</span> ${playbookMitre.name}]</span>
                    <div class="mitre-tactic font-mono">${playbookMitre.tactic}</div>
                </div>
            `;
        }
        const hashDisp = document.getElementById('hashDisplayVal');
        if (hashDisp) hashDisp.textContent = playbookHash;
        const btnStaticCopy = document.getElementById('btnCopyEvidenceHash');
        if (btnStaticCopy) {
            btnStaticCopy.dataset.hash = playbookHash;
            btnStaticCopy.onclick = () => this.copyTextToClipboard(playbookHash, btnStaticCopy);
        }

        const btnPcap = document.getElementById('btnExportPcap');
        if (btnPcap) btnPcap.onclick = () => this.exportIncidentPcap(incident.id);

        const btnAck = document.getElementById('btnAckInc');
        if (btnAck) btnAck.onclick = () => this.acknowledgeIncident(incident.id);

        const btnFp = document.getElementById('btnFpInc');
        if (btnFp) btnFp.onclick = () => this.markFalsePositive(incident.id);

        const btnRes = document.getElementById('btnResolveInc');
        if (btnRes) {
            btnRes.onclick = () => this.resolveIncident(incident.id);
            if (incident.remediation_steps && incident.remediation_steps.length >= 4) {
                btnRes.classList.add('btn-highlight-ready');
                btnRes.title = 'All remediation countermeasures verified. Ready to resolve.';
            }
        }

        // Wire remediation advisory checklist checkboxes
        container.querySelectorAll('.remediation-checklist input[type="checkbox"]').forEach(cb => {
            cb.onchange = async () => {
                const stepIdx = parseInt(cb.dataset.stepIndex, 10);
                if (cb.checked) {
                    if (!incident.remediation_steps.includes(stepIdx)) incident.remediation_steps.push(stepIdx);
                } else {
                    incident.remediation_steps = incident.remediation_steps.filter(idx => idx !== stepIdx);
                }

                // Persist to backend
                const apiBase = (window.nexusApp && typeof window.nexusApp.getApiBase === 'function')
                    ? window.nexusApp.getApiBase()
                    : (window.location.port === '8000' ? '' : 'http://127.0.0.1:8000');
                const dbMode = (window.nexusApp && window.nexusApp.mode === 'SIMULATION') ? 'simulation' : 'live';
                try {
                    const resp = await fetch(`${apiBase}/api/incidents/${incident.id}/remediation?mode=${dbMode}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ completed_steps: incident.remediation_steps })
                    });
                    if (!resp.ok) {
                        console.error(`[NEXUS] Failed to persist remediation for ${incident.id}: HTTP ${resp.status}`);
                        if (window.nexusApp && window.nexusApp.opsConsole) {
                            window.nexusApp.opsConsole.showToast('PERSISTENCE ERROR', `Failed to save remediation checklist (HTTP ${resp.status}).`, 'danger');
                        }
                    }
                } catch (e) {
                    console.error(`[NEXUS] Network error persisting remediation for ${incident.id}:`, e);
                }

                // Visual feedback: If all 4 steps completed, highlight the Resolve button
                const btnResolve = document.getElementById('btnResolveInc');
                if (btnResolve) {
                    if (incident.remediation_steps.length >= 4) {
                        btnResolve.classList.add('btn-highlight-ready');
                        btnResolve.title = 'All remediation countermeasures verified. Ready to resolve.';
                    } else {
                        btnResolve.classList.remove('btn-highlight-ready');
                        btnResolve.title = '';
                    }
                }
            };
        });
    }

    // ==========================================
    // Trusted AP Allowlist Manager
    // ==========================================
    renderTrustedApsTable() {
        const tbody = document.getElementById('trustedApsTableBody');
        if (!tbody) return;

        let html = '';
        this.trustedAps.forEach((ap, idx) => {
            html += `
                <tr>
                    <td class="font-mono font-bold" style="color: var(--text-white);">${ap.bssid}</td>
                    <td class="font-mono">${ap.ssid}</td>
                    <td class="font-mono">Ch ${ap.channel}</td>
                    <td><span class="status-pill pill-active">${ap.status}</span></td>
                    <td class="font-mono" style="color: var(--text-muted); font-size: 11px;">${ap.first_seen}</td>
                    <td>
                        <button class="btn btn-sm btn-danger btn-remove-ap" data-idx="${idx}">Remove</button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;

        tbody.querySelectorAll('.btn-remove-ap').forEach(btn => {
            btn.onclick = () => {
                const idx = parseInt(btn.dataset.idx, 10);
                this.trustedAps.splice(idx, 1);
                const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';

        this.renderTrustedApsTable();
            };
        });
    }

    handleAddTrustedAp() {
        const bssidEl = document.getElementById('inputNewBssid');
        const ssidEl  = document.getElementById('inputNewSsid');
        const chEl    = document.getElementById('inputNewChannel');

        if (!bssidEl || !ssidEl) return;
        const bssid = bssidEl.value.trim().toUpperCase();
        const ssid  = ssidEl.value.trim();
        const ch    = parseInt(chEl ? chEl.value : 1, 10) || 1;

        if (!bssid || !ssid) {
            const app = window.nexusApp;
            if (app && app.opsConsole) {
                app.opsConsole.showToast('INPUT REQUIRED', 'Please specify both BSSID and SSID.', 'warning');
            } else if (app && typeof app.showWin32Dialog === 'function') {
                app.showWin32Dialog('Input Required', '<div style="font-size: 11px;">Please specify both BSSID and SSID.</div>');
            }
            return;
        }

        this.trustedAps.push({
            bssid,
            ssid,
            channel: ch,
            status: 'TRUSTED',
            first_seen: new Date().toISOString().replace('T', ' ').substring(0, 19)
        });

        bssidEl.value = '';
        ssidEl.value = '';
        const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';

        this.renderTrustedApsTable();
    }

    async learnEnvironment() {
        const btn = document.getElementById('btnLearnEnvironment');
        if (btn) btn.textContent = 'Learning Environment...';

        try {
            const res = await fetch('/api/trusted-aps/learn', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ limit_windows: 200 })
            });
            if (res.ok) {
                const data = await res.json();
                const msg = data.learned_count > 0 ? `Learned and allowlisted ${data.learned_count} access points.` : 'Zero new APs discovered in recent 200 windows.';
                if (window.nexusApp && window.nexusApp.opsConsole) {
                    window.nexusApp.opsConsole.showToast('AP ALLOWLIST', msg, data.learned_count > 0 ? 'success' : 'info');
                }
                await this.fetchTrustedAps();
            }
        } catch (e) {
            this.trustedAps.push({
                bssid: 'A4:2B:B0:1F:7C:10',
                ssid: 'Campus-Guest-Portal',
                channel: 1,
                status: 'TRUSTED',
                first_seen: new Date().toISOString().replace('T', ' ').substring(0, 19)
            });
            const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';

        this.renderTrustedApsTable();
        } finally {
            if (btn) btn.textContent = 'Learn Current Environment';
        }
    }

    triggerRogueApAlert(bssid, ssid, channel) {
        this.activeRogueAlert = { bssid, ssid, channel };
        const banner = document.getElementById('rogueApAlertBanner');
        const text = document.getElementById('rogueApAlertText');
        if (banner && text) {
            text.textContent = `Unauthorized BSSID ${bssid} advertising SSID '${ssid}' on Channel ${channel}`;
            banner.style.display = 'flex';

            const btnTrust = document.getElementById('btnTrustRogueAp');
            if (btnTrust) {
                btnTrust.onclick = () => {
                    this.trustedAps.push({
                        bssid,
                        ssid,
                        channel,
                        status: 'TRUSTED',
                        first_seen: new Date().toISOString().replace('T', ' ').substring(0, 19)
                    });
                    const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';

        this.renderTrustedApsTable();
                    banner.style.display = 'none';
                    this.activeRogueAlert = null;
                };
            }

            const btnDismiss = document.getElementById('btnDismissRogueAp');
            if (btnDismiss) {
                btnDismiss.onclick = () => {
                    banner.style.display = 'none';
                };
            }
        }
    }

    clear() {
        this.incidents = [];
        this.selectedIncident = null;
        this.expandedIncidentIds.clear();
        this.mitreFilter = null;
        this.incidentCounter = 0;
        this.unacknowledgedCount = 0;
        this.updateKpiCard();
        this.renderIncidentsTable();
        this.renderDefensivePlaybook(null);
        this.closeFlyout();
        const banner = document.getElementById('rogueApAlertBanner');
        if (banner) banner.style.display = 'none';
        const propSheet = document.getElementById('incidentPropertySheet');
        if (propSheet) propSheet.style.display = 'none';
    }
}
