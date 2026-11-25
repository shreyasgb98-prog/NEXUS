// NEXUS AI: Workstation Settings & Pragma Manager
// Manages local Ollama configuration, SQLite pragma inspection, telemetry pruning, and detector parameters.

class SettingsManager {
    constructor() {
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        this.initialized = true;

        const btnSaveSettings = document.getElementById('btnSaveSettings');
        if (btnSaveSettings) {
            btnSaveSettings.onclick = () => this.saveSettings();
        }

        const btnTestLlm = document.getElementById('btnTestLlmConnection');
        if (btnTestLlm) {
            btnTestLlm.onclick = () => this.testLlmEndpoint();
        }

        this.loadSettings();
    }

    async loadSettings() {
        // Dynamic Database Pragmas inspection
        try {
            const res = await fetch('/api/database/status');
            if (res.ok) {
                const data = await res.json();
                const inJournal = document.getElementById('inputSqliteJournal');
                const inSync = document.getElementById('inputSqliteSync');
                const inDbSize = document.getElementById('inputSqliteDbSize');

                if (inJournal && data.journal_mode) {
                    inJournal.value = `WAL Mode (PRAGMA journal_mode=${data.journal_mode.toUpperCase()})`;
                }
                if (inSync && data.synchronous !== undefined) {
                    inSync.value = `${data.synchronous.toUpperCase()} (PRAGMA synchronous=${data.synchronous})`;
                }
                if (inDbSize && data.size_bytes !== undefined) {
                    inDbSize.value = `${data.size_bytes.toLocaleString()} bytes (${(data.size_bytes / 1024).toFixed(1)} KB)`;
                }
            }
        } catch (e) {
            // Standalone fallback
        }

        // Load local preferences
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
                if (s.alpha && inAlpha) inAlpha.value = s.alpha;
                if (s.zScore && inZ) inZ.value = s.zScore;
                if (s.fixedThreshold && inFixed) inFixed.value = s.fixedThreshold;
                if (s.warmup && inWarmup) inWarmup.value = s.warmup;
            }
        } catch (e) {
            // Standalone fallback
        }
    }

    async saveSettings() {
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
        const alpha = inAlpha ? parseFloat(inAlpha.value) || 0.12 : 0.12;
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
            // Standalone fallback
        }

        // Send POST /api/settings with updated detector parameters
        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    alpha: alpha,
                    z_threshold: zScore,
                    warmup_windows: warmup,
                    fixed_threshold: fixedThreshold
                })
            });
        } catch (e) {
            // Standalone fallback
        }

        // If prune days changed, dispatch POST /api/telemetry/prune
        if (prevPruneDays !== null && prevPruneDays !== pruneDays) {
            const retentionHours = (parseInt(pruneDays, 10) || 7) * 24;
            try {
                await fetch('/api/telemetry/prune', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Nexus-Key': apiKey || 'nexus-local-dev-token'
                    },
                    body: JSON.stringify({ retention_hours: retentionHours })
                });
            } catch (e) {
                // Standalone fallback
            }
        }

        const app = window.nexusApp;
        if (app && app.wazuhConsole) {
            app.wazuhConsole.showToast('SETTINGS SAVED', 'Local Ollama endpoint, model parameters, and retention policies updated.', 'success', 4000);
        }
    }

    async testLlmEndpoint() {
        const btn = document.getElementById('btnTestLlmConnection');
        const inUrl = document.getElementById('inputLlmUrl');
        const inModel = document.getElementById('inputLlmModel');
        const inKey = document.getElementById('inputApiKey');

        const statusContainer = document.getElementById('llmStatusContainer');
        const statusText = document.getElementById('llmStatusText');

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
                    base_url: endpointUrl,
                    endpoint_url: endpointUrl,
                    model: model,
                    api_key: apiKey
                })
            });

            const data = await resp.json();
            if (statusContainer) statusContainer.style.display = 'block';

            if (data.status === 'online') {
                const latency = data.latency_ms || 0;
                let color = '#22c55e'; // Green if < 100ms
                if (latency >= 500) {
                    color = '#ef4444'; // Red if >= 500ms
                } else if (latency >= 100) {
                    color = '#f59e0b'; // Amber if < 500ms
                }

                if (statusText) {
                    statusText.style.color = color;
                    statusText.textContent = `ONLINE: ${latency}ms latency | Model '${model}': ${data.model_found ? 'READY' : 'NOT FOUND'}`;
                }

                if (btn) {
                    btn.textContent = `ONLINE (${latency}ms)`;
                    btn.style.color = color;
                    btn.style.borderColor = color;
                }

                const app = window.nexusApp;
                if (app && app.wazuhConsole) {
                    app.wazuhConsole.showToast('ENDPOINT ONLINE', `Ollama Online (${latency}ms) | Model '${model}' ${data.model_found ? 'Ready' : 'Not Loaded'}`, 'success');
                }
            } else {
                const errStr = data.error || 'Connection refused';
                if (statusText) {
                    statusText.style.color = '#ef4444';
                    statusText.textContent = `OFFLINE: ${errStr}`;
                }
                if (btn) {
                    btn.textContent = 'OFFLINE / FAILED';
                    btn.style.color = '#ef4444';
                    btn.style.borderColor = '#ef4444';
                }
                const app = window.nexusApp;
                if (app && app.wazuhConsole) {
                    app.wazuhConsole.showToast('ENDPOINT OFFLINE', `Ollama Offline: ${errStr}`, 'danger');
                }
            }
        } catch (err) {
            const errStr = err.message || 'Connection refused';
            if (statusContainer) statusContainer.style.display = 'block';
            if (statusText) {
                statusText.style.color = '#ef4444';
                statusText.textContent = `OFFLINE: ${errStr}`;
            }
            if (btn) {
                btn.textContent = 'OFFLINE / FAILED';
                btn.style.color = '#ef4444';
                btn.style.borderColor = '#ef4444';
            }
            const app = window.nexusApp;
            if (app && app.wazuhConsole) {
                app.wazuhConsole.showToast('ENDPOINT OFFLINE', `Ollama Offline: ${errStr}`, 'danger');
            }
        } finally {
            if (btn) {
                btn.disabled = false;
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.color = '';
                    btn.style.borderColor = '';
                }, 5000);
            }
        }
    }
}

// Global instance
window.SettingsManager = SettingsManager;
