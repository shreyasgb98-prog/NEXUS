// NEXUS AI: Empirical Benchmark & Ablation Study Evaluation Module
// Fetches live detector benchmark curves and architectural ablation performance from SQLite telemetry.

class EvaluationManager {
    constructor() {
        this.initialized = false;
    }

    init() {
        if (this.initialized) return;
        this.initialized = true;

        const btnRunSweep = document.getElementById('btnRunSweep');
        if (btnRunSweep) {
            btnRunSweep.onclick = () => {
                const app = window.nexusApp;
                if (app && typeof app.renderThresholdSweepChart === 'function') {
                    app.renderThresholdSweepChart();
                }
                this.loadAblationTable();
                if (app && app.opsConsole) {
                    app.opsConsole.showToast('SWEEP COMPUTED', 'Empirical threshold sweep completed across Z = 2.0σ to 5.0σ.', 'success', 4000);
                }
            };
        }

        this.loadAblationTable();
    }

    getApiContext() {
        const app = window.nexusApp;
        const apiBase = (app && typeof app.getApiBase === 'function')
            ? app.getApiBase()
            : (window.location.port === '8000' ? '' : 'http://127.0.0.1:8000');
        const dbMode = (app && app.mode === 'SIMULATION') ? 'simulation' : 'live';
        return { apiBase, dbMode };
    }

    async loadAblationTable() {
        try {
            const { apiBase, dbMode } = this.getApiContext();
            const resp = await fetch(`${apiBase}/api/evaluation/ablation?mode=${dbMode}`);
            if (!resp.ok) return;
            const data = await resp.json();
            const cfgs = data.configurations || {};

            const c1 = cfgs.config_1_fixed_threshold;
            const c2 = cfgs.config_2_adaptive_no_freeze;
            const c3 = cfgs.config_3_adaptive_with_freeze;
            const c4 = cfgs.config_4_nexus_complete;

            const setVal = (id, val) => {
                const el = document.getElementById(id);
                if (el && typeof val === 'number') el.textContent = val.toFixed(2);
            };

            if (c1) {
                setVal('ablFixedF1', c1.f1);
                setVal('ablFixedFpr', c1.fpr);
            }
            if (c2) {
                setVal('ablNoFreezeF1', c2.f1);
                setVal('ablNoFreezeFpr', c2.fpr);
            }
            if (c3) {
                setVal('ablFreezeF1', c3.f1);
                setVal('ablFreezeFpr', c3.fpr);
            }
            if (c4) {
                setVal('ablFullF1', c4.f1);
                setVal('ablNexusF1', c4.f1);
                setVal('ablNexusFpr', c4.fpr);
            }
        } catch (e) {
            // Standalone fallback
        }
    }

    async fetchThresholdSweep() {
        try {
            const { apiBase, dbMode } = this.getApiContext();
            const resp = await fetch(`${apiBase}/api/evaluation/threshold-sweep?mode=${dbMode}`);
            if (!resp.ok) return null;
            return await resp.json();
        } catch (e) {
            return null;
        }
    }
}

// Global instance
window.EvaluationManager = EvaluationManager;
