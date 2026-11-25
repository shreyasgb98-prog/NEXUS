// NEXUS AI: Telemetry Table Manager (SnowUI Style)
// Formats high-density stream logs, manages tabbed views (Incidents, Trusted APs, Telemetry Log),
// and updates the detector comparison benchmark table.

class TelemetryTableManager {
    constructor(config) {
        this.telemetryTbody = document.getElementById(config.telemetryTbodyId);
        this.alertsTbody = document.getElementById(config.alertsTbodyId);
        this.evidenceContainer = document.getElementById(config.evidenceContainerId);
        this.explanationContainer = document.getElementById(config.explanationContainerId);
        this.eventTagElement = document.getElementById(config.eventTagId);
        this.comparisonTbody = document.getElementById(config.comparisonTbodyId);
        this.evalFootnote = document.getElementById(config.evalFootnoteId);

        this.maxTelemetryRows = 500;
        this.alerts = [];
        this.selectedAlert = null;
        this.windowFilterStart = null;
        this.windowFilterEnd = null;

        this.initTableTabs();
    }

    initTableTabs() {
        const tabTrustedAps = document.getElementById('tabShowTrustedAps');
        const tabTelemetry = document.getElementById('tabShowTelemetry');
        const tabAlerts = document.getElementById('tabShowAlerts');

        const apsContainer = document.getElementById('trustedApsContainer');
        const telContainer = document.getElementById('telemetryTableContainer');
        const alertsContainer = document.getElementById('alertsTableContainer');

        const activateTab = (activeTab, showContainer) => {
            [tabTrustedAps, tabTelemetry, tabAlerts].forEach(t => {
                if (t) t.classList.remove('active');
            });
            [apsContainer, telContainer, alertsContainer].forEach(c => {
                if (c) c.style.display = 'none';
            });
            if (activeTab) activeTab.classList.add('active');
            if (showContainer) showContainer.style.display = 'block';
        };

        if (tabTrustedAps) {
            tabTrustedAps.onclick = () => activateTab(tabTrustedAps, apsContainer);
        }
        if (tabTelemetry) {
            tabTelemetry.onclick = () => activateTab(tabTelemetry, telContainer);
        }
        if (tabAlerts) {
            tabAlerts.onclick = () => activateTab(tabAlerts, alertsContainer);
        }
    }

    setWindowFilter(startWin, endWin) {
        this.windowFilterStart = (startWin !== undefined && startWin !== null) ? startWin : null;
        this.windowFilterEnd = (endWin !== undefined && endWin !== null) ? endWin : null;

        if (!this.telemetryTbody) return;
        const hasFilter = (this.windowFilterStart !== null && this.windowFilterEnd !== null);
        Array.from(this.telemetryTbody.children).forEach(tr => {
            const winId = parseInt(tr.dataset.windowId, 10);
            if (!hasFilter || isNaN(winId)) {
                tr.style.display = '';
            } else {
                tr.style.display = (winId >= this.windowFilterStart && winId <= this.windowFilterEnd) ? '' : 'none';
            }
        });
    }

    addTelemetryRow(row) {
        if (!this.telemetryTbody) return;
        const tr = document.createElement('tr');
        tr.dataset.windowId = row.window_id;

        if (this.windowFilterStart !== null && this.windowFilterEnd !== null) {
            const winId = row.window_id;
            if (winId < this.windowFilterStart || winId > this.windowFilterEnd) {
                tr.style.display = 'none';
            }
        }

        const isAnomaly = row.z_score >= 3.5 || row.state.includes('ANOMALY');
        const zSign = row.z_score >= 0 ? '+' : '';

        let pillClass = 'pill-active';
        if (row.state.includes('WARMUP')) pillClass = 'pill-warmup';
        else if (isAnomaly) pillClass = 'pill-high';

        tr.innerHTML = `
            <td class="font-mono">#${String(row.window_id).padStart(5, '0')}</td>
            <td class="font-mono">${row.rssi} dBm</td>
            <td class="font-mono ${isAnomaly ? 'text-rose font-bold' : ''}">${zSign}${row.z_score.toFixed(2)} &sigma;</td>
            <td class="font-mono">${row.deauth_rate} /win</td>
            <td><span class="status-pill ${pillClass}">${row.state}</span></td>
        `;

        this.telemetryTbody.insertBefore(tr, this.telemetryTbody.firstChild);
        while (this.telemetryTbody.children.length > this.maxTelemetryRows) {
            this.telemetryTbody.removeChild(this.telemetryTbody.lastChild);
        }
    }

    addAlertEvent(alertRecord) {
        if (!this.alertsTbody) return;
        this.alerts.unshift(alertRecord);
        const tr = document.createElement('tr');

        let sevClass = 'pill-low';
        if (alertRecord.severity === 'high') sevClass = 'pill-high';
        else if (alertRecord.severity === 'medium') sevClass = 'pill-medium';

        tr.innerHTML = `
            <td class="font-mono">#${alertRecord.window}</td>
            <td style="font-weight: 500; color: var(--text-white);">${alertRecord.type}</td>
            <td><span class="status-pill ${sevClass}">${alertRecord.severity.toUpperCase()}</span></td>
            <td class="font-mono">${alertRecord.confidence.toFixed(2)}</td>
        `;

        tr.onclick = () => {
            Array.from(this.alertsTbody.children).forEach(c => c.classList.remove('selected'));
            tr.classList.add('selected');
            this.displayEvidence(alertRecord);
        };

        this.alertsTbody.insertBefore(tr, this.alertsTbody.firstChild);
        tr.classList.add('selected');
        this.displayEvidence(alertRecord);
    }

    displayEvidence(alertRecord) {
        this.selectedAlert = alertRecord;

        if (this.eventTagElement) {
            let sevClass = 'pill-low';
            if (alertRecord.severity === 'high') sevClass = 'pill-high';
            else if (alertRecord.severity === 'medium') sevClass = 'pill-medium';

            this.eventTagElement.className = `status-pill ${sevClass}`;
            this.eventTagElement.textContent = `${alertRecord.id} | [${alertRecord.severity.toUpperCase()}] CONF: ${alertRecord.confidence.toFixed(2)}`;
        }

        const { explanation, ...rawEvidence } = alertRecord;

        if (this.evidenceContainer) {
            this.evidenceContainer.textContent = JSON.stringify(rawEvidence, null, 2);
        }

        if (this.explanationContainer) {
            this.explanationContainer.textContent = explanation || '// No local anomaly explanation generated.';
        }
    }

    updateDetectorComparison(metrics) {
        if (!this.comparisonTbody) return;

        const formatMetric = (val) => (typeof val === 'number' && !isNaN(val)) ? val.toFixed(2) : '--';
        const formatLatency = (val) => (typeof val === 'number' && !isNaN(val)) ? val.toFixed(1) : '--';

        const detectors = [
            { key: 'fixed', name: 'Fixed (deauth \u2265 5)' },
            { key: 'adaptive', name: 'Adaptive (z > 3.5\u03C3)' },
            { key: 'nexus', name: 'NEXUS (adaptive + corr)' }
        ];

        let html = '';
        for (const det of detectors) {
            const m = metrics[det.key] || {};
            html += `
                <tr>
                    <td style="font-weight: 500;">${det.name}</td>
                    <td class="font-mono">${formatMetric(m.precision)}</td>
                    <td class="font-mono">${formatMetric(m.recall)}</td>
                    <td class="font-mono">${formatMetric(m.f1)}</td>
                    <td class="font-mono">${formatMetric(m.fpr)}</td>
                    <td class="font-mono">${m.attacks_caught || 0}/${m.total_attacks || 0}</td>
                    <td class="font-mono">${formatLatency(m.latency)}</td>
                </tr>
            `;
        }
        this.comparisonTbody.innerHTML = html;

        if (this.evalFootnote) {
            this.evalFootnote.textContent = `Evaluated windows after warm-up: ${metrics.evaluated_windows || 0} | Labelled attack windows: ${metrics.labelled_attack_windows || 0}`;
        }
    }

    clear() {
        if (this.telemetryTbody) this.telemetryTbody.innerHTML = '';
        if (this.alertsTbody) this.alertsTbody.innerHTML = '';
        if (this.evidenceContainer) this.evidenceContainer.textContent = '// No alert selected';
        if (this.explanationContainer) this.explanationContainer.textContent = '// No alert selected';
        if (this.eventTagElement) {
            this.eventTagElement.className = 'status-pill pill-low';
            this.eventTagElement.textContent = 'EV-NONE';
        }
        this.alerts = [];
        this.selectedAlert = null;
    }
}
