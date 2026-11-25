// NEXUS AI: Wazuh-Style SIEM Log Explorer
// Reactive filter bar, field sidebar, mini-histogram, and expandable document rows
// for high-density telemetry window inspection.

class SIEMLogExplorer {
    constructor() {
        this.allWindows = [];
        this.activeFilters = [];
        // Default visible columns
        this.activeFields = new Set(['window_id', 'data_source', 'deauth', 'mgmt', 'ble', 'z_deauth', 'flag_nexus', 'is_attack_labelled']);
        this.expandedRows = new Set();

        this.FIELD_DEFS = [
            { key: 'window_id',          label: 'window_id',          type: '#' },
            { key: 'epoch_ms',           label: 'epoch_ms',           type: '#' },
            { key: 'data_source',        label: 'data_source',        type: 't' },
            { key: 'deauth',             label: 'deauth',             type: '#' },
            { key: 'mgmt',               label: 'mgmt',               type: '#' },
            { key: 'ble',                label: 'ble',                type: '#' },
            { key: 'rogue',              label: 'rogue',              type: '#' },
            { key: 'nfc',                label: 'nfc',                type: '#' },
            { key: 'rssi',               label: 'rssi',               type: '#' },
            { key: 'z_deauth',           label: 'z_deauth',           type: '#' },
            { key: 'z_mgmt',             label: 'z_mgmt',             type: '#' },
            { key: 'z_ble',              label: 'z_ble',              type: '#' },
            { key: 'z_rogue',            label: 'z_rogue',            type: '#' },
            { key: 'flag_nexus',         label: 'flag_nexus',         type: '#' },
            { key: 'is_attack_labelled', label: 'is_attack_labelled', type: '#' },
        ];

        this._initialized = false;
    }

    // Called once when the Telemetry tab is first shown or on first ingest
    _ensureDOM() {
        const container = document.getElementById('telemetryTableContainer');
        if (!container || this._initialized) return;
        this._initialized = true;

        container.innerHTML = `
            <div class="siem-filter-bar">
                <input id="siemFilterInput" type="text" class="siem-filter-input" placeholder="Filter: severity:high  deauth > 0  source:live" autocomplete="off">
                <button id="siemFilterApply" class="btn">Apply</button>
                <div id="siemFilterChips" class="siem-chips"></div>
            </div>
            <div class="siem-layout">
                <div class="siem-field-sidebar" id="siemFieldSidebar">
                    <div class="siem-sidebar-header">Available Fields</div>
                    <div id="siemFieldList"></div>
                </div>
                <div class="siem-main">
                    <canvas id="siemHistogramCanvas" class="siem-histogram" height="50"></canvas>
                    <div class="siem-log-scroll">
                        <table class="data-table siem-log-table">
                            <thead id="siemLogHead"></thead>
                            <tbody id="siemLogBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('siemFilterApply').onclick = () => this._applyFilterInput();
        document.getElementById('siemFilterInput').onkeydown = (e) => {
            if (e.key === 'Enter') this._applyFilterInput();
        };

        this.renderFieldSidebar();
        this.refresh();
    }

    // Called by app.js every time a new window record is processed
    ingestWindow(windowRecord) {
        this.allWindows.push(windowRecord);
        // Cap at 500 to keep DOM performance bounded
        if (this.allWindows.length > 500) this.allWindows.shift();
        if (this._initialized) this.refresh();
    }

    // Flat-field extractor handling nested payload/metrics
    getFieldValue(w, key) {
        switch (key) {
            case 'deauth':   return (w.payload && w.payload.deauth  != null) ? w.payload.deauth  : 0;
            case 'mgmt':     return (w.payload && w.payload.mgmt    != null) ? w.payload.mgmt    : 0;
            case 'ble':      return (w.payload && w.payload.ble     != null) ? w.payload.ble     : 0;
            case 'rogue':    return (w.payload && w.payload.rogue   != null) ? w.payload.rogue   : 0;
            case 'nfc':      return (w.payload && w.payload.nfc     != null) ? w.payload.nfc     : 0;
            case 'rssi':     return (w.payload && w.payload.rssi    != null) ? w.payload.rssi    : -70;
            case 'z_deauth': return (w.metrics && w.metrics.deauth) ? w.metrics.deauth.z_score  : 0;
            case 'z_mgmt':   return (w.metrics && w.metrics.mgmt)   ? w.metrics.mgmt.z_score    : 0;
            case 'z_ble':    return (w.metrics && w.metrics.ble)    ? w.metrics.ble.z_score     : 0;
            case 'z_rogue':  return (w.metrics && w.metrics.rogue)  ? w.metrics.rogue.z_score   : 0;
            default:         return w[key] != null ? w[key] : '';
        }
    }

    // Parse a single filter token: "field:value", "field > N", "field < N", "field >= N"
    _parseToken(token) {
        token = token.trim();
        if (!token) return null;

        // Numeric comparisons: field > N, field < N, field >= N, field <= N
        const numMatch = token.match(/^(\w+)\s*(>=|<=|>|<)\s*([\d.\-]+)$/);
        if (numMatch) {
            return { field: numMatch[1], op: numMatch[2], value: parseFloat(numMatch[3]) };
        }

        // Equality / contains: field:value
        const eqMatch = token.match(/^(\w+):(.+)$/);
        if (eqMatch) {
            const rawVal = eqMatch[2];
            const numVal = parseFloat(rawVal);
            return { field: eqMatch[1], op: 'eq', value: isNaN(numVal) ? rawVal : numVal };
        }

        return null;
    }

    _applyFilterInput() {
        const input = document.getElementById('siemFilterInput');
        if (!input) return;
        const raw = input.value.trim();
        if (!raw) return;

        // Support multiple space-separated tokens
        const tokens = raw.split(/\s{2,}|\s+(?=\w+[:><])/).filter(Boolean);
        for (const token of tokens) {
            const filter = this._parseToken(token);
            if (filter) {
                // De-duplicate by field+op+value
                const key = `${filter.field}${filter.op}${filter.value}`;
                if (!this.activeFilters.find(f => `${f.field}${f.op}${f.value}` === key)) {
                    this.activeFilters.push(filter);
                }
            }
        }
        input.value = '';
        this.refresh();
    }

    _matchesFilters(w) {
        for (const f of this.activeFilters) {
            const val = this.getFieldValue(w, f.field);
            if (f.op === 'eq') {
                if (typeof f.value === 'string') {
                    if (!String(val).toLowerCase().includes(f.value.toLowerCase())) return false;
                } else {
                    if (val !== f.value) return false;
                }
            } else if (f.op === '>') {
                if (!(val > f.value)) return false;
            } else if (f.op === '<') {
                if (!(val < f.value)) return false;
            } else if (f.op === '>=') {
                if (!(val >= f.value)) return false;
            } else if (f.op === '<=') {
                if (!(val <= f.value)) return false;
            }
        }
        return true;
    }

    renderFieldSidebar() {
        const list = document.getElementById('siemFieldList');
        if (!list) return;
        let html = '';
        for (const fd of this.FIELD_DEFS) {
            const isActive = this.activeFields.has(fd.key);
            html += `
                <div class="siem-field-item ${isActive ? 'active' : ''}" data-field="${fd.key}" title="Click to toggle column / add filter">
                    <span class="field-type-badge">${fd.type}</span>
                    <span class="siem-field-label">${fd.label}</span>
                </div>
            `;
        }
        list.innerHTML = html;
        list.querySelectorAll('.siem-field-item').forEach(el => {
            el.onclick = () => this._toggleField(el.dataset.field);
        });
    }

    _toggleField(fieldKey) {
        if (this.activeFields.has(fieldKey)) {
            if (this.activeFields.size > 2) this.activeFields.delete(fieldKey);
        } else {
            this.activeFields.add(fieldKey);
        }
        this.renderFieldSidebar();
        this.refresh();
    }

    renderHistogram(windows) {
        const canvas = document.getElementById('siemHistogramCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.offsetWidth || 400;
        const H = 50;
        canvas.width = W;
        canvas.height = H;
        ctx.clearRect(0, 0, W, H);

        const BUCKETS = 20;
        const total = windows.length;
        if (total === 0) return;

        // Split windows into BUCKETS equal-time buckets
        const bucketSize = Math.ceil(total / BUCKETS);
        const counts = [];
        for (let i = 0; i < BUCKETS; i++) {
            const slice = windows.slice(i * bucketSize, (i + 1) * bucketSize);
            counts.push(slice.length);
        }
        const maxCount = Math.max(...counts, 1);

        const barW = (W / BUCKETS) - 2;
        for (let i = 0; i < BUCKETS; i++) {
            const barH = Math.max(2, (counts[i] / maxCount) * (H - 6));
            const x = i * (W / BUCKETS) + 1;
            const y = H - barH - 2;
            ctx.fillStyle = '#38bdf8';
            ctx.globalAlpha = 0.65;
            ctx.fillRect(x, y, barW, barH);
        }
        ctx.globalAlpha = 1.0;
    }

    renderLogTable(filteredWindows) {
        const head = document.getElementById('siemLogHead');
        const body = document.getElementById('siemLogBody');
        if (!head || !body) return;

        const fields = this.FIELD_DEFS.filter(fd => this.activeFields.has(fd.key));

        // Header
        let thHtml = '<tr><th style="width:28px;"></th>';
        for (const fd of fields) {
            thHtml += `<th>${fd.label}</th>`;
        }
        thHtml += '</tr>';
        head.innerHTML = thHtml;

        // Rows — newest first, cap at 100 displayed rows
        const displayRows = filteredWindows.slice(-100).reverse();
        let rowHtml = '';
        for (const w of displayRows) {
            const isAnomaly = w.flag_nexus === 1;
            const rowClass = isAnomaly ? 'siem-row-anomaly' : '';
            rowHtml += `<tr class="${rowClass}" data-wid="${w.window_id}">`;
            rowHtml += `<td><button class="siem-expand-btn" data-wid="${w.window_id}" aria-label="Expand row">&#x25B6;</button></td>`;
            for (const fd of fields) {
                const val = this.getFieldValue(w, fd.key);
                let display = val;
                if (fd.type === '#' && typeof val === 'number') {
                    display = Number.isInteger(val) ? val : val.toFixed(2);
                }
                rowHtml += `<td class="font-mono">${display}</td>`;
            }
            rowHtml += '</tr>';
        }
        body.innerHTML = rowHtml;

        // Attach expand button listeners
        body.querySelectorAll('.siem-expand-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const wid = parseInt(btn.dataset.wid, 10);
                const parentTr = btn.closest('tr');
                this._toggleRowExpand(wid, parentTr, filteredWindows.find(w => w.window_id === wid));
            };
        });
    }

    _toggleRowExpand(windowId, parentTr, windowRecord) {
        const existingExpanded = parentTr.nextSibling;
        if (existingExpanded && existingExpanded.classList && existingExpanded.classList.contains('siem-expanded-row')) {
            existingExpanded.remove();
            this.expandedRows.delete(windowId);
            const btn = parentTr.querySelector('.siem-expand-btn');
            if (btn) btn.innerHTML = '&#x25B6;';
            return;
        }

        this.expandedRows.add(windowId);
        const btn = parentTr.querySelector('.siem-expand-btn');
        if (btn) btn.innerHTML = '&#x25BC;';

        const expandedTr = document.createElement('tr');
        expandedTr.className = 'siem-expanded-row';
        const colCount = parentTr.children.length;
        expandedTr.innerHTML = `<td colspan="${colCount}">${this._buildExpandedDoc(windowRecord)}</td>`;
        parentTr.after(expandedTr);

        // Tab switching inside expanded doc
        expandedTr.querySelectorAll('.siem-doc-tab').forEach(tab => {
            tab.onclick = () => {
                const docEl = expandedTr.querySelector('.siem-expanded-doc');
                docEl.querySelectorAll('.siem-doc-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const pane = tab.dataset.pane;
                docEl.querySelectorAll('.siem-doc-pane').forEach(p => {
                    p.style.display = p.dataset.pane === pane ? 'block' : 'none';
                });
            };
        });
    }

    _buildExpandedDoc(w) {
        if (!w) return '<div class="siem-expanded-doc">No data</div>';

        // Build flat display map
        const flatFields = this.FIELD_DEFS.map(fd => ({
            label: fd.label,
            value: this.getFieldValue(w, fd.key)
        }));

        let tableRows = '';
        for (const f of flatFields) {
            const display = (typeof f.value === 'number' && !Number.isInteger(f.value))
                ? f.value.toFixed(3)
                : f.value;
            tableRows += `<tr><td>${f.label}</td><td>${display}</td></tr>`;
        }

        const jsonStr = JSON.stringify({
            window_id: w.window_id,
            epoch_ms: w.epoch_ms,
            data_source: w.data_source,
            payload: w.payload,
            metrics: w.metrics,
            flags: w.flags,
            is_attack_labelled: w.is_attack_labelled,
            flag_fixed: w.flag_fixed,
            flag_adaptive: w.flag_adaptive,
            flag_nexus: w.flag_nexus
        }, null, 2);

        return `
            <div class="siem-expanded-doc">
                <div class="siem-doc-tabs">
                    <button class="siem-doc-tab active" data-pane="table">Table</button>
                    <button class="siem-doc-tab" data-pane="json">JSON</button>
                </div>
                <div class="siem-doc-pane" data-pane="table" style="display:block;">
                    <table class="siem-doc-table"><tbody>${tableRows}</tbody></table>
                </div>
                <div class="siem-doc-pane" data-pane="json" style="display:none;">
                    <pre class="siem-doc-json">${jsonStr}</pre>
                </div>
            </div>
        `;
    }

    renderFilterChips() {
        const chips = document.getElementById('siemFilterChips');
        if (!chips) return;
        let html = '';
        this.activeFilters.forEach((f, idx) => {
            html += `
                <span class="siem-chip">
                    <span>${f.field} ${f.op} ${f.value}</span>
                    <span class="siem-chip-remove" data-idx="${idx}" title="Remove filter">&times;</span>
                </span>
            `;
        });
        chips.innerHTML = html;
        chips.querySelectorAll('.siem-chip-remove').forEach(el => {
            el.onclick = () => {
                this.activeFilters.splice(parseInt(el.dataset.idx, 10), 1);
                this.refresh();
            };
        });
    }

    refresh() {
        if (!this._initialized) return;
        const filtered = this.allWindows.filter(w => this._matchesFilters(w));
        this.renderFilterChips();
        this.renderHistogram(filtered);
        this.renderLogTable(filtered);
    }

    clear() {
        this.allWindows = [];
        this.activeFilters = [];
        this.expandedRows.clear();
        if (this._initialized) {
            const body = document.getElementById('siemLogBody');
            if (body) body.innerHTML = '';
            const chips = document.getElementById('siemFilterChips');
            if (chips) chips.innerHTML = '';
            const canvas = document.getElementById('siemHistogramCanvas');
            if (canvas) {
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }
    }
}
