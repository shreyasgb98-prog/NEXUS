// NEXUS AI: Anti-Aliased Canvas Stacked 4-Signal Chart (SnowUI Style)
// Displays Deauth, Wi-Fi Mgmt, BLE, and Rogue AP simultaneously in synchronized vertical tracks
// with EWMA baseline envelopes (mean +- 3 sigma), contiguous attack window highlights,
// interactive hover crosshair scrubber, and window focus navigation.

class TelemetryChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.history = []; // Array of multi-signal window records
        this.maxPoints = 65;
        this.hoverIndex = -1;
        this.highlightedWindowId = null;
        this.highlightTimer = null;

        // Track definitions
        this.tracks = [
            { key: 'deauth', label: 'DEAUTH FRAMES', unit: 'frames/win', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.08)' },
            { key: 'mgmt',   label: 'WI-FI MGMT FRAMES', unit: 'frames/win', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.08)' },
            { key: 'ble',    label: 'BLE ADVERTS', unit: 'adverts/win', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.08)' },
            { key: 'rogue',  label: 'ROGUE AP DETECTION', unit: 'rogue/win', color: '#f43f5e', bg: 'rgba(244, 63, 94, 0.08)' }
        ];

        this.initEvents();
        this.resize();
    }

    initEvents() {
        window.addEventListener('resize', () => this.resize());

        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const width = rect.width;
            const leftPad = 135;
            const rightPad = 20;
            const plotWidth = width - leftPad - rightPad;

            if (x >= leftPad && x <= width - rightPad && this.history.length > 1) {
                const step = plotWidth / (this.maxPoints - 1);
                const offset = this.maxPoints - this.history.length;
                const idx = Math.round((x - leftPad) / step) - offset;
                if (idx >= 0 && idx < this.history.length) {
                    this.hoverIndex = idx;
                } else {
                    this.hoverIndex = -1;
                }
            } else {
                this.hoverIndex = -1;
            }
            this.render();
        });

        this.canvas.addEventListener('mouseleave', () => {
            this.hoverIndex = -1;
            this.render();
        });
    }

    resize() {
        if (!this.canvas || !this.canvas.parentElement) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return;
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = `${rect.width}px`;
        this.canvas.style.height = `${rect.height}px`;
        this.ctx.resetTransform();
        this.ctx.scale(dpr, dpr);
        this.render();
    }

    addMultiPoint(point) {
        this.history.push(point);
        if (this.history.length > this.maxPoints) {
            this.history.shift();
        }
        this.render();
    }

    // Backward-compatibility wrapper for single-point callers
    addPoint(point) {
        if (point.signals) {
            this.addMultiPoint(point);
            return;
        }
        // Normalize single feature call into multi-signal record
        const last = this.history.length > 0 ? this.history[this.history.length - 1] : null;
        const record = {
            window_id: point.window_id || (last ? last.window_id + 1 : 1),
            is_attack_labelled: point.is_attack_labelled || 0,
            signals: {
                deauth: { observed: point.observed || 0, mean: point.mean || 0, sd: point.sd || 1, flagged: point.flagged || false },
                mgmt:   { observed: (last && last.signals) ? last.signals.mgmt.observed : 80, mean: 80, sd: 4, flagged: false },
                ble:    { observed: (last && last.signals) ? last.signals.ble.observed : 25, mean: 25, sd: 4, flagged: false },
                rogue:  { observed: (last && last.signals) ? last.signals.rogue.observed : 0, mean: 0, sd: 0.1, flagged: false }
            }
        };
        this.addMultiPoint(record);
    }

    clear() {
        this.history = [];
        this.hoverIndex = -1;
        this.highlightedWindowId = null;
        this.render();
    }

    highlightWindow(targetWindowId) {
        this.highlightedWindowId = parseInt(targetWindowId, 10);
        this.render();
        if (this.highlightTimer) clearTimeout(this.highlightTimer);
        this.highlightTimer = setTimeout(() => {
            this.highlightedWindowId = null;
            this.render();
        }, 5000);
    }

    getPalette() {
        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        if (isLight) {
            return {
                isLight: true,
                bg: '#ffffff',
                emptyText: '#475569',
                mutedStroke: '#e2e8f0',
                mutedText: '#475569',
                gridLine: '#e2e8f0',
                divider: '#cbd5e1',
                axisText: '#475569',
                nowText: '#0284c7',
                titleText: '#0f172a',
                subText: '#475569',
                envelopeStroke: 'rgba(71, 85, 105, 0.45)',
                attackFill: 'rgba(190, 18, 60, 0.10)',
                attackStroke: '#be123c',
                attackText: '#be123c',
                anomalyFill: '#be123c',
                anomalyStroke: '#ffffff',
                highlightColor: '#0284c7',
                crosshair: 'rgba(15, 23, 42, 0.45)',
                tooltipBg: '#ffffff',
                tooltipBorder: '#64748b',
                tooltipTitle: '#0f172a',
                tracks: {
                    deauth: { color: '#0284c7', bg: 'rgba(2, 132, 199, 0.12)' },
                    mgmt:   { color: '#15803d', bg: 'rgba(21, 128, 61, 0.10)' },
                    ble:    { color: '#b45309', bg: 'rgba(180, 83, 9, 0.10)' },
                    rogue:  { color: '#be123c', bg: 'rgba(190, 18, 60, 0.12)' }
                }
            };
        }
        return {
            isLight: false,
            bg: '#0d0d0f',
            emptyText: '#94a3b8',
            mutedStroke: '#1e1e24',
            mutedText: '#64748b',
            gridLine: null,
            divider: '#2c2c31',
            axisText: '#94a3b8',
            nowText: '#38bdf8',
            titleText: '#f4f4f5',
            subText: '#94a3b8',
            envelopeStroke: 'rgba(148, 163, 184, 0.35)',
            attackFill: 'rgba(244, 63, 94, 0.12)',
            attackStroke: 'rgba(244, 63, 94, 0.45)',
            attackText: '#f43f5e',
            anomalyFill: '#f43f5e',
            anomalyStroke: '#ffffff',
            highlightColor: '#38bdf8',
            crosshair: 'rgba(255, 255, 255, 0.65)',
            tooltipBg: '#18181b',
            tooltipBorder: '#38383e',
            tooltipTitle: '#ffffff',
            tracks: {
                deauth: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.08)' },
                mgmt:   { color: '#22c55e', bg: 'rgba(34, 197, 94, 0.08)' },
                ble:    { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.08)' },
                rogue:  { color: '#f43f5e', bg: 'rgba(244, 63, 94, 0.08)' }
            }
        };
    }

    render() {
        const { ctx, canvas } = this;
        if (!canvas || !ctx) return;
        let width = parseFloat(canvas.style.width) || canvas.width;
        let height = parseFloat(canvas.style.height) || canvas.height;
        if ((parseFloat(canvas.style.width) <= 0 || canvas.width <= 0 || parseFloat(canvas.style.height) <= 0 || canvas.height <= 0) && !this._resizing) {
            this._resizing = true;
            this.resize();
            this._resizing = false;
            width = parseFloat(canvas.style.width) || canvas.width;
            height = parseFloat(canvas.style.height) || canvas.height;
        }
        if (width <= 0 || height <= 0) return;

        const palette = this.getPalette();

        // Theme-aware canvas background
        ctx.fillStyle = palette.bg;
        ctx.fillRect(0, 0, width, height);

        if (this.history.length < 2) {
            ctx.fillStyle = palette.emptyText;
            ctx.font = '11px Consolas, monospace';
            ctx.textAlign = 'left';
            ctx.fillText('Awaiting telemetry stream...', 16, 28);
            return;
        }

        const leftPad = 145;
        const rightPad = 20;
        const topPad = 8;
        const bottomPad = 22;
        const plotWidth = width - leftPad - rightPad;
        const totalPlotHeight = height - topPad - bottomPad;
        if (plotWidth <= 0 || totalPlotHeight <= 0) return;
        const trackHeight = totalPlotHeight / this.tracks.length;

        const step = plotWidth / (this.maxPoints - 1);
        const offset = this.maxPoints - this.history.length;

        // 1. Render Grouped Contiguous Attack Windows across all tracks
        this.renderContiguousAttackSpans(ctx, offset, step, leftPad, topPad, totalPlotHeight, palette);

        // 2. Render each of the 4 synchronized tracks
        this.tracks.forEach((track, tIdx) => {
            const trackTop = topPad + (tIdx * trackHeight);
            const trackBottom = trackTop + trackHeight;

            if (track.hidden) {
                // If track is hidden via signal selector, draw muted empty baseline
                ctx.strokeStyle = palette.mutedStroke;
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(0, trackBottom);
                ctx.lineTo(leftPad + plotWidth, trackBottom);
                ctx.stroke();

                ctx.fillStyle = palette.mutedText;
                ctx.font = '9px Consolas, monospace';
                ctx.textAlign = 'left';
                ctx.fillText(`[MUTED] ${track.label}`, 12, trackTop + (trackHeight / 2) + 3);
                return;
            }

            this.renderTrack(ctx, track, tIdx, trackTop, trackBottom, trackHeight, offset, step, leftPad, plotWidth, palette);
        });

        // 3. Render time / window X-axis labels at bottom
        this.renderXAxis(ctx, offset, step, leftPad, width, height, bottomPad, palette);

        // 4. Render window highlight line if triggered via chat badge
        if (this.highlightedWindowId != null) {
            this.renderWindowHighlight(ctx, offset, step, leftPad, topPad, totalPlotHeight, palette);
        }

        // 5. Render interactive crosshair scrubber and tooltip if hovering
        if (this.hoverIndex >= 0 && this.hoverIndex < this.history.length) {
            this.renderScrubber(ctx, offset, step, leftPad, topPad, totalPlotHeight, width, palette);
        }
    }

    renderContiguousAttackSpans(ctx, offset, step, leftPad, topPad, totalPlotHeight, palette) {
        let spanStart = -1;
        for (let i = 0; i < this.history.length; i++) {
            const pt = this.history[i];
            const hasSignal =
                (pt.signals?.deauth?.observed || 0) > 0 ||
                (pt.signals?.rogue?.observed || 0) > 0 ||
                Boolean(pt.signals?.deauth?.flagged) ||
                Boolean(pt.signals?.rogue?.flagged) ||
                Boolean(pt.signals?.ble?.flagged);
            const isAttack = pt.is_attack_labelled === 1 && hasSignal;
            if (isAttack && spanStart === -1) {
                spanStart = i;
            } else if (!isAttack && spanStart !== -1) {
                this.drawAttackSpan(ctx, spanStart, i - 1, offset, step, leftPad, topPad, totalPlotHeight, palette);
                spanStart = -1;
            }
        }
        if (spanStart !== -1) {
            this.drawAttackSpan(ctx, spanStart, this.history.length - 1, offset, step, leftPad, topPad, totalPlotHeight, palette);
        }
    }

    drawAttackSpan(ctx, startIdx, endIdx, offset, step, leftPad, topPad, totalPlotHeight, palette) {
        const x1 = leftPad + ((startIdx + offset) * step);
        const x2 = leftPad + ((endIdx + offset) * step);
        const w = Math.max(x2 - x1, step);

        ctx.fillStyle = palette.attackFill;
        ctx.fillRect(x1 - (step / 2), topPad, w, totalPlotHeight);

        // Border accents
        ctx.strokeStyle = palette.attackStroke;
        ctx.lineWidth = 1;
        ctx.strokeRect(x1 - (step / 2), topPad, w, totalPlotHeight);

        // Centered "ATTACK" label if span is at least 36px wide
        if (w >= 36) {
            ctx.fillStyle = palette.attackText;
            ctx.font = 'bold 9px Consolas, monospace';
            ctx.textAlign = 'center';
            ctx.fillText('ATTACK', x1 - (step / 2) + (w / 2), topPad + 12);
        }
    }

    renderTrack(ctx, track, tIdx, trackTop, trackBottom, trackHeight, offset, step, leftPad, plotWidth, palette) {
        const trackColors = palette.tracks[track.key] || { color: track.color, bg: track.bg };

        // Optional light-mode coordinate gridline at mid-track
        if (palette.gridLine) {
            ctx.strokeStyle = palette.gridLine;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(leftPad, trackTop + (trackHeight / 2));
            ctx.lineTo(leftPad + plotWidth, trackTop + (trackHeight / 2));
            ctx.stroke();
        }

        // Track baseline separator hairline
        ctx.strokeStyle = palette.divider;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, trackBottom);
        ctx.lineTo(leftPad + plotWidth, trackBottom);
        ctx.stroke();

        // Calculate dynamic max value for track
        let maxVal = 2;
        this.history.forEach(pt => {
            const sig = pt.signals ? pt.signals[track.key] : null;
            if (sig) {
                const upper = sig.mean + (3 * sig.sd);
                if (sig.observed > maxVal) maxVal = sig.observed;
                if (upper > maxVal) maxVal = upper;
            }
        });
        maxVal = Math.ceil(maxVal * 1.15);

        const getY = (val) => {
            const clamped = Math.max(0, Math.min(val, maxVal));
            const innerPad = 6;
            const innerHeight = trackHeight - (innerPad * 2);
            return (trackBottom - innerPad) - ((clamped / maxVal) * innerHeight);
        };

        // Extract points for spline
        const observedPts = [];
        const envelopePts = [];

        this.history.forEach((pt, i) => {
            const sig = pt.signals ? pt.signals[track.key] : null;
            if (!sig) return;
            const x = leftPad + ((i + offset) * step);
            const yObs = getY(sig.observed);
            const yUpper = getY(sig.mean + (3 * sig.sd));
            const yLower = getY(Math.max(0, sig.mean - (3 * sig.sd)));
            const yMean = getY(sig.mean);

            observedPts.push({ x, y: yObs, observed: sig.observed, flagged: sig.flagged });
            envelopePts.push({ x, yUpper, yLower, yMean });
        });

        // Draw Envelope Area (mean +- 3 sigma)
        if (!this.hideEnvelope && envelopePts.length > 1) {
            ctx.beginPath();
            ctx.moveTo(envelopePts[0].x, envelopePts[0].yUpper);
            for (let i = 1; i < envelopePts.length; i++) {
                ctx.lineTo(envelopePts[i].x, envelopePts[i].yUpper);
            }
            for (let i = envelopePts.length - 1; i >= 0; i--) {
                ctx.lineTo(envelopePts[i].x, envelopePts[i].yLower);
            }
            ctx.closePath();
            ctx.fillStyle = trackColors.bg;
            ctx.fill();

            // Dashed Mean Line
            ctx.beginPath();
            ctx.setLineDash([3, 3]);
            ctx.strokeStyle = palette.envelopeStroke;
            ctx.lineWidth = 1;
            ctx.moveTo(envelopePts[0].x, envelopePts[0].yMean);
            for (let i = 1; i < envelopePts.length; i++) {
                ctx.lineTo(envelopePts[i].x, envelopePts[i].yMean);
            }
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // Draw Observed Signal Line
        if (observedPts.length > 1) {
            ctx.beginPath();
            ctx.strokeStyle = trackColors.color;
            ctx.lineWidth = 1.75;
            this.drawSpline(ctx, observedPts);
            ctx.stroke();

            // Draw Anomaly Markers
            observedPts.forEach(pt => {
                if (pt.flagged) {
                    ctx.beginPath();
                    ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
                    ctx.fillStyle = palette.anomalyFill;
                    ctx.fill();
                    ctx.strokeStyle = palette.anomalyStroke;
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                }
            });
        }

        // Track Sidebar Label & Current Telemetry Value
        const latest = this.history[this.history.length - 1];
        const latestSig = latest && latest.signals ? latest.signals[track.key] : null;
        const latestVal = latestSig ? latestSig.observed : 0;
        const latestMean = latestSig ? latestSig.mean.toFixed(1) : '0.0';

        ctx.fillStyle = palette.titleText;
        ctx.font = 'bold 10px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(track.label, 10, trackTop + 14);

        ctx.fillStyle = trackColors.color;
        ctx.font = 'bold 12px Consolas, monospace';
        ctx.fillText(`${latestVal} ${track.unit}`, 10, trackTop + 29);

        ctx.fillStyle = palette.subText;
        ctx.font = '9px Consolas, monospace';
        ctx.fillText(`μ: ${latestMean} | max: ${maxVal}`, 10, trackTop + 41);
    }

    drawSpline(ctx, pts) {
        if (pts.length < 2) return;
        ctx.moveTo(pts[0].x, pts[0].y);

        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i === 0 ? 0 : i - 1];
            const p1 = pts[i];
            const p2 = pts[i + 1];
            const p3 = pts[i + 2 < pts.length ? i + 2 : i + 1];

            const cp1x = p1.x + (p2.x - p0.x) / 6;
            const cp1y = p1.y + (p2.y - p0.y) / 6;
            const cp2x = p2.x - (p3.x - p1.x) / 6;
            const cp2y = p2.y - (p3.y - p1.y) / 6;

            ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
        }
    }

    renderXAxis(ctx, offset, step, leftPad, width, height, bottomPad, palette) {
        ctx.font = '10px Consolas, monospace';
        ctx.textAlign = 'center';

        const last = this.history.length > 0 ? this.history[this.history.length - 1] : null;
        const xNow = last ? Math.min(leftPad + ((this.history.length - 1 + offset) * step), width - 52) : -999;

        const labelInterval = 10;
        ctx.fillStyle = palette.axisText;
        for (let i = 0; i < this.history.length; i += labelInterval) {
            const pt = this.history[i];
            const x = leftPad + ((i + offset) * step);

            // Suppress periodic tick label if distance to trailing (NOW) label is < 38px
            if (last && Math.abs(xNow - x) < 38) {
                continue;
            }
            ctx.fillText(`W#${pt.window_id}`, x, height - 6);
        }

        // Draw last window marker
        if (last) {
            ctx.fillStyle = palette.nowText;
            ctx.fillText(`W#${last.window_id} (NOW)`, xNow, height - 6);
        }
    }

    renderWindowHighlight(ctx, offset, step, leftPad, topPad, totalPlotHeight, palette) {
        const idx = this.history.findIndex(pt => pt.window_id === this.highlightedWindowId);
        if (idx !== -1) {
            const x = leftPad + ((idx + offset) * step);
            ctx.strokeStyle = palette.highlightColor;
            ctx.lineWidth = 2;
            ctx.setLineDash([4, 2]);
            ctx.beginPath();
            ctx.moveTo(x, topPad);
            ctx.lineTo(x, topPad + totalPlotHeight);
            ctx.stroke();
            ctx.setLineDash([]);

            ctx.fillStyle = palette.highlightColor;
            ctx.font = 'bold 10px Consolas, monospace';
            ctx.textAlign = 'center';
            ctx.fillText(`TARGET WIN #${this.highlightedWindowId}`, x, topPad + 10);
        }
    }

    renderScrubber(ctx, offset, step, leftPad, topPad, totalPlotHeight, width, palette) {
        const pt = this.history[this.hoverIndex];
        if (!pt) return;
        const x = leftPad + ((this.hoverIndex + offset) * step);

        // Vertical Scrubber Line
        ctx.strokeStyle = palette.crosshair;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, topPad);
        ctx.lineTo(x, topPad + totalPlotHeight);
        ctx.stroke();

        // Operational Tooltip Box
        const deauthVal = pt.signals ? pt.signals.deauth.observed : 0;
        const mgmtVal   = pt.signals ? pt.signals.mgmt.observed : 0;
        const bleVal    = pt.signals ? pt.signals.ble.observed : 0;
        const rogueVal  = pt.signals ? pt.signals.rogue.observed : 0;
        const isAttack  = pt.is_attack_labelled === 1;

        const tipW = 160;
        const tipH = 92;
        let tipX = x + 12;
        if (tipX + tipW > width - 10) tipX = x - tipW - 12;
        const tipY = topPad + 12;

        ctx.fillStyle = palette.tooltipBg;
        ctx.fillRect(tipX, tipY, tipW, tipH);
        ctx.strokeStyle = palette.tooltipBorder;
        ctx.lineWidth = 1;
        ctx.strokeRect(tipX, tipY, tipW, tipH);

        ctx.fillStyle = palette.tooltipTitle;
        ctx.font = 'bold 10px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(`Window #${pt.window_id} ${isAttack ? '[ATTACK]' : ''}`, tipX + 8, tipY + 16);

        ctx.font = '10px Consolas, monospace';
        ctx.fillStyle = palette.tracks.deauth.color;
        ctx.fillText(`Deauth: ${deauthVal} frames`, tipX + 8, tipY + 32);

        ctx.fillStyle = palette.tracks.mgmt.color;
        ctx.fillText(`Mgmt:   ${mgmtVal} frames`, tipX + 8, tipY + 47);

        ctx.fillStyle = palette.tracks.ble.color;
        ctx.fillText(`BLE:    ${bleVal} adverts`, tipX + 8, tipY + 62);

        ctx.fillStyle = palette.tracks.rogue.color;
        ctx.fillText(`Rogue:  ${rogueVal} nodes`, tipX + 8, tipY + 77);
    }
}
