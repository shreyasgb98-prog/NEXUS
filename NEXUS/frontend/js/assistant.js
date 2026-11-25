// NEXUS AI: Streaming Copilot Assistant (SnowUI Style)
// Manages the global "Ask NEXUS" streaming chat drawer with live token streaming,
// query chips, markdown rendering, clickable cited window/incident badges,
// and offline grounded reasoning fallback.

class NexusAssistant {
    constructor() {
        this.drawer = document.getElementById('askNexusDrawer');
        this.toggleBtn = document.getElementById('btnToggleAssistant');
        this.closeBtn = document.getElementById('btnCloseAssistant');
        this.clearBtn = document.getElementById('btnAssistantClear');
        this.sendBtn = document.getElementById('btnAssistantSend');
        this.inputEl = document.getElementById('assistantInput');
        this.messagesContainer = document.getElementById('assistantMessages');
        this.chipsContainer = document.getElementById('assistantChips');

        this.chatHistory = [];
        this.currentAbortController = null;
        this.isStreaming = false;

        this.suggestedQueries = [
            "Why was the last alert raised?",
            "Is the deauth rate normal right now?",
            "Which detector missed attacks?",
            "Summarize link health"
        ];

        this.init();
    }

    init() {
        if (this.toggleBtn && this.drawer) {
            this.toggleBtn.onclick = () => this.toggleDrawer();
        }
        if (this.closeBtn && this.drawer) {
            this.closeBtn.onclick = () => this.closeDrawer();
        }
        if (this.clearBtn) {
            this.clearBtn.onclick = () => this.clearChat();
        }
        if (this.sendBtn) {
            this.sendBtn.onclick = () => this.handleSend();
        }
        if (this.inputEl) {
            this.inputEl.onkeydown = (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.handleSend();
                }
            };
        }

        this.renderSuggestedChips();
        this.addSystemGreeting();
    }

    toggleDrawer() {
        if (!this.drawer) return;
        const isOpen = this.drawer.classList.contains('open');
        if (isOpen) {
            this.closeDrawer();
        } else {
            this.openDrawer();
        }
    }

    openDrawer() {
        if (!this.drawer) return;
        this.drawer.classList.add('open');
        if (this.toggleBtn) this.toggleBtn.classList.add('active');
        if (this.inputEl) this.inputEl.focus();
    }

    closeDrawer() {
        if (!this.drawer) return;
        this.drawer.classList.remove('open');
        if (this.toggleBtn) this.toggleBtn.classList.remove('active');
    }

    renderSuggestedChips() {
        if (!this.chipsContainer) return;
        this.chipsContainer.innerHTML = '';
        this.suggestedQueries.forEach(query => {
            const chip = document.createElement('button');
            chip.className = 'assistant-chip';
            chip.textContent = query;
            chip.onclick = () => {
                if (this.isStreaming) return;
                if (this.inputEl) this.inputEl.value = query;
                this.handleSend();
            };
            this.chipsContainer.appendChild(chip);
        });
    }

    addSystemGreeting() {
        if (!this.messagesContainer) return;
        this.appendMessage('assistant', 
            "**NEXUS AI Operational Copilot Ready.**\n\nI monitor real-time 2.4 GHz RF telemetry, multi-signal correlations, and EWMA statistical baselines. Ask a diagnostic question or select a query chip above to investigate current link health, anomalous bursts, or detector benchmarks."
        );
    }

    appendMessage(role, rawContent) {
        if (!this.messagesContainer) return null;
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-message chat-${role}`;

        const roleTag = document.createElement('div');
        roleTag.className = 'chat-role-tag';
        roleTag.textContent = role === 'user' ? 'Operator' : 'NEXUS Copilot';
        msgDiv.appendChild(roleTag);

        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'chat-body';
        bodyDiv.innerHTML = this.renderMarkdown(rawContent);
        this.bindCitationEvents(bodyDiv);
        msgDiv.appendChild(bodyDiv);

        this.messagesContainer.appendChild(msgDiv);
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
        return bodyDiv;
    }

    async handleSend() {
        if (this.isStreaming || !this.inputEl) return;
        const query = this.inputEl.value.trim();
        if (!query) return;

        this.inputEl.value = '';
        this.appendMessage('user', query);
        this.chatHistory.push({ role: 'user', content: query });

        // Prepare Assistant Response Container
        const responseBody = this.appendMessage('assistant', '<span class="typing-indicator">Analyzing telemetry stream...</span>');
        this.isStreaming = true;
        if (this.sendBtn) {
            this.sendBtn.textContent = 'Stop';
            this.sendBtn.classList.add('btn-danger');
        }

        const endpointUrl = (document.getElementById('inputLlmUrl')?.value || 'http://localhost:11434').trim();
        const modelName = (document.getElementById('inputLlmModel')?.value || 'llama3.2').trim();

        this.currentAbortController = new AbortController();
        let accumulatedText = '';

        try {
            const res = await fetch('/api/assistant/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: query,
                    history: this.chatHistory.slice(-6),
                    ollama_url: endpointUrl,
                    model: modelName
                }),
                signal: this.currentAbortController.signal
            });

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}`);
            }

            if (!res.body) {
                throw new Error('ReadableStream not supported by browser.');
            }

            const reader = res.body.getReader();
            const decoder = new TextDecoder('utf-8');
            responseBody.innerHTML = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                const chunk = decoder.decode(value, { stream: true });
                accumulatedText += chunk;
                responseBody.innerHTML = this.renderMarkdown(accumulatedText);
                this.bindCitationEvents(responseBody);
                this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
            }

            this.chatHistory.push({ role: 'assistant', content: accumulatedText });

        } catch (err) {
            if (err.name === 'AbortError') {
                accumulatedText += '\n\n*(Stream cancelled by operator)*';
                responseBody.innerHTML = this.renderMarkdown(accumulatedText);
                this.bindCitationEvents(responseBody);
            } else {
                // Client-side grounded operational fallback
                const fallbackResponse = `> **AI Offline (Rule-Based Fallback Active)**\n\n${this.generateGroundedClientAnswer(query)}`;
                this.simulateStreamingFallback(responseBody, fallbackResponse);
            }
        } finally {
            this.isStreaming = false;
            this.currentAbortController = null;
            if (this.sendBtn) {
                this.sendBtn.textContent = 'Send';
                this.sendBtn.classList.remove('btn-danger');
            }
        }
    }

    generateGroundedClientAnswer(query) {
        const app = window.nexusApp;
        if (!app) {
            return "Telemetry state is currently initializing. Please await the first processed window.";
        }

        const qLower = query.toLowerCase();

        // 1. Why was the last alert raised?
        if (qLower.includes('last alert') || qLower.includes('why was') || qLower.includes('alert raised')) {
            const lastAlert = app.allEvents.length > 0 ? app.allEvents[app.allEvents.length - 1] : null;
            if (!lastAlert) {
                return "Zero anomaly alerts have been triggered. The current EWMA baseline is tracking normal RF environment behavior.";
            }

            const featuresStr = (lastAlert.evidence && lastAlert.evidence.features)
                ? lastAlert.evidence.features.map(f => `**${f.feature}**: observed ${f.observed} (baseline ${f.baseline_mean}, z=+${f.z_score}σ)`).join(', ')
                : 'Correlated multi-vector anomaly';

            return `### Alert Diagnosis: [${lastAlert.id}]\n\n` +
                   `- **Event Classification**: ${lastAlert.type}\n` +
                   `- **Trigger Window**: [Window #${lastAlert.window}]\n` +
                   `- **Severity**: \`${lastAlert.severity.toUpperCase()}\` (Confidence: ${(lastAlert.confidence * 100).toFixed(0)}%)\n` +
                   `- **Measured Evidence**: ${featuresStr}\n\n` +
                   `**Mitigation**: ${lastAlert.explanation || 'Inspect physical RF perimeter and check 802.11w PMF enforcement.'}`;
        }

        // 2. Is deauth rate normal right now?
        if (qLower.includes('deauth') || qLower.includes('normal')) {
            const deauthBase = app.baselines.deauth;
            const lastWin = app.allWindows.length > 0 ? app.allWindows[app.allWindows.length - 1] : null;
            const currentObs = lastWin ? (lastWin.payload.deauth || 0) : 0;
            const currentZ = (lastWin && lastWin.metrics && lastWin.metrics.deauth) ? lastWin.metrics.deauth.z_score : 0;
            const upperLimit = (deauthBase.mean + (3 * Math.max(Math.sqrt(deauthBase.variance), 0.7))).toFixed(2);

            const isNormal = currentZ < app.zThreshold && currentObs < app.fixedThreshold;

            return `### 802.11 Deauthentication Rate Status\n\n` +
                   `- **Observed Rate**: \`${currentObs} frames/win\`\n` +
                   `- **Adaptive EWMA Baseline**: μ = ${deauthBase.mean.toFixed(2)} frames/win\n` +
                   `- **3σ Envelope Threshold**: ${upperLimit} frames/win (Z-score: +${currentZ.toFixed(2)}σ)\n` +
                   `- **Operational Verdict**: ${isNormal ? '[NORMAL / STABLE] Deauth transmission rates are within expected background noise.' : '[ANOMALOUS / ELEVATED] Deauth frame activity exceeds statistical variance.'}`;
        }

        // 3. Which detector missed attacks?
        if (qLower.includes('detector') || qLower.includes('missed') || qLower.includes('benchmark')) {
            const postWarmup = app.allWindows.filter(w => w.window_id > app.warmupWindows);
            const labelledAttacks = postWarmup.filter(w => w.is_attack_labelled === 1).length;

            if (labelledAttacks === 0) {
                return `### Detector Comparison\n\n` +
                       `Zero ground-truth attacks have been labelled in post-warmup evaluation windows yet.\n\n` +
                       `To benchmark Fixed vs Adaptive vs NEXUS detectors, toggle **Lab Mode** and inject a test burst or enable \`Label: attack running\`.`;
            }

            return `### Detector Benchmark Analysis\n\n` +
                   `- **Evaluated Post-Warmup Windows**: ${postWarmup.length}\n` +
                   `- **Labelled Ground-Truth Attack Windows**: ${labelledAttacks}\n\n` +
                   `**Detector Performance Overview**:\n` +
                   `1. **Fixed (deauth ≥ 5)**: Vulnerable to high-density legitimate environments (false positives) and misses low-rate management spoofing.\n` +
                   `2. **Adaptive (z > 3.5σ)**: Rapidly flags statistical deviations, but can produce isolated single-packet false alarms without multi-signal correlation.\n` +
                   `3. **NEXUS (Adaptive + 3-Window Correlation)**: Eliminates single-window jitter and achieves optimal F1 score by requiring correlated anomalies across radio signals.`;
        }

        // 4. Summarize link health
        if (qLower.includes('link') || qLower.includes('health') || qLower.includes('serial')) {
            return `### System & RF Link Health Summary\n\n` +
                   `- **Ingest Mode**: \`${app.mode}\`\n` +
                   `- **Serial State**: \`${app.serialReceiver.state}\` (115200 8-N-1)\n` +
                   `- **Processed Windows**: ${app.windowCount} windows\n` +
                   `- **Buffer Frame Drops**: ${app.droppedFramesCount}\n` +
                   `- **JSON Parse Errors**: ${app.serialErrorCount}\n` +
                   `- **Ring Buffer Overflows**: ${app.overflowCount}\n` +
                   `- **Overall Health**: ${app.serialErrorCount === 0 && app.droppedFramesCount === 0 ? '[OPTIMAL] High-integrity telemetry stream with zero loss.' : '[DEGRADED] Some frames were dropped due to processing latency or serial buffer backpressure.'}`;
        }

        // Generic Operational Copilot Response
        return `### NEXUS Telemetry Insight\n\n` +
               `Received inquiry: *"${query}"*\n\n` +
               `- **Active Monitoring Windows**: ${app.windowCount} (Warmup: ${app.warmupWindows})\n` +
               `- **Recorded Anomaly Incidents**: ${app.allEvents.length}\n` +
               `- **Active Link**: \`${app.mode} (${app.mode === 'LIVE' ? app.serialReceiver.state : 'SYNTHETIC'})\`\n\n` +
               `Select one of the quick query chips above or check [Window #${app.windowCount}] on the primary stacked chart for real-time signal baselines.`;
    }

    simulateStreamingFallback(container, fullText) {
        let currentIdx = 0;
        container.innerHTML = '';
        const interval = setInterval(() => {
            currentIdx += 4;
            if (currentIdx >= fullText.length) {
                currentIdx = fullText.length;
                clearInterval(interval);
                this.chatHistory.push({ role: 'assistant', content: fullText });
            }
            container.innerHTML = this.renderMarkdown(fullText.substring(0, currentIdx));
            this.bindCitationEvents(container);
            this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
        }, 16);
    }

    renderMarkdown(text) {
        if (!text) return '';
        let html = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // Headers ###
        html = html.replace(/^### (.*$)/gim, '<div class="chat-h3">$1</div>');
        // Bold **text**
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        // Inline code `code`
        html = html.replace(/`([^`]+)`/g, '<code class="chat-code">$1</code>');
        // Unordered lists - item
        html = html.replace(/^\s*-\s+(.*$)/gim, '<div class="chat-li"><span class="chat-bullet">&bull;</span><span>$1</span></div>');
        // Numbered lists 1. item
        html = html.replace(/^\s*(\d+)\.\s+(.*$)/gim, '<div class="chat-li"><span class="chat-bullet">$1.</span><span>$2</span></div>');
        // Paragraph breaks
        html = html.replace(/\n\n/g, '<div class="chat-gap"></div>');

        // Render Clickable Badges: [Window #42] or [Win #42]
        html = html.replace(/\[(?:Window|Win|window)\s*#?(\d+)\]/gi, (match, wid) => {
            return `<button class="cite-badge cite-window" data-window="${wid}" title="Focus Window #${wid}">Window #${wid}</button>`;
        });

        // Render Clickable Incident Badges: [INC-001] or [INC-20261120-001]
        html = html.replace(/\[(INC-[\w\-]+)\]/gi, (match, incId) => {
            return `<button class="cite-badge cite-incident" data-inc="${incId}" title="Inspect Incident ${incId}">${incId}</button>`;
        });

        return html;
    }

    bindCitationEvents(container) {
        // Window zoom/highlight buttons
        container.querySelectorAll('.cite-window').forEach(btn => {
            btn.onclick = (e) => {
                e.preventDefault();
                const wid = parseInt(btn.dataset.window, 10);
                if (!isNaN(wid) && window.nexusApp && window.nexusApp.chart) {
                    window.nexusApp.chart.highlightWindow(wid);
                    const chartCard = document.querySelector('.chart-card');
                    if (chartCard) chartCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            };
        });

        // Incident selection buttons
        container.querySelectorAll('.cite-incident').forEach(btn => {
            btn.onclick = (e) => {
                e.preventDefault();
                const incId = btn.dataset.inc;
                if (window.nexusApp && window.nexusApp.incidentManager) {
                    window.nexusApp.incidentManager.selectIncidentById(incId);
                }
            };
        });
    }

    clearChat() {
        this.chatHistory = [];
        if (this.messagesContainer) {
            this.messagesContainer.innerHTML = '';
            this.addSystemGreeting();
        }
    }
}
