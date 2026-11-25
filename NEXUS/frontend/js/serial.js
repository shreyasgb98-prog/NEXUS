class WebSerialReceiver {
    constructor(callbacks) {
        this.port = null;
        this.reader = null;
        this.keepReading = false;
        this.isFrameAligned = false;
        this.callbacks = callbacks || {}; // onWindow, onStateChange, onError

        this.state = 'DISCONNECTED';
        this.errorCount = 0;
        this.droppedFrames = 0;
        this.overflowCount = 0;

        this._boundDisconnect = (event) => {
            if (this.port && event.target === this.port) {
                this.disconnect();
            }
        };

        if (typeof navigator !== 'undefined' && 'serial' in navigator) {
            navigator.serial.addEventListener('disconnect', this._boundDisconnect);
        }
    }

    setState(newState) {
        this.state = newState;
        if (this.callbacks.onStateChange) {
            this.callbacks.onStateChange(this.state);
        }
    }

    logError(type, detail) {
        this.errorCount++;
        if (this.callbacks.onError) {
            this.callbacks.onError({
                type,
                detail,
                totalErrors: this.errorCount,
                droppedFrames: this.droppedFrames,
                overflowCount: this.overflowCount
            });
        }
    }

    async connect(baudRate = 115200) {
        if (typeof navigator === 'undefined' || !('serial' in navigator)) {
            const app = window.nexusApp;
            if (app && app.wazuhConsole) {
                app.wazuhConsole.showToast('SERIAL ERROR', 'Web Serial API is not supported in this browser. Use Chromium-based Google Chrome or Microsoft Edge.', 'danger');
            } else if (app && typeof app.showWin32Dialog === 'function') {
                app.showWin32Dialog('Web Serial API Unsupported', '<div style="font-size: 11px;">Web Serial API is not supported in this browser. Use Chromium-based Google Chrome or Microsoft Edge.</div>');
            }
            return false;
        }

        try {
            if (this.port || this.reader) {
                await this.disconnect();
            }

            this.setState(`CONNECTING (${baudRate})`);
            this.port = await navigator.serial.requestPort();
            await this.port.open({ baudRate });
            this.keepReading = true;
            this.isFrameAligned = false;
            this.setState('ACTIVE_MONITORING');
            this.readStream();
            return true;
        } catch (err) {
            this.logError('SERIAL_CONNECT_FAIL', err.message);
            this.setState('DISCONNECTED');
            return false;
        }
    }

    async autoConnect(baudRate = 115200) {
        if (typeof navigator === 'undefined' || !('serial' in navigator)) return false;
        try {
            const ports = await navigator.serial.getPorts();
            if (ports && ports.length > 0) {
                if (this.port || this.reader) {
                    await this.disconnect();
                }
                this.port = ports[0];
                await this.port.open({ baudRate });
                this.keepReading = true;
                this.isFrameAligned = false;
                this.setState('ACTIVE_MONITORING');
                this.readStream();
                return true;
            }
        } catch (err) {
            this.logError('SERIAL_AUTOCONNECT_FAIL', err.message);
            this.setState('DISCONNECTED');
        }
        return false;
    }

    async disconnect() {
        this.keepReading = false;
        this.isFrameAligned = false;

        if (this.reader) {
            try {
                await this.reader.cancel();
            } catch (e) {
                // Ignore cancel exceptions during teardown
            }
            try {
                this.reader.releaseLock();
            } catch (e) {
                // Ignore releaseLock exceptions during teardown
            }
            this.reader = null;
        }

        if (this.port) {
            try {
                await this.port.close();
            } catch (e) {
                // Ignore close exceptions during teardown
            }
            this.port = null;
        }

        this.setState('DISCONNECTED');
    }

    async sendSerialCommand(jsonCommand) {
        if (!this.port || !this.port.writable) {
            this.logError('SERIAL_WRITE_FAIL', 'Serial port is not open or writable');
            return false;
        }

        try {
            const jsonStr = (typeof jsonCommand === 'string' ? jsonCommand.trim() : JSON.stringify(jsonCommand)) + '\n';

            if (typeof TextEncoderStream !== 'undefined' && typeof this.port.writable.pipeTo === 'function') {
                const textEncoder = new TextEncoderStream();
                const pipePromise = textEncoder.readable.pipeTo(this.port.writable, { preventClose: true });
                const writer = textEncoder.writable.getWriter();
                await writer.write(jsonStr);
                await writer.close();
                await pipePromise.catch(() => {});
            } else {
                const encoder = new TextEncoder();
                const writer = this.port.writable.getWriter();
                await writer.write(encoder.encode(jsonStr));
                writer.releaseLock();
            }
            return true;
        } catch (err) {
            this.logError('SERIAL_WRITE_ERROR', err.message);
            return false;
        }
    }

    async readStream() {
        let lineBuffer = '';
        this.isFrameAligned = false;

        try {
            const decoder = new TextDecoder();
            this.reader = this.port.readable.getReader();

            while (this.keepReading) {
                const { value, done } = await this.reader.read();
                if (done) break;
                if (!value) continue;

                const textChunk = typeof value === 'string' ? value : decoder.decode(value, { stream: true });
                lineBuffer += textChunk;

                // Receive buffer safeguard: flush if exceeding 8192 bytes
                if (lineBuffer.length > 8192) {
                    this.overflowCount++;
                    this.setState('BUFFER_OVERFLOW');
                    this.logError('RX_BUFFER_OVERFLOW', 'Serial receive buffer exceeded 8192 bytes limit');
                    lineBuffer = '';
                    this.isFrameAligned = false;
                    this.setState('ACTIVE_MONITORING');
                    continue;
                }

                // Initial frame alignment: discard in-flight bytes until first complete newline (\n)
                if (!this.isFrameAligned) {
                    const firstNewlineIdx = lineBuffer.indexOf('\n');
                    if (firstNewlineIdx === -1) {
                        // Complete newline not reached yet, wait for next incoming chunk
                        continue;
                    }
                    // Discard truncated fragment up to and including the first newline
                    lineBuffer = lineBuffer.slice(firstNewlineIdx + 1);
                    this.isFrameAligned = true;
                }

                // If buffer does not contain a full line yet, wait for more data
                if (!lineBuffer.includes('\n')) {
                    continue;
                }

                // Split strictly on \n
                const lines = lineBuffer.split('\n');
                // Retain trailing incomplete segment in buffer
                lineBuffer = lines.pop();

                for (const rawLine of lines) {
                    // Trim carriage returns (\r) and surrounding whitespace
                    const trimmed = rawLine.replace(/\r/g, '').trim();
                    if (!trimmed) continue;

                    // Structural boundary verification
                    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
                        this.droppedFrames++;
                        this.logError('MALFORMED_FRAME_DROP', trimmed);
                        continue;
                    }

                    // Targeted JSON.parse inside isolated try/catch block
                    try {
                        const payload = JSON.parse(trimmed);
                        if (
                            typeof payload.deauth === 'undefined' ||
                            typeof payload.mgmt === 'undefined' ||
                            typeof payload.ble === 'undefined' ||
                            typeof payload.rogue === 'undefined' ||
                            typeof payload.nfc === 'undefined'
                        ) {
                            this.droppedFrames++;
                            this.logError('INVALID_TELEMETRY_SCHEMA', trimmed);
                            continue;
                        }

                        if (this.callbacks.onWindow) {
                            this.callbacks.onWindow(payload);
                        }
                    } catch (parseErr) {
                        // Malformed frame: increment dropped frames and discard without breaking stream
                        this.droppedFrames++;
                        this.logError('JSON_PARSE_ERROR', `${parseErr.message} | ${trimmed}`);
                    }
                }
            }
        } catch (streamErr) {
            if (this.keepReading) {
                this.logError('STREAM_READ_ERROR', streamErr.message);
                this.setState('DISCONNECTED');
            }
        } finally {
            if (this.reader) {
                try {
                    this.reader.releaseLock();
                } catch (e) {
                    // Ignore release lock exception
                }
                this.reader = null;
            }
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebSerialReceiver;
}
