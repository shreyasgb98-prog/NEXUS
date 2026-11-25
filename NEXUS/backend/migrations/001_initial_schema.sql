-- Initial Schema Migration for NEXUS AI
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS telemetry_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER NOT NULL,
    epoch_ms INTEGER NOT NULL,
    deauth_count INTEGER NOT NULL,
    mgmt_count INTEGER NOT NULL,
    ble_count INTEGER NOT NULL,
    rogue_count INTEGER NOT NULL,
    nfc_count INTEGER NOT NULL,
    rssi_mean REAL DEFAULT -70.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_epoch_ms ON telemetry_windows(epoch_ms);
CREATE INDEX IF NOT EXISTS idx_telemetry_window_id ON telemetry_windows(window_id);

CREATE TABLE IF NOT EXISTS baseline_metrics (
    feature_name TEXT PRIMARY KEY,
    mean REAL NOT NULL,
    variance REAL NOT NULL,
    std_dev REAL NOT NULL,
    updated_epoch_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    window_id INTEGER NOT NULL,
    epoch_ms INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    signals_correlated INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    explanation_text TEXT NOT NULL,
    FOREIGN KEY(window_id) REFERENCES telemetry_windows(window_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_epoch_ms ON alert_events(epoch_ms);
CREATE INDEX IF NOT EXISTS idx_alerts_event_type ON alert_events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_window_id ON alert_events(window_id);

CREATE TABLE IF NOT EXISTS serial_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_ms INTEGER NOT NULL,
    error_type TEXT NOT NULL,
    raw_payload TEXT
);

CREATE INDEX IF NOT EXISTS idx_errors_epoch_ms ON serial_errors(epoch_ms);
