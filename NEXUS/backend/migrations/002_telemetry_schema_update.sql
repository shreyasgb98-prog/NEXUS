-- Migration 002: Enhance schema for full telemetry, baselines, alert events, and persistent error tracking
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- 1. Unique index on telemetry_windows(window_id) to ensure foreign key integrity
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_window_id_unique ON telemetry_windows(window_id);

-- 2. Add telemetry columns per Section 3.3 (FR-9, FR-12, FR-13) and Listing 5.1
ALTER TABLE telemetry_windows ADD COLUMN data_source TEXT NOT NULL DEFAULT 'live';
ALTER TABLE telemetry_windows ADD COLUMN is_attack_labelled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN flag_fixed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN flag_adaptive INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN flag_nexus INTEGER NOT NULL DEFAULT 0;

-- EWMA baseline values (running mean and variance for each monitored feature)
ALTER TABLE telemetry_windows ADD COLUMN ewma_deauth_mean REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_deauth_var REAL DEFAULT 1.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_mgmt_mean REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_mgmt_var REAL DEFAULT 1.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_ble_mean REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_ble_var REAL DEFAULT 1.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_rogue_mean REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN ewma_rogue_var REAL DEFAULT 1.0;

-- Computed z-scores per feature
ALTER TABLE telemetry_windows ADD COLUMN z_deauth REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN z_mgmt REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN z_ble REAL DEFAULT 0.0;
ALTER TABLE telemetry_windows ADD COLUMN z_rogue REAL DEFAULT 0.0;

-- Additional indexes on telemetry_windows for rolling queries and filtering
CREATE INDEX IF NOT EXISTS idx_telemetry_data_source ON telemetry_windows(data_source);
CREATE INDEX IF NOT EXISTS idx_telemetry_attack_labelled ON telemetry_windows(is_attack_labelled);
CREATE INDEX IF NOT EXISTS idx_telemetry_source_epoch ON telemetry_windows(data_source, epoch_ms);

-- 3. Enhance alert_events matching Appendix A.3
ALTER TABLE alert_events ADD COLUMN type_key TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_events ADD COLUMN data_source TEXT NOT NULL DEFAULT 'live';
ALTER TABLE alert_events ADD COLUMN explanation TEXT;

-- Synchronize explanation column with existing explanation_text if present
UPDATE alert_events SET explanation = explanation_text WHERE explanation IS NULL;

-- Indexes for alert_events
CREATE INDEX IF NOT EXISTS idx_alerts_data_source ON alert_events(data_source);
CREATE INDEX IF NOT EXISTS idx_alerts_type_key ON alert_events(type_key);
CREATE INDEX IF NOT EXISTS idx_alerts_source_epoch ON alert_events(data_source, epoch_ms);

-- 4. Baseline state configuration table for persisting hyperparameters and counters
CREATE TABLE IF NOT EXISTS baseline_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    alpha REAL NOT NULL DEFAULT 0.9,
    z_threshold REAL NOT NULL DEFAULT 3.5,
    warmup_windows INTEGER NOT NULL DEFAULT 30,
    processed_windows INTEGER NOT NULL DEFAULT 0,
    updated_epoch_ms INTEGER NOT NULL
);

INSERT OR IGNORE INTO baseline_state (id, alpha, z_threshold, warmup_windows, processed_windows, updated_epoch_ms)
VALUES (1, 0.9, 3.5, 30, 0, 0);

-- 5. Persistent error counters table for frame-drop and malformed JSON error counters
CREATE TABLE IF NOT EXISTS serial_error_counters (
    error_key TEXT PRIMARY KEY,
    total_count INTEGER NOT NULL DEFAULT 0,
    last_epoch_ms INTEGER NOT NULL
);

INSERT OR IGNORE INTO serial_error_counters (error_key, total_count, last_epoch_ms) VALUES
('MALFORMED_FRAME_DROP', 0, 0),
('JSON_PARSE_ERROR', 0, 0),
('RX_BUFFER_OVERFLOW', 0, 0),
('SERIAL_PORT_DISCONNECT', 0, 0),
('SERIAL_OPEN_FAILURE', 0, 0);

CREATE INDEX IF NOT EXISTS idx_errors_error_type ON serial_errors(error_type);
