-- 006_add_injection_and_advisory.sql
-- Adds frame injection detection, hardware OUI profiling, and remediation advisories

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER,
    epoch_ms INTEGER
);

ALTER TABLE telemetry ADD COLUMN raw_injection_count INTEGER DEFAULT 0;
ALTER TABLE telemetry ADD COLUMN is_laa_randomized INTEGER DEFAULT 0;
ALTER TABLE telemetry ADD COLUMN hardware_profile TEXT DEFAULT 'UNKNOWN';

ALTER TABLE incidents ADD COLUMN raw_injection_count INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN is_laa_randomized INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN hardware_profile TEXT DEFAULT 'UNKNOWN';
ALTER TABLE incidents ADD COLUMN remediation_advisory TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_telemetry_hardware ON telemetry(hardware_profile);

-- Synchronize telemetry_windows table
ALTER TABLE telemetry_windows ADD COLUMN raw_injection_count INTEGER DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN is_laa_randomized INTEGER DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN hardware_profile TEXT DEFAULT 'UNKNOWN';

CREATE INDEX IF NOT EXISTS idx_telemetry_windows_hardware ON telemetry_windows(hardware_profile);
CREATE INDEX IF NOT EXISTS idx_incidents_hardware ON incidents(hardware_profile);
