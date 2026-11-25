-- 005_add_forensic_attribution.sql
-- Adds attacker MAC fingerprinting, 802.11 reason codes, and physical proximity zones

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER,
    epoch_ms INTEGER
);

ALTER TABLE telemetry ADD COLUMN attacker_mac TEXT DEFAULT '';
ALTER TABLE telemetry ADD COLUMN target_mac TEXT DEFAULT '';
ALTER TABLE telemetry ADD COLUMN attacker_rssi INTEGER DEFAULT 0;
ALTER TABLE telemetry ADD COLUMN deauth_reason INTEGER DEFAULT 0;
ALTER TABLE telemetry ADD COLUMN proximity_zone TEXT DEFAULT 'NONE';

ALTER TABLE incidents ADD COLUMN attacker_mac TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN target_mac TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN attacker_rssi INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN tool_signature TEXT DEFAULT 'UNKNOWN';
ALTER TABLE incidents ADD COLUMN deauth_reason INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN proximity_zone TEXT DEFAULT 'NONE';

CREATE INDEX IF NOT EXISTS idx_telemetry_attacker ON telemetry(attacker_mac);
CREATE INDEX IF NOT EXISTS idx_incidents_attacker ON incidents(attacker_mac);

-- Synchronize telemetry_windows table
ALTER TABLE telemetry_windows ADD COLUMN attacker_mac TEXT DEFAULT '';
ALTER TABLE telemetry_windows ADD COLUMN target_mac TEXT DEFAULT '';
ALTER TABLE telemetry_windows ADD COLUMN attacker_rssi INTEGER DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN deauth_reason INTEGER DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN proximity_zone TEXT DEFAULT 'NONE';

CREATE INDEX IF NOT EXISTS idx_telemetry_windows_attacker ON telemetry_windows(attacker_mac);

-- Incident workflow columns
ALTER TABLE incidents ADD COLUMN id TEXT;
ALTER TABLE incidents ADD COLUMN start_window INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN last_window INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN last_epoch_ms INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN title TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN primary_type TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN confidence REAL DEFAULT 0.0;
ALTER TABLE incidents ADD COLUMN signals_involved_json TEXT DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_incidents_id ON incidents(id);
CREATE INDEX IF NOT EXISTS idx_incidents_primary_type ON incidents(primary_type);
CREATE INDEX IF NOT EXISTS idx_incidents_last_epoch ON incidents(last_epoch_ms);

-- Alert events threat intelligence columns
ALTER TABLE alert_events ADD COLUMN mitre_technique TEXT DEFAULT '';
ALTER TABLE alert_events ADD COLUMN owasp_category TEXT DEFAULT '';
ALTER TABLE alert_events ADD COLUMN suggested_action TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alert_events(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_alerts_owasp ON alert_events(owasp_category);
