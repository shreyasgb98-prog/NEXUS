-- Migration 003: Enriched RF Telemetry, Trusted AP Allowlist, and Structured Incident Management
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- 1. Enriched Telemetry Columns for telemetry_windows
ALTER TABLE telemetry_windows ADD COLUMN unique_bssids INTEGER DEFAULT 0;
ALTER TABLE telemetry_windows ADD COLUMN top_sources_json TEXT DEFAULT '[]';
ALTER TABLE telemetry_windows ADD COLUMN channel INTEGER DEFAULT 1;
ALTER TABLE telemetry_windows ADD COLUMN rssi_min REAL DEFAULT -90.0;
ALTER TABLE telemetry_windows ADD COLUMN rssi_max REAL DEFAULT -30.0;

CREATE INDEX IF NOT EXISTS idx_telemetry_channel_epoch ON telemetry_windows(channel, epoch_ms);

-- 2. Trusted Access Point Allowlist Table
CREATE TABLE IF NOT EXISTS trusted_aps (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    channel INTEGER NOT NULL,
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_trusted_aps_ssid ON trusted_aps(ssid);
CREATE INDEX IF NOT EXISTS idx_trusted_aps_active ON trusted_aps(is_active);

-- 3. Structured Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    start_epoch_ms INTEGER NOT NULL,
    end_epoch_ms INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    event_count INTEGER NOT NULL DEFAULT 1,
    associated_event_ids_json TEXT NOT NULL DEFAULT '[]',
    target_bssid TEXT,
    summary TEXT NOT NULL,
    analyst_notes TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_incidents_start_epoch ON incidents(start_epoch_ms);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_event_type ON incidents(event_type);

-- 4. Incident Timeline Events Table
CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    epoch_ms INTEGER NOT NULL,
    entry_type TEXT NOT NULL,
    detail TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_timeline_incident_epoch ON incident_timeline(incident_id, epoch_ms);
CREATE INDEX IF NOT EXISTS idx_timeline_epoch_ms ON incident_timeline(epoch_ms);
CREATE INDEX IF NOT EXISTS idx_timeline_entry_type ON incident_timeline(entry_type);
