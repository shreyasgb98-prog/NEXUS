-- 008_add_hardware_whitelist.sql
-- Persists authorized access points in SQLite for hardware synchronization

CREATE TABLE IF NOT EXISTS hardware_whitelist (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    channel INTEGER DEFAULT 0,
    added_epoch_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hw_whitelist_bssid ON hardware_whitelist(bssid);
