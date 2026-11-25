-- Migration 009: Add updated_at to incidents table and raw_frames table
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS raw_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_ms INTEGER NOT NULL,
    payload TEXT
);

CREATE INDEX IF NOT EXISTS idx_raw_frames_epoch ON raw_frames(epoch_ms);

ALTER TABLE incidents ADD COLUMN updated_at INTEGER DEFAULT 0;
ALTER TABLE incidents ADD COLUMN remediation_steps TEXT DEFAULT '[]';
