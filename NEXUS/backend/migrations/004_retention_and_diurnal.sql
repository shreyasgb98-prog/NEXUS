-- Migration 004: Data Retention Pruning, Diurnal Baseline Tracking, and Evaluation Cache
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- 1. Diurnal Time-of-Day Feature Baseline Table
CREATE TABLE IF NOT EXISTS baseline_hourly (
    feature_name TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL CHECK (hour_of_day >= 0 AND hour_of_day <= 23),
    mean REAL NOT NULL DEFAULT 0.0,
    variance REAL NOT NULL DEFAULT 1.0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (feature_name, hour_of_day)
);

CREATE INDEX IF NOT EXISTS idx_baseline_hourly_feature ON baseline_hourly(feature_name);

-- 2. Evaluation Cache Table for Threshold Sweeps and Ablation Benchmarks
CREATE TABLE IF NOT EXISTS evaluation_cache (
    cache_key TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    generated_epoch_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eval_cache_epoch ON evaluation_cache(generated_epoch_ms);

-- 3. Telemetry Retention Cleanup Index
CREATE INDEX IF NOT EXISTS idx_telemetry_prune ON telemetry_windows(epoch_ms, is_attack_labelled);
