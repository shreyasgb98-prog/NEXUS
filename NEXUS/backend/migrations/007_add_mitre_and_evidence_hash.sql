-- 007_add_mitre_and_evidence_hash.sql
-- Persists MITRE ATT&CK technique IDs, tactics, and canonical SHA-256 evidence checksums

ALTER TABLE incidents ADD COLUMN mitre_technique_id TEXT DEFAULT 'T1200';
ALTER TABLE incidents ADD COLUMN mitre_technique_name TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN mitre_tactic TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN evidence_hash TEXT DEFAULT '';

ALTER TABLE alert_events ADD COLUMN mitre_technique_id TEXT DEFAULT 'T1200';
ALTER TABLE alert_events ADD COLUMN mitre_technique_name TEXT DEFAULT '';
ALTER TABLE alert_events ADD COLUMN mitre_tactic TEXT DEFAULT '';
ALTER TABLE alert_events ADD COLUMN evidence_hash TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_incidents_mitre_id ON incidents(mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_incidents_evidence_hash ON incidents(evidence_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_evidence_hash ON alert_events(evidence_hash);
