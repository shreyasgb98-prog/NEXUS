import unittest
import tempfile
import os
import sys
import json
import time
from pathlib import Path
from unittest.mock import patch
import requests
from fastapi import HTTPException

# Ensure both local and repo-root import paths resolve
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
repo_root = backend_dir.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from app.config import (
        EWMA_ALPHA,
        Z_SCORE_THRESHOLD,
        STD_DEV_FLOOR,
        MIN_DEAUTH_COUNT,
        FIXED_DEAUTH_THRESHOLD,
        WARMUP_WINDOWS,
        CORRELATION_SPAN,
        EVENT_COOLDOWN_WINDOWS,
        DEFAULT_LLM_TIMEOUT_SEC
    )
    from app.baseline_model import AdaptiveBaselineEngine
    from app.correlation_engine import CorrelationEngine
    from app.evidence_builder import EvidenceBuilder
    from app.explainer import ExplainerEngine, DefensiveKnowledgeRetriever
    from app.rag_index import DefensiveRAGIndex
    from app.metrics_evaluator import compute_detector_metrics, compute_threshold_sweep, compute_ablation_analysis
    from app.incident_manager import IncidentManager
    from app.assistant import AskNexusAssistant
    from app.replay_engine import CSVReplayEngine
    from app.database import (
        get_connection,
        apply_migrations,
        insert_telemetry_window,
        insert_alert_event,
        insert_serial_error,
        save_baseline_state,
        save_baseline_metric,
        fetch_baseline_state,
        fetch_baseline_metrics,
        fetch_recent_telemetry,
        fetch_telemetry_rolling_window,
        fetch_all_telemetry,
        update_window_attack_label,
        update_window_range_attack_label,
        update_alert_explanation,
        fetch_alert_by_id,
        fetch_recent_alerts,
        fetch_alerts_rolling_window,
        fetch_all_alerts,
        fetch_windows_for_metrics,
        reset_telemetry_database,
        fetch_serial_error_counters,
        fetch_serial_error_count,
        query_alert_logs,
        insert_enriched_telemetry_window,
        fetch_trusted_aps,
        upsert_trusted_ap,
        bulk_learn_trusted_aps,
        create_incident,
        insert_incident_record,
        update_incident_status,
        fetch_active_incidents,
        fetch_incident_with_timeline,
        fetch_false_positive_stats,
        db_get_alerts,
        db_get_window,
        db_compare_detectors,
        db_get_baseline,
        db_link_health,
        prune_old_windows,
        prune_historical_telemetry,
        fetch_hourly_baseline,
        save_hourly_baseline,
        fetch_evaluation_windows,
        get_evaluation_cache,
        set_evaluation_cache,
        query_recent_incidents
    )
    from app.main import (
        process_telemetry_window,
        WindowIngestPayload,
        LabelWindowPayload,
        LabelRangePayload,
        LabelModePayload,
        get_system_status,
        ingest_telemetry_window,
        label_telemetry_window,
        label_telemetry_range,
        set_label_mode,
        get_detector_comparison,
        query_logs,
        export_events,
        export_telemetry,
        reset_telemetry_state,
        correlation_engine,
        learn_trusted_aps,
        get_trusted_aps,
        add_or_update_trusted_ap,
        get_incidents,
        change_incident_status,
        start_csv_replay,
        stop_csv_replay,
        get_csv_replay_status,
        get_evaluation_threshold_sweep,
        get_evaluation_ablation,
        prune_telemetry_endpoint,
        PrunePayload,
        verify_api_key,
        API_KEY,
        TrustedApPayload,
        IncidentStatusPayload,
        AssistantChatPayload,
        ReplayStartPayload,
        IncidentSyncPayload,
        sync_incident_endpoint,
        incident_manager,
        assistant_engine,
        replay_engine,
        baseline_engine
    )
except ImportError:
    from NEXUS.backend.app.config import (
        EWMA_ALPHA,
        Z_SCORE_THRESHOLD,
        STD_DEV_FLOOR,
        MIN_DEAUTH_COUNT,
        FIXED_DEAUTH_THRESHOLD,
        WARMUP_WINDOWS,
        CORRELATION_SPAN,
        EVENT_COOLDOWN_WINDOWS,
        DEFAULT_LLM_TIMEOUT_SEC
    )
    from NEXUS.backend.app.baseline_model import AdaptiveBaselineEngine
    from NEXUS.backend.app.correlation_engine import CorrelationEngine
    from NEXUS.backend.app.evidence_builder import EvidenceBuilder
    from NEXUS.backend.app.explainer import ExplainerEngine, DefensiveKnowledgeRetriever
    from NEXUS.backend.app.rag_index import DefensiveRAGIndex
    from NEXUS.backend.app.metrics_evaluator import (
        compute_detector_metrics,
        compute_threshold_sweep,
        compute_ablation_analysis
    )
    from NEXUS.backend.app.database import (
        get_connection,
        apply_migrations,
        insert_telemetry_window,
        insert_alert_event,
        insert_serial_error,
        save_baseline_state,
        save_baseline_metric,
        fetch_baseline_state,
        fetch_baseline_metrics,
        fetch_recent_telemetry,
        fetch_telemetry_rolling_window,
        fetch_all_telemetry,
        update_window_attack_label,
        update_window_range_attack_label,
        update_alert_explanation,
        fetch_alert_by_id,
        fetch_recent_alerts,
        fetch_alerts_rolling_window,
        fetch_all_alerts,
        fetch_windows_for_metrics,
        reset_telemetry_database,
        fetch_serial_error_counters,
        fetch_serial_error_count,
        query_alert_logs,
        insert_enriched_telemetry_window,
        fetch_trusted_aps,
        upsert_trusted_ap,
        bulk_learn_trusted_aps,
        create_incident,
        insert_incident_record,
        update_incident_status,
        fetch_active_incidents,
        fetch_incident_with_timeline,
        fetch_false_positive_stats,
        db_get_alerts,
        db_get_window,
        db_compare_detectors,
        db_get_baseline,
        db_link_health,
        prune_old_windows,
        prune_historical_telemetry,
        fetch_hourly_baseline,
        save_hourly_baseline,
        fetch_evaluation_windows,
        get_evaluation_cache,
        set_evaluation_cache,
        query_recent_incidents
    )
    from NEXUS.backend.app.main import (
        process_telemetry_window,
        WindowIngestPayload,
        LabelWindowPayload,
        LabelRangePayload,
        LabelModePayload,
        get_system_status,
        ingest_telemetry_window,
        label_telemetry_window,
        label_telemetry_range,
        set_label_mode,
        get_detector_comparison,
        query_logs,
        export_events,
        export_telemetry,
        reset_telemetry_state,
        correlation_engine,
        learn_trusted_aps,
        get_trusted_aps,
        add_or_update_trusted_ap,
        get_incidents,
        change_incident_status,
        start_csv_replay,
        stop_csv_replay,
        get_csv_replay_status,
        get_evaluation_threshold_sweep,
        get_evaluation_ablation,
        prune_telemetry_endpoint,
        PrunePayload,
        verify_api_key,
        API_KEY,
        TrustedApPayload,
        IncidentStatusPayload,
        AssistantChatPayload,
        ReplayStartPayload,
        IncidentSyncPayload,
        sync_incident_endpoint,
        incident_manager,
        assistant_engine,
        replay_engine,
        baseline_engine
    )

def generate_quiet_window(i: int) -> dict:
    return {
        "deauth": 1 if i % 7 == 0 else 0,
        "mgmt": 80 + ((3 * i) % 5) - 2,
        "ble": 25 + ((2 * i) % 5) - 2,
        "rogue": 0,
        "nfc": 0
    }

class TestTable62FunctionalVerification(unittest.TestCase):
    """Verifies all 8 functional test cases (TC-01 through TC-08) from Table 6.2 of the project report."""

    def setUp(self):
        self.engine = AdaptiveBaselineEngine(warmup_windows=30, z_threshold=3.5)
        self.correlation = CorrelationEngine(span=3, cooldown=8)

    def test_tc01_warmup_suppression(self):
        """TC-01: 30 quiet windows (warm-up). Expected: 0 flagged windows, 0 events."""
        flagged_count = 0
        events_count = 0

        for i in range(30):
            w = generate_quiet_window(i)
            res = self.engine.evaluate_window(w)
            if any(res["flags"].values()):
                flagged_count += 1
            ev = self.correlation.process(res)
            if ev is not None:
                events_count += 1

        self.assertEqual(flagged_count, 0)
        self.assertEqual(events_count, 0)
        self.assertFalse(self.engine.is_warmed_up)

    def test_tc02_post_warmup_quiet_stability(self):
        """TC-02: 20 further quiet windows (windows 31 to 50). Expected: 0 flagged windows, 0 events."""
        for i in range(30):
            res = self.engine.evaluate_window(generate_quiet_window(i))
            self.correlation.process(res)

        flagged_count = 0
        events_count = 0
        for i in range(30, 50):
            res = self.engine.evaluate_window(generate_quiet_window(i))
            self.assertTrue(self.engine.is_warmed_up)
            if any(res["flags"].values()):
                flagged_count += 1
            ev = self.correlation.process(res)
            if ev is not None:
                events_count += 1

        self.assertEqual(flagged_count, 0)
        self.assertEqual(events_count, 0)

    def test_tc03_and_tc04_deauth_burst_and_baseline_freeze(self):
        """TC-03: 5 burst windows (deauth=12, mgmt=110, ble=25).
        TC-04: Baseline deauth mean 0.196 before and after the burst."""
        for i in range(50):
            res = self.engine.evaluate_window(generate_quiet_window(i))
            self.correlation.process(res)

        pre_burst_deauth_mean = round(self.engine.baselines["deauth"].mean, 3)
        self.assertEqual(pre_burst_deauth_mean, 0.196)

        burst_events = []
        flags_fixed = []
        flags_adaptive = []
        flags_nexus = []

        for _ in range(5):
            burst_payload = {"deauth": 12, "mgmt": 110, "ble": 25, "rogue": 0, "nfc": 0}
            res = self.engine.evaluate_window(burst_payload)
            ev = self.correlation.process(res)
            if ev is not None:
                burst_events.append(ev)

            flags_fixed.append(1 if burst_payload["deauth"] >= FIXED_DEAUTH_THRESHOLD else 0)
            flags_adaptive.append(1 if any(res["flags"].values()) else 0)
            flags_nexus.append(1 if self.correlation.last_fire else 0)

        # TC-03 Assertions: 1 event, high severity, 0.99 confidence, 2 correlated signals
        self.assertEqual(len(burst_events), 1)
        ev0 = burst_events[0]
        self.assertEqual(ev0["event_type"], "Deauthentication burst")
        self.assertEqual(ev0["type_key"], "deauth")
        self.assertEqual(ev0["severity"], "high")
        self.assertEqual(ev0["confidence"], 0.99)
        self.assertEqual(ev0["signals_correlated"], 2)

        # Flagged in 5 of 5 windows across Fixed, Adaptive, and NEXUS detectors
        self.assertEqual(flags_fixed, [1, 1, 1, 1, 1])
        self.assertEqual(flags_adaptive, [1, 1, 1, 1, 1])
        self.assertEqual(flags_nexus, [1, 1, 1, 1, 1])

        # TC-04 Assertion: Baseline not contaminated by the burst
        post_burst_deauth_mean = round(self.engine.baselines["deauth"].mean, 3)
        self.assertEqual(post_burst_deauth_mean, 0.196)

    def test_tc05_rogue_access_point_direct_flag(self):
        """TC-05: 1 window with unknown BSSID under known SSID (rogue=1, mgmt=82).
        Expected: 1 event: Possible evil-twin access point, confidence 0.66, severity medium."""
        for i in range(35):
            self.correlation.process(self.engine.evaluate_window(generate_quiet_window(i)))

        rogue_payload = {"deauth": 0, "mgmt": 82, "ble": 25, "rogue": 1, "nfc": 0}
        eval_res = self.engine.evaluate_window(rogue_payload)
        ev = self.correlation.process(eval_res)

        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "Possible evil-twin access point")
        self.assertEqual(ev["type_key"], "rogue")
        self.assertEqual(ev["confidence"], 0.66)
        self.assertEqual(ev["severity"], "medium")

    def test_tc06_ble_advertisement_flood(self):
        """TC-06: 1 window with ble=170 (quiet level ~25).
        Expected: 1 event: BLE advertisement flood, confidence 0.85, severity high."""
        for i in range(35):
            self.correlation.process(self.engine.evaluate_window(generate_quiet_window(i)))

        ble_payload = {"deauth": 0, "mgmt": 80, "ble": 170, "rogue": 0, "nfc": 0}
        eval_res = self.engine.evaluate_window(ble_payload)
        ev = self.correlation.process(eval_res)

        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "BLE advertisement flood")
        self.assertEqual(ev["type_key"], "ble")
        self.assertEqual(ev["confidence"], 0.85)
        self.assertEqual(ev["severity"], "high")

    def test_tc07_single_moderate_deviation_suppressed_by_correlation(self):
        """TC-07: 1 window with ble=31 after 45 quiet windows (mean ~25.08, SD ~1.46, z=4.06).
        Expected: Adaptive detector flagged window; NEXUS detector did not; 0 new events."""
        for i in range(45):
            self.correlation.process(self.engine.evaluate_window(generate_quiet_window(i)))

        ble_mod_payload = {"deauth": 0, "mgmt": 80, "ble": 31, "rogue": 0, "nfc": 0}
        eval_res = self.engine.evaluate_window(ble_mod_payload)
        ev = self.correlation.process(eval_res)

        ble_metrics = eval_res["metrics"]["ble"]
        self.assertAlmostEqual(ble_metrics["baseline_mean"], 25.08, delta=0.05)
        self.assertAlmostEqual(ble_metrics["baseline_sd"], 1.46, delta=0.05)
        self.assertAlmostEqual(ble_metrics["z_score"], 4.06, delta=0.05)

        # Adaptive detector flagged the window
        self.assertTrue(eval_res["flags"]["ble"])
        # NEXUS detector suppressed event due to lack of corroboration
        self.assertFalse(self.correlation.last_fire)
        self.assertIsNone(ev)

    def test_tc08_nfc_read_counter_increment(self):
        """TC-08: 1 window with nfc = 1. Expected: NFC/RFID counter increments by 1."""
        status_before = get_system_status()
        nfc_before = status_before.get("nfc_reads", 0)

        ingest_res = ingest_telemetry_window(WindowIngestPayload(
            deauth=0,
            mgmt=80,
            ble=25,
            rogue=0,
            nfc=1,
            data_source="simulation"
        ))
        self.assertEqual(ingest_res["raw"]["nfc"], 1)

        status_after = get_system_status()
        self.assertEqual(status_after["nfc_reads"], nfc_before + 1)


class TestParallelDetectorEvaluationAndMetrics(unittest.TestCase):
    """Verifies live/labelled comparison metrics computation across Fixed, Adaptive, and NEXUS detectors."""

    def test_compute_detector_metrics_formulae(self):
        windows = []
        for w in range(1, 31):
            windows.append({
                "window_id": w,
                "is_attack_labelled": 0,
                "flag_fixed": 0,
                "flag_adaptive": 0,
                "flag_nexus": 0
            })

        for w in range(31, 41):
            windows.append({
                "window_id": w,
                "is_attack_labelled": 0,
                "flag_fixed": 0,
                "flag_adaptive": 1 if w == 35 else 0,
                "flag_nexus": 0
            })

        for w in range(41, 51):
            windows.append({
                "window_id": w,
                "is_attack_labelled": 1,
                "flag_fixed": 1 if w >= 43 else 0,
                "flag_adaptive": 1,
                "flag_nexus": 1
            })

        metrics = compute_detector_metrics(windows, warmup_windows=30)
        dets = metrics["detectors"]

        # Adaptive baseline
        self.assertEqual(dets["adaptive_baseline"]["tp"], 10)
        self.assertEqual(dets["adaptive_baseline"]["fp"], 1)
        self.assertEqual(dets["adaptive_baseline"]["fn"], 0)
        self.assertEqual(dets["adaptive_baseline"]["recall"], 1.0)
        self.assertAlmostEqual(dets["adaptive_baseline"]["precision"], round(10/11, 2))
        self.assertEqual(dets["adaptive_baseline"]["attacks_caught"], "1/1")
        self.assertEqual(dets["adaptive_baseline"]["latency_windows"], 0.0)

        # Fixed threshold
        self.assertEqual(dets["fixed_threshold"]["tp"], 8)
        self.assertEqual(dets["fixed_threshold"]["fp"], 0)
        self.assertEqual(dets["fixed_threshold"]["fn"], 2)
        self.assertEqual(dets["fixed_threshold"]["recall"], 0.8)
        self.assertEqual(dets["fixed_threshold"]["precision"], 1.0)
        self.assertEqual(dets["fixed_threshold"]["attacks_caught"], "1/1")
        self.assertEqual(dets["fixed_threshold"]["latency_windows"], 2.0)

        # NEXUS detector
        self.assertEqual(dets["nexus"]["tp"], 10)
        self.assertEqual(dets["nexus"]["fp"], 0)
        self.assertEqual(dets["nexus"]["recall"], 1.0)
        self.assertEqual(dets["nexus"]["precision"], 1.0)
        self.assertEqual(dets["nexus"]["f1"], 1.0)
        self.assertEqual(dets["nexus"]["fpr"], 0.0)
        self.assertEqual(dets["nexus"]["attacks_caught"], "1/1")
        self.assertEqual(dets["nexus"]["latency_windows"], 0.0)


class TestDatabaseLayer(unittest.TestCase):
    """Verifies SQLite3 WAL mode, pragmas, prepared statements, and migrations."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        apply_migrations(self.temp_db_path)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_connection_pragmas(self):
        conn = get_connection(self.temp_db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

        cursor.execute("PRAGMA synchronous;")
        synchronous = cursor.fetchone()[0]
        self.assertEqual(synchronous, 1)

        cursor.execute("PRAGMA foreign_keys;")
        foreign_keys = cursor.fetchone()[0]
        self.assertEqual(foreign_keys, 1)
        conn.close()

    def test_telemetry_windows_schema_and_fr_compliance(self):
        conn = get_connection(self.temp_db_path)
        row_id = insert_telemetry_window(
            conn,
            window_id=101,
            epoch_ms=1700000000000,
            deauth_count=14,
            mgmt_count=120,
            ble_count=35,
            rogue_count=0,
            nfc_count=1,
            rssi_mean=-68.5,
            data_source="simulation",
            is_attack_labelled=1,
            flag_fixed=1,
            flag_adaptive=1,
            flag_nexus=1,
            ewma_deauth_mean=0.5,
            ewma_deauth_var=0.25,
            ewma_mgmt_mean=90.0,
            ewma_mgmt_var=4.0,
            ewma_ble_mean=25.0,
            ewma_ble_var=2.0,
            ewma_rogue_mean=0.0,
            ewma_rogue_var=0.0,
            z_deauth=19.2,
            z_mgmt=15.0,
            z_ble=7.07,
            z_rogue=0.0
        )
        self.assertGreater(row_id, 0)

        rows = fetch_recent_telemetry(conn, limit=1)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["window_id"], 101)
        self.assertEqual(r["data_source"], "simulation")
        self.assertEqual(r["deauth_count"], 14)
        self.assertEqual(r["is_attack_labelled"], 1)
        self.assertEqual(r["flag_nexus"], 1)
        conn.close()

    def test_range_labelling_and_reset(self):
        conn = get_connection(self.temp_db_path)
        for w in range(1, 11):
            insert_telemetry_window(
                conn,
                window_id=w,
                epoch_ms=1700000000000 + w * 1000,
                deauth_count=0,
                mgmt_count=80,
                ble_count=25,
                rogue_count=0,
                nfc_count=0,
                is_attack_labelled=0
            )

        updated = update_window_range_attack_label(conn, start_window_id=3, end_window_id=7, is_attack_labelled=1)
        self.assertEqual(updated, 5)

        all_t = fetch_all_telemetry(conn)
        self.assertEqual(len(all_t), 10)
        labelled = [row for row in all_t if row["is_attack_labelled"] == 1]
        self.assertEqual(len(labelled), 5)

        reset_telemetry_database(conn)
        post_reset = fetch_all_telemetry(conn)
        self.assertEqual(len(post_reset), 0)
        conn.close()


class TestEnrichedDatabaseAndIncidentsLayer(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        apply_migrations(self.temp_db_path)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_migration_003_tables_and_indexes(self):
        conn = get_connection(self.temp_db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT version FROM schema_versions ORDER BY version ASC;")
        versions = [r["version"] for r in cursor.fetchall()]
        self.assertIn(3, versions)

        cursor.execute("PRAGMA table_info(telemetry_windows);")
        col_names = {r["name"] for r in cursor.fetchall()}
        for expected_col in ("unique_bssids", "top_sources_json", "channel", "rssi_min", "rssi_max"):
            self.assertIn(expected_col, col_names)

        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table';")
        table_names = {r["name"] for r in cursor.fetchall()}
        self.assertIn("trusted_aps", table_names)
        self.assertIn("incidents", table_names)
        self.assertIn("incident_timeline", table_names)

        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index';")
        index_names = {r["name"] for r in cursor.fetchall()}
        required_indexes = {
            "idx_telemetry_channel_epoch",
            "idx_trusted_aps_ssid",
            "idx_trusted_aps_active",
            "idx_incidents_start_epoch",
            "idx_incidents_status",
            "idx_incidents_event_type",
            "idx_timeline_incident_epoch"
        }
        for idx in required_indexes:
            self.assertIn(idx, index_names)

        conn.close()

    def test_enriched_telemetry_window_lifecycle(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        window_payload = {
            "window_id": 501,
            "epoch_ms": now_ms,
            "data_source": "live",
            "deauth_count": 8,
            "mgmt_count": 150,
            "ble_count": 42,
            "rogue_count": 0,
            "nfc_count": 0,
            "rssi_mean": -65.4,
            "unique_bssids": 7,
            "top_sources_json": [{"prefix": "AA:BB:CC", "count": 28}],
            "channel": 11,
            "rssi_min": -82.0,
            "rssi_max": -40.0,
            "is_attack_labelled": 1,
            "flag_fixed": 1,
            "flag_adaptive": 1,
            "flag_nexus": 1,
            "ewma_deauth_mean": 0.4,
            "ewma_deauth_var": 0.2,
            "z_deauth": 11.2
        }

        insert_enriched_telemetry_window(window_payload, conn=conn)

        fetched = db_get_window(501, conn=conn)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["window_id"], 501)
        self.assertEqual(fetched["channel"], 11)
        self.assertEqual(fetched["unique_bssids"], 7)
        self.assertAlmostEqual(fetched["rssi_min"], -82.0)
        self.assertAlmostEqual(fetched["rssi_max"], -40.0)
        self.assertIn("AA:BB:CC", fetched["top_sources_json"])

        conn.close()

    def test_trusted_aps_operations(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        upsert_trusted_ap(
            bssid="00:11:22:aa:bb:cc",
            ssid="Campus_Secure_AP",
            channel=6,
            epoch_ms=now_ms,
            conn=conn
        )

        aps = fetch_trusted_aps(conn=conn)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0]["bssid"], "00:11:22:AA:BB:CC")
        self.assertEqual(aps[0]["channel"], 6)

        upsert_trusted_ap(
            bssid="00:11:22:AA:BB:CC",
            ssid="Campus_Secure_AP",
            channel=11,
            epoch_ms=now_ms + 5000,
            conn=conn
        )
        aps_updated = fetch_trusted_aps(conn=conn)
        self.assertEqual(len(aps_updated), 1)
        self.assertEqual(aps_updated[0]["channel"], 11)

        batch_aps = [
            {"bssid": "11:22:33:44:55:66", "ssid": "Office_WiFi_1", "channel": 1},
            {"bssid": "22:33:44:55:66:77", "ssid": "Office_WiFi_2", "channel": 6}
        ]
        count = bulk_learn_trusted_aps(batch_aps, conn=conn)
        self.assertEqual(count, 2)

        all_trusted = fetch_trusted_aps(conn=conn)
        self.assertEqual(len(all_trusted), 3)

        conn.close()

    def test_incident_workflow_and_feedback(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        incident_id = create_incident({
            "incident_id": "INC-20261120-001",
            "start_epoch_ms": now_ms,
            "end_epoch_ms": now_ms,
            "event_type": "DEAUTH_FLOOD",
            "severity": "HIGH",
            "status": "OPEN",
            "event_count": 3,
            "associated_event_ids_json": ["EV-001", "EV-002", "EV-003"],
            "target_bssid": "34:85:18:99:A1:C0",
            "summary": "Coordinated deauthentication burst exceeding threshold"
        }, conn=conn)

        self.assertEqual(incident_id, "INC-20261120-001")

        active = fetch_active_incidents(conn=conn)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["incident_id"], "INC-20261120-001")
        self.assertEqual(active[0]["status"], "OPEN")

        ok_ack = update_incident_status(
            incident_id="INC-20261120-001",
            new_status="ACKNOWLEDGED",
            note="Investigating channel 6 interference",
            epoch_ms=now_ms + 1000,
            conn=conn
        )
        self.assertTrue(ok_ack)

        ok_fp = update_incident_status(
            incident_id="INC-20261120-001",
            new_status="FALSE_POSITIVE",
            note="Authorized roaming stress test verified",
            epoch_ms=now_ms + 2000,
            conn=conn
        )
        self.assertTrue(ok_fp)

        inc_record = fetch_incident_with_timeline("INC-20261120-001", conn=conn)
        self.assertEqual(inc_record["status"], "FALSE_POSITIVE")
        self.assertIn("Authorized roaming stress test", inc_record["analyst_notes"])

        timeline = inc_record["timeline"]
        self.assertGreaterEqual(len(timeline), 3)
        entry_types = [t["entry_type"] for t in timeline]
        self.assertIn("ALERT_TRIGGERED", entry_types)
        self.assertIn("STATUS_CHANGE", entry_types)
        self.assertIn("ANALYST_NOTE", entry_types)

        fp_stats = fetch_false_positive_stats(conn=conn)
        self.assertEqual(fp_stats["total_incidents"], 1)
        self.assertEqual(fp_stats["false_positive_count"], 1)
        self.assertEqual(fp_stats["false_positive_rate"], 1.0)
        self.assertEqual(len(fp_stats["by_event_type"]), 1)
        self.assertEqual(fp_stats["by_event_type"][0]["event_type"], "DEAUTH_FLOOD")

        conn.close()

    def test_streaming_llm_query_functions(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        for wid in range(1, 16):
            insert_enriched_telemetry_window({
                "window_id": wid,
                "epoch_ms": now_ms - ((20 - wid) * 1000),
                "data_source": "live",
                "deauth_count": 10 if wid in (5, 10, 15) else 0,
                "mgmt_count": 120 if wid in (5, 10, 15) else 80,
                "ble_count": 30,
                "rogue_count": 0,
                "nfc_count": 0,
                "rssi_mean": -68.0,
                "flag_fixed": 1 if wid in (5, 10, 15) else 0,
                "flag_adaptive": 1 if wid in (5, 8, 10, 15) else 0,
                "flag_nexus": 1 if wid in (5, 10, 15) else 0
            }, conn=conn)

        insert_alert_event(
            conn=conn,
            event_id="EV-101",
            window_id=10,
            epoch_ms=now_ms - 5000,
            type_key="deauth",
            event_type="Deauthentication burst",
            severity="high",
            confidence=0.99,
            signals_correlated=2,
            data_source="live",
            evidence_json='{"signals_correlated": 2}',
            explanation="802.11 deauth burst detected"
        )

        alerts_all = db_get_alerts(time_range_seconds=3600, conn=conn)
        self.assertEqual(len(alerts_all), 1)

        alerts_filtered = db_get_alerts(time_range_seconds=3600, alert_type="deauth", conn=conn)
        self.assertEqual(len(alerts_filtered), 1)

        alerts_empty = db_get_alerts(time_range_seconds=3600, alert_type="rogue", conn=conn)
        self.assertEqual(len(alerts_empty), 0)

        comparison = db_compare_detectors(limit=20, conn=conn)
        self.assertEqual(comparison["windows_evaluated"], 15)
        self.assertEqual(comparison["counts"]["fixed_detector"], 3)
        self.assertEqual(comparison["counts"]["adaptive_detector"], 4)
        self.assertEqual(comparison["counts"]["nexus_detector"], 3)
        self.assertEqual(comparison["overlaps"]["fixed_and_nexus"], 3)

        save_baseline_state(conn, alpha=0.9, z_threshold=3.5, warmup_windows=30, processed_windows=15, updated_epoch_ms=now_ms)
        save_baseline_metric(conn, feature_name="deauth", mean=0.2, variance=0.1, std_dev=0.7, updated_epoch_ms=now_ms)

        base_deauth = db_get_baseline("deauth", conn=conn)
        self.assertIsNotNone(base_deauth)
        self.assertEqual(base_deauth["feature_name"], "deauth")
        self.assertEqual(base_deauth["alpha"], 0.9)
        self.assertEqual(base_deauth["z_threshold"], 3.5)

        insert_serial_error(conn, epoch_ms=now_ms, error_type="MALFORMED_FRAME_DROP", raw_payload="bad_line")
        health = db_link_health(conn=conn)
        self.assertIn("status", health)
        self.assertIn("dropped_frames", health)
        self.assertEqual(health["dropped_frames"], 1)
        self.assertEqual(health["continuity_gaps_detected"], 0)

        conn.close()

    def test_retention_pruning(self):
        conn = get_connection(self.temp_db_path)
        cutoff_ms = 1700000050000

        # Window 1: Old, unlabelled, no alert -> should be pruned
        insert_telemetry_window(conn, window_id=1, epoch_ms=cutoff_ms - 20000, deauth_count=0, mgmt_count=50, ble_count=10, rogue_count=0, nfc_count=0, is_attack_labelled=0)
        # Window 2: Old, unlabelled, but has alert -> MUST NOT be pruned
        insert_telemetry_window(conn, window_id=2, epoch_ms=cutoff_ms - 15000, deauth_count=10, mgmt_count=120, ble_count=20, rogue_count=0, nfc_count=0, is_attack_labelled=0)
        insert_alert_event(conn, event_id="EV-RET-01", window_id=2, epoch_ms=cutoff_ms - 15000, type_key="deauth", event_type="Deauth", severity="high", confidence=0.95, signals_correlated=1, data_source="live", evidence_json="{}", explanation="Alert test")
        # Window 3: Old, labelled as attack -> MUST NOT be pruned
        insert_telemetry_window(conn, window_id=3, epoch_ms=cutoff_ms - 10000, deauth_count=12, mgmt_count=100, ble_count=20, rogue_count=0, nfc_count=0, is_attack_labelled=1)
        # Window 4: Newer than cutoff -> MUST NOT be pruned
        insert_telemetry_window(conn, window_id=4, epoch_ms=cutoff_ms + 5000, deauth_count=0, mgmt_count=60, ble_count=15, rogue_count=0, nfc_count=0, is_attack_labelled=0)

        pruned = prune_old_windows(cutoff_ms, conn=conn)
        self.assertEqual(pruned, 1)

        remaining_wins = [w["window_id"] for w in fetch_all_telemetry(conn)]
        self.assertNotIn(1, remaining_wins)
        self.assertIn(2, remaining_wins)
        self.assertIn(3, remaining_wins)
        self.assertIn(4, remaining_wins)

        conn.close()

    def test_diurnal_hourly_baseline(self):
        conn = get_connection(self.temp_db_path)

        save_hourly_baseline("deauth", hour_of_day=14, mean=0.35, variance=0.12, count=120, conn=conn)
        record = fetch_hourly_baseline("deauth", hour_of_day=14, conn=conn)
        self.assertIsNotNone(record)
        self.assertEqual(record["feature_name"], "deauth")
        self.assertEqual(record["hour_of_day"], 14)
        self.assertAlmostEqual(record["mean"], 0.35)
        self.assertAlmostEqual(record["variance"], 0.12)
        self.assertEqual(record["sample_count"], 120)

        save_hourly_baseline("deauth", hour_of_day=14, mean=0.40, variance=0.15, count=130, conn=conn)
        record_updated = fetch_hourly_baseline("deauth", hour_of_day=14, conn=conn)
        self.assertAlmostEqual(record_updated["mean"], 0.40)
        self.assertEqual(record_updated["sample_count"], 130)

        none_record = fetch_hourly_baseline("deauth", hour_of_day=3, conn=conn)
        self.assertIsNone(none_record)

        conn.close()

    def test_evaluation_cache_and_queries(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        insert_telemetry_window(conn, window_id=201, epoch_ms=now_ms, deauth_count=1, mgmt_count=50, ble_count=10, rogue_count=0, nfc_count=0, data_source="eval_set", is_attack_labelled=0)
        insert_telemetry_window(conn, window_id=202, epoch_ms=now_ms + 1000, deauth_count=12, mgmt_count=110, ble_count=10, rogue_count=0, nfc_count=0, data_source="eval_set", is_attack_labelled=1)

        eval_all = fetch_evaluation_windows(data_source="eval_set", conn=conn)
        self.assertEqual(len(eval_all), 2)

        eval_labelled = fetch_evaluation_windows(data_source="eval_set", only_labelled=True, conn=conn)
        self.assertEqual(len(eval_labelled), 1)
        self.assertEqual(eval_labelled[0]["window_id"], 202)

        cache_payload = json.dumps({"f1": 0.98, "precision": 1.0, "recall": 0.96})
        set_evaluation_cache("ablation_run_01", cache_payload, now_ms, conn=conn)

        cached_item = get_evaluation_cache("ablation_run_01", conn=conn)
        self.assertIsNotNone(cached_item)
        self.assertEqual(cached_item["cache_key"], "ablation_run_01")
        self.assertEqual(cached_item["data"]["f1"], 0.98)
        self.assertEqual(cached_item["generated_epoch_ms"], now_ms)

        self.assertIsNone(get_evaluation_cache("non_existent_key", conn=conn))

        conn.close()

    def test_insert_alert_event_dict_and_threat_metadata(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        # Insert telemetry window so foreign key succeeds
        insert_telemetry_window(
            conn,
            window_id=701,
            epoch_ms=now_ms,
            deauth_count=18,
            mgmt_count=130,
            ble_count=20,
            rogue_count=0,
            nfc_count=0,
            is_attack_labelled=1
        )

        alert_payload = {
            "id": "EV-THREAT-01",
            "window_id": 701,
            "epoch_ms": now_ms,
            "event_type": "Deauthentication Flood",
            "severity": "HIGH",
            "confidence": 0.99,
            "signals_correlated": 2,
            "evidence_json": json.dumps({"deauth_z": 18.2, "mgmt_z": 8.1}),
            "mitre_technique": "T1499.001",
            "owasp_category": "W01",
            "suggested_action": "Enforce 802.11w Protected Management Frames"
        }

        row_id = insert_alert_event(alert_payload, conn=conn)
        self.assertGreater(row_id, 0)

        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, window_id, epoch_ms, event_type, severity, confidence, "
            "       signals_correlated, evidence_json, mitre_technique, owasp_category, suggested_action "
            "FROM alert_events WHERE event_id = ?;",
            ("EV-THREAT-01",)
        )
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["window_id"], 701)
        self.assertEqual(row["event_type"], "Deauthentication Flood")
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["confidence"], 0.99)
        self.assertEqual(row["signals_correlated"], 2)
        self.assertEqual(row["mitre_technique"], "T1499.001")
        self.assertEqual(row["owasp_category"], "W01")
        self.assertEqual(row["suggested_action"], "Enforce 802.11w Protected Management Frames")

        conn.close()

    def test_insert_incident_record_columns(self):
        conn = get_connection(self.temp_db_path)
        now_ms = int(time.time() * 1000)

        inc_payload = {
            "id": "INC-TEST-001",
            "start_window": 105,
            "last_window": 109,
            "start_epoch_ms": now_ms - 4000,
            "last_epoch_ms": now_ms,
            "title": "Correlated Deauth Burst and Evil-Twin AP",
            "primary_type": "MULTI_VECTOR",
            "severity": "HIGH",
            "confidence": 0.97,
            "status": "OPEN",
            "event_count": 4,
            "signals_involved_json": json.dumps(["deauth", "rogue_ap"])
        }

        created_id = insert_incident_record(inc_payload, conn=conn)
        self.assertEqual(created_id, "INC-TEST-001")

        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, start_window, last_window, start_epoch_ms, last_epoch_ms, "
            "       title, primary_type, severity, confidence, status, event_count, signals_involved_json "
            "FROM incidents WHERE id = ?;",
            ("INC-TEST-001",)
        )
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "INC-TEST-001")
        self.assertEqual(row["start_window"], 105)
        self.assertEqual(row["last_window"], 109)
        self.assertEqual(row["start_epoch_ms"], now_ms - 4000)
        self.assertEqual(row["last_epoch_ms"], now_ms)
        self.assertEqual(row["title"], "Correlated Deauth Burst and Evil-Twin AP")
        self.assertEqual(row["primary_type"], "MULTI_VECTOR")
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["confidence"], 0.97)
        self.assertEqual(row["status"], "OPEN")
        self.assertEqual(row["event_count"], 4)
        self.assertIn("rogue_ap", row["signals_involved_json"])

        conn.close()


class TestExplainerLayer(unittest.TestCase):
    """Verifies rule-based grounded explanations, knowledge retrieval, and LLM fallback."""

    def setUp(self):
        self.explainer = ExplainerEngine()
        self.rag_index = DefensiveRAGIndex()

    def test_rule_based_deauth_explanation_formatting(self):
        evidence = {
            "features": [
                {"feature": "deauth", "observed": 13, "baseline_mean": 0.6, "baseline_sd": 0.7, "z_score": 17.71},
                {"feature": "mgmt", "observed": 141, "baseline_mean": 96.91, "baseline_sd": 7.94, "z_score": 7.94}
            ],
            "signals_correlated": 2
        }
        text = self.explainer.generate_rule_explanation("Deauthentication burst", evidence)
        self.assertIn("802.11 deauthentication frames", text)
        self.assertIn("deauth was 13 against a baseline of 0.6 (z = 17.71)", text)
        self.assertIn("mgmt was 141 against a baseline of 96.91 (z = 7.94)", text)
        self.assertIn("802.11w Protected Management Frames", text)

    def test_rag_retrieval_all_categories(self):
        # 1. Deauth retrieval
        docs_deauth = self.rag_index.search("deauthentication flood wireless", top_k=2)
        self.assertGreater(len(docs_deauth), 0)
        self.assertTrue(any("T1499" in d["id"] or "80211W" in d["id"] for d in docs_deauth))

        # 2. Rogue AP / Evil-Twin retrieval
        docs_rogue = self.rag_index.search("evil-twin access point rogue SSID", top_k=2)
        self.assertGreater(len(docs_rogue), 0)
        self.assertTrue(any("T1584" in d["id"] or "T1557" in d["id"] or "ROGUE" in d["id"] for d in docs_rogue))

        # 3. BLE flooding retrieval
        docs_ble = self.rag_index.search("BLE advertisement flooding radio channels", top_k=1)
        self.assertEqual(len(docs_ble), 1)
        self.assertIn("BLE", docs_ble[0]["id"])

        # 4. NFC/RFID skimming retrieval
        docs_nfc = self.rag_index.search("NFC RFID tag skimming interrogation replay", top_k=1)
        self.assertEqual(len(docs_nfc), 1)
        self.assertIn("NFC", docs_nfc[0]["id"])

    def test_generate_rag_explanation_ollama_mocked(self):
        evidence = {
            "features": [{"feature": "deauth", "observed": 14, "baseline_mean": 0.5, "baseline_sd": 0.7, "z_score": 19.2}],
            "signals_correlated": 1
        }
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = json.dumps({"response": "Anomalous deauth flood observed. Enforce 802.11w PMF."}).encode("utf-8")

        with patch("requests.post", return_value=mock_resp):
            res = self.explainer.generate_rag_explanation("Deauthentication burst", evidence, model="llama3.2")
            self.assertEqual(res["source"], "ollama")
            self.assertEqual(res["model"], "llama3.2")
            self.assertIn("Anomalous deauth flood", res["explanation"])
            self.assertGreater(len(res["retrieved_refs"]), 0)
            self.assertTrue(any("T1499" in r["id"] or "80211W" in r["id"] for r in res["retrieved_refs"]))

    def test_generate_llm_explanation_mocked(self):
        evidence = {
            "features": [{"feature": "rogue", "observed": 1, "baseline_mean": 0.0, "baseline_sd": 0.7, "z_score": 1.43}],
            "signals_correlated": 1
        }
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = json.dumps({
            "response": "Rogue AP impersonation detected. Deploy 802.1X EAP-TLS."
        }).encode("utf-8")

        with patch("requests.post", return_value=mock_resp):
            res = self.explainer.generate_llm_explanation("Possible evil-twin access point", evidence)
            self.assertEqual(res["source"], "ollama")
            self.assertIn("Rogue AP impersonation", res["explanation"])
            self.assertEqual(len(res["retrieved_refs"]), 0)

    def test_generate_rag_explanation_offline_fallback(self):
        evidence = {
            "features": [{"feature": "ble", "observed": 180, "baseline_mean": 25.0, "baseline_sd": 2.0, "z_score": 77.5}],
            "signals_correlated": 1
        }
        with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Offline")):
            res = self.explainer.generate_rag_explanation("BLE advertisement flood", evidence)
            self.assertEqual(res["source"], "rule_based_fallback")
            self.assertIn("Bluetooth Low Energy", res["explanation"])
            self.assertIn("ble was 180 against a baseline of 25.0", res["explanation"])
            self.assertGreater(len(res["retrieved_refs"]), 0)

    def test_guardrail_prompt_structure(self):
        evidence = {
            "features": [{"feature": "deauth", "observed": 12, "baseline_mean": 0.2, "baseline_sd": 0.7, "z_score": 16.86}],
            "signals_correlated": 1
        }
        captured_payloads = []

        def capture_post(url, json=None, *args, **kwargs):
            if json:
                captured_payloads.append(json)
            raise requests.exceptions.ConnectionError("Offline")

        with patch("requests.post", side_effect=capture_post):
            self.explainer.generate_rag_explanation("Deauthentication burst", evidence)

        self.assertGreater(len(captured_payloads), 0)
        prompt_str = captured_payloads[0].get("prompt", "")
        # Verify strict guardrails present in prompt
        self.assertIn("NEXUS AI defensive security explainer", prompt_str)
        self.assertIn("You do NOT decide whether an attack occurred", prompt_str)
        self.assertIn("Do NOT invent numbers", prompt_str)
        self.assertIn("16.86", prompt_str) # Evidence z-score present
        self.assertIn("T1499", prompt_str) # Retrieved MITRE reference present

    def test_explainer_default_timeout_is_60_seconds(self):
        self.assertEqual(DEFAULT_LLM_TIMEOUT_SEC, 60.0)
        self.assertEqual(self.explainer.timeout, 60.0)

    def test_rag_explanation_with_operator_question_mocked(self):
        evidence = {
            "features": [{"feature": "deauth", "observed": 14, "baseline_mean": 0.5, "baseline_sd": 0.7, "z_score": 19.2}],
            "signals_correlated": 1
        }
        captured_payloads = []
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = json.dumps({
            "response": "Passive telemetry observed 14 deauth frames against 0.5 baseline. Credentials cannot be inferred."
        }).encode("utf-8")

        def capture_post(url, json=None, *args, **kwargs):
            if json:
                captured_payloads.append(json)
            return mock_resp

        with patch("requests.post", side_effect=capture_post):
            res = self.explainer.generate_rag_explanation(
                "Deauthentication burst",
                evidence,
                question="Are my network credentials stolen?"
            )

        self.assertEqual(res["source"], "ollama")
        self.assertEqual(res["question"], "Are my network credentials stolen?")
        self.assertIn("Credentials cannot be inferred", res["explanation"])

        # Verify question and strict guardrail instructions in prompt
        self.assertGreater(len(captured_payloads), 0)
        prompt_str = captured_payloads[0].get("prompt", "")
        self.assertIn("Operator Question:\nAre my network credentials stolen?", prompt_str)
        self.assertIn("refuse to speculate beyond the measured observations", prompt_str)

    def test_rag_explanation_with_operator_question_fallback(self):
        evidence = {
            "features": [{"feature": "rogue", "observed": 1, "baseline_mean": 0.0, "baseline_sd": 0.7, "z_score": 1.43}],
            "signals_correlated": 1
        }
        with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Offline")):
            res = self.explainer.generate_rag_explanation(
                "Possible evil-twin access point",
                evidence,
                question="Which client connected to the rogue AP?"
            )

        self.assertEqual(res["source"], "rule_based_fallback")
        self.assertEqual(res["question"], "Which client connected to the rogue AP?")
        self.assertIn("Operator Question Response", res["explanation"])
        self.assertIn("Speculation beyond measured passive telemetry is refused", res["explanation"])


class TestRestAndExportEndpoints(unittest.TestCase):
    """Verifies REST logic for ingestion, labelling, detector comparison, and JSON/CSV export (FR-11)."""

    def setUp(self):
        reset_telemetry_state()

    def test_window_ingest_and_comparison_api(self):
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**{**generate_quiet_window(i), "data_source": "live"}))

        set_label_mode(LabelModePayload(active=True))
        self.assertTrue(get_system_status()["active_labelling"])

        for _ in range(5):
            ingest_telemetry_window(WindowIngestPayload(
                deauth=14,
                mgmt=120,
                ble=25,
                rogue=0,
                nfc=0,
                data_source="live"
            ))

        set_label_mode(LabelModePayload(active=False))

        metrics = get_detector_comparison()
        self.assertIn("detectors", metrics)
        nexus_det = metrics["detectors"]["nexus"]
        self.assertEqual(nexus_det["attacks_caught"], "1/1")
        self.assertEqual(nexus_det["tp"], 5)
        self.assertEqual(nexus_det["recall"], 1.0)

    def test_export_events_and_telemetry_csv_json(self):
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**{**generate_quiet_window(i), "data_source": "live"}))

        ingest_telemetry_window(WindowIngestPayload(
            deauth=15,
            mgmt=130,
            ble=25,
            rogue=0,
            nfc=0,
            data_source="live"
        ))

        # 1. Export events JSON
        r_ev_json = export_events(format="json")
        self.assertEqual(r_ev_json.media_type, "application/json")
        events_data = eval(r_ev_json.body.decode("utf-8")) if hasattr(r_ev_json, "body") else []
        self.assertGreater(len(events_data), 0)

        # 2. Export events CSV
        r_ev_csv = export_events(format="csv")
        self.assertEqual(r_ev_csv.media_type, "text/csv")
        csv_text = r_ev_csv.body.decode("utf-8") if hasattr(r_ev_csv, "body") else ""
        self.assertIn("event_id,window_id", csv_text)

        # 3. Export telemetry CSV
        r_tel_csv = export_telemetry(format="csv")
        self.assertEqual(r_tel_csv.media_type, "text/csv")
        csv_tel_text = r_tel_csv.body.decode("utf-8") if hasattr(r_tel_csv, "body") else ""
        self.assertIn("window_id,epoch_ms,data_source,deauth", csv_tel_text)

    def test_telemetry_ingest_frontend_payload_and_wal_persistence(self):
        frontend_payload = WindowIngestPayload(
            window_id=105,
            deauth=12,
            mgmt=90,
            ble=20,
            rogue=1,
            nfc=1,
            ch=6,
            bssid_cnt=4,
            rssi_min=-85.0,
            rssi_avg=-68.0,
            rssi_max=-55.0,
            top=[{"bssid": "00:11:22:33:44:55", "ssid": "TestNet", "ch": 6}],
            data_source="live"
        )
        result = ingest_telemetry_window(frontend_payload)
        self.assertEqual(result["window_id"], 105)
        self.assertIn("raw", result)
        self.assertEqual(result["raw"]["window_id"], 105)

        # Verify record in SQLite telemetry_windows table
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, "
            "rogue_count, nfc_count, rssi_mean, channel, unique_bssids, top_sources_json "
            "FROM telemetry_windows WHERE window_id = 105;"
        )
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["window_id"], 105)
        self.assertEqual(row["deauth_count"], 12)
        self.assertEqual(row["mgmt_count"], 90)
        self.assertEqual(row["ble_count"], 20)
        self.assertEqual(row["rogue_count"], 1)
        self.assertEqual(row["nfc_count"], 1)
        self.assertEqual(row["channel"], 6)
        self.assertEqual(row["unique_bssids"], 4)
        self.assertAlmostEqual(row["rssi_mean"], -68.0, places=1)
        self.assertIn("00:11:22:33:44:55", row["top_sources_json"])

    def test_telemetry_reset_clears_database_and_returns_ok(self):
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**{**generate_quiet_window(i), "data_source": "live"}))

        burst = ingest_telemetry_window(WindowIngestPayload(
            deauth=16,
            mgmt=110,
            ble=25,
            rogue=0,
            nfc=0,
            data_source="live"
        ))
        self.assertIsNotNone(burst.get("alert"))

        # Verify tables have records before reset
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(id) AS cnt FROM telemetry_windows;")
        self.assertGreater(cur.fetchone()["cnt"], 0)
        cur.execute("SELECT COUNT(id) AS cnt FROM alert_events;")
        self.assertGreater(cur.fetchone()["cnt"], 0)
        conn.close()

        # Reset telemetry state and database
        reset_res = reset_telemetry_state()
        self.assertEqual(reset_res, {"status": "database_reset_ok"})

        # Verify all tables cleared
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(id) AS cnt FROM telemetry_windows;")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        cur.execute("SELECT COUNT(id) AS cnt FROM alert_events;")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        cur.execute("SELECT COUNT(incident_id) AS cnt FROM incidents;")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        conn.close()

    def test_telemetry_ingest_auth_default_header(self):
        # Default header value passes (returns None without exception)
        self.assertIsNone(verify_api_key())
        self.assertIsNone(verify_api_key("nexus-local-dev-token"))

        # Invalid header raises 401
        with self.assertRaises(HTTPException) as ctx:
            verify_api_key("invalid_key_attempt")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_incident_sync_endpoint_and_copilot_ingestion(self):
        reset_telemetry_state()

        sync_payload = IncidentSyncPayload(
            alert={
                "id": "EVT-SIM-999",
                "window": 55,
                "event_type": "Deauthentication Flood Attack",
                "severity": "high",
                "confidence": 0.95,
                "signals_correlated": 2,
                "data_source": "simulation",
                "evidence": {"features": [{"feature": "deauth", "observed": 18, "baseline_mean": 0.5, "z_score": 12.4}]}
            },
            incident={
                "id": "INC-SIM-888",
                "title": "Simulated Rogue Access Point Incident",
                "primary_type": "ROGUE_AP",
                "severity": "HIGH",
                "confidence": 0.92,
                "status": "OPEN",
                "start_epoch_ms": int(time.time() * 1000),
                "event_count": 1
            }
        )
        res = sync_incident_endpoint(sync_payload)
        self.assertEqual(res["status"], "synchronized")
        self.assertEqual(res["alert_id"], "EVT-SIM-999")
        self.assertEqual(res["incident_id"], "INC-SIM-888")

        # Verify window mapping persisted into SQLite nexus.db as window 55
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT window_id FROM alert_events WHERE event_id = 'EVT-SIM-999';")
        alert_row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(alert_row)
        self.assertEqual(alert_row["window_id"], 55)

        # Verify recent incidents tool reflects synced simulation incidents
        recent = query_recent_incidents(limit=5)
        self.assertTrue(any(r["id"] == "INC-SIM-888" for r in recent))
        matching = next(r for r in recent if r["id"] == "INC-SIM-888")
        self.assertEqual(matching["title"], "Simulated Rogue Access Point Incident")
        self.assertEqual(matching["primary_type"], "ROGUE_AP")
        self.assertEqual(matching["severity"], "HIGH")
        self.assertEqual(matching["status"], "OPEN")
        self.assertEqual(matching["event_count"], 1)

        # Verify Copilot ingestion for "Why was the last alert raised?"
        intent, data = assistant_engine.route_query("Why was the last alert raised?")
        self.assertEqual(intent, "alerts_and_incident")
        self.assertTrue(any(a["event_id"] == "EVT-SIM-999" for a in data.get("recent_alerts_300s", [])))
        self.assertTrue(any(i["id"] == "INC-SIM-888" for i in data.get("recent_incidents", [])))

        deterministic_resp = assistant_engine.generate_deterministic_response(intent, data)
        self.assertIn("EVT-SIM-999", deterministic_resp)
        self.assertIn("window 55", deterministic_resp)

    def test_logs_query_endpoint(self):
        # 1. Populate windows and multiple alert events
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**{**generate_quiet_window(i), "data_source": "live"}))

        # Alert 1: Deauth burst
        r1 = ingest_telemetry_window(WindowIngestPayload(
            deauth=14,
            mgmt=120,
            ble=25,
            rogue=0,
            nfc=0,
            data_source="live"
        ))
        # Clear cooldown to allow Alert 2
        correlation_engine.last_event_window = -999

        # Alert 2: Rogue AP
        r2 = ingest_telemetry_window(WindowIngestPayload(
            deauth=0,
            mgmt=82,
            ble=25,
            rogue=1,
            nfc=0,
            data_source="live"
        ))

        # Query 1: Filter by query string `q="evil-twin"`
        q_results = query_logs(q="evil-twin")
        self.assertGreater(len(q_results), 0)
        for row in q_results:
            self.assertIn("evil-twin", row["event_type"].lower())

        # Query 2: Filter by severity
        high_results = query_logs(severity="high")
        self.assertGreater(len(high_results), 0)
        for row in high_results:
            self.assertEqual(row["severity"], "high")

        # Query 3: Filter by data_source
        sim_results = query_logs(data_source="simulation")
        self.assertGreater(len(sim_results), 0)
        for row in sim_results:
            self.assertEqual(row["data_source"], "simulation")

        # Query 4: Filter by limit
        lim_results = query_logs(limit=1)
        self.assertEqual(len(lim_results), 1)

        # Query 5: Filter by window_id
        target_win = r1["window_id"]
        win_results = query_logs(window_id=target_win)
        self.assertGreater(len(win_results), 0)
        self.assertEqual(win_results[0]["window_id"], target_win)


class TestNexusAssistantAndAdvancedEngines(unittest.TestCase):
    def setUp(self):
        reset_telemetry_state()

    def test_ask_nexus_router_intents(self):
        assistant = AskNexusAssistant()

        # 1. Why was the last alert raised?
        intent1, data1 = assistant.route_query("Why was the last alert raised?")
        self.assertEqual(intent1, "alerts_and_incident")
        self.assertIn("recent_alerts_300s", data1)

        # 2. Detector comparison / missed attacks
        intent2, data2 = assistant.route_query("Which detector missed attacks during the test?")
        self.assertEqual(intent2, "detector_comparison")
        self.assertIn("counts", data2)

        # 3. Baseline feature query
        intent3, data3 = assistant.route_query("Is the deauth rate normal right now?")
        self.assertEqual(intent3, "baseline_and_window")
        self.assertEqual(data3["feature"], "deauth")

        # 4. Link health
        intent4, data4 = assistant.route_query("Is the serial link healthy?")
        self.assertEqual(intent4, "link_health")
        self.assertIn("status", data4)

        # 5. Window ID lookup
        intent5, data5 = assistant.route_query("Show me telemetry for window 42")
        self.assertEqual(intent5, "window_lookup")
        self.assertEqual(data5["window_id"], 42)

        # 6. Hourly alert history
        intent6, data6 = assistant.route_query("What happened in the last hour?")
        self.assertEqual(intent6, "hourly_alerts")
        self.assertIn("alert_count", data6)

    def test_anti_hallucination_numeric_verification(self):
        assistant = AskNexusAssistant()
        dataset = {
            "window_id": 45,
            "deauth_count": 18,
            "z_deauth": 4.25,
            "rssi_mean": -68.4
        }

        # Response citing only authentic dataset numbers
        grounded_text = "Window 45 observed 18 deauth frames with z-score 4.25 and RSSI -68.4 dBm."
        verified_ok = assistant.verify_numeric_hallucinations(grounded_text, dataset)
        self.assertNotIn("Verification Flag", verified_ok)

        # Response citing hallucinated numbers
        hallucinated_text = "Window 45 saw 999 rogue frames attacking 88 stations."
        verified_flagged = assistant.verify_numeric_hallucinations(hallucinated_text, dataset)
        self.assertIn("Verification Flag", verified_flagged)
        self.assertIn("999", verified_flagged)

    def test_assistant_chat_streaming_offline(self):
        assistant = AskNexusAssistant(ollama_url="offline")
        response_text = assistant.generate_chat("Is the link healthy?")
        self.assertGreater(len(response_text), 0)
        self.assertIn("Serial Link Health", response_text)

    def test_trusted_ap_allowlist_and_rogue_detection(self):
        # 1. Add authorized AP
        add_resp = add_or_update_trusted_ap(TrustedApPayload(
            bssid="AA:BB:CC:DD:EE:01",
            ssid="Enterprise-Secure",
            channel=6,
            is_active=1
        ))
        self.assertEqual(add_resp["status"], "upserted")

        # 2. Verify in allowlist
        aps = get_trusted_aps()
        self.assertTrue(any(a["bssid"] == "AA:BB:CC:DD:EE:01" for a in aps))

        # 3. Warm up baseline engine
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**generate_quiet_window(i)))

        # 4. Ingest telemetry where an unknown BSSID advertises the protected SSID
        rogue_result = ingest_telemetry_window(WindowIngestPayload(
            deauth=0,
            mgmt=45,
            ble=10,
            rogue=1,
            nfc=0,
            ch=6,
            top=[{"bssid": "DE:AD:BE:EF:00:99", "ssid": "Enterprise-Secure", "ch": 6}]
        ))

        alert = rogue_result.get("alert")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["type_key"], "rogue")
        self.assertIn("DE:AD:BE:EF:00:99", alert["evidence"].get("grounded_reason", ""))
        self.assertIn("Enterprise-Secure", alert["evidence"].get("grounded_reason", ""))

    def test_incident_aggregation_and_false_positive_feedback(self):
        # 1. Warm up baseline
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**generate_quiet_window(i)))

        # 2. Trigger first alert event
        res1 = ingest_telemetry_window(WindowIngestPayload(
            deauth=16,
            mgmt=110,
            ble=20,
            rogue=0,
            nfc=0
        ))
        alert1 = res1.get("alert")
        self.assertIsNotNone(alert1)
        inc_id = alert1.get("incident_id")
        self.assertIsNotNone(inc_id)

        # Clear correlation cooldown to permit immediate secondary alert
        correlation_engine.last_event_window = -999

        # 3. Trigger second alert event within 60s
        res2 = ingest_telemetry_window(WindowIngestPayload(
            deauth=18,
            mgmt=125,
            ble=22,
            rogue=0,
            nfc=0
        ))
        alert2 = res2.get("alert")
        self.assertIsNotNone(alert2)
        # Should be aggregated into the existing incident
        self.assertEqual(alert2.get("incident_id"), inc_id)
        self.assertEqual(res2["incident"]["action"], "AGGREGATED")
        self.assertEqual(res2["incident"]["event_count"], 2)

        # 4. Mark incident as FALSE_POSITIVE and verify closed-loop sensitivity adjustment
        initial_var = baseline_engine.baselines["deauth"].variance
        status_res = change_incident_status(inc_id, IncidentStatusPayload(
            status="FALSE_POSITIVE",
            note="Bench calibration verified benign transmission"
        ))
        self.assertTrue(status_res["updated"])

        # Variance should have adjusted upwards to reduce sensitivity
        self.assertGreater(baseline_engine.baselines["deauth"].variance, initial_var)
        self.assertIn(res1["window_id"], incident_manager.get_false_positive_windows())

    def test_csv_replay_engine(self):
        csv_data = (
            "window_id,deauth,mgmt,ble,rogue,nfc,rssi,is_attack_labelled,ch,bssid_cnt\n"
            "1,0,32,15,0,0,-71.0,0,1,3\n"
            "2,1,28,14,0,0,-70.5,0,1,3\n"
            "3,0,30,16,0,0,-71.2,0,1,3\n"
        )
        start_res = start_csv_replay(ReplayStartPayload(
            csv_content=csv_data,
            speed_ms=50,
            source_name="unit_test.csv"
        ))
        self.assertEqual(start_res["status"], "started")
        self.assertEqual(replay_engine.source_name, "unit_test.csv")

        status = get_csv_replay_status()
        self.assertIn("running", status)

        stop_res = stop_csv_replay()
        self.assertEqual(stop_res["status"], "stopped")
        self.assertFalse(replay_engine.running)

    def test_expanded_defensive_corpus_25_entries(self):
        rag = DefensiveRAGIndex()
        self.assertGreaterEqual(len(rag.documents), 25)

        # Test retrieval for 802.11w Protected Management Frames
        results_pmf = rag.search("802.11w protected management frames deauthentication", top_k=2)
        self.assertGreater(len(results_pmf), 0)
        found_ids = [r["id"] for r in results_pmf]
        self.assertTrue("REF-OWASP-W01-80211W" in found_ids or "REF-MITRE-T1499" in found_ids)

        # Test retrieval for Rogue AP and evil twin
        results_rogue = rag.search("rogue access point evil twin 802.1X certificate", top_k=2)
        self.assertGreater(len(results_rogue), 0)
        rogue_ids = [r["id"] for r in results_rogue]
        self.assertTrue("REF-OWASP-W02-ROGUE-ISOLATION" in rogue_ids or "REF-MITRE-T1557-001" in rogue_ids or "REF-OWASP-W03-WPA3-ENTERPRISE" in rogue_ids)

    def test_api_key_security(self):
        # 1. Valid API key passes without exception
        self.assertIsNone(verify_api_key(API_KEY))

        # 2. Invalid API key raises 401 Unauthorized
        with self.assertRaises(HTTPException) as ctx_invalid:
            verify_api_key("unauthorized_bad_key")
        self.assertEqual(ctx_invalid.exception.status_code, 401)
        self.assertEqual(ctx_invalid.exception.detail, "Unauthorized write operation")

        # 3. Missing API key raises 401 Unauthorized
        with self.assertRaises(HTTPException) as ctx_none:
            verify_api_key(None)
        self.assertEqual(ctx_none.exception.status_code, 401)

    def test_threshold_sweep_endpoint(self):
        reset_telemetry_state()
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**generate_quiet_window(i)))

        set_label_mode(LabelModePayload(active=True))
        for _ in range(5):
            ingest_telemetry_window(WindowIngestPayload(
                deauth=14,
                mgmt=120,
                ble=25,
                rogue=0,
                nfc=0,
                data_source="simulation"
            ))
        set_label_mode(LabelModePayload(active=False))

        sweep_res = get_evaluation_threshold_sweep()
        self.assertIn("results", sweep_res)
        self.assertEqual(len(sweep_res["results"]), 11)
        self.assertEqual(sweep_res["sweep_range"], [2.5, 5.0])
        self.assertEqual(sweep_res["step"], 0.25)
        self.assertIn(sweep_res["optimal_z"], [round(2.5 + i * 0.25, 2) for i in range(11)])
        self.assertEqual(sweep_res["results"][0]["z_threshold"], 2.5)
        self.assertEqual(sweep_res["results"][-1]["z_threshold"], 5.0)
        for pt in sweep_res["results"]:
            self.assertIn("precision", pt)
            self.assertIn("recall", pt)
            self.assertIn("f1", pt)
            self.assertIn("fpr", pt)

    def test_ablation_analysis_endpoint(self):
        reset_telemetry_state()
        for i in range(35):
            ingest_telemetry_window(WindowIngestPayload(**generate_quiet_window(i)))

        set_label_mode(LabelModePayload(active=True))
        for _ in range(5):
            ingest_telemetry_window(WindowIngestPayload(
                deauth=14,
                mgmt=120,
                ble=25,
                rogue=0,
                nfc=0,
                data_source="simulation"
            ))
        set_label_mode(LabelModePayload(active=False))

        ablation_res = get_evaluation_ablation()
        self.assertIn("configurations", ablation_res)
        configs = ablation_res["configurations"]
        self.assertIn("config_1_fixed_threshold", configs)
        self.assertIn("config_2_adaptive_no_freeze", configs)
        self.assertIn("config_3_adaptive_with_freeze", configs)
        self.assertIn("config_4_nexus_complete", configs)
        self.assertIn("f1", configs["config_4_nexus_complete"])
        self.assertIn("fpr", configs["config_4_nexus_complete"])

    def test_diurnal_baseline_seasonal_adjustment(self):
        engine = AdaptiveBaselineEngine(warmup_windows=30, z_threshold=3.5)
        # Warm up at hour 14
        for _ in range(35):
            engine.evaluate_window({"deauth": 2, "mgmt": 80, "ble": 25, "rogue": 0, "nfc": 0}, hour=14)

        deauth_base = engine.baselines["deauth"]
        self.assertGreater(deauth_base.hourly_counts[14], 0)
        eff_mean = deauth_base.get_effective_mean(14)
        self.assertAlmostEqual(eff_mean, 2.0, delta=0.5)

        # Baseline profile report
        profile = engine.get_hourly_profile("deauth")
        self.assertEqual(len(profile), 24)
        self.assertAlmostEqual(profile[14], 2.0, delta=0.5)

        # High burst z-score computation
        z = deauth_base.compute_z_score(18.0, hour=14)
        self.assertGreater(z, 3.5)

    def test_prune_telemetry_endpoint(self):
        reset_telemetry_state()
        conn = get_connection()
        old_epoch = int((time.time() - (50 * 3600)) * 1000)

        # Insert 1 old unflagged window
        insert_enriched_telemetry_window({
            "window_id": 901,
            "epoch_ms": old_epoch,
            "data_source": "simulation",
            "deauth": 0,
            "mgmt": 50,
            "ble": 10,
            "rogue": 0,
            "nfc": 0,
            "rssi_min": -70.0,
            "rssi_avg": -65.0,
            "rssi_max": -60.0,
            "is_flagged": 0,
            "is_attack_labelled": 0
        }, conn=conn)

        # Insert 1 old flagged window associated with an alert event
        insert_enriched_telemetry_window({
            "window_id": 902,
            "epoch_ms": old_epoch + 1000,
            "data_source": "simulation",
            "deauth": 15,
            "mgmt": 120,
            "ble": 25,
            "rogue": 0,
            "nfc": 0,
            "rssi_min": -70.0,
            "rssi_avg": -65.0,
            "rssi_max": -60.0,
            "is_flagged": 1,
            "is_attack_labelled": 1
        }, conn=conn)
        insert_alert_event(
            conn=conn,
            event_id="EVT-OLD-01",
            window_id=902,
            epoch_ms=old_epoch + 1000,
            type_key="deauth",
            event_type="Deauthentication flood attack",
            severity="high",
            confidence=0.95,
            signals_correlated=1,
            data_source="simulation",
            evidence_json="{}",
            explanation=""
        )
        conn.close()

        # Prune older than 48 hours
        prune_res = prune_telemetry_endpoint(PrunePayload(retention_hours=48))
        self.assertGreaterEqual(prune_res["deleted_windows"], 1)

        # Verify old unflagged window was pruned
        conn2 = get_connection()
        cur = conn2.cursor()
        cur.execute("SELECT window_id FROM telemetry_windows WHERE window_id = 901;")
        self.assertIsNone(cur.fetchone())

        # Verify alert window was preserved
        cur.execute("SELECT window_id FROM telemetry_windows WHERE window_id = 902;")
        self.assertIsNotNone(cur.fetchone())
        conn2.close()

    def test_lexicon_compliance(self):
        import re
        banned = ['delve', 'robust', 'seamless', 'pivotal', 'crucial', 'tapestry', 'leverage', 'holistic', 'game-changer', 'beacon']
        pattern = re.compile(r'\b(' + '|'.join(banned) + r')\b', re.IGNORECASE)
        backend_dir = Path(__file__).resolve().parent.parent
        app_dir = backend_dir / "app"

        violations = []
        for root, _, files in os.walk(app_dir):
            for f in files:
                if f.endswith('.py'):
                    fpath = Path(root) / f
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                        for idx, line in enumerate(fp, 1):
                            m = pattern.findall(line)
                            if m:
                                violations.append((fpath.name, idx, m, line.strip()))

        self.assertEqual(violations, [], f"Found banned words: {violations}")


if __name__ == "__main__":
    unittest.main()
