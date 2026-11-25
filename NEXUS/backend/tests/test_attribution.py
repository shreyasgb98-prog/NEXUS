import unittest
import sys
import json
import time
import httpx
from pathlib import Path
from unittest.mock import MagicMock, patch

# Configure path imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import HTTPException
import asyncio

from app.incident_manager import (
    IncidentManager,
    map_reason_code_to_signature,
    categorize_rssi_proximity,
    map_incident_to_mitre,
    compute_evidence_hash,
    MITRE_ATTACK_MAP
)
from app.database import (
    get_connection,
    apply_migrations,
    insert_telemetry_window,
    create_incident,
    fetch_incident_with_timeline,
    fetch_incident_by_id,
    update_incident_remediation
)
from app.main import (
    process_telemetry_window,
    serial_manager,
    incident_manager,
    add_hardware_whitelist,
    clear_hardware_whitelist,
    delete_hardware_whitelist_by_path,
    get_hardware_whitelist,
    HardwareWhitelistPayload,
    reset_telemetry_state,
    generate_incidents_report,
    get_database_status,
    update_settings,
    SettingsPayload,
    batch_incident_status_endpoint,
    BatchIncidentStatusPayload,
    BatchStatusUpdate,
    EndpointTestPayload,
    assistant_test_endpoint,
    prune_telemetry_endpoint,
    PrunePayload,
    update_incident_remediation_endpoint,
    get_incident_by_id_endpoint,
    RemediationUpdatePayload,
    get_telemetry_recent,
    baseline_engine
)
from app.config import (
    EWMA_ALPHA,
    Z_SCORE_THRESHOLD,
    WARMUP_WINDOWS,
    FIXED_DEAUTH_THRESHOLD
)
from app.assistant import AskNexusAssistant, _fallback_rule_based_response


class TestSignatureAttribution(unittest.TestCase):
    """Verifies 802.11 Reason Code to tool signature attribution mapping."""

    def test_reason_code_7_aireplay_mdk4(self):
        sig = map_reason_code_to_signature(7)
        self.assertEqual(sig, "Adversary Deauth Exploit (aireplay-ng / mdk4 signature)")

    def test_reason_code_2_session_hijack(self):
        sig = map_reason_code_to_signature(2)
        self.assertEqual(sig, "Session Hijack / Force Re-authentication (MDK3 signature)")

    def test_reason_code_6_association_injection(self):
        sig = map_reason_code_to_signature(6)
        self.assertEqual(sig, "Association Injection Flooding")

    def test_reason_code_1_unspecified(self):
        sig = map_reason_code_to_signature(1)
        self.assertEqual(sig, "Generic / Unspecified Disconnection")

    def test_reason_code_3_client_roam(self):
        sig = map_reason_code_to_signature(3)
        self.assertEqual(sig, "Legitimate Client Roam / Station Leaving")

    def test_reason_code_8_bss_transition(self):
        sig = map_reason_code_to_signature(8)
        self.assertEqual(sig, "Standard BSS Transition")

    def test_unmapped_reason_code(self):
        sig = map_reason_code_to_signature(99)
        self.assertEqual(sig, "Standard Disassociation (Reason 99)")


class TestProximityCategorization(unittest.TestCase):
    """Verifies RSSI physical proximity boundary categorization."""

    def test_immediate_proximity_zone(self):
        # rssi >= -45 dBm
        self.assertEqual(categorize_rssi_proximity(-42), "IMMEDIATE (< 3m, inside room)")
        self.assertEqual(categorize_rssi_proximity(-45), "IMMEDIATE (< 3m, inside room)")
        self.assertEqual(categorize_rssi_proximity(-30), "IMMEDIATE (< 3m, inside room)")

    def test_mid_range_proximity_zone(self):
        # -45 > rssi >= -70 dBm
        self.assertEqual(categorize_rssi_proximity(-46), "MID-RANGE (5-15m, inside building)")
        self.assertEqual(categorize_rssi_proximity(-60), "MID-RANGE (5-15m, inside building)")
        self.assertEqual(categorize_rssi_proximity(-70), "MID-RANGE (5-15m, inside building)")

    def test_perimeter_proximity_zone(self):
        # rssi < -70 dBm
        self.assertEqual(categorize_rssi_proximity(-71), "PERIMETER (> 15m, outside structure)")
        self.assertEqual(categorize_rssi_proximity(-85), "PERIMETER (> 15m, outside structure)")

    def test_zero_rssi_none(self):
        self.assertEqual(categorize_rssi_proximity(0), "NONE")


class TestIncidentManagerForensicEnrichment(unittest.TestCase):
    """Verifies incident evaluation enriches records with attribution metadata."""

    def setUp(self):
        self.mgr = IncidentManager()

    def test_evaluate_window_for_incidents_enrichment(self):
        window_data = {
            "window_id": 42,
            "atk_src": "AA:BB:CC:DD:EE:01",
            "atk_dst": "11:22:33:44:55:66",
            "atk_rssi": -42,
            "atk_reason": 7
        }
        alert_record = {
            "id": "EVT-TEST-001",
            "event_type": "Deauthentication Flood",
            "type_key": "deauth",
            "severity": "HIGH",
            "confidence": 0.95,
            "window_id": 42,
            "evidence": {"deauth_count": 45}
        }

        conn = get_connection()
        res = self.mgr.evaluate_window_for_incidents(window_data, alert_record, conn=conn)
        conn.close()

        self.assertIsNotNone(res)
        self.assertEqual(res["attacker_mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(res["target_mac"], "11:22:33:44:55:66")
        self.assertEqual(res["attacker_rssi"], -42)
        self.assertEqual(res["deauth_reason"], 7)
        self.assertEqual(res["tool_signature"], "Adversary Deauth Exploit (aireplay-ng / mdk4 signature)")
        self.assertEqual(res["proximity_zone"], "IMMEDIATE (< 3m, inside room)")


class TestMainPipelineAndWhitelist(unittest.TestCase):
    """Verifies telemetry pipeline attribution persistence and serial whitelist endpoints."""

    def setUp(self):
        reset_telemetry_state()

    def test_process_telemetry_window_persists_attribution(self):
        payload = {
            "window_id": 101,
            "deauth": 20,
            "mgmt": 40,
            "ble": 5,
            "rogue": 0,
            "nfc": 0,
            "atk_src": "DE:AD:BE:EF:00:07",
            "atk_dst": "CA:FE:BA:BE:00:01",
            "atk_rssi": -42,
            "atk_reason": 7,
            "data_source": "test_stream"
        }

        res = process_telemetry_window(payload, data_source="test_stream")
        self.assertIsNotNone(res)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone "
            "FROM telemetry_windows WHERE window_id = 101;"
        )
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["attacker_mac"], "DE:AD:BE:EF:00:07")
        self.assertEqual(row["target_mac"], "CA:FE:BA:BE:00:01")
        self.assertEqual(row["attacker_rssi"], -42)
        self.assertEqual(row["deauth_reason"], 7)
        self.assertEqual(row["proximity_zone"], "IMMEDIATE (< 3m, inside room)")

    def test_hardware_whitelist_endpoints(self):
        with patch.object(serial_manager, "is_connected", return_value=True):
            with patch.object(serial_manager, "write_command", return_value=True) as mock_write:
                add_res = add_hardware_whitelist(HardwareWhitelistPayload(ssid="Lab_WiFi", bssid="AA:BB:CC:11:22:33"))
                self.assertEqual(add_res["status"], "whitelist_added")
                self.assertTrue(add_res["dispatched_to_uart"])
                self.assertEqual(add_res["command"], {"cmd": "wl_add", "ssid": "Lab_WiFi", "bssid": "AA:BB:CC:11:22:33"})
                mock_write.assert_called_with({"cmd": "wl_add", "ssid": "Lab_WiFi", "bssid": "AA:BB:CC:11:22:33"})

                clear_res = clear_hardware_whitelist()
                self.assertEqual(clear_res["status"], "whitelist_cleared")
                self.assertTrue(clear_res["dispatched_to_uart"])
                self.assertEqual(clear_res["command"], {"cmd": "wl_clear"})
                mock_write.assert_called_with({"cmd": "wl_clear"})


class TestAskNexusForensicInquiries(unittest.TestCase):
    """Verifies Ask NEXUS Copilot responses for attacker attribution and proximity."""

    def setUp(self):
        self.assistant = AskNexusAssistant()
        reset_telemetry_state()

        # Seed an incident with attribution metadata
        now_ms = int(time.time() * 1000)
        self.test_incident_id = f"INC-{time.strftime('%Y%m%d', time.gmtime(now_ms/1000))}-99999"
        conn = get_connection()
        create_incident({
            "incident_id": self.test_incident_id,
            "title": "Adversary Deauth Flood",
            "primary_type": "DEAUTH",
            "event_type": "Deauth Attack",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "status": "OPEN",
            "event_count": 3,
            "start_epoch_ms": now_ms - 5000,
            "end_epoch_ms": now_ms,
            "attacker_mac": "DE:AD:BE:EF:00:01",
            "target_mac": "00:11:22:33:44:55",
            "target_bssid": "00:11:22:33:44:55",
            "attacker_rssi": -42,
            "deauth_reason": 7,
            "tool_signature": "Adversary Deauth Exploit (aireplay-ng / mdk4 signature)",
            "proximity_zone": "IMMEDIATE (< 3m, inside room)"
        }, conn=conn)
        conn.close()

    def test_query_who_was_attacking(self):
        query = f"Who was attacking in incident #{self.test_incident_id}?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "attacker_attribution")

        response = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("DE:AD:BE:EF:00:01", response)
        self.assertIn("00:11:22:33:44:55", response)
        self.assertIn("Adversary Deauth Exploit (aireplay-ng / mdk4 signature)", response)

    def test_query_how_close_was_attacker(self):
        query = "How close was the attacker?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "attacker_proximity")

        response = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("-42", response)
        self.assertIn("IMMEDIATE (< 3m, inside room)", response)

    def test_query_reason_code_observed(self):
        query = "What reason code was observed?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "reason_code_inquiry")

        response = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("Code 7", response)
        self.assertIn("Adversary Deauth Exploit (aireplay-ng / mdk4 signature)", response)
        self.assertIn("automated offensive tool", response)

    def test_query_reason_code_legitimate_roam(self):
        query = "Explain reason code 3"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "reason_code_inquiry")

        response = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("Code 3", response)
        self.assertIn("Legitimate Client Roam / Station Leaving", response)
        self.assertIn("legitimate client roaming", response)

    def test_inj_telemetry_ingestion(self):
        reset_telemetry_state()
        res = process_telemetry_window({
            "deauth": 15,
            "mgmt": 40,
            "ble": 0,
            "rogue": 0,
            "nfc": 0,
            "inj": 12,
            "atk_src": "11:22:33:44:55:66",
            "atk_dst": "AA:BB:CC:DD:EE:FF",
            "atk_rssi": -55,
            "atk_reason": 7
        }, data_source="test_inj")
        self.assertIsNotNone(res)
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_injection_count FROM telemetry_windows WHERE data_source = 'test_inj' ORDER BY epoch_ms DESC LIMIT 1;")
        row = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 12)

    def test_win_hardware_window_id_ingestion(self):
        reset_telemetry_state()
        res = process_telemetry_window({
            "win": 4242,
            "deauth": 2,
            "mgmt": 10,
            "ble": 0,
            "rogue": 0,
            "nfc": 0,
            "inj": 0,
        }, data_source="test_win_stream")
        self.assertIsNotNone(res)
        self.assertEqual(res["window_id"], 4242)
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT window_id FROM telemetry_windows WHERE data_source = 'test_win_stream' ORDER BY epoch_ms DESC LIMIT 1;")
        row = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 4242)


class TestMitreAndEvidenceHashing(unittest.TestCase):
    """Verifies MITRE ATT&CK taxonomy classification and SHA-256 evidence hashing."""

    def test_mitre_mapping_known_attacks(self):
        deauth_map = map_incident_to_mitre("DEAUTH_FLOOD")
        self.assertEqual(deauth_map["technique_id"], "T1498.001")
        self.assertEqual(deauth_map["tactic"], "Impact (TA0040)")

        rogue_map = map_incident_to_mitre("ROGUE_AP_EVIL_TWIN")
        self.assertEqual(rogue_map["technique_id"], "T1557.004")
        self.assertEqual(rogue_map["tactic"], "Credential Access (TA0006)")

        jamming_map = map_incident_to_mitre("RF_JAMMING_ANOMALY")
        self.assertEqual(jamming_map["technique_id"], "T1464")
        self.assertEqual(jamming_map["tactic"], "Impact (TA0040)")

        spoof_map = map_incident_to_mitre("MAC_SPOOFING_DETECTED")
        self.assertEqual(spoof_map["technique_id"], "T1036")
        self.assertEqual(spoof_map["tactic"], "Defense Evasion (TA0005)")

    def test_mitre_mapping_fallback(self):
        fallback = map_incident_to_mitre("UNKNOWN_CUSTOM_ANOMALY")
        self.assertEqual(fallback["technique_id"], "T1200")
        self.assertEqual(fallback["tactic"], "Initial Access (TA0001)")

    def test_compute_evidence_hash_determinism(self):
        rec = {
            "id": "EVT-20261124-0001",
            "epoch_ms": 1732440000000,
            "attacker_mac": "24:0A:C4:00:11:22",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "event_type": "DEAUTH_FLOOD"
        }
        h1 = compute_evidence_hash(rec)
        h2 = compute_evidence_hash(rec)
        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, h2)

        import hashlib
        expected_canonical = "EVT-20261124-0001|1732440000000|24:0A:C4:00:11:22|00:11:22:33:44:55|7|DEAUTH_FLOOD"
        expected_hash = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()
        self.assertEqual(h1, expected_hash)

    def test_evaluate_window_mitre_and_evidence_enrichment(self):
        im = IncidentManager(aggregation_window_ms=60000)
        now_ms = int(time.time() * 1000)
        window = {
            "window_id": 99,
            "epoch_ms": now_ms,
            "atk_src": "24:0A:C4:AA:BB:CC",
            "atk_dst": "00:11:22:33:44:55",
            "atk_rssi": -48,
            "atk_reason": 7,
            "alert": {
                "id": "ALT-99-TEST",
                "event_type": "Deauth Flood",
                "epoch_ms": now_ms,
                "evidence": {}
            }
        }
        result = im.evaluate_window_for_incidents(window)
        self.assertIsNotNone(result)

        alert = window["alert"]
        self.assertEqual(alert["mitre_technique_id"], "T1498.001")
        self.assertEqual(alert["mitre_technique_name"], "Network Denial of Service: Direct Network Flood")
        self.assertEqual(alert["mitre_tactic"], "Impact (TA0040)")
        self.assertEqual(len(alert["evidence_hash"]), 64)
        self.assertEqual(alert["evidence"]["mitre_technique_id"], "T1498.001")
        self.assertEqual(alert["evidence"]["evidence_hash"], alert["evidence_hash"])

    def test_ingest_alert_persistence_and_aggregation(self):
        im = IncidentManager(aggregation_window_ms=60000)
        now_ms = int(time.time() * 1000)
        alert1 = {
            "id": "ALT-HASH-1",
            "event_type": "DEAUTH_FLOOD",
            "epoch_ms": now_ms,
            "window_id": 101,
            "attacker_mac": "24:0A:C4:11:22:33",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "evidence": {}
        }
        res1 = im.ingest_alert(alert1)
        self.assertEqual(res1["action"], "CREATED")
        self.assertEqual(res1["mitre_technique_id"], "T1498.001")
        self.assertTrue(len(res1["evidence_hash"]) == 64)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
            "FROM incidents WHERE id = ?;",
            (res1["incident_id"],)
        )
        row = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["mitre_technique_id"], "T1498.001")
        self.assertEqual(row["mitre_tactic"], "Impact (TA0040)")
        self.assertEqual(row["evidence_hash"], res1["evidence_hash"])

        # Second sequential alert within aggregation window
        alert2 = {
            "id": "ALT-HASH-2",
            "event_type": "DEAUTH_FLOOD",
            "epoch_ms": now_ms + 1000,
            "window_id": 102,
            "attacker_mac": "24:0A:C4:11:22:33",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "evidence": {}
        }
        res2 = im.ingest_alert(alert2)
        self.assertEqual(res2["action"], "AGGREGATED")
        self.assertEqual(res2["incident_id"], res1["incident_id"])
        self.assertEqual(res2["mitre_technique_id"], "T1498.001")
        self.assertEqual(res2["evidence_hash"], res1["evidence_hash"])


class TestOfflineTechnicalExplanations(unittest.TestCase):
    """Verifies offline rule-based technical explanations and defensive corpus passages."""

    def test_ble_flood_inquiry_fallback(self):
        query = "What are the BLE flood anomaly indicators?"
        resp = _fallback_rule_based_response(query)
        self.assertIsNotNone(resp)
        self.assertIn("100ms", resp)
        self.assertIn("1024ms", resp)
        self.assertIn("buffer exhaustion", resp)
        self.assertIn("sliding-window", resp)

    def test_pmf_80211w_inquiry_fallback(self):
        query = "Explain 802.11w protected management frames"
        resp = _fallback_rule_based_response(query)
        self.assertIsNotNone(resp)
        self.assertIn("AES-128 CMAC", resp)
        self.assertIn("Broadcast Integrity Protocol", resp)
        self.assertIn("PHY/MAC layer", resp)

    def test_detector_comparison_inquiry_fallback(self):
        query = "Compare fixed threshold vs ewma detector performance"
        resp = _fallback_rule_based_response(query)
        self.assertIsNotNone(resp)
        self.assertIn("EWMA", resp)
        self.assertIn("diurnal", resp)
        self.assertIn("model poisoning", resp)

    def test_sequence_discontinuity_inquiry_fallback(self):
        query = "How does sequence number discontinuity detect raw packet injection?"
        resp = _fallback_rule_based_response(query)
        self.assertIsNotNone(resp)
        self.assertIn("12-bit sequence counter", resp)
        self.assertIn("Scapy", resp)
        self.assertIn("delta discontinuities", resp)

    def test_defensive_corpus_passages_exist(self):
        corpus_path = Path(__file__).resolve().parent.parent / "knowledge_base" / "defensive_corpus.json"
        with open(corpus_path, "r", encoding="utf-8") as f:
            docs = json.load(f)
        doc_ids = {d["id"] for d in docs}
        self.assertIn("REF-ARCH-PMF-DEEP-DIVE", doc_ids)
        self.assertIn("REF-ARCH-BLE-FLOOD-ANOMALY", doc_ids)
        self.assertIn("REF-ARCH-EWMA-VS-FIXED", doc_ids)
        self.assertIn("REF-ARCH-SEQ-DISCONTINUITY", doc_ids)


class TestComplianceReportGeneration(unittest.TestCase):
    """Verifies executive compliance and incident audit report generation."""

    def setUp(self):
        self.assistant = AskNexusAssistant()
        reset_telemetry_state()

        conn = get_connection()
        now_ms = int(time.time() * 1000)
        create_incident({
            "incident_id": "INC-20261124-99999",
            "title": "Adversary Deauth Attack Campaign",
            "primary_type": "DEAUTH",
            "event_type": "Deauth Flood",
            "severity": "CRITICAL",
            "status": "OPEN",
            "event_count": 8,
            "attacker_mac": "24:0A:C4:AA:BB:CC",
            "target_mac": "00:11:22:33:44:55",
            "target_bssid": "00:11:22:33:44:55",
            "attacker_rssi": -45,
            "deauth_reason": 7,
            "tool_signature": "Adversary Deauth Exploit (aireplay-ng / mdk4 signature)",
            "proximity_zone": "IMMEDIATE (< 3m, inside room)",
            "mitre_technique_id": "T1498.001",
            "mitre_technique_name": "Network Denial of Service: Direct Network Flood",
            "mitre_tactic": "Impact (TA0040)",
            "evidence_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
        }, conn=conn)
        conn.close()

    def test_offline_deterministic_compliance_report(self):
        incidents = [{
            "incident_id": "INC-20261124-99999",
            "event_type": "Deauth Flood",
            "primary_type": "DEAUTH",
            "severity": "CRITICAL",
            "attacker_mac": "24:0A:C4:AA:BB:CC",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "proximity_zone": "IMMEDIATE (< 3m, inside room)",
            "attacker_rssi": -45,
            "hardware_profile": "Espressif Deauther / Rogue Node (ESP8266/ESP32)",
            "mitre_technique_id": "T1498.001",
            "mitre_technique_name": "Network Denial of Service: Direct Network Flood",
            "mitre_tactic": "Impact (TA0040)",
            "evidence_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
        }]
        baseline = {
            "alpha": 0.12,
            "z_cutoff": 3.5,
            "features": {
                "deauth": {"alpha": 0.12, "mean": 1.45, "std_dev": 0.85}
            }
        }
        report = self.assistant.generate_compliance_report(incidents, baseline)
        self.assertIsNotNone(report)

        # Verify all 6 mandatory sections
        self.assertIn("## 1. Executive Summary & Assessment", report)
        self.assertIn("## 2. Physical & Spectral Attack Forensics", report)
        self.assertIn("## 3. Threat Classification (MITRE ATT&CK Mapping)", report)
        self.assertIn("## 4. Statistical Anomaly Verification (EWMA Mean/Variance Deviation)", report)
        self.assertIn("## 5. Actionable Countermeasures & Remediation (IEEE 802.11w PMF Guidance)", report)
        self.assertIn("## 6. Chain of Custody & Cryptographic Evidence Ledger", report)

        # Verify forensic factual values
        self.assertIn("INC-20261124-99999", report)
        self.assertIn("24:0A:C4:AA:BB:CC", report)
        self.assertIn("T1498.001", report)
        self.assertIn("a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0", report)
        self.assertIn("IEEE 802.11w", report)

    def test_api_generate_report_endpoint(self):
        res = generate_incidents_report(limit=5)
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["incident_count"], 1)
        self.assertIn("report_markdown", res)
        self.assertIn("## 1. Executive Summary & Assessment", res["report_markdown"])
        self.assertIn("## 6. Chain of Custody & Cryptographic Evidence Ledger", res["report_markdown"])
        self.assertIsInstance(res["generated_at"], int)


class TestRemediationRoutes(unittest.TestCase):
    """Verifies settings sync, live pragma inspection, persistent whitelist, batch triage, and recent filtering."""

    def setUp(self):
        reset_telemetry_state()

    def tearDown(self):
        reset_telemetry_state()

    def test_database_status_pragmas(self):
        res = get_database_status()
        self.assertEqual(res["journal_mode"], "wal")
        self.assertEqual(res["foreign_keys"], 1)
        self.assertIn(res["synchronous"], (1, 2, "normal", "NORMAL", "full", "FULL"))
        self.assertIn("size_bytes", res)
        self.assertIn("telemetry_rows", res)
        self.assertIn("incident_rows", res)
        self.assertIn("whitelist_rows", res)

    def test_settings_runtime_synchronization(self):
        payload = SettingsPayload(
            alpha=0.15,
            z_threshold=4.0,
            warmup_windows=50,
            fixed_threshold=12
        )
        res = update_settings(payload)
        self.assertEqual(res["status"], "applied")
        self.assertEqual(res["current_settings"]["alpha"], 0.15)
        self.assertEqual(res["current_settings"]["z_threshold"], 4.0)
        self.assertEqual(res["current_settings"]["warmup_windows"], 50)
        self.assertEqual(res["current_settings"]["warmup_limit"], 50)
        self.assertEqual(baseline_engine.alpha, 0.15)
        self.assertEqual(baseline_engine.z_threshold, 4.0)
        self.assertEqual(baseline_engine.warmup_limit, 50)

        # Bounds validation tests
        with self.assertRaises(HTTPException):
            update_settings(SettingsPayload(alpha=0.005))
        with self.assertRaises(HTTPException):
            update_settings(SettingsPayload(alpha=1.5))
        with self.assertRaises(HTTPException):
            update_settings(SettingsPayload(z_threshold=0.5))
        with self.assertRaises(HTTPException):
            update_settings(SettingsPayload(z_threshold=15.0))
        with self.assertRaises(HTTPException):
            update_settings(SettingsPayload(warmup_windows=2))

        # Restore defaults
        update_settings(SettingsPayload(
            alpha=EWMA_ALPHA,
            z_threshold=Z_SCORE_THRESHOLD,
            warmup_windows=WARMUP_WINDOWS,
            fixed_threshold=FIXED_DEAUTH_THRESHOLD
        ))

    def test_persistent_hardware_whitelist(self):
        # 1. Add entry to whitelist
        add_payload = HardwareWhitelistPayload(
            bssid="00:11:22:33:44:55",
            ssid="SecuredLab",
            channel=6
        )
        add_res = add_hardware_whitelist(add_payload)
        self.assertEqual(add_res["status"], "whitelist_added")

        # 2. Query persistent entries from SQLite
        entries = get_hardware_whitelist()
        self.assertTrue(any(e["bssid"] == "00:11:22:33:44:55" and e["ssid"] == "SecuredLab" for e in entries))

        # 3. Test DELETE by path parameter
        del_path_res = delete_hardware_whitelist_by_path("00:11:22:33:44:55")
        self.assertEqual(del_path_res["status"], "whitelist_deleted")
        self.assertTrue(del_path_res["deleted"])

        # 4. Verify deleted
        entries_after = get_hardware_whitelist()
        self.assertFalse(any(e["bssid"] == "00:11:22:33:44:55" for e in entries_after))

        # 5. Add and delete via clear payload
        add_hardware_whitelist(add_payload)
        del_payload = HardwareWhitelistPayload(bssid="00:11:22:33:44:55")
        del_res = clear_hardware_whitelist(del_payload)
        self.assertEqual(del_res["status"], "whitelist_cleared")
        self.assertEqual(del_res["deleted_count"], 1)

    def test_batch_incident_status_triage(self):
        conn = get_connection()
        now_ms = int(time.time() * 1000)
        create_incident({
            "incident_id": "INC-BATCH-001",
            "title": "Batch Incident 1",
            "primary_type": "DEAUTH",
            "status": "OPEN",
            "start_epoch_ms": now_ms
        }, conn=conn)
        create_incident({
            "incident_id": "INC-BATCH-002",
            "title": "Batch Incident 2",
            "primary_type": "ROGUE",
            "status": "OPEN",
            "start_epoch_ms": now_ms
        }, conn=conn)
        conn.close()

        # Batch triage via incident_ids (Finding 1.3)
        update_payload = BatchStatusUpdate(
            incident_ids=["INC-BATCH-001", "INC-BATCH-002"],
            status="RESOLVED"
        )
        batch_res = batch_incident_status_endpoint(update_payload)
        self.assertEqual(batch_res["status"], "success")
        self.assertEqual(batch_res["updated_count"], 2)
        self.assertEqual(batch_res["incident_ids"], ["INC-BATCH-001", "INC-BATCH-002"])

        # Validate invalid status rejection
        with self.assertRaises(HTTPException):
            batch_incident_status_endpoint(BatchStatusUpdate(
                incident_ids=["INC-BATCH-001"],
                status="UNAUTHORIZED_STATUS"
            ))

        # Fallback triage via from_status / to_status
        payload = BatchIncidentStatusPayload(
            from_status="RESOLVED",
            to_status="OPEN",
            note=" [Batch Re-opened via Triage]"
        )
        res = batch_incident_status_endpoint(payload)
        self.assertEqual(res["new_status"], "OPEN")
        self.assertGreaterEqual(res["updated_count"], 2)

    def test_assistant_test_endpoint_diagnostic(self):
        # Verify diagnostic parameter validation without triggering sandboxed IOCP loop
        coro = assistant_test_endpoint(EndpointTestPayload(
            base_url="",
            model="llama3.2"
        ))
        try:
            res = coro.send(None)
        except StopIteration as e:
            res = e.value
        finally:
            coro.close()
        self.assertFalse(res["available"])
        self.assertIn("error", res)

    def test_telemetry_prune_frames_and_windows(self):
        res = prune_telemetry_endpoint(PrunePayload(retention_hours=24))
        self.assertEqual(res["status"], "pruned")
        self.assertIn("deleted_windows", res)
        self.assertIn("deleted_frames", res)

    def test_telemetry_recent_data_source_filtering(self):
        conn = get_connection()
        now_ms = int(time.time() * 1000)
        insert_telemetry_window(
            conn,
            window_id=901,
            epoch_ms=now_ms,
            deauth_count=5,
            mgmt_count=30,
            ble_count=0,
            rogue_count=0,
            nfc_count=0,
            data_source="live_serial"
        )
        insert_telemetry_window(
            conn,
            window_id=902,
            epoch_ms=now_ms + 1000,
            deauth_count=25,
            mgmt_count=50,
            ble_count=0,
            rogue_count=0,
            nfc_count=0,
            data_source="simulation_run"
        )
        conn.close()

        # Query filtering by data_source
        live_rows = get_telemetry_recent(limit=10, data_source="live_serial")
        self.assertTrue(len(live_rows) > 0)
        self.assertTrue(all(r["data_source"] == "live_serial" for r in live_rows))

    def test_incident_remediation_persistence(self):
        conn = get_connection()
        now_ms = int(time.time() * 1000)
        create_incident({
            "incident_id": "INC-REMED-101",
            "title": "Remediation Checklist Incident",
            "primary_type": "DEAUTH",
            "status": "OPEN",
            "start_epoch_ms": now_ms
        }, conn=conn)
        conn.close()

        # Update remediation steps
        payload = RemediationUpdatePayload(completed_steps=[0, 1])
        res = update_incident_remediation_endpoint("INC-REMED-101", payload)
        self.assertEqual(res["status"], "updated")
        self.assertEqual(res["incident_id"], "INC-REMED-101")
        self.assertEqual(res["completed_steps"], [0, 1])

        # Retrieve incident and verify remediation_steps column is projected
        inc = get_incident_by_id_endpoint("INC-REMED-101")
        self.assertIsNotNone(inc)
        self.assertIn("remediation_steps", inc)
        self.assertIn("updated_at", inc)
        steps_val = inc["remediation_steps"]
        if isinstance(steps_val, str):
            steps_list = json.loads(steps_val)
        else:
            steps_list = steps_val
        self.assertEqual(steps_list, [0, 1])

        # Non-existent incident raises 404
        with self.assertRaises(HTTPException):
            update_incident_remediation_endpoint("NON_EXISTENT_ID", payload)


if __name__ == "__main__":
    unittest.main()
