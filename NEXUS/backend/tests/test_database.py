import unittest
import tempfile
import os
import sqlite3
import hashlib
import json
from pathlib import Path
from NEXUS.backend.app.database import (
    init_db,
    get_connection,
    fetch_sqlite_pragmas,
    fetch_database_status,
    insert_telemetry_window,
    insert_enriched_telemetry_window,
    insert_telemetry,
    fetch_recent_telemetry,
    fetch_telemetry_rolling_window,
    fetch_all_telemetry,
    insert_alert_event,
    fetch_alerts,
    fetch_all_alerts,
    fetch_alert_by_id,
    fetch_recent_alerts,
    fetch_alerts_rolling_window,
    query_alert_logs,
    db_get_alerts,
    insert_hardware_whitelist,
    upsert_hardware_whitelist,
    delete_hardware_whitelist,
    fetch_all_hardware_whitelist,
    fetch_hardware_whitelist,
    is_bssid_whitelisted,
    insert_incident,
    insert_incident_record,
    update_incident,
    batch_update_incident_status,
    fetch_incidents,
    fetch_incident_by_id,
    fetch_active_incidents,
    fetch_incident_with_timeline,
    db_get_incident_summary,
    query_recent_incidents,
    db_get_window,
    reset_telemetry_database
)

class DatabaseForensicsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "nexus_test.db")
        init_db(self.db_path)
        self.conn = get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_connection_pragmas(self):
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

        cursor.execute("PRAGMA synchronous;")
        sync = cursor.fetchone()[0]
        # NORMAL is synchronous level 1
        self.assertEqual(sync, 1)

        cursor.execute("PRAGMA foreign_keys;")
        fk = cursor.fetchone()[0]
        self.assertEqual(fk, 1)

    def test_migration_tracking(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT version, filename FROM schema_versions WHERE version IN (5, 6, 7, 8) ORDER BY version;")
        rows = cursor.fetchall()
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["version"], 5)
        self.assertEqual(rows[0]["filename"], "005_add_forensic_attribution.sql")
        self.assertEqual(rows[1]["version"], 6)
        self.assertEqual(rows[1]["filename"], "006_add_injection_and_advisory.sql")
        self.assertEqual(rows[2]["version"], 7)
        self.assertEqual(rows[2]["filename"], "007_add_mitre_and_evidence_hash.sql")
        self.assertEqual(rows[3]["version"], 8)
        self.assertEqual(rows[3]["filename"], "008_add_hardware_whitelist.sql")

    def test_fetch_sqlite_pragmas(self):
        pragmas = fetch_sqlite_pragmas(self.conn)
        self.assertEqual(pragmas["journal_mode"], "wal")
        self.assertEqual(pragmas["synchronous"], 1)
        self.assertEqual(pragmas["foreign_keys"], 1)

        # Test with internal connection opening
        pragmas_standalone = fetch_sqlite_pragmas()
        self.assertEqual(pragmas_standalone["journal_mode"], "wal")
        self.assertEqual(pragmas_standalone["synchronous"], 1)
        self.assertEqual(pragmas_standalone["foreign_keys"], 1)

    def test_telemetry_forensic_persistence(self):
        rowid = insert_telemetry_window(
            conn=self.conn,
            window_id=101,
            epoch_ms=1700000000000,
            deauth_count=12,
            mgmt_count=30,
            ble_count=4,
            rogue_count=2,
            nfc_count=1,
            rssi_mean=-62.5,
            data_source="simulation",
            attacker_mac="AA:BB:CC:DD:EE:01",
            target_mac="11:22:33:44:55:01",
            attacker_rssi=-48,
            deauth_reason=3,
            proximity_zone="IMMEDIATE",
            raw_injection_count=45,
            is_laa_randomized=1,
            hardware_profile="ESPRESSIF_ESP32"
        )
        self.assertGreater(rowid, 0)

        records = fetch_recent_telemetry(conn=self.conn, limit=5)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["window_id"], 101)
        self.assertEqual(rec["attacker_mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(rec["target_mac"], "11:22:33:44:55:01")
        self.assertEqual(rec["attacker_rssi"], -48)
        self.assertEqual(rec["deauth_reason"], 3)
        self.assertEqual(rec["proximity_zone"], "IMMEDIATE")
        self.assertEqual(rec["raw_injection_count"], 45)
        self.assertEqual(rec["is_laa_randomized"], 1)
        self.assertEqual(rec["hardware_profile"], "ESPRESSIF_ESP32")

        window_rec = db_get_window(101, conn=self.conn)
        self.assertIsNotNone(window_rec)
        self.assertEqual(window_rec["attacker_mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(window_rec["raw_injection_count"], 45)
        self.assertEqual(window_rec["is_laa_randomized"], 1)
        self.assertEqual(window_rec["hardware_profile"], "ESPRESSIF_ESP32")

    def test_enriched_telemetry_and_wrapper(self):
        insert_enriched_telemetry_window(
            {
                "window_id": 102,
                "epoch_ms": 1700000001000,
                "attacker_mac": "AA:BB:CC:DD:EE:02",
                "target_mac": "11:22:33:44:55:02",
                "attacker_rssi": -55,
                "deauth_reason": 7,
                "proximity_zone": "NEARBY",
                "raw_injection_count": 88,
                "is_laa_randomized": 0,
                "hardware_profile": "RASPBERRY_PI_FOUNDATION"
            },
            conn=self.conn
        )
        insert_telemetry(
            self.conn,
            {
                "window_id": 103,
                "epoch_ms": 1700000002000,
                "attacker_mac": "AA:BB:CC:DD:EE:03",
                "target_mac": "11:22:33:44:55:03",
                "attacker_rssi": -78,
                "deauth_reason": 1,
                "proximity_zone": "FAR",
                "raw_injection_count": 12,
                "is_laa_randomized": 1,
                "hardware_profile": "REALTEK_SEMICONDUCTOR"
            }
        )
        records = fetch_all_telemetry(conn=self.conn)
        self.assertEqual(len(records), 2)
        macs = {r["attacker_mac"] for r in records}
        self.assertIn("AA:BB:CC:DD:EE:02", macs)
        self.assertIn("AA:BB:CC:DD:EE:03", macs)

        rec102 = [r for r in records if r["window_id"] == 102][0]
        self.assertEqual(rec102["raw_injection_count"], 88)
        self.assertEqual(rec102["hardware_profile"], "RASPBERRY_PI_FOUNDATION")

    def test_alert_mitre_and_evidence_hash_persistence(self):
        custom_hash = hashlib.sha256(b"custom_evidence_payload").hexdigest()
        insert_alert_event(
            {
                "event_id": "EV-TEST-001",
                "window_id": 1,
                "epoch_ms": 1700000000000,
                "event_type": "Deauthentication Flood",
                "severity": "HIGH",
                "confidence": 0.95,
                "signals_correlated": 2,
                "evidence": {"deauth_count": 85, "bssid": "00:11:22:33:44:55"},
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service",
                "mitre_tactic": "Impact",
                "evidence_hash": custom_hash
            },
            conn=self.conn
        )

        ev_payload = {"probe_count": 42}
        expected_hash = hashlib.sha256(json.dumps(ev_payload).encode("utf-8")).hexdigest()
        insert_alert_event(
            {
                "event_id": "EV-TEST-002",
                "window_id": 1,
                "epoch_ms": 1700000010000,
                "event_type": "Rogue AP Detected",
                "severity": "MEDIUM",
                "confidence": 0.88,
                "signals_correlated": 1,
                "evidence": ev_payload,
                "mitre_technique_id": "T1557",
                "mitre_technique_name": "Adversary-in-the-Middle",
                "mitre_tactic": "Credential Access"
            },
            conn=self.conn
        )

        # 1. Test fetch_alert_by_id
        alert1 = fetch_alert_by_id(self.conn, "EV-TEST-001")
        self.assertIsNotNone(alert1)
        self.assertEqual(alert1["mitre_technique_id"], "T1498")
        self.assertEqual(alert1["mitre_technique_name"], "Network Denial of Service")
        self.assertEqual(alert1["mitre_tactic"], "Impact")
        self.assertEqual(alert1["evidence_hash"], custom_hash)

        alert2 = fetch_alert_by_id(self.conn, "EV-TEST-002")
        self.assertIsNotNone(alert2)
        self.assertEqual(alert2["mitre_technique_id"], "T1557")
        self.assertEqual(alert2["mitre_technique_name"], "Adversary-in-the-Middle")
        self.assertEqual(alert2["mitre_tactic"], "Credential Access")
        self.assertEqual(alert2["evidence_hash"], expected_hash)

        # 2. Test fetch_alerts
        alerts_list = fetch_alerts(conn=self.conn, limit=10)
        self.assertEqual(len(alerts_list), 2)
        self.assertIn("mitre_technique_id", alerts_list[0])
        self.assertIn("evidence_hash", alerts_list[0])

        # 3. Test fetch_all_alerts
        all_alerts = fetch_all_alerts(self.conn)
        self.assertEqual(len(all_alerts), 2)
        self.assertEqual(all_alerts[0]["mitre_technique_id"], "T1498")

        # 4. Test fetch_recent_alerts
        recent_alerts = fetch_recent_alerts(self.conn, limit=5)
        self.assertEqual(len(recent_alerts), 2)

        # 5. Test fetch_alerts_rolling_window
        rolling_alerts = fetch_alerts_rolling_window(self.conn, 1700000000000, 1700000020000)
        self.assertEqual(len(rolling_alerts), 2)

        # 6. Test query_alert_logs
        queried = query_alert_logs(self.conn, q="Deauth")
        self.assertEqual(len(queried), 1)
        self.assertEqual(queried[0]["mitre_technique_id"], "T1498")

        # 7. Test db_get_alerts
        db_alerts = db_get_alerts(time_range_seconds=1000000000, conn=self.conn)
        self.assertGreaterEqual(len(db_alerts), 2)
        self.assertEqual(db_alerts[0]["evidence_hash"], expected_hash)

    def test_incident_insert_update_and_fetch(self):
        inc_id = insert_incident(
            incident_dict={
                "id": "INC-20261124-001",
                "start_epoch_ms": 1700000000000,
                "end_epoch_ms": 1700000060000,
                "title": "802.11 Deauth Flood Attack",
                "primary_type": "DEAUTH_FLOOD",
                "severity": "HIGH",
                "confidence": 0.95,
                "status": "OPEN",
                "attacker_mac": "00:11:22:33:44:55",
                "target_mac": "66:77:88:99:AA:BB",
                "attacker_rssi": -39,
                "tool_signature": "MDK4",
                "deauth_reason": 7,
                "proximity_zone": "IMMEDIATE",
                "raw_injection_count": 120,
                "is_laa_randomized": 0,
                "hardware_profile": "ALFA_NETWORK_AWHUS036ACH",
                "remediation_advisory": "Isolate targeted AP channel and enforce 802.11w PMF",
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service",
                "mitre_tactic": "Impact"
            },
            conn=self.conn
        )
        self.assertEqual(inc_id, "INC-20261124-001")

        inc = fetch_incident_by_id("INC-20261124-001", conn=self.conn)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["attacker_mac"], "00:11:22:33:44:55")
        self.assertEqual(inc["target_mac"], "66:77:88:99:AA:BB")
        self.assertEqual(inc["attacker_rssi"], -39)
        self.assertEqual(inc["tool_signature"], "MDK4")
        self.assertEqual(inc["deauth_reason"], 7)
        self.assertEqual(inc["proximity_zone"], "IMMEDIATE")
        self.assertEqual(inc["raw_injection_count"], 120)
        self.assertEqual(inc["is_laa_randomized"], 0)
        self.assertEqual(inc["hardware_profile"], "ALFA_NETWORK_AWHUS036ACH")
        self.assertEqual(inc["remediation_advisory"], "Isolate targeted AP channel and enforce 802.11w PMF")
        self.assertEqual(inc["mitre_technique_id"], "T1498")
        self.assertEqual(inc["mitre_technique_name"], "Network Denial of Service")
        self.assertEqual(inc["mitre_tactic"], "Impact")
        self.assertTrue(len(inc["evidence_hash"]) > 0)

        # Update forensic attribution, hardware profile, advisory, MITRE technique, and status
        updated = update_incident(
            "INC-20261124-001",
            updates={
                "tool_signature": "ESP32_DEAUTHER",
                "proximity_zone": "NEARBY",
                "status": "ACKNOWLEDGED",
                "raw_injection_count": 150,
                "hardware_profile": "ESPRESSIF_SYSTEMS",
                "remediation_advisory": "Blacklist MAC on WLC and trigger channel hop",
                "mitre_technique_id": "T1557",
                "mitre_technique_name": "Adversary-in-the-Middle",
                "mitre_tactic": "Credential Access",
                "evidence_hash": "sha256_custom_incident_hash_789"
            },
            conn=self.conn
        )
        self.assertTrue(updated)

        inc_updated = fetch_incident_by_id("INC-20261124-001", conn=self.conn)
        self.assertEqual(inc_updated["tool_signature"], "ESP32_DEAUTHER")
        self.assertEqual(inc_updated["proximity_zone"], "NEARBY")
        self.assertEqual(inc_updated["status"], "ACKNOWLEDGED")
        self.assertEqual(inc_updated["raw_injection_count"], 150)
        self.assertEqual(inc_updated["hardware_profile"], "ESPRESSIF_SYSTEMS")
        self.assertEqual(inc_updated["remediation_advisory"], "Blacklist MAC on WLC and trigger channel hop")
        self.assertEqual(inc_updated["mitre_technique_id"], "T1557")
        self.assertEqual(inc_updated["mitre_technique_name"], "Adversary-in-the-Middle")
        self.assertEqual(inc_updated["mitre_tactic"], "Credential Access")
        self.assertEqual(inc_updated["evidence_hash"], "sha256_custom_incident_hash_789")

        all_incidents = fetch_incidents(conn=self.conn, limit=10)
        self.assertEqual(len(all_incidents), 1)
        self.assertEqual(all_incidents[0]["attacker_mac"], "00:11:22:33:44:55")
        self.assertEqual(all_incidents[0]["raw_injection_count"], 150)
        self.assertEqual(all_incidents[0]["hardware_profile"], "ESPRESSIF_SYSTEMS")
        self.assertEqual(all_incidents[0]["remediation_advisory"], "Blacklist MAC on WLC and trigger channel hop")
        self.assertEqual(all_incidents[0]["mitre_technique_id"], "T1557")
        self.assertEqual(all_incidents[0]["evidence_hash"], "sha256_custom_incident_hash_789")

        active_incidents = fetch_active_incidents(conn=self.conn)
        self.assertEqual(len(active_incidents), 1)
        self.assertEqual(active_incidents[0]["hardware_profile"], "ESPRESSIF_SYSTEMS")
        self.assertEqual(active_incidents[0]["mitre_technique_id"], "T1557")

        summary = db_get_incident_summary("INC-20261124-001", conn=self.conn)
        self.assertEqual(summary["hardware_profile"], "ESPRESSIF_SYSTEMS")
        self.assertEqual(summary["mitre_technique_id"], "T1557")

        recent = query_recent_incidents(limit=5, conn=self.conn)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["hardware_profile"], "ESPRESSIF_SYSTEMS")
        self.assertEqual(recent[0]["mitre_technique_id"], "T1557")

    def test_fetch_recent_telemetry_data_source_filtering(self):
        insert_telemetry_window(
            conn=self.conn,
            window_id=201,
            epoch_ms=1700000000000,
            deauth_count=5,
            mgmt_count=10,
            ble_count=0,
            rogue_count=0,
            nfc_count=0,
            data_source="live"
        )
        insert_telemetry_window(
            conn=self.conn,
            window_id=202,
            epoch_ms=1700000010000,
            deauth_count=8,
            mgmt_count=15,
            ble_count=0,
            rogue_count=0,
            nfc_count=0,
            data_source="simulation"
        )
        insert_telemetry_window(
            conn=self.conn,
            window_id=203,
            epoch_ms=1700000020000,
            deauth_count=2,
            mgmt_count=20,
            ble_count=0,
            rogue_count=0,
            nfc_count=0,
            data_source="live"
        )

        all_recent = fetch_recent_telemetry(conn=self.conn, limit=10)
        self.assertEqual(len(all_recent), 3)

        live_only = fetch_recent_telemetry(conn=self.conn, limit=10, data_source="live")
        self.assertEqual(len(live_only), 2)
        for row in live_only:
            self.assertEqual(row["data_source"], "live")

        sim_only = fetch_recent_telemetry(conn=self.conn, limit=10, data_source="simulation")
        self.assertEqual(len(sim_only), 1)
        self.assertEqual(sim_only[0]["window_id"], 202)
        self.assertEqual(sim_only[0]["data_source"], "simulation")

    def test_hardware_whitelist_crud(self):
        res1 = upsert_hardware_whitelist("00:11:22:33:44:AA", "Corp-Main", 1, conn=self.conn)
        self.assertTrue(res1)
        res2 = upsert_hardware_whitelist("00:11:22:33:44:BB", "Corp-IoT", 6, conn=self.conn)
        self.assertTrue(res2)

        items = fetch_hardware_whitelist(conn=self.conn)
        self.assertEqual(len(items), 2)
        bssids = {item["bssid"] for item in items}
        self.assertIn("00:11:22:33:44:AA", bssids)
        self.assertIn("00:11:22:33:44:BB", bssids)

        upsert_hardware_whitelist("00:11:22:33:44:AA", "Corp-Main-5G", 36, conn=self.conn)
        items_updated = fetch_hardware_whitelist(conn=self.conn)
        self.assertEqual(len(items_updated), 2)
        aa_entry = [i for i in items_updated if i["bssid"] == "00:11:22:33:44:AA"][0]
        self.assertEqual(aa_entry["ssid"], "Corp-Main-5G")
        self.assertEqual(aa_entry["channel"], 36)

        deleted_count = delete_hardware_whitelist("00:11:22:33:44:AA", conn=self.conn)
        self.assertEqual(deleted_count, 1)
        items_after_single_del = fetch_hardware_whitelist(conn=self.conn)
        self.assertEqual(len(items_after_single_del), 1)
        self.assertEqual(items_after_single_del[0]["bssid"], "00:11:22:33:44:BB")

        deleted_all_count = delete_hardware_whitelist(conn=self.conn)
        self.assertEqual(deleted_all_count, 1)
        items_empty = fetch_hardware_whitelist(conn=self.conn)
        self.assertEqual(len(items_empty), 0)

    def test_batch_update_incident_status(self):
        insert_incident(
            incident_dict={
                "id": "INC-BATCH-001",
                "title": "Batch Target 1",
                "primary_type": "DEAUTH_FLOOD",
                "status": "OPEN",
                "analyst_notes": "Initial log 1"
            },
            conn=self.conn
        )
        insert_incident(
            incident_dict={
                "id": "INC-BATCH-002",
                "title": "Batch Target 2",
                "primary_type": "DEAUTH_FLOOD",
                "status": "OPEN",
                "analyst_notes": "Initial log 2"
            },
            conn=self.conn
        )
        insert_incident(
            incident_dict={
                "id": "INC-BATCH-003",
                "title": "Batch Target 3",
                "primary_type": "ROGUE_AP",
                "status": "INVESTIGATING",
                "analyst_notes": "Do not touch"
            },
            conn=self.conn
        )

        updated_rows = batch_update_incident_status(
            from_status="OPEN",
            to_status="RESOLVED",
            note=" | BATCH_RESOLVED",
            conn=self.conn
        )
        self.assertEqual(updated_rows, 2)

        inc1 = fetch_incident_by_id("INC-BATCH-001", conn=self.conn)
        inc2 = fetch_incident_by_id("INC-BATCH-002", conn=self.conn)
        inc3 = fetch_incident_by_id("INC-BATCH-003", conn=self.conn)

        self.assertEqual(inc1["status"], "RESOLVED")
        self.assertEqual(inc1["analyst_notes"], "Initial log 1 | BATCH_RESOLVED")
        self.assertEqual(inc2["status"], "RESOLVED")
        self.assertEqual(inc2["analyst_notes"], "Initial log 2 | BATCH_RESOLVED")

        self.assertEqual(inc3["status"], "INVESTIGATING")
        self.assertEqual(inc3["analyst_notes"], "Do not touch")

    def test_hardware_whitelist_interface_finding_7_1(self):
        res = insert_hardware_whitelist(self.conn, "00:AA:BB:CC:DD:EE", "Lab-Secure-AP", 6)
        self.assertTrue(res)

        self.assertTrue(is_bssid_whitelisted(self.conn, "00:AA:BB:CC:DD:EE"))
        self.assertFalse(is_bssid_whitelisted(self.conn, "FF:FF:FF:FF:FF:FF"))

        wl = fetch_all_hardware_whitelist(self.conn)
        self.assertEqual(len(wl), 1)
        self.assertEqual(wl[0]["bssid"], "00:AA:BB:CC:DD:EE")
        self.assertEqual(wl[0]["ssid"], "Lab-Secure-AP")
        self.assertEqual(wl[0]["channel"], 6)
        self.assertIn("added_epoch_ms", wl[0])

        del_res = delete_hardware_whitelist(self.conn, "00:AA:BB:CC:DD:EE")
        self.assertTrue(del_res)
        self.assertFalse(is_bssid_whitelisted(self.conn, "00:AA:BB:CC:DD:EE"))
        self.assertEqual(len(fetch_all_hardware_whitelist(self.conn)), 0)

    def test_fetch_database_status_finding_3_3(self):
        status = fetch_database_status(self.conn)
        self.assertIsInstance(status, dict)
        self.assertEqual(status["journal_mode"], "wal")
        self.assertEqual(status["synchronous"], 1)
        self.assertEqual(status["foreign_keys"], 1)
        self.assertGreater(status["page_count"], 0)
        self.assertGreater(status["page_size"], 0)
        self.assertEqual(status["database_bytes"], status["page_count"] * status["page_size"])
        self.assertGreaterEqual(status["telemetry_windows_count"], 0)
        self.assertGreaterEqual(status["incidents_count"], 0)
        self.assertGreaterEqual(status["hardware_whitelist_count"], 0)

    def test_fetch_recent_telemetry_projections_finding_6_1(self):
        insert_telemetry_window(
            conn=self.conn,
            window_id=301,
            epoch_ms=1700000000000,
            deauth_count=3,
            mgmt_count=12,
            ble_count=1,
            rogue_count=0,
            nfc_count=0,
            channel=6,
            rssi_mean=-55.5,
            data_source="replay"
        )
        rows = fetch_recent_telemetry(self.conn, limit=5, data_source="replay")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        expected_cols = [
            "id", "epoch_ms", "window_id", "deauth_count", "mgmt_count",
            "ble_count", "rogue_count", "nfc_count", "channel",
            "bssid_count", "rssi_min", "rssi_avg", "rssi_max", "data_source"
        ]
        for col in expected_cols:
            self.assertIn(col, row, f"Column '{col}' missing from fetch_recent_telemetry projection")
        self.assertEqual(row["data_source"], "replay")
        self.assertEqual(row["window_id"], 301)

    def test_zero_wildcard_queries_in_database_py(self):
        db_file = Path(__file__).resolve().parent.parent / "app" / "database.py"
        content = db_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            upper_line = line.upper()
            if "SELECT *" in upper_line:
                self.fail(f"Found prohibited SELECT * on line {idx}: {line}")

    def test_lexicon_ban(self):
        banned = [
            "delve", "robust", "seamless", "pivotal", "crucial",
            "tapestry", "leverage", "holistic", "beacon", "game-changer"
        ]
        db_file = Path(__file__).resolve().parent.parent / "app" / "database.py"
        content = db_file.read_text(encoding="utf-8").lower()
        for word in banned:
            self.assertNotIn(word, content, f"Banned word '{word}' found in database.py")

if __name__ == "__main__":
    unittest.main()
