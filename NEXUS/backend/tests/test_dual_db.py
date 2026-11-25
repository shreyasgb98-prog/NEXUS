import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from NEXUS.backend.app import database, main


class TestDualDatabaseIsolation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.live_db = str(Path(self.temp_dir.name) / "nexus.db")
        self.sim_db = str(Path(self.temp_dir.name) / "nexus_sim.db")

        self.patcher_live = patch.object(database, "DB_PATH", self.live_db)
        self.patcher_sim = patch.object(database, "SIM_DB_PATH", self.sim_db)
        self.patcher_live.start()
        self.patcher_sim.start()

        database.init_db(self.live_db)
        main.baseline_engine.reset()
        main.correlation_engine.reset()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.patcher_live.stop()
        self.patcher_sim.stop()
        self.temp_dir.cleanup()

    def test_simulation_ingestion_isolation_and_purge(self):
        # 1. Ingest 10 simulation windows
        for i in range(1, 11):
            resp = self.client.post(
                "/api/telemetry/ingest",
                json={
                    "window_id": i,
                    "deauth": 1,
                    "mgmt": 20,
                    "ble": 5,
                    "rogue": 0,
                    "nfc": 0,
                    "data_source": "simulation (synthetic)",
                },
            )
            self.assertEqual(resp.status_code, 200)

        # Verify nexus_sim.db has 10 rows while nexus.db has 0 rows
        sim_conn = database.get_connection(db_mode="sim")
        live_conn = database.get_connection(db_mode="live")
        try:
            sim_count = sim_conn.execute("SELECT COUNT(id) AS cnt FROM telemetry_windows;").fetchone()["cnt"]
            live_count = live_conn.execute("SELECT COUNT(id) AS cnt FROM telemetry_windows;").fetchone()["cnt"]
            self.assertEqual(sim_count, 10)
            self.assertEqual(live_count, 0)

            # Verify WAL and foreign_keys PRAGMAs on nexus_sim.db
            pragmas = database.fetch_sqlite_pragmas(sim_conn)
            self.assertEqual(pragmas["journal_mode"], "wal")
            self.assertEqual(pragmas["synchronous"], 1)
            self.assertEqual(pragmas["foreign_keys"], 1)
        finally:
            sim_conn.close()
            live_conn.close()

        # 2. Purge simulation database
        purge_resp = self.client.post("/api/telemetry/purge-simulations")
        self.assertEqual(purge_resp.status_code, 200)
        self.assertEqual(
            purge_resp.json(),
            {"status": "purged", "message": "Simulation database cleared successfully."},
        )

        sim_conn = database.get_connection(db_mode="sim")
        try:
            sim_count_after = sim_conn.execute("SELECT COUNT(id) AS cnt FROM telemetry_windows;").fetchone()["cnt"]
            self.assertEqual(sim_count_after, 0)
        finally:
            sim_conn.close()

    def test_mode_routed_recent_and_incidents(self):
        # Ingest 3 live windows and 4 simulation windows
        for i in range(1, 4):
            self.client.post(
                "/api/telemetry/ingest",
                json={
                    "window_id": i,
                    "deauth": 0,
                    "mgmt": 10,
                    "ble": 2,
                    "rogue": 0,
                    "nfc": 0,
                    "data_source": "live",
                },
            )
        for i in range(101, 105):
            self.client.post(
                "/api/telemetry/ingest",
                json={
                    "window_id": i,
                    "deauth": 2,
                    "mgmt": 30,
                    "ble": 4,
                    "rogue": 0,
                    "nfc": 0,
                    "data_source": "simulation (synthetic)",
                },
            )

        # 3. Verify GET /api/telemetry/recent?mode=sim&limit=100 vs mode=live&limit=100
        sim_recent = self.client.get("/api/telemetry/recent?mode=sim&limit=100")
        live_recent = self.client.get("/api/telemetry/recent?mode=live&limit=100")
        self.assertEqual(sim_recent.status_code, 200)
        self.assertEqual(live_recent.status_code, 200)

        sim_rows = sim_recent.json()
        live_rows = live_recent.json()
        self.assertEqual([r["window_id"] for r in sim_rows], [101, 102, 103, 104])
        self.assertEqual([r["window_id"] for r in live_rows], [1, 2, 3])

        # Verify limit <= 0 falls back to up to 1000 rows
        sim_recent_zero_limit = self.client.get("/api/telemetry/recent?mode=sim&limit=0")
        self.assertEqual(sim_recent_zero_limit.status_code, 200)
        self.assertEqual(len(sim_recent_zero_limit.json()), 4)

        # Verify GET /api/incidents?mode=sim and mode=live
        sim_inc = self.client.get("/api/incidents?mode=sim")
        live_inc = self.client.get("/api/incidents?mode=live")
        self.assertEqual(sim_inc.status_code, 200)
        self.assertEqual(live_inc.status_code, 200)
        self.assertIn("active_incidents", sim_inc.json())
        self.assertIn("active_incidents", live_inc.json())


if __name__ == "__main__":
    unittest.main()
