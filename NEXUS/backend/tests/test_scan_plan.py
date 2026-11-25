import unittest
import sys
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

# Configure path imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.baseline_model import AdaptiveBaselineEngine, BaselineModel
from app.database import get_connection, fetch_channel_activity_stats
from app.main import (
    baseline_engine,
    serial_manager,
    process_telemetry_window,
    reset_telemetry_state,
    get_adaptive_scan_plan,
    set_adaptive_scan_plan_override,
    ScanPlanOverridePayload
)


class TestChannelProfiling(unittest.TestCase):
    """Verifies channel density tracking and optimal scan plan calculation across warmup."""

    def setUp(self):
        self.engine = AdaptiveBaselineEngine(warmup_windows=30)

    def test_baseline_model_alias(self):
        """Verifies BaselineModel alias resolves directly to AdaptiveBaselineEngine."""
        self.assertIs(BaselineModel, AdaptiveBaselineEngine)

    def test_channel_profiling_dominant_channel_selection(self):
        """Simulates 30-window warmup sequence and confirms dominant channel selection."""
        # Warmup sequence:
        # Channel 1: 10 windows with low management traffic (mgmt=10, 1 BSSID)
        # Channel 6: 10 windows with high management traffic (mgmt=95, 4 BSSIDs)
        # Channel 11: 10 windows with moderate management traffic (mgmt=30, 2 BSSIDs)
        for i in range(10):
            self.engine.evaluate_window({
                "ch": 1,
                "mgmt": 10,
                "deauth": 0,
                "ble": 5,
                "rogue": 0,
                "bssid_cnt": 1,
                "top": [{"bssid": "11:22:33:44:55:01"}]
            })

        for i in range(10):
            self.engine.evaluate_window({
                "ch": 6,
                "mgmt": 95,
                "deauth": 0,
                "ble": 12,
                "rogue": 0,
                "bssid_cnt": 4,
                "top": [
                    {"bssid": "66:77:88:99:AA:01"},
                    {"bssid": "66:77:88:99:AA:02"},
                    {"bssid": "66:77:88:99:AA:03"},
                    {"bssid": "66:77:88:99:AA:04"}
                ]
            })

        for i in range(10):
            self.engine.evaluate_window({
                "ch": 11,
                "mgmt": 30,
                "deauth": 0,
                "ble": 8,
                "rogue": 0,
                "bssid_cnt": 2,
                "top": [{"bssid": "B1:B2:B3:B4:B5:01"}, {"bssid": "B1:B2:B3:B4:B5:02"}]
            })

        self.assertEqual(self.engine.processed_windows, 30)
        self.assertFalse(self.engine.is_warmed_up)

        # 31st window triggers warmed_up state
        self.engine.evaluate_window({
            "ch": 6,
            "mgmt": 90,
            "deauth": 0,
            "ble": 10,
            "rogue": 0,
            "bssid_cnt": 4
        })
        self.assertTrue(self.engine.is_warmed_up)

        plan = self.engine.get_optimal_scan_plan()

        self.assertEqual(plan["cmd"], "scan_plan")
        self.assertEqual(plan["primary_ch"], 6)
        self.assertEqual(plan["dwell_primary_ms"], 1700)
        self.assertEqual(plan["dwell_patrol_ms"], 50)

    def test_manual_channel_override_and_validation(self):
        """Verifies manual override priority and input boundary checking."""
        self.engine.set_manual_primary_channel(11)
        plan = self.engine.get_optimal_scan_plan()
        self.assertEqual(plan["primary_ch"], 11)

        with self.assertRaises(ValueError):
            self.engine.set_manual_primary_channel(0)

        with self.assertRaises(ValueError):
            self.engine.set_manual_primary_channel(14)

    def test_reset_clears_channel_histogram(self):
        """Verifies reset purges channel density statistics and manual channel pins."""
        self.engine.evaluate_window({"ch": 6, "mgmt": 100, "bssid_cnt": 5})
        self.engine.set_manual_primary_channel(6)
        self.engine.reset()

        self.assertEqual(self.engine.processed_windows, 0)
        self.assertIsNone(self.engine.manual_primary_ch)
        self.assertEqual(self.engine.channel_activity[6]["mgmt_frames"], 0)
        self.assertEqual(self.engine.channel_activity[6]["windows"], 0)


class TestScanPlanEndpoints(unittest.TestCase):
    """Verifies FastAPI endpoints for adaptive scanning plan query and override."""

    def setUp(self):
        reset_telemetry_state()

    def test_get_scan_plan_during_warmup_returns_round_robin(self):
        """Before warmup completion, GET /api/telemetry/scan-plan returns round-robin mode."""
        plan = get_adaptive_scan_plan()
        self.assertEqual(plan["cmd"], "scan_plan")
        self.assertEqual(plan["mode"], "round_robin")
        self.assertFalse(plan["warmed_up"])
        self.assertEqual(plan["dwell_primary_ms"], 100)
        self.assertEqual(plan["dwell_patrol_ms"], 100)

    def test_get_scan_plan_post_warmup_returns_learned_adaptive_plan(self):
        """After 30 warmup windows, GET /api/telemetry/scan-plan returns adaptive plan."""
        # Ingest 31 windows with channel 6 dominant
        for i in range(31):
            process_telemetry_window({
                "window_id": i + 1,
                "ch": 6,
                "mgmt": 110,
                "deauth": 0,
                "ble": 15,
                "rogue": 0,
                "bssid_cnt": 3
            }, data_source="simulation")

        plan = get_adaptive_scan_plan()
        self.assertEqual(plan["cmd"], "scan_plan")
        self.assertEqual(plan["mode"], "adaptive")
        self.assertTrue(plan["warmed_up"])
        self.assertEqual(plan["primary_ch"], 6)
        self.assertEqual(plan["dwell_primary_ms"], 1700)
        self.assertEqual(plan["dwell_patrol_ms"], 50)

    def test_post_scan_plan_manual_override_valid(self):
        """POST /api/telemetry/scan-plan overrides primary channel."""
        payload = ScanPlanOverridePayload(primary_ch=11)
        res = set_adaptive_scan_plan_override(payload)

        self.assertEqual(res["status"], "configured")
        self.assertEqual(res["scan_plan"]["cmd"], "scan_plan")
        self.assertEqual(res["scan_plan"]["primary_ch"], 11)
        self.assertEqual(res["scan_plan"]["dwell_primary_ms"], 1700)
        self.assertEqual(res["scan_plan"]["dwell_patrol_ms"], 50)

    def test_post_scan_plan_invalid_channels_rejected(self):
        """POST /api/telemetry/scan-plan rejects channel numbers outside 1..13 with HTTP 400."""
        for invalid_ch in [0, 14, -1, 99]:
            payload = ScanPlanOverridePayload(primary_ch=invalid_ch)
            with self.assertRaises(HTTPException) as ctx:
                set_adaptive_scan_plan_override(payload)
            self.assertEqual(ctx.exception.status_code, 400)

    def test_post_scan_plan_dispatches_to_uart_when_connected(self):
        """POST /api/telemetry/scan-plan dispatches JSON command if serial is connected."""
        with patch.object(serial_manager, "is_connected", return_value=True):
            with patch.object(serial_manager, "write_command", return_value=True) as mock_write:
                payload = ScanPlanOverridePayload(primary_ch=3)
                res = set_adaptive_scan_plan_override(payload)

                self.assertTrue(res["dispatched_to_uart"])
                mock_write.assert_called_once()
                dispatched_cmd = mock_write.call_args[0][0]
                self.assertEqual(dispatched_cmd["cmd"], "scan_plan")
                self.assertEqual(dispatched_cmd["primary_ch"], 3)
                self.assertEqual(dispatched_cmd["dwell_primary_ms"], 1700)
                self.assertEqual(dispatched_cmd["dwell_patrol_ms"], 50)

    def test_database_channel_activity_stats(self):
        """Verifies database helper fetches channel density statistics with explicit projection."""
        conn = get_connection()
        stats = fetch_channel_activity_stats(conn, limit_windows=30)
        conn.close()
        self.assertIsInstance(stats, list)


if __name__ == "__main__":
    unittest.main()
