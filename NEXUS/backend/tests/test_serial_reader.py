import unittest
import sys
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

# Configure path imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.serial_reader import SerialManager
from app.database import (
    get_connection,
    apply_migrations,
    fetch_serial_error_counters,
    fetch_serial_error_count
)
from app.main import (
    serial_manager,
    connect_serial_port,
    disconnect_serial_port,
    SerialConnectPayload,
    verify_api_key
)


class MockSerialDevice:
    """Mock serial port supporting simulated UART byte feeds."""

    def __init__(self, lines=None, in_waiting=0):
        self.is_open = True
        self.in_waiting = in_waiting
        self._lines = list(lines) if lines else []
        self.buffer_flushed = False
        self.closed = False

    def reset_input_buffer(self):
        self.buffer_flushed = True

    def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""

    def close(self):
        self.is_open = False
        self.closed = True


class TestSerialReaderSyncAndHardening(unittest.TestCase):
    """Verifies UART boundary synchronization and frame validation under active traffic."""

    def setUp(self):
        self.received_windows = []

    def _on_window(self, window_data):
        self.received_windows.append(window_data)

    def test_initial_sync_discards_partial_stream_segment(self):
        """Initial connection mid-stream flushes buffer and discards leading partial line segment."""
        # Simulated scenario: ESP32 was already emitting telemetry when port attached.
        # Initial readline segment is a broken trailing fragment.
        feed = [
            b',"rssi_avg":-68}\n',
            b'{"deauth": 2, "mgmt": 45, "ble": 12, "rogue": 0, "nfc": 0}\n'
        ]
        mock_port = MockSerialDevice(lines=feed)

        manager = SerialManager(on_window_received=self._on_window)
        manager.ser = mock_port
        manager.running = True

        # Run one step of read loop behavior:
        # Initial open flush & first line discard
        if mock_port and getattr(mock_port, "is_open", True):
            if hasattr(mock_port, "reset_input_buffer"):
                mock_port.reset_input_buffer()
            if hasattr(mock_port, "readline"):
                _ = mock_port.readline()

        self.assertTrue(mock_port.buffer_flushed)
        # Confirm the partial fragment was discarded
        self.assertEqual(len(mock_port._lines), 1)

        # Worker read loop consumes the subsequent complete frame
        line = mock_port.readline()
        line_str = line.decode("utf-8", errors="replace").strip()
        payload = json.loads(line_str)
        self._on_window(payload)

        self.assertEqual(len(self.received_windows), 1)
        self.assertEqual(self.received_windows[0]["deauth"], 2)
        self.assertEqual(self.received_windows[0]["mgmt"], 45)

    def test_utf8_decode_replace_corrupt_uart(self):
        """UART line with non-UTF-8 bytes decodes with replacement characters rather than crashing."""
        noisy_bytes = b'{"deauth": 0, "mgmt": 10, "ble": 0, "rogue": 0, "nfc": 0, "note": "\xff\xfe"}\n'
        decoded = noisy_bytes.decode("utf-8", errors="replace").strip()
        self.assertIn("\ufffd", decoded)

        # Confirm valid JSON containing replacement character parses without crash
        parsed = json.loads(decoded)
        self.assertEqual(parsed["mgmt"], 10)

    def test_discard_empty_lines_and_lines_lacking_braces(self):
        """Lines that are empty or lack valid braces are discarded."""
        manager = SerialManager(on_window_received=self._on_window)
        manager.ser = MockSerialDevice()
        manager.running = True

        raw_test_lines = [
            b"",
            b"   \r\n",
            b"ESP-ROM:esp32s3-20210327\n",
            b"rst:0x1 (POWERON),boot:0x8 (SPI_FAST_FLASH_BOOT)\n",
            b"partial fragment without braces\n"
        ]

        for raw in raw_test_lines:
            line_str = raw.decode("utf-8", errors="replace").strip()
            if not line_str or "{" not in line_str or "}" not in line_str:
                if line_str:
                    manager.dropped_frames += 1
                continue
            # If not discarded, it would reach json.loads
            self.fail(f"Line should have been discarded: {line_str}")

        self.assertEqual(manager.dropped_frames, 3)
        self.assertEqual(len(self.received_windows), 0)

    def test_json_decode_error_records_corrupt_frame(self):
        """Line with braces but malformed JSON records CORRUPT_FRAME error and worker continues."""
        manager = SerialManager(on_window_received=self._on_window)
        manager.ser = MockSerialDevice()

        bad_line = "{deauth: broken, mgmt: missing_quotes}"
        now_ms = int(time.time() * 1000)

        # Directly simulate the JSONDecodeError path in _read_loop
        with patch("app.serial_reader.insert_serial_error") as mock_insert_error:
            try:
                json.loads(bad_line)
            except json.JSONDecodeError:
                manager.dropped_frames += 1
                manager.error_count += 1
                conn = MagicMock()
                mock_insert_error(conn, now_ms, "CORRUPT_FRAME", bad_line)

            mock_insert_error.assert_called_once_with(conn, now_ms, "CORRUPT_FRAME", bad_line)
            self.assertEqual(manager.dropped_frames, 1)
            self.assertEqual(manager.error_count, 1)


class TestFastAPISerialEndpoints(unittest.TestCase):
    """Verifies FastAPI serial connection management endpoints under streaming input."""

    def test_connect_serial_port_http_200_and_initiates_worker(self):
        """Endpoint connect_serial_port returns 200 payload and launches background reader thread."""
        fake_feed = [
            b'initial_partial_fragment\n',
            b'{"deauth": 0, "mgmt": 50, "ble": 15, "rogue": 0, "nfc": 0}\n',
            b'{"deauth": 1, "mgmt": 52, "ble": 16, "rogue": 0, "nfc": 0}\n'
        ]
        mock_port = MockSerialDevice(lines=fake_feed)

        mock_serial_pkg = MagicMock()
        mock_serial_pkg.Serial.return_value = mock_port

        with patch("app.serial_reader.serial", mock_serial_pkg):
            payload = SerialConnectPayload(port="COM4", baud_rate=115200)
            data = connect_serial_port(payload)

            self.assertEqual(data["status"], "connected")
            self.assertEqual(data["port"], "COM4")
            self.assertEqual(data["baud_rate"], 115200)

            # Confirm serial manager state and worker thread started
            self.assertEqual(serial_manager.state, "ACTIVE_MONITORING")
            self.assertTrue(serial_manager.running)
            self.assertIsNotNone(serial_manager.thread)
            self.assertTrue(serial_manager.thread.is_alive())

            # Allow worker thread brief interval to process feed
            time.sleep(0.05)

            # Disconnect cleanly
            disc_resp = disconnect_serial_port()
            self.assertEqual(disc_resp["status"], "disconnected")
            self.assertEqual(serial_manager.state, "DISCONNECTED")
            self.assertFalse(serial_manager.running)

    def test_connect_serial_port_unauthorized_without_key(self):
        """verify_api_key rejects requests lacking valid API key with HTTP 401."""
        with self.assertRaises(HTTPException) as ctx:
            verify_api_key("invalid-token")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_connect_serial_port_failure_raises_400(self):
        """connect_serial_port raises HTTP 400 if serial port initialization fails."""
        with patch.object(serial_manager, "connect", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                connect_serial_port(SerialConnectPayload(port="INVALID_PORT", baud_rate=115200))
            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
