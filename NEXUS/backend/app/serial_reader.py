import json
import time
import threading
from typing import Optional, Callable, Dict, Any
try:
    import serial
except ImportError:
    serial = None
from .database import get_connection, insert_serial_error

class SerialManager:
    def __init__(self, on_window_received: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.port: Optional[str] = None
        self.baud_rate: int = 115200
        self.ser: Optional[serial.Serial] = None
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None
        self.on_window_received = on_window_received
        
        self.state: str = "DISCONNECTED"
        self.error_count: int = 0
        self.dropped_frames: int = 0
        self.raw_rx_buffer_overflow_count: int = 0

    def connect(self, port: str, baud_rate: int = 115200) -> bool:
        self.disconnect()
        self.port = port
        self.baud_rate = baud_rate
        self.state = f"CONNECTING ({self.baud_rate})"

        if serial is None:
            self.state = "DISCONNECTED"
            self._log_error("SERIAL_OPEN_FAILURE", "pyserial not installed")
            return False

        try:
            self.ser = serial.Serial(self.port, self.baud_rate, timeout=1.0)
            self.running = True
            self.thread = threading.Thread(target=self._read_loop, daemon=True)
            self.thread.start()
            self.state = "ACTIVE_MONITORING"
            return True
        except Exception as e:
            self.state = "DISCONNECTED"
            self._log_error("SERIAL_OPEN_FAILURE", str(e))
            return False

    def is_connected(self) -> bool:
        return bool(self.running and self.ser and getattr(self.ser, "is_open", False))

    def write_command(self, cmd_dict: Dict[str, Any]) -> bool:
        if not self.is_connected():
            return False
        try:
            line = json.dumps(cmd_dict) + "\n"
            self.ser.write(line.encode("utf-8"))
            if hasattr(self.ser, "flush"):
                self.ser.flush()
            return True
        except Exception as e:
            self._log_error("SERIAL_WRITE_ERROR", str(e))
            return False

    def disconnect(self) -> None:
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        if self.ser and getattr(self.ser, "is_open", False):
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        self.state = "DISCONNECTED"

    def _log_error(self, error_type: str, raw_payload: str) -> None:
        self.error_count += 1
        now_ms = int(time.time() * 1000)
        try:
            conn = get_connection()
            insert_serial_error(conn, now_ms, error_type, raw_payload)
            conn.close()
        except Exception:
            pass

    def _read_loop(self) -> None:
        # Guarantee synchronization on a fresh newline boundary on initial connection open
        if self.ser and getattr(self.ser, "is_open", True):
            try:
                if hasattr(self.ser, "reset_input_buffer"):
                    self.ser.reset_input_buffer()
                if hasattr(self.ser, "readline"):
                    _ = self.ser.readline()
            except Exception:
                pass

        while self.running and self.ser and getattr(self.ser, "is_open", True):
            try:
                # Check for buffer overflow conditions
                if hasattr(self.ser, "in_waiting") and self.ser.in_waiting > 4096:
                    self.raw_rx_buffer_overflow_count += 1
                    self.state = "BUFFER_OVERFLOW"
                    self._log_error("RX_BUFFER_OVERFLOW", f"in_waiting={self.ser.in_waiting}")
                    if hasattr(self.ser, "reset_input_buffer"):
                        self.ser.reset_input_buffer()
                    self.state = "ACTIVE_MONITORING"
                    continue

                line_raw = self.ser.readline()
                if not line_raw:
                    continue

                if isinstance(line_raw, bytes):
                    line_str = line_raw.decode("utf-8", errors="replace").strip()
                else:
                    line_str = str(line_raw).strip()

                # Discard empty lines or lines lacking valid JSON braces ('{' and '}')
                if not line_str or "{" not in line_str or "}" not in line_str:
                    if line_str:
                        self.dropped_frames += 1
                    continue

                try:
                    payload = json.loads(line_str)
                except json.JSONDecodeError:
                    self.dropped_frames += 1
                    self.error_count += 1
                    now_ms = int(time.time() * 1000)
                    try:
                        conn = get_connection()
                        insert_serial_error(conn, now_ms, "CORRUPT_FRAME", line_str)
                        conn.close()
                    except Exception:
                        pass
                    continue

                try:
                    for field in ("deauth", "mgmt", "ble", "rogue", "nfc"):
                        if field not in payload:
                            raise ValueError(f"Missing telemetry field: {field}")

                    if self.on_window_received:
                        self.on_window_received(payload)
                except Exception as parse_err:
                    self.dropped_frames += 1
                    self._log_error("MALFORMED_FRAME_DROP", f"{parse_err} | {line_str}")

            except (serial.SerialException if serial else OSError, OSError) as port_err:
                self._log_error("SERIAL_PORT_DISCONNECT", str(port_err))
                self.state = "DISCONNECTED"
                self.running = False
                break
