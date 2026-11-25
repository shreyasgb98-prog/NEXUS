import csv
import io
import time
import asyncio
from typing import Dict, Any, Optional, Callable, List

class CSVReplayEngine:
    """Streams historical or labelled CSV telemetry windows through the detection pipeline."""

    def __init__(self):
        self.running: bool = False
        self.task: Optional[asyncio.Task] = None
        self.current_row: int = 0
        self.total_rows: int = 0
        self.speed_ms: int = 100
        self.source_name: str = ""

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "current_row": self.current_row,
            "total_rows": self.total_rows,
            "speed_ms": self.speed_ms,
            "source_name": self.source_name
        }

    async def _replay_loop(
        self,
        rows: List[Dict[str, Any]],
        on_window: Callable[[Dict[str, Any], str], Any]
    ) -> None:
        self.running = True
        self.total_rows = len(rows)
        self.current_row = 0

        try:
            for idx, r in enumerate(rows):
                if not self.running:
                    break

                self.current_row = idx + 1
                on_window(r, "replay")

                delay_sec = max(0.01, self.speed_ms / 1000.0)
                await asyncio.sleep(delay_sec)
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    def start_replay(
        self,
        csv_text: str,
        speed_ms: int = 100,
        source_name: str = "dataset.csv",
        on_window: Optional[Callable[[Dict[str, Any], str], Any]] = None
    ) -> bool:
        self.stop_replay()

        self.speed_ms = max(10, min(speed_ms, 5000))
        self.source_name = source_name

        # Parse CSV rows
        f = io.StringIO(csv_text.strip())
        reader = csv.DictReader(f)
        parsed_rows: List[Dict[str, Any]] = []

        for row in reader:
            parsed: Dict[str, Any] = {
                "deauth": int(row.get("deauth", row.get("deauth_count", 0))),
                "mgmt": int(row.get("mgmt", row.get("mgmt_count", 0))),
                "ble": int(row.get("ble", row.get("ble_count", 0))),
                "rogue": int(row.get("rogue", row.get("rogue_count", 0))),
                "nfc": int(row.get("nfc", row.get("nfc_count", 0))),
                "rssi": float(row.get("rssi", row.get("rssi_mean", -70.0))),
                "is_attack_labelled": int(row.get("is_attack_labelled", row.get("label", 0))),
                "ch": int(row.get("ch", row.get("channel", 1))),
                "bssid_cnt": int(row.get("bssid_cnt", row.get("unique_bssids", 0))),
                "rssi_min": float(row.get("rssi_min", -90.0)),
                "rssi_max": float(row.get("rssi_max", -30.0))
            }
            parsed_rows.append(parsed)

        if not parsed_rows:
            return False

        if on_window:
            try:
                loop = asyncio.get_running_loop()
                self.task = loop.create_task(self._replay_loop(parsed_rows, on_window))
            except RuntimeError:
                self.running = False

        return True

    def stop_replay(self) -> None:
        self.running = False
        if self.task and not self.task.done():
            self.task.cancel()
            self.task = None
