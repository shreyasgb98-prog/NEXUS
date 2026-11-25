from datetime import datetime, timezone
from typing import Dict, Any

class EvidenceBuilder:
    def __init__(self):
        self.event_counter: int = 0

    def reset(self) -> None:
        self.event_counter = 0

    def build_record(
        self,
        window_id: int,
        event_type: str,
        type_key: str,
        severity: str,
        confidence: float,
        evidence_dict: Dict[str, Any],
        explanation_text: str,
        data_source: str = "live (serial)"
    ) -> Dict[str, Any]:
        self.event_counter += 1
        event_id = f"EV-{self.event_counter:03d}"
        iso_time = datetime.now(timezone.utc).isoformat()

        return {
            "id": event_id,
            "window": window_id,
            "time": iso_time,
            "type_key": type_key,
            "type": event_type,
            "severity": severity,
            "confidence": confidence,
            "data_source": data_source,
            "evidence": evidence_dict,
            "explanation": explanation_text
        }
