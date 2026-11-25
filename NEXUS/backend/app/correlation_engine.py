from typing import Dict, Any, List, Optional
from collections import deque
from .config import (
    CORRELATION_SPAN,
    EVENT_COOLDOWN_WINDOWS,
    CONF_BASE,
    CONF_MULTI_SIGNAL_WEIGHT,
    CONF_ZMAX_WEIGHT,
    CONF_ROGUE_WEIGHT,
    CONF_MAX
)

class CorrelationEngine:
    def __init__(self, span: int = CORRELATION_SPAN, cooldown: int = EVENT_COOLDOWN_WINDOWS):
        self.span = span
        self.cooldown = cooldown
        self.window_history: deque = deque(maxlen=span)
        self.last_event_window: int = -999
        self.last_fire: bool = False
        self.trusted_aps: Dict[str, Dict[str, Any]] = {}

    def set_trusted_aps(self, ap_map: Dict[str, Dict[str, Any]]) -> None:
        self.trusted_aps = {k.strip().upper(): v for k, v in ap_map.items()}

    def reset(self) -> None:
        self.window_history.clear()
        self.last_event_window = -999
        self.last_fire = False

    def process(self, evaluated_window: Dict[str, Any], raw_payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        window_id = evaluated_window["window_id"]
        flags = dict(evaluated_window["flags"])
        metrics = evaluated_window["metrics"]

        # Check for unauthorized transmitter BSSIDs or protected SSID impersonation
        grounded_rogue_detail: Optional[str] = None
        target_bssid: Optional[str] = None
        target_ssid: Optional[str] = None

        if raw_payload:
            top_sources = raw_payload.get("top", raw_payload.get("top_sources", []))
            if isinstance(top_sources, str):
                try:
                    import json
                    top_sources = json.loads(top_sources)
                except Exception:
                    top_sources = []

            known_protected_ssids = {
                ap.get("ssid", "") for ap in self.trusted_aps.values() if ap.get("ssid")
            }

            if isinstance(top_sources, list):
                for src in top_sources:
                    if isinstance(src, dict) and "bssid" in src:
                        cand_bssid = str(src.get("bssid", "")).strip().upper()
                        cand_ssid = str(src.get("ssid", ""))
                        cand_ch = int(src.get("ch", src.get("channel", raw_payload.get("ch", 1))))

                        # If BSSID is not in allowlist
                        if cand_bssid and cand_bssid not in self.trusted_aps:
                            if cand_ssid and cand_ssid in known_protected_ssids:
                                grounded_rogue_detail = (
                                    f"BSSID {cand_bssid} appeared advertising SSID {cand_ssid} not in allowlist"
                                )
                                target_bssid = cand_bssid
                                target_ssid = cand_ssid
                                flags["rogue"] = True
                                break
                            elif cand_ch in (1, 6, 11) and int(raw_payload.get("rogue", 0)) > 0:
                                grounded_rogue_detail = (
                                    f"BSSID {cand_bssid} appeared advertising SSID {cand_ssid or 'UNKNOWN'} not in allowlist"
                                )
                                target_bssid = cand_bssid
                                target_ssid = cand_ssid
                                flags["rogue"] = True
                                break

        self.window_history.append({
            "window_id": window_id,
            "flags": flags,
            "metrics": metrics
        })

        if not evaluated_window["warmed_up"]:
            self.last_fire = False
            return None

        # Collect distinct flagged features across the span
        distinct_flagged = set()
        max_z = 0.0
        rogue_active = False

        for item in self.window_history:
            for feat, is_flagged in item["flags"].items():
                if is_flagged:
                    distinct_flagged.add(feat)
                    z_val = item["metrics"][feat]["z_score"]
                    if z_val > max_z:
                        max_z = z_val
                    if feat == "rogue":
                        rogue_active = True

        fire = (len(distinct_flagged) >= 2) or (max_z >= 8.0) or rogue_active
        self.last_fire = fire

        if not fire:
            return None

        # Check cooldown boundary: new event only if more than cooldown windows elapsed
        if (window_id - self.last_event_window) <= self.cooldown:
            return None

        self.last_event_window = window_id
        n = max(len(distinct_flagged), 1)

        # Confidence calculation formula
        conf = CONF_BASE + (CONF_MULTI_SIGNAL_WEIGHT * (n - 1)) + (CONF_ZMAX_WEIGHT * min(max_z, 10.0))
        if rogue_active:
            conf += CONF_ROGUE_WEIGHT
        confidence = round(min(CONF_MAX, conf), 2)

        # Severity mapping
        if confidence >= 0.85:
            severity = "high"
        elif confidence >= 0.65:
            severity = "medium"
        else:
            severity = "low"

        # Determine primary event classification
        if rogue_active:
            event_type = "Possible evil-twin access point"
            type_key = "rogue"
        elif "deauth" in distinct_flagged:
            event_type = "Deauthentication burst"
            type_key = "deauth"
        elif "ble" in distinct_flagged:
            event_type = "BLE advertisement flood"
            type_key = "ble"
        else:
            event_type = "Management frame anomaly"
            type_key = "mgmt"

        # Collect measured evidence payload with deterministic order
        feature_order = {"deauth": 0, "mgmt": 1, "ble": 2, "rogue": 3}
        sorted_flagged = sorted(distinct_flagged, key=lambda f: feature_order.get(f, 99))
        evidence_features = []
        for feat in sorted_flagged:
            evidence_features.append({
                "feature": feat,
                "observed": metrics[feat]["observed"],
                "baseline_mean": metrics[feat]["baseline_mean"],
                "baseline_sd": metrics[feat]["baseline_sd"],
                "z_score": metrics[feat]["z_score"]
            })

        evidence_payload = {
            "features": evidence_features,
            "signals_correlated": len(distinct_flagged)
        }
        if grounded_rogue_detail:
            evidence_payload["grounded_reason"] = grounded_rogue_detail
        if target_bssid:
            evidence_payload["target_bssid"] = target_bssid
        if target_ssid:
            evidence_payload["target_ssid"] = target_ssid

        return {
            "window_id": window_id,
            "event_type": event_type,
            "type_key": type_key,
            "severity": severity,
            "confidence": confidence,
            "signals_correlated": len(distinct_flagged),
            "target_bssid": target_bssid,
            "grounded_reason": grounded_rogue_detail,
            "evidence": evidence_payload
        }
