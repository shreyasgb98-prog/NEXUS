import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Set
from .database import (
    get_connection,
    create_incident,
    update_incident,
    update_incident_status,
    aggregate_alert_to_incident,
    fetch_active_incidents,
    fetch_incident_with_timeline,
    fetch_false_positive_stats
)

def map_reason_code_to_signature(code: int) -> str:
    """Maps 802.11 Reason Codes to adversary tool signatures or standard disassociation types."""
    reason_map = {
        7: "Adversary Deauth Exploit (aireplay-ng / mdk4 signature)",
        2: "Session Hijack / Force Re-authentication (MDK3 signature)",
        6: "Association Injection Flooding",
        1: "Generic / Unspecified Disconnection",
        3: "Legitimate Client Roam / Station Leaving",
        8: "Standard BSS Transition",
    }
    try:
        val = int(code)
    except (ValueError, TypeError):
        val = 0
    return reason_map.get(val, f"Standard Disassociation (Reason {val})")


def categorize_rssi_proximity(rssi: int) -> str:
    """Categorizes physical proximity from measured RSSI (dBm)."""
    try:
        val = int(rssi)
    except (ValueError, TypeError):
        val = 0

    if val == 0:
        return "NONE"
    elif val >= -45:
        return "IMMEDIATE (< 3m, inside room)"
    elif -45 > val >= -70:
        return "MID-RANGE (5-15m, inside building)"
    else:  # val < -70
        return "PERIMETER (> 15m, outside structure)"


def is_mac_randomized(mac_str: str) -> bool:
    """Checks the IEEE Locally Administered Address (LAA) bit in the first octet."""
    if not mac_str or len(mac_str) < 2:
        return False
    try:
        clean_mac = mac_str.replace("-", ":")
        first_byte = int(clean_mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


OFFENSIVE_OUI_MAP = {
    "24:0A:C4": "Espressif Deauther / Rogue Node (ESP8266/ESP32)",
    "30:AE:A4": "Espressif Embedded Transceiver",
    "84:F3:EB": "Espressif Wireless SoC",
    "B8:27:EB": "Raspberry Pi (Pwnagotchi / Kali Linux)",
    "DC:A6:32": "Raspberry Pi 4 / Embedded Attack Rig",
    "E4:5F:01": "Raspberry Pi Foundation Transceiver",
    "00:C0:CA": "Alfa Network High-Power Injection Card",
}


def identify_hardware_profile(mac_str: str) -> str:
    """Identifies offensive transceiver hardware profiles or spoofed LAA MAC randomization."""
    if not mac_str or len(mac_str) < 8:
        return "UNKNOWN"
    if is_mac_randomized(mac_str):
        return "Anti-Forensic MAC Randomization (Spoofed LAA)"
    clean_mac = mac_str.replace("-", ":").upper()
    prefix = clean_mac[:8]
    return OFFENSIVE_OUI_MAP.get(prefix, "Standard Commercial NIC")


def generate_remediation_advisory(incident_type: str, reason_code: int = 0, injection_detected: bool = False) -> str:
    """Generates standard IEEE 802.11w / 802.1X mitigation advisories based on attack vector."""
    norm_type = str(incident_type).lower().strip()
    if norm_type in ("deauth", "deauth_flood") or reason_code in (2, 7) or "deauth" in norm_type or injection_detected:
        return (
            "MANDATE IEEE 802.11w (PMF / WPA3-SAE): Protected Management Frames cryptographically sign "
            "deauthentication frames with an AES-128 CMAC (BIP). This renders spoofed deauthentication "
            "and disassociation frames unprocessable by connected client stations."
        )
    elif norm_type in ("rogue_ap", "evil_twin") or "rogue" in norm_type or "twin" in norm_type:
        return (
            "ENFORCE IEEE 802.1X EAP-TLS: Deploy certificate-based mutual authentication with strict server "
            "root certificate pinning on client endpoints. Disallow fallback to WPA2-PSK to neutralize "
            "unauthorized evil twin RADIUS proxies."
        )
    elif norm_type in ("ble_anomaly", "ble") or "ble" in norm_type or "bluetooth" in norm_type:
        return (
            "ENFORCE BLE SECURE CONNECTIONS (LE SC): Enforce ECDH pairing with numeric comparison and "
            "enable dynamic Identity Resolving Key (IRK) address rotation to prevent rogue advertising spoofing."
        )
    return "CONTINUE TELEMETRY SURVEILLANCE: Maintain baseline monitoring."


MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "DEAUTH_FLOOD": {
        "tactic": "Impact (TA0040)",
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "reference": "https://attack.mitre.org/techniques/T1498/001/"
    },
    "ROGUE_AP": {
        "tactic": "Credential Access (TA0006)",
        "technique_id": "T1557.004",
        "technique_name": "Adversary-in-the-Middle: Rogue Access Point",
        "reference": "https://attack.mitre.org/techniques/T1557/004/"
    },
    "RF_JAMMING": {
        "tactic": "Impact (TA0040)",
        "technique_id": "T1464",
        "technique_name": "Radio Jamming",
        "reference": "https://attack.mitre.org/techniques/T1464/"
    },
    "MAC_SPOOFING": {
        "tactic": "Defense Evasion (TA0005)",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "reference": "https://attack.mitre.org/techniques/T1036/"
    }
}


def map_incident_to_mitre(event_type: str) -> Dict[str, str]:
    """Maps wireless anomaly event type to standardized MITRE ATT&CK technique."""
    norm = str(event_type).upper().strip()
    if "DEAUTH" in norm:
        return MITRE_ATTACK_MAP["DEAUTH_FLOOD"]
    elif "ROGUE" in norm or "TWIN" in norm:
        return MITRE_ATTACK_MAP["ROGUE_AP"]
    elif "JAM" in norm or "CARRIER" in norm:
        return MITRE_ATTACK_MAP["RF_JAMMING"]
    elif "SPOOF" in norm or "RANDOM" in norm:
        return MITRE_ATTACK_MAP["MAC_SPOOFING"]
    return {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1200",
        "technique_name": "Hardware Additions / Wireless Interception",
        "reference": "https://attack.mitre.org/techniques/T1200/"
    }


def compute_evidence_hash(record: Dict[str, Any]) -> str:
    """Generates an immutable SHA-256 digest over the canonical incident record."""
    canonical = (
        f"{record.get('id') or record.get('incident_id', '')}|"
        f"{record.get('epoch_ms', '')}|"
        f"{record.get('attacker_mac', '')}|"
        f"{record.get('target_mac') or record.get('target_bssid', '')}|"
        f"{record.get('deauth_reason', 0)}|"
        f"{record.get('event_type') or record.get('type', '')}"
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class IncidentManager:
    """Aggregates sequential telemetry alert events into security incidents with timeline tracking."""

    def __init__(self, aggregation_window_ms: int = 60000):
        self.aggregation_window_ms = aggregation_window_ms
        self.active_incident_cache: Dict[str, Dict[str, Any]] = {}
        self.false_positive_windows: Set[int] = set()

    def evaluate_window_for_incidents(
        self,
        window_data: Dict[str, Any],
        alert_record: Optional[Dict[str, Any]] = None,
        conn=None
    ) -> Optional[Dict[str, Any]]:
        """Evaluates window telemetry and enriches incident payloads with forensic attribution."""
        alert = alert_record or window_data.get("alert")
        if not alert:
            return None

        evidence = alert.get("evidence", {}) if isinstance(alert, dict) else {}
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = {}

        atk_mac = (
            window_data.get("atk_src")
            or window_data.get("attacker_mac")
            or evidence.get("attacker_mac")
            or alert.get("attacker_mac")
            or ""
        )
        target_mac = (
            window_data.get("atk_dst")
            or window_data.get("target_mac")
            or evidence.get("target_mac")
            or evidence.get("target_bssid")
            or alert.get("target_mac")
            or alert.get("target_bssid")
            or ""
        )
        try:
            raw_rssi = (
                window_data.get("atk_rssi")
                if window_data.get("atk_rssi") is not None
                else (window_data.get("attacker_rssi") if window_data.get("attacker_rssi") is not None else evidence.get("attacker_rssi", 0))
            )
            atk_rssi = int(raw_rssi) if raw_rssi is not None else 0
        except (ValueError, TypeError):
            atk_rssi = 0

        try:
            raw_reason = (
                window_data.get("atk_reason")
                if window_data.get("atk_reason") is not None
                else (window_data.get("deauth_reason") if window_data.get("deauth_reason") is not None else evidence.get("deauth_reason", 0))
            )
            deauth_reason = int(raw_reason) if raw_reason is not None else 0
        except (ValueError, TypeError):
            deauth_reason = 0

        tool_sig = map_reason_code_to_signature(deauth_reason) if deauth_reason else "UNKNOWN"
        proximity = categorize_rssi_proximity(atk_rssi)
        hw_profile = identify_hardware_profile(str(atk_mac).strip().upper())
        remediation = generate_remediation_advisory(alert.get("event_type", ""), deauth_reason, bool(deauth_reason in (2, 6, 7)))

        alert["attacker_mac"] = str(atk_mac).strip().upper()
        alert["target_mac"] = str(target_mac).strip().upper()
        alert["attacker_rssi"] = atk_rssi
        alert["tool_signature"] = tool_sig
        alert["deauth_reason"] = deauth_reason
        alert["proximity_zone"] = proximity
        alert["hardware_profile"] = hw_profile
        alert["remediation_advisory"] = remediation

        mitre_data = map_incident_to_mitre(alert.get("event_type", alert.get("type", "")))
        evidence_hash = compute_evidence_hash(alert)
        alert["mitre_technique_id"] = mitre_data["technique_id"]
        alert["mitre_technique_name"] = mitre_data["technique_name"]
        alert["mitre_tactic"] = mitre_data["tactic"]
        alert["evidence_hash"] = evidence_hash

        if isinstance(alert.get("evidence"), dict):
            alert["evidence"]["attacker_mac"] = alert["attacker_mac"]
            alert["evidence"]["target_mac"] = alert["target_mac"]
            alert["evidence"]["attacker_rssi"] = atk_rssi
            alert["evidence"]["tool_signature"] = tool_sig
            alert["evidence"]["deauth_reason"] = deauth_reason
            alert["evidence"]["proximity_zone"] = proximity
            alert["evidence"]["hardware_profile"] = hw_profile
            alert["evidence"]["remediation_advisory"] = remediation
            alert["evidence"]["mitre_technique_id"] = mitre_data["technique_id"]
            alert["evidence"]["mitre_technique_name"] = mitre_data["technique_name"]
            alert["evidence"]["mitre_tactic"] = mitre_data["tactic"]
            alert["evidence"]["evidence_hash"] = evidence_hash

        return self.ingest_alert(alert, conn=conn)

    def ingest_alert(
        self,
        alert_record: Dict[str, Any],
        conn=None
    ) -> Dict[str, Any]:
        close_on_exit = False
        if conn is None:
            conn = get_connection()
            close_on_exit = True

        try:
            event_id = alert_record.get("id", alert_record.get("event_id", ""))
            event_type = alert_record.get("type", alert_record.get("event_type", "Wireless Anomaly"))
            type_key = alert_record.get("type_key", "anomaly")
            severity = str(alert_record.get("severity", "MEDIUM")).upper()
            epoch_ms = int(alert_record.get("epoch_ms", time.time() * 1000))
            window_id = int(alert_record.get("window_id", 0))

            evidence = alert_record.get("evidence", {})
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {}

            target_bssid = evidence.get("target_bssid") or alert_record.get("target_mac")
            grounded_reason = evidence.get("grounded_reason", "")

            attacker_mac = str(alert_record.get("attacker_mac") or evidence.get("attacker_mac") or "").strip().upper()
            target_mac = str(alert_record.get("target_mac") or evidence.get("target_mac") or target_bssid or "").strip().upper()

            raw_rssi = alert_record.get("attacker_rssi") if alert_record.get("attacker_rssi") is not None else evidence.get("attacker_rssi", 0)
            try:
                attacker_rssi = int(raw_rssi) if raw_rssi is not None else 0
            except (ValueError, TypeError):
                attacker_rssi = 0

            raw_reason = alert_record.get("deauth_reason") if alert_record.get("deauth_reason") is not None else evidence.get("deauth_reason", 0)
            try:
                deauth_reason = int(raw_reason) if raw_reason is not None else 0
            except (ValueError, TypeError):
                deauth_reason = 0

            tool_signature = str(
                alert_record.get("tool_signature")
                or evidence.get("tool_signature")
                or (map_reason_code_to_signature(deauth_reason) if deauth_reason else "UNKNOWN")
            )
            proximity_zone = str(
                alert_record.get("proximity_zone")
                or evidence.get("proximity_zone")
                or categorize_rssi_proximity(attacker_rssi)
            )
            hardware_profile = str(
                alert_record.get("hardware_profile")
                or evidence.get("hardware_profile")
                or identify_hardware_profile(attacker_mac)
            )
            remediation_advisory = str(
                alert_record.get("remediation_advisory")
                or evidence.get("remediation_advisory")
                or generate_remediation_advisory(event_type, deauth_reason, bool(deauth_reason in (2, 6, 7)))
            )

            if not alert_record.get("mitre_technique_id"):
                mitre_info = map_incident_to_mitre(event_type)
                alert_record["mitre_technique_id"] = mitre_info["technique_id"]
                alert_record["mitre_technique_name"] = mitre_info["technique_name"]
                alert_record["mitre_tactic"] = mitre_info["tactic"]
            if not alert_record.get("evidence_hash"):
                alert_record["evidence_hash"] = compute_evidence_hash(alert_record)

            mitre_technique_id = alert_record.get("mitre_technique_id", "T1200")
            mitre_technique_name = alert_record.get("mitre_technique_name", "")
            mitre_tactic = alert_record.get("mitre_tactic", "")
            evidence_hash = alert_record.get("evidence_hash", compute_evidence_hash(alert_record))

            # Look for an existing open incident in active cache within 60-second aggregation window
            matched_incident_id: Optional[str] = None
            for inc_id, inc_data in list(self.active_incident_cache.items()):
                if inc_data.get("status") not in ("OPEN", "ACKNOWLEDGED"):
                    continue

                time_diff = epoch_ms - inc_data["end_epoch_ms"]
                if time_diff <= self.aggregation_window_ms:
                    # Match by attack vector, target BSSID, or attacker MAC
                    if (
                        inc_data["event_type"] == event_type
                        or (target_bssid and inc_data.get("target_bssid") == target_bssid)
                        or (attacker_mac and inc_data.get("attacker_mac") == attacker_mac)
                    ):
                        matched_incident_id = inc_id
                        break

            if matched_incident_id:
                # Aggregate into existing incident
                inc_cache = self.active_incident_cache[matched_incident_id]
                inc_cache["end_epoch_ms"] = epoch_ms
                inc_cache["event_count"] += 1
                if event_id not in inc_cache["associated_events"]:
                    inc_cache["associated_events"].append(event_id)

                if attacker_mac and not inc_cache.get("attacker_mac"):
                    inc_cache["attacker_mac"] = attacker_mac
                if target_mac and not inc_cache.get("target_mac"):
                    inc_cache["target_mac"] = target_mac
                if attacker_rssi and not inc_cache.get("attacker_rssi"):
                    inc_cache["attacker_rssi"] = attacker_rssi
                if deauth_reason and not inc_cache.get("deauth_reason"):
                    inc_cache["deauth_reason"] = deauth_reason
                    inc_cache["tool_signature"] = tool_signature
                if proximity_zone != "NONE" and inc_cache.get("proximity_zone") == "NONE":
                    inc_cache["proximity_zone"] = proximity_zone
                if not inc_cache.get("evidence_hash"):
                    inc_cache["evidence_hash"] = evidence_hash
                if not inc_cache.get("mitre_technique_id") or inc_cache.get("mitre_technique_id") == "T1200":
                    if mitre_technique_id != "T1200":
                        inc_cache["mitre_technique_id"] = mitre_technique_id
                        inc_cache["mitre_technique_name"] = mitre_technique_name
                        inc_cache["mitre_tactic"] = mitre_tactic

                summary_detail = (
                    f"Correlated alert {event_id} at window {window_id}: "
                    f"{grounded_reason if grounded_reason else event_type}"
                )
                aggregate_alert_to_incident(
                    incident_id=matched_incident_id,
                    event_id=event_id,
                    epoch_ms=epoch_ms,
                    severity=severity,
                    summary_detail=summary_detail,
                    conn=conn
                )
                update_incident(
                    matched_incident_id,
                    updates={
                        "attacker_mac": inc_cache.get("attacker_mac", ""),
                        "target_mac": inc_cache.get("target_mac", ""),
                        "attacker_rssi": inc_cache.get("attacker_rssi", 0),
                        "tool_signature": inc_cache.get("tool_signature", "UNKNOWN"),
                        "deauth_reason": inc_cache.get("deauth_reason", 0),
                        "proximity_zone": inc_cache.get("proximity_zone", "NONE"),
                        "mitre_technique_id": inc_cache.get("mitre_technique_id", "T1200"),
                        "mitre_technique_name": inc_cache.get("mitre_technique_name", ""),
                        "mitre_tactic": inc_cache.get("mitre_tactic", ""),
                        "evidence_hash": inc_cache.get("evidence_hash", "")
                    },
                    conn=conn
                )
                return {
                    "incident_id": matched_incident_id,
                    "action": "AGGREGATED",
                    "event_count": inc_cache["event_count"],
                    "status": inc_cache["status"],
                    "attacker_mac": inc_cache.get("attacker_mac", ""),
                    "target_mac": inc_cache.get("target_mac", ""),
                    "attacker_rssi": inc_cache.get("attacker_rssi", 0),
                    "tool_signature": inc_cache.get("tool_signature", "UNKNOWN"),
                    "deauth_reason": inc_cache.get("deauth_reason", 0),
                    "proximity_zone": inc_cache.get("proximity_zone", "NONE"),
                    "mitre_technique_id": inc_cache.get("mitre_technique_id", "T1200"),
                    "mitre_technique_name": inc_cache.get("mitre_technique_name", ""),
                    "mitre_tactic": inc_cache.get("mitre_tactic", ""),
                    "evidence_hash": inc_cache.get("evidence_hash", "")
                }
            else:
                # Create a fresh incident
                date_str = time.strftime("%Y%m%d", time.gmtime(epoch_ms / 1000))
                short_seq = f"{epoch_ms % 100000:05d}"
                new_incident_id = f"INC-{date_str}-{short_seq}"

                summary_text = (
                    f"{event_type} detected at window {window_id}. "
                    f"{grounded_reason if grounded_reason else 'Statistical variance anomaly confirmed by multi-signal correlation.'}"
                )

                incident_payload = {
                    "incident_id": new_incident_id,
                    "start_epoch_ms": epoch_ms,
                    "end_epoch_ms": epoch_ms,
                    "event_type": event_type,
                    "severity": severity,
                    "status": "OPEN",
                    "event_count": 1,
                    "associated_event_ids_json": [event_id],
                    "target_bssid": target_bssid or target_mac,
                    "summary": summary_text,
                    "analyst_notes": f"Hardware: {hardware_profile} | Remediation: {remediation_advisory}",
                    "attacker_mac": attacker_mac,
                    "target_mac": target_mac,
                    "attacker_rssi": attacker_rssi,
                    "tool_signature": tool_signature,
                    "deauth_reason": deauth_reason,
                    "proximity_zone": proximity_zone,
                    "hardware_profile": hardware_profile,
                    "remediation_advisory": remediation_advisory,
                    "mitre_technique_id": alert_record.get("mitre_technique_id", "T1200"),
                    "mitre_technique_name": alert_record.get("mitre_technique_name", ""),
                    "mitre_tactic": alert_record.get("mitre_tactic", ""),
                    "evidence_hash": alert_record.get("evidence_hash", compute_evidence_hash(alert_record))
                }

                created_id = create_incident(incident_payload, conn=conn)

                self.active_incident_cache[created_id] = {
                    "incident_id": created_id,
                    "start_epoch_ms": epoch_ms,
                    "end_epoch_ms": epoch_ms,
                    "event_type": event_type,
                    "severity": severity,
                    "status": "OPEN",
                    "event_count": 1,
                    "associated_events": [event_id],
                    "target_bssid": target_bssid or target_mac,
                    "attacker_mac": attacker_mac,
                    "target_mac": target_mac,
                    "attacker_rssi": attacker_rssi,
                    "tool_signature": tool_signature,
                    "deauth_reason": deauth_reason,
                    "proximity_zone": proximity_zone,
                    "hardware_profile": hardware_profile,
                    "remediation_advisory": remediation_advisory,
                    "mitre_technique_id": incident_payload["mitre_technique_id"],
                    "mitre_technique_name": incident_payload["mitre_technique_name"],
                    "mitre_tactic": incident_payload["mitre_tactic"],
                    "evidence_hash": incident_payload["evidence_hash"]
                }

                return {
                    "incident_id": created_id,
                    "action": "CREATED",
                    "event_count": 1,
                    "status": "OPEN",
                    "attacker_mac": attacker_mac,
                    "target_mac": target_mac,
                    "attacker_rssi": attacker_rssi,
                    "tool_signature": tool_signature,
                    "deauth_reason": deauth_reason,
                    "proximity_zone": proximity_zone,
                    "hardware_profile": hardware_profile,
                    "remediation_advisory": remediation_advisory,
                    "mitre_technique_id": incident_payload["mitre_technique_id"],
                    "mitre_technique_name": incident_payload["mitre_technique_name"],
                    "mitre_tactic": incident_payload["mitre_tactic"],
                    "evidence_hash": incident_payload["evidence_hash"]
                }
        finally:
            if close_on_exit:
                conn.close()

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        note: str = "",
        baseline_engine=None,
        conn=None
    ) -> bool:
        close_on_exit = False
        if conn is None:
            conn = get_connection()
            close_on_exit = True

        try:
            now_ms = int(time.time() * 1000)
            clean_status = new_status.strip().upper()

            success = update_incident_status(
                incident_id=incident_id,
                new_status=clean_status,
                note=note,
                epoch_ms=now_ms,
                conn=conn
            )
            if not success:
                return False

            if incident_id in self.active_incident_cache:
                self.active_incident_cache[incident_id]["status"] = clean_status
                if clean_status in ("RESOLVED", "FALSE_POSITIVE"):
                    del self.active_incident_cache[incident_id]

            # Closed-loop feedback: on FALSE_POSITIVE, adjust baseline model sensitivity
            if clean_status == "FALSE_POSITIVE":
                incident_details = fetch_incident_with_timeline(incident_id, conn=conn)
                event_type = incident_details.get("event_type", "").lower()
                
                # Map incident event type to underlying feature name
                target_feat = "deauth"
                if "ble" in event_type:
                    target_feat = "ble"
                elif "rogue" in event_type or "twin" in event_type:
                    target_feat = "rogue"
                elif "management" in event_type or "mgmt" in event_type:
                    target_feat = "mgmt"

                if baseline_engine is not None and hasattr(baseline_engine, "adjust_sensitivity_on_false_positive"):
                    baseline_engine.adjust_sensitivity_on_false_positive(target_feat)

                # Collect associated window IDs to adjust evaluation benchmark
                raw_events = incident_details.get("associated_event_ids_json", "[]")
                try:
                    event_ids = json.loads(raw_events) if isinstance(raw_events, str) else raw_events
                    cursor = conn.cursor()
                    for eid in event_ids:
                        cursor.execute("SELECT window_id FROM alert_events WHERE event_id = ?;", (eid,))
                        row = cursor.fetchone()
                        if row and row["window_id"]:
                            self.false_positive_windows.add(int(row["window_id"]))
                except Exception:
                    pass

            return True
        finally:
            if close_on_exit:
                conn.close()

    def get_false_positive_windows(self) -> Set[int]:
        return set(self.false_positive_windows)

    def reset(self) -> None:
        self.active_incident_cache.clear()
        self.false_positive_windows.clear()
