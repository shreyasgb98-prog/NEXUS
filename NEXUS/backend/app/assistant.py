import re
import json
import time
import httpx
from typing import Dict, Any, List, Optional, Tuple, AsyncGenerator, Set
from .database import (
    db_get_alerts,
    db_get_window,
    db_compare_detectors,
    db_get_baseline,
    db_link_health,
    db_get_incident_summary,
    query_recent_incidents as db_query_recent_incidents
)
from .incident_manager import (
    map_reason_code_to_signature,
    categorize_rssi_proximity,
    is_mac_randomized,
    identify_hardware_profile,
    generate_remediation_advisory
)
from .config import OLLAMA_DEFAULT_URL, OLLAMA_DEFAULT_MODEL, DEFAULT_LLM_TIMEOUT_SEC

SYSTEM_PROMPT = (
    "You are NEXUS AI Defensive Assistant, an embedded wireless security telemetry analyzer. "
    "Analyze only the provided structured database telemetry JSON. "
    "Cite specific window_id, event_id, and incident_id. "
    "Only state facts directly present in the provided JSON data. "
    "Never guess unseen traffic. Never speculate beyond measured observations."
)

class AskNexusAssistant:
    """Deterministic routing assistant with anti-hallucination numeric validation and Ollama streaming."""

    def __init__(self, ollama_url: str = OLLAMA_DEFAULT_URL, model: str = OLLAMA_DEFAULT_MODEL):
        self.ollama_url = ollama_url
        self.model = model
        self.timeout_sec = DEFAULT_LLM_TIMEOUT_SEC
        self._ollama_reachable_cached: Optional[bool] = None

    async def is_ollama_reachable(self, url: Optional[str] = None) -> bool:
        """Probes local Ollama instance reachability and pre-warms connection cache."""
        target_url = url or self.ollama_url
        if not target_url or target_url.lower() in ("offline", "none", "disabled", ""):
            self._ollama_reachable_cached = False
            return False
        try:
            client_timeout = httpx.Timeout(1.5, connect=1.0)
            async with httpx.AsyncClient(timeout=client_timeout) as client:
                resp = await client.get(f"{target_url.rstrip('/')}/api/tags")
                is_up = bool(resp.status_code == 200)
                self._ollama_reachable_cached = is_up
                return is_up
        except Exception:
            self._ollama_reachable_cached = False
            return False

    # -------------------------------------------------------------------------
    # Fixed Query Tools (Deterministic Pure SQL Execution)
    # -------------------------------------------------------------------------

    def tool_get_alerts(self, time_range_seconds: int = 3600, alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        return db_get_alerts(time_range_seconds=time_range_seconds, alert_type=alert_type)

    def tool_get_window(self, window_id: int) -> Optional[Dict[str, Any]]:
        return db_get_window(window_id=window_id)

    def tool_compare_detectors(self) -> Dict[str, Any]:
        return db_compare_detectors()

    def tool_get_baseline(self, feature: str = "deauth") -> Optional[Dict[str, Any]]:
        return db_get_baseline(feature=feature)

    def tool_link_health(self) -> Dict[str, Any]:
        return db_link_health()

    def tool_get_incident_summary(self, incident_id: Optional[str] = None) -> Dict[str, Any]:
        return db_get_incident_summary(incident_id=incident_id)

    def query_recent_incidents(self, limit: int = 5) -> List[Dict[str, Any]]:
        return db_query_recent_incidents(limit=limit)

    # -------------------------------------------------------------------------
    # Deterministic Intent & Keyword Query Router
    # -------------------------------------------------------------------------

    def route_query(self, message: str) -> Tuple[str, Dict[str, Any]]:
        text = message.lower().strip()

        # 1. Why was the last alert raised?
        if re.search(r"\b(why|last alert|recent alert|alert raised|what triggered)\b", text):
            alerts = self.tool_get_alerts(time_range_seconds=300)
            incidents = self.query_recent_incidents(limit=5)
            inc_summary = self.tool_get_incident_summary()
            return "alerts_and_incident", {
                "recent_alerts_300s": alerts[:5],
                "recent_incidents": incidents,
                "incident_status": inc_summary
            }

        # 2. Detector comparison / missed attacks
        if re.search(r"\b(missed|compare|detector|detectors|f1|precision|recall|benchmark)\b", text):
            comparison = self.tool_compare_detectors()
            return "detector_comparison", comparison

        # 3. Baseline questions (deauth, mgmt, ble, rogue)
        feat_match = re.search(r"\b(deauth|mgmt|management|ble|bluetooth|rogue|twin)\b", text)
        if re.search(r"\b(normal|baseline|rate|z-score|z_score|mean|variance|threshold)\b", text) and feat_match:
            raw_feat = feat_match.group(1)
            feat = "deauth"
            if raw_feat in ("mgmt", "management"):
                feat = "mgmt"
            elif raw_feat in ("ble", "bluetooth"):
                feat = "ble"
            elif raw_feat in ("rogue", "twin"):
                feat = "rogue"

            baseline = self.tool_get_baseline(feat)
            health = self.tool_link_health()
            last_win_id = health.get("last_window_id", 1)
            window_data = self.tool_get_window(last_win_id) if last_win_id else None
            return "baseline_and_window", {
                "feature": feat,
                "baseline": baseline,
                "latest_window": window_data
            }

        # 4. Link health / serial port status
        if re.search(r"\b(link|health|serial|buffer|overflow|dropped|dropped frames|connection|port)\b", text):
            health = self.tool_link_health()
            return "link_health", health

        # 5. Specific window lookup (e.g., "window 42", "window #15")
        win_match = re.search(r"\bwindow\s*(?:#|id)?\s*(\d+)\b", text)
        if win_match:
            win_id = int(win_match.group(1))
            window_data = self.tool_get_window(win_id)
            return "window_lookup", {"window_id": win_id, "data": window_data}

        # 6. 802.11w / Mitigation & Remediation inquiry
        if re.search(r"\b(802\.11w|pmf|mitigat|remediat|countermeasure|prevent|recommendation|wpa3|how to stop|how can we prevent)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            inc_data = self.tool_get_incident_summary(specific_id)
            return "remediation_advisory", inc_data

        # 7. OUI Hardware Profile & MAC Randomization inquiry
        if re.search(r"\b(hardware|oui|device type|randomiz|spoofed laa|vendor|chipset|rig|pwnagotchi|alfa|espressif|what device)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            inc_data = self.tool_get_incident_summary(specific_id)
            return "hardware_profile", inc_data

        # 8. Packet injection metrics inquiry
        if re.search(r"\b(injection|inject|packet injection|injection rate|injection metric)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            inc_data = self.tool_get_incident_summary(specific_id)
            return "injection_metrics", inc_data

        # 9. Attacker proximity query: "How close was the attacker?", "Attacker proximity"
        if re.search(r"\b(how close|proximity|distance|how near|physical proximity)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            inc_data = self.tool_get_incident_summary(specific_id)
            return "attacker_proximity", inc_data

        # 10. Reason code inquiry: "What reason code was observed?", "Reason code 7"
        if re.search(r"\b(reason code|deauth reason|disassociation reason|reason was observed|what reason)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            inc_data = self.tool_get_incident_summary(specific_id)
            code_match = re.search(r"\breason\s*(?:code)?\s*(\d+)\b", text)
            explicit_code = int(code_match.group(1)) if code_match else None
            return "reason_code_inquiry", {
                "incident_summary": inc_data,
                "explicit_code": explicit_code
            }

        # 11. Attacker attribution query: "Who was attacking in incident #X?", "Who attacked"
        if re.search(r"\b(who (?:was|is) attacking|who attacked|who was the attacker|who is the attacker|attacker identity|attacker mac|adversary attribution|culprit)\b", text):
            inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
            specific_id = inc_match.group(1).upper() if inc_match else None
            if not specific_id:
                num_match = re.search(r"\bincident\s*(?:#|id)?\s*([a-zA-Z0-9_\-]+)\b", text)
                if num_match:
                    cand = num_match.group(1).strip()
                    if cand.upper().startswith("INC-"):
                        specific_id = cand.upper()
                    elif cand.isdigit():
                        recent_incidents = self.query_recent_incidents(limit=10)
                        idx = int(cand) - 1
                        if 0 <= idx < len(recent_incidents):
                            specific_id = recent_incidents[idx].get("incident_id") or recent_incidents[idx].get("id")

            inc_data = self.tool_get_incident_summary(specific_id)
            return "attacker_attribution", inc_data

        # 12. Specific incident lookup (e.g., "incident INC-20261120-12345")
        inc_match = re.search(r"\b(inc-\d+-\d+)\b", text)
        if inc_match:
            inc_id = inc_match.group(1).upper()
            inc_data = self.tool_get_incident_summary(inc_id)
            return "incident_lookup", {"incident_id": inc_id, "data": inc_data}

        # 13. Time range alert history (e.g., "last hour", "past hour", "what happened")
        if re.search(r"\b(hour|past hour|last hour|what happened|history|events)\b", text):
            alerts = self.tool_get_alerts(time_range_seconds=3600)
            return "hourly_alerts", {"time_range_seconds": 3600, "alert_count": len(alerts), "alerts": alerts[:10]}

        # Default fallback: combined recent state
        health = self.tool_link_health()
        alerts = self.tool_get_alerts(time_range_seconds=600)
        return "general_status", {
            "link_status": health.get("status"),
            "recent_alerts_count": len(alerts),
            "recent_alerts": alerts[:3]
        }

    # -------------------------------------------------------------------------
    # Anti-Hallucination Numeric Verification
    # -------------------------------------------------------------------------

    def _extract_all_numbers(self, obj: Any) -> Set[str]:
        numbers: Set[str] = set()
        if isinstance(obj, (int, float)):
            abs_val = abs(obj)
            numbers.add(f"{obj}")
            numbers.add(f"{abs_val}")
            numbers.add(f"-{abs_val}")
            if isinstance(obj, float):
                numbers.add(f"{obj:.1f}")
                numbers.add(f"{abs_val:.1f}")
                numbers.add(f"-{abs_val:.1f}")
                numbers.add(f"{obj:.2f}")
                numbers.add(f"{abs_val:.2f}")
                numbers.add(f"-{abs_val:.2f}")
                numbers.add(f"{round(obj)}")
                numbers.add(f"{round(abs_val)}")
                numbers.add(f"-{round(abs_val)}")
        elif isinstance(obj, str):
            for match in re.findall(r"-?\b\d+(?:\.\d+)?\b", obj):
                numbers.add(match)
        elif isinstance(obj, dict):
            for v in obj.values():
                numbers.update(self._extract_all_numbers(v))
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                numbers.update(self._extract_all_numbers(item))
        return numbers

    def verify_numeric_hallucinations(self, generated_text: str, queried_dataset: Dict[str, Any]) -> str:
        valid_numbers = self._extract_all_numbers(queried_dataset)
        # Whitelist standard unit multipliers, small integers, and conventional constants
        whitelist = {"0", "1", "2", "3", "4", "5", "10", "24", "60", "100", "3600", "115200"}
        valid_numbers.update(whitelist)

        found_in_text = re.findall(r"\b\d+(?:\.\d+)?\b", generated_text)
        discrepancies = []
        for num in found_in_text:
            if num not in valid_numbers:
                # Check for float approximation
                try:
                    val = float(num)
                    matched = any(abs(float(vn) - val) < 0.05 for vn in valid_numbers if re.match(r"^-?\d+(?:\.\d+)?$", vn))
                    if not matched:
                        discrepancies.append(num)
                except ValueError:
                    discrepancies.append(num)

        if discrepancies:
            unique_disc = sorted(list(set(discrepancies)))
            correction_note = (
                f"\n\n[Verification Flag: Telemetry records confirm values from SQLite3 database; "
                f"unverified numeric tokens noted: {', '.join(unique_disc[:4])}]"
            )
            return generated_text + correction_note

        return generated_text

    # -------------------------------------------------------------------------
    # Deterministic Offline Summary Generator (Zero LLM Dependency)
    # -------------------------------------------------------------------------

    def generate_deterministic_response(self, intent: str, data: Dict[str, Any]) -> str:
        if intent == "alerts_and_incident":
            recent = data.get("recent_alerts_300s", [])
            recent_incidents = data.get("recent_incidents", [])
            inc_status = data.get("incident_status", {})
            if not recent and not recent_incidents and not inc_status.get("latest_incident"):
                return "No alerts were raised in the last 300 seconds. All monitored RF features remain within baseline thresholds."
            if recent:
                first = recent[0]
                win_id = first.get("window_id") or first.get("window") or 0
                inc_st = inc_status.get("latest_incident", {}).get("status", "OPEN") if inc_status else "OPEN"
                return (
                    f"Alert {first.get('event_id')} was triggered at window {win_id} for {first.get('event_type')} "
                    f"with {first.get('severity', '').upper()} severity (confidence {first.get('confidence', 0.0)}). "
                    f"Explanation: {first.get('explanation', 'Multi-signal variance surge')}. "
                    f"Active incident status: {inc_st}."
                )
            if recent_incidents:
                first_inc = recent_incidents[0]
                inc_id = first_inc.get("id") or first_inc.get("incident_id")
                return (
                    f"Incident {inc_id} was registered for {first_inc.get('primary_type') or first_inc.get('title')} "
                    f"with {first_inc.get('severity', '').upper()} severity (confidence {first_inc.get('confidence', 0.0)}). "
                    f"Status: {first_inc.get('status', 'OPEN')}, event count: {first_inc.get('event_count', 1)}."
                )

        if intent == "detector_comparison":
            counts = data.get("counts", {})
            noise = data.get("noise_suppression_rate_vs_adaptive", 0.0)
            return (
                f"Detector Benchmark Evaluation over {data.get('windows_evaluated', 0)} windows: "
                f"Fixed threshold flagged {counts.get('fixed_detector', 0)} times, "
                f"Adaptive baseline flagged {counts.get('adaptive_detector', 0)} times, and "
                f"NEXUS correlated detector flagged {counts.get('nexus_detector', 0)} times. "
                f"NEXUS noise suppression vs raw adaptive baseline is {round(noise * 100, 1)}%."
            )

        if intent == "baseline_and_window":
            feat = data.get("feature", "deauth")
            b = data.get("baseline") or {}
            w = data.get("latest_window") or {}
            mean = b.get("mean", 0.0)
            sd = b.get("std_dev", 1.0)
            obs = w.get(f"{feat}_count", 0)
            z = w.get(f"z_{feat}", 0.0)
            return (
                f"Baseline for {feat}: EWMA mean = {round(mean, 2)}, std dev = {round(sd, 2)}. "
                f"Latest window {w.get('window_id', 0)} recorded {obs} {feat} frames (z-score = {z}). "
                f"Status: {'Within normal baseline bounds' if abs(z) < 3.5 else 'Elevated above threshold'}."
            )

        if intent == "link_health":
            status = data.get("status", "HEALTHY")
            dropped = data.get("dropped_frames", 0)
            last_win = data.get("last_window_id", 0)
            continuity = data.get("continuity_gaps_detected", 0)
            return (
                f"Serial Link Health: {status}. Last ingested window ID: {last_win}. "
                f"Malformed dropped frames: {dropped}, Buffer overflows: {data.get('rx_buffer_overflows', 0)}, "
                f"Continuity sequence gaps: {continuity}."
            )

        if intent == "window_lookup":
            win_id = data.get("window_id", 0)
            w = data.get("data")
            if not w:
                return f"Window {win_id} not found in local SQLite telemetry database."
            return (
                f"Window {win_id} Telemetry: Deauth={w.get('deauth_count', 0)}, Mgmt={w.get('mgmt_count', 0)}, "
                f"BLE={w.get('ble_count', 0)}, Rogue={w.get('rogue_count', 0)}, NFC={w.get('nfc_count', 0)}, "
                f"RSSI Mean={w.get('rssi_mean', -70.0)} dBm. Attack Labelled={w.get('is_attack_labelled', 0)}, "
                f"NEXUS Flag={w.get('flag_nexus', 0)}."
            )

        if intent == "attacker_attribution":
            target = data.get("latest_incident") if (isinstance(data, dict) and "latest_incident" in data) else data
            if not target or not isinstance(target, dict):
                return "No incident attribution record located in database."
            inc_id = target.get("incident_id") or target.get("id") or "UNKNOWN"
            atk_mac = target.get("attacker_mac") or "UNKNOWN"
            target_bssid = target.get("target_bssid") or target.get("target_mac") or "BROADCAST"
            tool_sig = target.get("tool_signature") or "UNKNOWN"

            if (tool_sig == "UNKNOWN" or not tool_sig) and target.get("deauth_reason"):
                tool_sig = map_reason_code_to_signature(int(target.get("deauth_reason")))

            return (
                f"Incident {inc_id} Attacker Attribution: "
                f"Attacker MAC: {atk_mac}, "
                f"Target BSSID: {target_bssid}, "
                f"Tool Signature: {tool_sig}."
            )

        if intent == "attacker_proximity":
            target = data.get("latest_incident") if (isinstance(data, dict) and "latest_incident" in data) else data
            if not target or not isinstance(target, dict):
                return "No proximity telemetry available for the requested incident."
            inc_id = target.get("incident_id") or target.get("id") or "UNKNOWN"
            try:
                rssi = int(target.get("attacker_rssi", 0) or 0)
            except (ValueError, TypeError):
                rssi = 0
            prox_zone = target.get("proximity_zone") or categorize_rssi_proximity(rssi)
            return (
                f"Incident {inc_id} Attacker Proximity: "
                f"Measured RSSI: {rssi} dBm. "
                f"Proximity Category: {prox_zone}."
            )

        if intent == "reason_code_inquiry":
            explicit_code = data.get("explicit_code") if isinstance(data, dict) else None
            target = data.get("incident_summary", {}) if isinstance(data, dict) else {}
            if isinstance(target, dict) and "latest_incident" in target:
                target = target["latest_incident"]

            if explicit_code is not None:
                code = explicit_code
            elif isinstance(target, dict) and target.get("deauth_reason"):
                code = int(target.get("deauth_reason", 0) or 0)
            else:
                code = 0

            sig = map_reason_code_to_signature(code)
            if code in (7, 2, 6):
                assessment = f"Reason Code {code} indicates an automated offensive tool ({sig})."
            elif code in (3, 8):
                assessment = f"Reason Code {code} indicates legitimate client roaming or station transition ({sig})."
            elif code == 1:
                assessment = f"Reason Code 1 represents an unspecified disconnection ({sig}), commonly observed during RF degradation or generic deauth."
            else:
                assessment = f"Reason Code {code} represents standard 802.11 disassociation ({sig})."

            inc_id = target.get("incident_id") or target.get("id") if isinstance(target, dict) else None
            context = f" Observed in incident {inc_id}." if inc_id else ""
            return f"802.11 Reason Code {code} ({sig}).{context} {assessment}"

        if intent == "hardware_profile":
            target = data.get("latest_incident") if (isinstance(data, dict) and "latest_incident" in data) else data
            if not target or not isinstance(target, dict):
                return "No hardware profile telemetry available for the requested incident."
            inc_id = target.get("incident_id") or target.get("id") or "UNKNOWN"
            atk_mac = target.get("attacker_mac") or "UNKNOWN"
            is_rand = is_mac_randomized(atk_mac)
            stored_prof = target.get("hardware_profile")
            if stored_prof and stored_prof != "UNKNOWN":
                hw_prof = stored_prof
            else:
                hw_prof = identify_hardware_profile(atk_mac)
            mac_desc = "Anti-Forensic MAC Randomization (Spoofed LAA)" if is_rand else "Standard Universally Administered Address"
            return (
                f"Incident {inc_id} Hardware Profile: Attacker MAC {atk_mac} ({mac_desc}). "
                f"Identified Hardware OUI Profile: {hw_prof}."
            )

        if intent == "remediation_advisory":
            target = data.get("latest_incident") if (isinstance(data, dict) and "latest_incident" in data) else data
            if not target or not isinstance(target, dict):
                return "MANDATE IEEE 802.11w (PMF / WPA3-SAE) to protect management frames."
            inc_id = target.get("incident_id") or target.get("id") or "UNKNOWN"
            ev_type = target.get("primary_type") or target.get("event_type") or "deauth"
            try:
                reason = int(target.get("deauth_reason", 7) or 7)
            except (ValueError, TypeError):
                reason = 7
            stored_advisory = target.get("remediation_advisory")
            if stored_advisory and stored_advisory != "UNKNOWN":
                advisory = stored_advisory
            else:
                advisory = generate_remediation_advisory(ev_type, reason, bool(reason in (2, 6, 7)))
            return f"Remediation Advisory for Incident {inc_id} ({ev_type}): {advisory}"

        if intent == "injection_metrics":
            target = data.get("latest_incident") if (isinstance(data, dict) and "latest_incident" in data) else data
            if not target or not isinstance(target, dict):
                return "No packet injection telemetry recorded for this interval."
            inc_id = target.get("incident_id") or target.get("id") or "UNKNOWN"
            try:
                reason = int(target.get("deauth_reason", 0) or 0)
            except (ValueError, TypeError):
                reason = 0
            sig = target.get("tool_signature") or map_reason_code_to_signature(reason)
            ev_count = target.get("event_count", 1)
            is_inj = reason in (2, 6, 7) or "aireplay" in sig.lower() or "mdk" in sig.lower()
            inj_status = "CONFIRMED (Adversary frame injection detected)" if is_inj else "STANDARD (No offensive injection signature detected)"
            return (
                f"Incident {inc_id} Packet Injection Metrics: "
                f"Burst volume = {ev_count} events. Observed Reason Code = {reason} ({sig}). "
                f"Packet Injection: {inj_status}."
            )

        if intent == "hourly_alerts":
            cnt = data.get("alert_count", 0)
            return f"In the past 3600 seconds, {cnt} alert events were registered. Monitored link remains operational."

        return f"Telemetry query processed. Current link status: {data.get('link_status', 'HEALTHY')} with {data.get('recent_alerts_count', 0)} recent alerts."

    # -------------------------------------------------------------------------
    # Streaming Chat Generator (Ollama with Deterministic Fallback)
    # -------------------------------------------------------------------------

    def _fallback_rule_based_response(self, text: str) -> Optional[str]:
        return _fallback_rule_based_response(text)

    def generate_compliance_report(self, incidents: List[Dict[str, Any]], baseline: Dict[str, Any]) -> str:
        """
        Generates a formal executive defensive RF compliance and incident audit report in Markdown.
        Uses local Ollama with Llama 3.2 if available, or falls back to a deterministic structured template.
        """
        # 1. Structured prompt for Llama 3.2
        system_prompt = (
            "You are the NEXUS AI Chief Information Security Officer and Lead Defensive Wireless Engineer. "
            "Write a formal 'NEXUS AI - DEFENSIVE RF INCIDENT & COMPLIANCE REPORT' in clean GitHub-flavored Markdown. "
            "STRICT CONSTRAINT: You must adhere strictly to the supplied dataset. Do not invent or fabricate unrecorded "
            "incidents, attacker MACs, reason codes, MITRE IDs, or SHA-256 evidence digests. Cite only facts present in the dataset."
        )
        user_prompt = (
            f"Generate a formal defensive audit report structured into exactly these 6 sections:\n"
            f"1. Executive Summary & Assessment\n"
            f"2. Physical & Spectral Attack Forensics\n"
            f"3. Threat Classification (MITRE ATT&CK Mapping)\n"
            f"4. Statistical Anomaly Verification (EWMA Mean/Variance Deviation)\n"
            f"5. Actionable Countermeasures & Remediation (IEEE 802.11w PMF Guidance)\n"
            f"6. Chain of Custody & Cryptographic Evidence Ledger\n\n"
            f"Baseline Configuration:\n{json.dumps(baseline, indent=2)}\n\n"
            f"Incidents Telemetry Dataset ({len(incidents)} incidents):\n{json.dumps(incidents, indent=2)}"
        )

        url = self.ollama_url
        if url and url.lower() not in ("offline", "none", "disabled", ""):
            try:
                with httpx.Client(timeout=httpx.Timeout(2.0, connect=1.0)) as client:
                    resp = client.post(
                        f"{url.rstrip('/')}/api/generate",
                        json={
                            "model": self.model,
                            "prompt": f"{system_prompt}\n\n{user_prompt}",
                            "stream": False,
                            "options": {
                                "temperature": 0.2
                            }
                        }
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        text = data.get("response", "").strip()
                        if text:
                            return text
            except Exception:
                pass

        # 2. Deterministic offline markdown generation
        gen_time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        inc_count = len(incidents)

        # Section 1: Executive Summary & Assessment
        if inc_count == 0:
            exec_summary = (
                "During the evaluated operational window, zero security incidents were registered. "
                "All monitored physical and spectral telemetry features (deauthentication frames, management traffic, "
                "BLE advertisements, and rogue access points) remained within calibrated EWMA baseline thresholds. "
                "The wireless medium is categorized as NORMAL with zero uncontained threat vectors."
            )
        else:
            types = list({inc.get("primary_type") or inc.get("event_type", "ANOMALY") for inc in incidents})
            severities = list({inc.get("severity", "MEDIUM") for inc in incidents})
            exec_summary = (
                f"During the evaluated operational window, NEXUS AI recorded and correlated {inc_count} security incident(s). "
                f"Observed threat vectors encompass: {', '.join(types)}. Highest severity recorded: {', '.join(severities)}. "
                "Automated detection engines isolated transmitter hardware anomalies and enforced baseline parameter protection."
            )

        # Section 2: Physical & Spectral Attack Forensics
        forensics_lines = []
        if inc_count == 0:
            forensics_lines.append("No active or historical incident forensics available in local telemetry storage.")
        else:
            forensics_lines.append("| Incident ID | Attacker MAC | Target MAC / BSSID | Reason Code | Proximity Zone | Attacker RSSI | Hardware Profile |")
            forensics_lines.append("|---|---|---|---|---|---|---|")
            for inc in incidents:
                inc_id = inc.get("incident_id") or inc.get("id", "UNKNOWN")
                atk_mac = inc.get("attacker_mac") or "UNKNOWN"
                tgt_mac = inc.get("target_mac") or inc.get("target_bssid") or "BROADCAST"
                code = inc.get("deauth_reason", 0)
                prox = inc.get("proximity_zone", "NONE")
                rssi = f"{inc.get('attacker_rssi', 0)} dBm"
                hw = inc.get("hardware_profile", "UNKNOWN")
                forensics_lines.append(f"| {inc_id} | {atk_mac} | {tgt_mac} | {code} | {prox} | {rssi} | {hw} |")

        # Section 3: Threat Classification (MITRE ATT&CK Mapping)
        mitre_lines = []
        if inc_count == 0:
            mitre_lines.append("No active threats classified against the MITRE ATT&CK framework.")
        else:
            mitre_lines.append("| Incident ID | Event Type | MITRE Technique ID | Technique Name | Tactic |")
            mitre_lines.append("|---|---|---|---|---|")
            from .incident_manager import map_incident_to_mitre
            for inc in incidents:
                inc_id = inc.get("incident_id") or inc.get("id", "UNKNOWN")
                ev_type = inc.get("event_type") or inc.get("primary_type", "ANOMALY")
                m_default = map_incident_to_mitre(ev_type)
                raw_mid = inc.get("mitre_technique_id")
                m_id = raw_mid if (raw_mid and (raw_mid != "T1200" or "HARDWARE" in str(ev_type).upper())) else m_default["technique_id"]
                m_name = inc.get("mitre_technique_name") or m_default["technique_name"]
                m_tactic = inc.get("mitre_tactic") or m_default["tactic"]
                mitre_lines.append(f"| {inc_id} | {ev_type} | {m_id} | {m_name} | {m_tactic} |")

        # Section 4: Statistical Anomaly Verification (EWMA Mean/Variance Deviation)
        alpha = baseline.get("alpha", 0.12)
        z_cutoff = baseline.get("z_cutoff", 3.5)
        stat_lines = [
            f"- **Smoothing Factor (alpha):** {alpha}",
            f"- **Anomaly Decision Threshold:** Z >= {z_cutoff} standard deviations",
            f"- **Baseline Memory Management:** Freeze on Z > {z_cutoff} to prevent adversarial model poisoning."
        ]
        feats = baseline.get("features", {})
        if feats:
            stat_lines.append("\n**Learned Feature Statistics:**")
            for f_name, f_data in feats.items():
                stat_lines.append(f"- Feature `{f_name}`: Moving Mean = {f_data.get('mean', 0.0)}, Std Dev = {f_data.get('std_dev', 1.0)}")

        # Section 5: Actionable Countermeasures & Remediation (IEEE 802.11w PMF Guidance)
        remediation_lines = [
            "1. **MANDATE IEEE 802.11w Protected Management Frames (PMF / WPA3-SAE):**",
            "   Enforce PMF across all managed wireless infrastructure. Protected Management Frames append an AES-128 CMAC (BIP) "
            "to broadcast deauthentication and disassociation frames, causing client station PHY/MAC layers to discard spoofed frames.",
            "2. **Deploy IEEE 802.1X EAP-TLS with Root Certificate Pinning:**",
            "   Eliminate preshared keys (WPA2-PSK) to neutralize rogue access points and evil-twin RADIUS proxies.",
            "3. **Enforce Peripheral BLE Observation Limits:**",
            "   Apply sliding-window advertising rate limits and dynamic IRK address rotation on Bluetooth controllers."
        ]

        # Section 6: Chain of Custody & Cryptographic Evidence Ledger
        ledger_lines = []
        if inc_count == 0:
            ledger_lines.append("Cryptographic ledger contains no active incident records for this interval.")
        else:
            ledger_lines.append("| Incident ID | Event Type | Attacker MAC | Reason Code | MITRE Technique | SHA-256 Evidence Digest |")
            ledger_lines.append("|---|---|---|---|---|---|")
            from .incident_manager import map_incident_to_mitre
            for inc in incidents:
                inc_id = inc.get("incident_id") or inc.get("id", "UNKNOWN")
                ev_type = inc.get("event_type") or inc.get("primary_type", "ANOMALY")
                atk_mac = inc.get("attacker_mac") or "UNKNOWN"
                code = inc.get("deauth_reason", 0)
                raw_mid = inc.get("mitre_technique_id")
                m_id = raw_mid if (raw_mid and (raw_mid != "T1200" or "HARDWARE" in str(ev_type).upper())) else map_incident_to_mitre(ev_type)["technique_id"]
                h = inc.get("evidence_hash") or "N/A"
                ledger_lines.append(f"| {inc_id} | {ev_type} | {atk_mac} | {code} | {m_id} | `{h}` |")

        report = f"""# NEXUS AI - DEFENSIVE RF INCIDENT & COMPLIANCE REPORT

**Generated:** {gen_time_str}  
**Classification:** TLP:AMBER - STRICT INTERNAL AUDIT USE  
**Total Incidents Evaluated:** {inc_count}  

---

## 1. Executive Summary & Assessment
{exec_summary}

---

## 2. Physical & Spectral Attack Forensics
{chr(10).join(forensics_lines)}

---

## 3. Threat Classification (MITRE ATT&CK Mapping)
{chr(10).join(mitre_lines)}

---

## 4. Statistical Anomaly Verification (EWMA Mean/Variance Deviation)
{chr(10).join(stat_lines)}

---

## 5. Actionable Countermeasures & Remediation (IEEE 802.11w PMF Guidance)
{chr(10).join(remediation_lines)}

---

## 6. Chain of Custody & Cryptographic Evidence Ledger
{chr(10).join(ledger_lines)}
"""
        return report.strip()

    def generate_chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        ollama_url: Optional[str] = None,
        model: Optional[str] = None
    ) -> str:
        fallback_text = self._fallback_rule_based_response(message)
        if fallback_text:
            return fallback_text
        intent, queried_data = self.route_query(message)
        return self.generate_deterministic_response(intent, queried_data)

    async def stream_chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        ollama_url: Optional[str] = None,
        model: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        url = ollama_url or self.ollama_url
        chosen_model = model or self.model

        # 1. Deterministically route query to pure SQL tools
        intent, queried_data = self.route_query(message)

        # 2. Build structured ground-truth prompt payload
        prompt_content = (
            f"User Question: {message}\n"
            f"Query Intent: {intent}\n"
            f"Queried SQLite Telemetry Dataset:\n{json.dumps(queried_data, indent=2)}\n\n"
            f"Answer the user question concisely citing exact numbers from the dataset. "
            f"State only facts present in the dataset."
        )

        llm_connected = False
        accumulated_chunks: List[str] = []

        skip_llm = bool(ollama_url is None and self._ollama_reachable_cached is False)
        if not skip_llm and url and url.lower() not in ("offline", "none", "disabled", ""):
            try:
                client_timeout = httpx.Timeout(self.timeout_sec, connect=1.0)
                async with httpx.AsyncClient(timeout=client_timeout) as client:
                    req_payload = {
                        "model": chosen_model,
                        "prompt": prompt_content,
                        "system": SYSTEM_PROMPT,
                        "stream": True,
                        "options": {
                            "temperature": 0.1,
                            "num_predict": 300
                        }
                    }
                    async with client.stream("POST", f"{url.rstrip('/')}/api/generate", json=req_payload) as response:
                        if response.status_code == 200:
                            llm_connected = True
                            async for line in response.aiter_lines():
                                if not line:
                                    continue
                                try:
                                    chunk_json = json.loads(line)
                                    token = chunk_json.get("response", "")
                                    if token:
                                        accumulated_chunks.append(token)
                                        yield token
                                    if chunk_json.get("done", False):
                                        break
                                except Exception:
                                    continue

                            # Verify numeric accuracy of full stream
                            full_response = "".join(accumulated_chunks)
                            verified = self.verify_numeric_hallucinations(full_response, queried_data)
                            if len(verified) > len(full_response):
                                diff = verified[len(full_response):]
                                yield diff
            except Exception:
                llm_connected = False

        # If LLM was unreachable or aborted, yield deterministic grounded fallback response
        if not llm_connected or not accumulated_chunks:
            fallback_text = self._fallback_rule_based_response(message)
            if not fallback_text:
                fallback_text = self.generate_deterministic_response(intent, queried_data)
            words = fallback_text.split(" ")
            for i, w in enumerate(words):
                yield w + (" " if i < len(words) - 1 else "")

def _fallback_rule_based_response(text: str) -> Optional[str]:
    """Generates detailed technical explanations for architectural, protocol, and detector evaluation prompts when Ollama is offline."""
    query = str(text or "").strip()

    # 1. BLE flood inquiries
    if re.search(r"\b(ble|bluetooth)\b.*\b(flood|indicator|advertisement|burst)\b", query, re.IGNORECASE):
        return (
            "BLE Advertisement Flood Indicators: Ambient Bluetooth Low Energy (BLE) peripheral devices "
            "transmit advertising packets at regular intervals between 100ms and 1024ms (with 0ms–10ms pseudo-random jitter) "
            "across primary advertising channels 37, 38, and 39. In contrast, adversarial flooding tools inject rapid bursts "
            "of thousands of randomized or malformed advertising PDUs per second, overwhelming controller HCI packet buffers "
            "and inducing receiver stack buffer exhaustion. Defensive mitigation: Deploy sliding-window rate limiters, calculate "
            "recursive EWMA baseline statistics on advertising packet frequency, and flag anomalous bursts when z-scores exceed "
            "3.5 sigma to isolate or throttle offending transmitter MAC addresses."
        )

    # 2. PMF / 802.11w inquiries
    if re.search(r"\b(802\.11w|pmf|protected management frames)\b", query, re.IGNORECASE):
        return (
            "IEEE 802.11w Protected Management Frames (PMF): 802.11w establishes cryptographic encapsulation for management frames. "
            "Unicast management frames are encrypted and authenticated using the negotiated pairwise transient key (CCMP/GCMP). "
            "Broadcast and multicast management frames (such as deauthentication and disassociation frames) append a Broadcast "
            "Integrity Protocol (BIP) Information Element verified via an AES-128 CMAC (Cipher-based Message Authentication Code). "
            "Receiving station PHY/MAC layers inspect the cryptographic CMAC signature and discard spoofed deauthentication frames "
            "without terminating the authenticated association state, rendering unauthenticated injection attacks completely invalid."
        )

    # 3. Detector comparison / benchmark inquiries
    if re.search(r"\b(compare|comparison|detector|fixed threshold|ewma|missed attacks)\b", query, re.IGNORECASE):
        return (
            "Detector Comparison (EWMA Baseline vs Fixed Static Threshold): Static cutoffs apply rigid frame thresholds "
            "that fail in dynamic wireless environments, either missing stealthy low-rate deauthentication floods (false negatives) "
            "or triggering excessive false alarms during diurnal traffic peaks and shift changes (false positives). "
            "In contrast, the NEXUS recursive Exponentially Weighted Moving Average (EWMA) continuously tracks moving mean "
            "and variance (alpha = 0.12) to adapt to diurnal shifts. When an attack surge occurs (Z > 3.5 sigma), the baseline "
            "update is frozen to prevent adversary model poisoning, ensuring reliable anomaly isolation and high noise suppression."
        )

    # 4. Sequence number / raw injection inquiries
    if re.search(r"\b(sequence|seq|discontinuity|raw packet|injection)\b", query, re.IGNORECASE):
        return (
            "Sequence Control Discontinuity & Raw Injection Rationale: Legitimate 802.11 hardware transceivers increment the "
            "12-bit sequence counter (ranging from 0 to 4095) sequentially on the radio chipset for every transmitted frame. "
            "In contrast, software-based injection tools (such as Scapy, aireplay-ng, or raw C sockets) transmit frames with "
            "static sequence numbers (frequently static zero values) or step jumps exceeding normal increment deltas. "
            "By monitoring per-transmitter sequence deltas and delta discontinuities ((seq_curr - seq_prev) % 4096), the detector "
            "exposes raw packet injection and flags spoofed transmitter activity with high confidence."
        )

    return None

def query_recent_incidents(limit: int = 5) -> List[Dict[str, Any]]:
    return db_query_recent_incidents(limit=limit)
