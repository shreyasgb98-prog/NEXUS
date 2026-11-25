import json
import requests
from typing import Dict, Any, List, Optional

from .config import (
    OLLAMA_DEFAULT_URL,
    OLLAMA_DEFAULT_MODEL,
    DEFAULT_LLM_TIMEOUT_SEC
)
from .rag_index import DefensiveRAGIndex

class ExplainerEngine:
    """Offline defensive explainer combining RAG retrieval and local Ollama LLM inference."""

    def __init__(
        self,
        ollama_url: str = OLLAMA_DEFAULT_URL,
        model_name: str = OLLAMA_DEFAULT_MODEL,
        timeout: float = DEFAULT_LLM_TIMEOUT_SEC
    ):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.timeout = timeout
        self.rag_index = DefensiveRAGIndex()

    def generate_rule_explanation(
        self,
        event_type: str,
        evidence: Dict[str, Any],
        question: Optional[str] = None
    ) -> str:
        features = evidence.get("features", [])
        evidence_summary_parts = []
        for feat in features:
            evidence_summary_parts.append(
                f"{feat['feature']} was {feat['observed']} against a baseline of {feat['baseline_mean']} (z = {feat['z_score']})"
            )
        evidence_summary = "; ".join(evidence_summary_parts) if evidence_summary_parts else "unspecified features"

        lower_type = event_type.lower()
        if "deauth" in lower_type:
            base_text = (
                f"A burst of 802.11 deauthentication frames forcibly disconnects clients and is commonly used "
                f"before a man-in-the-middle attempt or simply to deny service. In this window: {evidence_summary}. "
                f"Suggested defensive step: Enable 802.11w Protected Management Frames (required in WPA3), move critical "
                f"devices to WPA3 where supported, and locate the transmitting source before taking further action."
            )
        elif "evil-twin" in lower_type or "rogue" in lower_type:
            base_text = (
                f"An access point was observed advertising a known SSID with an unverified BSSID ({evidence_summary}). "
                f"Clients risk association with an adversary node. Suggested defensive step: Inspect physical access "
                f"points, isolate the untrusted BSSID, and verify access point authentication settings."
            )
        elif "ble" in lower_type:
            base_text = (
                f"A surge in Bluetooth Low Energy (BLE) advertisements was observed ({evidence_summary}). "
                f"Suggested defensive step: Inspect local 2.4 GHz radio sources, identify high-volume advertising addresses, "
                f"and verify whether a localized battery-exhaustion or scanning flood is active."
            )
        elif "nfc" in lower_type or "rfid" in lower_type:
            base_text = (
                f"Anomalous rapid NFC/RFID interrogation detected ({evidence_summary}). "
                f"Suggested defensive step: Inspect entry controller logs, enforce cryptographic tag authentication "
                f"over static UIDs, and evaluate physical reader shielding."
            )
        else:
            base_text = (
                f"Statistical anomaly flagged in wireless telemetry stream ({evidence_summary}). "
                f"Suggested defensive step: Review 2.4 GHz spectrum activity, inspect access point management frames, "
                f"and verify radio frequency transmitter authorization."
            )

        if question:
            return (
                f"{base_text}\n\nOperator Question Response: Based strictly on the confirmed evidence ({evidence_summary}), "
                f"no additional unmeasured parameters can be verified. Speculation beyond measured passive telemetry is refused."
            )
        return base_text

    def retrieve_defensive_guidance(
        self,
        event_type: str,
        evidence: Dict[str, Any],
        top_k: int = 2,
        question: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        query = self.rag_index.format_query_from_evidence(event_type, evidence)
        if question:
            query = f"{question} {query}"
        return self.rag_index.search(query, top_k=top_k)

    def generate_rag_explanation(
        self,
        event_type: str,
        evidence: Dict[str, Any],
        ollama_url: Optional[str] = None,
        model: Optional[str] = None,
        question: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        target_ollama_url = ollama_url or self.ollama_url
        target_model = model or self.model_name
        target_timeout = timeout if timeout is not None else self.timeout

        retrieved_docs = self.retrieve_defensive_guidance(event_type, evidence, top_k=2, question=question)
        ref_summaries = []
        for doc in retrieved_docs:
            ref_summaries.append(
                f"[{doc.get('id', 'REF')}] {doc.get('title', '')}\n"
                f"Threat Mechanism: {doc.get('threat_mechanism', '')}\n"
                f"Mitigation: {doc.get('defensive_mitigation', '')}"
            )
        retrieved_text = "\n\n".join(ref_summaries)

        system_prompt = (
            "You are the NEXUS AI defensive security explainer.\n"
            "Your role is strictly to explain machine-detected anomalous wireless events and answer operator inquiries.\n"
            "You do NOT decide whether an attack occurred; the statistical detection engine has already made that determination.\n"
            "You must base your response ONLY on the confirmed structured evidence and the defensive reference material provided.\n"
            "Refuse to speculate beyond the measured telemetry. Do NOT invent numbers, features, timestamps, MAC addresses, SSIDs, or any identifiers not present in the evidence."
        )

        if question:
            user_prompt = (
                f"Event Type: {event_type}\n\n"
                f"Confirmed Evidence:\n{json.dumps(evidence, indent=2)}\n\n"
                f"Retrieved Defensive References (OWASP / MITRE ATT&CK):\n{retrieved_text}\n\n"
                f"Operator Question:\n{question}\n\n"
                f"Instructions:\n"
                f"Answer the operator question strictly using ONLY the supplied confirmed evidence and retrieved defensive references. "
                f"If the question requests information not contained in the measured telemetry or references, state clearly that "
                f"it cannot be determined from passive RF sensor telemetry and refuse to speculate beyond the measured observations."
            )
        else:
            user_prompt = (
                f"Event Type: {event_type}\n\n"
                f"Confirmed Evidence:\n{json.dumps(evidence, indent=2)}\n\n"
                f"Retrieved Defensive References (OWASP / MITRE ATT&CK):\n{retrieved_text}\n\n"
                f"Instructions:\n"
                f"1. State the observed telemetry versus the learned baseline values and z-scores.\n"
                f"2. Explain why this deviation indicates anomalous wireless behavior based on the retrieved reference.\n"
                f"3. Provide concrete defensive steps grounded in the reference material."
            )

        formatted_refs = [
            {
                "id": doc.get("id"),
                "title": doc.get("title"),
                "technique_id": doc.get("technique_id", ""),
                "framework": doc.get("framework", ""),
                "retrieval_score": doc.get("retrieval_score", 0.0),
                "retrieval_engine": doc.get("retrieval_engine", "")
            }
            for doc in retrieved_docs
        ]

        # 1. Attempt Local Ollama Runner
        if target_ollama_url and target_ollama_url.lower() not in ("offline", "disabled", "none"):
            try:
                resp = requests.post(
                    f"{target_ollama_url.rstrip('/')}/api/generate",
                    json={
                        "model": target_model,
                        "prompt": f"{system_prompt}\n\n{user_prompt}",
                        "stream": False
                    },
                    timeout=target_timeout
                )
                if resp.status_code == 200:
                    resp_json = resp.json()
                    text = resp_json.get("response", "").strip()
                    if text:
                        return {
                            "explanation": text,
                            "source": "ollama",
                            "model": target_model,
                            "retrieved_refs": formatted_refs,
                            "question": question
                        }
            except Exception:
                pass

        # 2. Deterministic Rule-Based Fallback when Ollama is offline
        rule_text = self.generate_rule_explanation(event_type, evidence, question=question)
        return {
            "explanation": rule_text,
            "source": "rule_based_fallback",
            "model": "deterministic_rule_engine",
            "retrieved_refs": formatted_refs,
            "question": question
        }

    def generate_llm_explanation(
        self,
        event_type: str,
        evidence: Dict[str, Any],
        ollama_url: Optional[str] = None,
        model: Optional[str] = None,
        question: Optional[str] = None
    ) -> Dict[str, Any]:
        """Calls local Ollama directly with confirmed evidence payload."""
        target_ollama_url = ollama_url or self.ollama_url
        target_model = model or self.model_name

        system_prompt = (
            "You are the NEXUS AI defensive security explainer.\n"
            "State observed telemetry versus learned baselines and provide defensive remediation grounded strictly in the evidence."
        )
        user_prompt = f"Event Type: {event_type}\nConfirmed Evidence:\n{json.dumps(evidence, indent=2)}"
        if question:
            user_prompt += f"\nOperator Question:\n{question}"

        if target_ollama_url and target_ollama_url.lower() not in ("offline", "disabled", "none"):
            try:
                resp = requests.post(
                    f"{target_ollama_url.rstrip('/')}/api/generate",
                    json={
                        "model": target_model,
                        "prompt": f"{system_prompt}\n\n{user_prompt}",
                        "stream": False
                    },
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    resp_json = resp.json()
                    text = resp_json.get("response", "").strip()
                    if text:
                        return {
                            "explanation": text,
                            "source": "ollama",
                            "model": target_model,
                            "retrieved_refs": [],
                            "question": question
                        }
            except Exception:
                pass

        rule_text = self.generate_rule_explanation(event_type, evidence, question=question)
        return {
            "explanation": rule_text,
            "source": "rule_based_fallback",
            "model": "deterministic_rule_engine",
            "retrieved_refs": [],
            "question": question
        }

# Backward compatibility alias
DefensiveKnowledgeRetriever = DefensiveRAGIndex
