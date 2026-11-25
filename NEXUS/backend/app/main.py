import os
import io
import csv
import json
import time
import struct
import asyncio
import httpx
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Response, UploadFile, File, Header, Depends
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import (
    BASE_DIR,
    DB_PATH,
    WARMUP_WINDOWS,
    FIXED_DEAUTH_THRESHOLD,
    EWMA_ALPHA,
    Z_SCORE_THRESHOLD
)
from .database import (
    apply_migrations,
    get_connection,
    insert_telemetry_window,
    insert_alert_event,
    save_baseline_state,
    save_baseline_metric,
    fetch_baseline_state,
    fetch_baseline_metrics,
    fetch_recent_telemetry,
    count_telemetry_windows,
    fetch_telemetry_rolling_window,
    fetch_all_telemetry,
    update_window_attack_label,
    update_window_range_attack_label,
    fetch_recent_alerts,
    fetch_alerts_rolling_window,
    fetch_all_alerts,
    fetch_windows_for_metrics,
    reset_telemetry_database,
    purge_simulation_database,
    fetch_serial_error_counters,
    fetch_serial_error_count,
    query_alert_logs,
    fetch_trusted_aps,
    upsert_trusted_ap,
    bulk_learn_trusted_aps,
    get_trusted_aps_map,
    learn_trusted_aps_from_telemetry,
    create_incident,
    update_incident_status,
    fetch_active_incidents,
    fetch_incidents,
    fetch_incident_with_timeline,
    fetch_false_positive_stats,
    prune_historical_telemetry,
    insert_incident_record,
    fetch_sqlite_pragmas,
    fetch_database_status,
    insert_hardware_whitelist,
    upsert_hardware_whitelist,
    delete_hardware_whitelist,
    fetch_all_hardware_whitelist,
    fetch_hardware_whitelist,
    batch_update_incident_status,
    update_incident_remediation,
    fetch_incident_by_id
)
from .baseline_model import AdaptiveBaselineEngine
from .correlation_engine import CorrelationEngine
from .evidence_builder import EvidenceBuilder
from .serial_reader import SerialManager
from .metrics_evaluator import compute_detector_metrics, compute_threshold_sweep, compute_ablation_analysis
from .incident_manager import IncidentManager, map_reason_code_to_signature, categorize_rssi_proximity
from .assistant import AskNexusAssistant
from .replay_engine import CSVReplayEngine

API_KEY = os.getenv("NEXUS_API_KEY", "nexus-local-dev-token")

def verify_api_key(x_nexus_key: Optional[str] = Header(default="nexus-local-dev-token", alias="X-Nexus-Key")):
    resolved_key = "nexus-local-dev-token" if (x_nexus_key is not None and not isinstance(x_nexus_key, str)) else x_nexus_key
    if resolved_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized write operation")

app = FastAPI(title="NEXUS AI Telemetry Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5500",
        "null"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

apply_migrations()

baseline_engine = AdaptiveBaselineEngine()
correlation_engine = CorrelationEngine()
evidence_builder = EvidenceBuilder()
incident_manager = IncidentManager()
assistant_engine = AskNexusAssistant()
replay_engine = CSVReplayEngine()

# Initialize trusted AP allowlist cache in correlation engine
try:
    _init_conn = get_connection()
    correlation_engine.set_trusted_aps(get_trusted_aps_map(_init_conn))
    _init_conn.close()
except Exception:
    pass

@app.on_event("startup")
async def startup_event():
    try:
        # Pre-warm Ollama cache so the first query has zero probe latency
        asyncio.create_task(assistant_engine.is_ollama_reachable(assistant_engine.ollama_url))
    except Exception:
        pass

connected_clients: List[WebSocket] = []
active_attack_labelling: bool = False
cumulative_nfc_reads: int = 0

class PrunePayload(BaseModel):
    retention_hours: int = 48

class WindowIngestPayload(BaseModel):
    window_id: Optional[int] = None
    win: Optional[int] = None
    deauth: int = 0
    mgmt: int = 0
    ble: int = 0
    rogue: int = 0
    nfc: int = 0
    ch: Optional[int] = 1
    channel: Optional[int] = None
    bssid_cnt: Optional[int] = 0
    unique_bssids: Optional[int] = None
    rssi: Optional[float] = -70.0
    rssi_min: Optional[float] = -90.0
    rssi_avg: Optional[float] = -70.0
    rssi_max: Optional[float] = -30.0
    top: Optional[List[Dict[str, Any]]] = None
    top_sources: Optional[List[Dict[str, Any]]] = None
    top_sources_json: Optional[str] = None
    data_source: Optional[str] = "live"
    is_attack_labelled: Optional[int] = None
    atk_src: Optional[str] = None
    atk_dst: Optional[str] = None
    atk_rssi: Optional[int] = None
    atk_reason: Optional[int] = None
    attacker_mac: Optional[str] = None
    target_mac: Optional[str] = None
    attacker_rssi: Optional[int] = None
    deauth_reason: Optional[int] = None
    proximity_zone: Optional[str] = None
    inj: Optional[int] = 0
    raw_injection_count: Optional[int] = 0

class HardwareWhitelistPayload(BaseModel):
    ssid: Optional[str] = ""
    bssid: Optional[str] = ""
    channel: Optional[int] = 0

class SettingsPayload(BaseModel):
    alpha: Optional[float] = None
    z_threshold: Optional[float] = None
    fixed_threshold: Optional[int] = None
    warmup_windows: Optional[int] = None

class BatchStatusUpdate(BaseModel):
    incident_ids: Optional[List[Any]] = None
    status: Optional[str] = None
    from_status: Optional[str] = None
    to_status: Optional[str] = None
    note: Optional[str] = ""

BatchIncidentStatusPayload = BatchStatusUpdate

class TrustedApPayload(BaseModel):
    bssid: str
    ssid: str
    channel: int = 1
    is_active: int = 1

class LearnTrustedApsPayload(BaseModel):
    limit_windows: Optional[int] = 200
    aps: Optional[List[Dict[str, Any]]] = None

class IncidentStatusPayload(BaseModel):
    status: str
    note: Optional[str] = ""

class RemediationUpdatePayload(BaseModel):
    completed_steps: List[int]

class IncidentSyncPayload(BaseModel):
    alert: Optional[Dict[str, Any]] = None
    incident: Optional[Dict[str, Any]] = None

class GenerateReportPayload(BaseModel):
    limit: Optional[int] = 20

class AssistantChatPayload(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = None
    ollama_url: Optional[str] = None
    model: Optional[str] = None

class EndpointTestPayload(BaseModel):
    base_url: Optional[str] = None
    endpoint_url: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None

AssistantTestEndpointPayload = EndpointTestPayload

class ReplayStartPayload(BaseModel):
    csv_content: str
    speed_ms: Optional[int] = 100
    source_name: Optional[str] = "replay.csv"

class LabelWindowPayload(BaseModel):
    window_id: int
    is_attack_labelled: int

class LabelRangePayload(BaseModel):
    start_window_id: int
    end_window_id: int
    is_attack_labelled: int

class LabelModePayload(BaseModel):
    active: bool

class SerialConnectPayload(BaseModel):
    port: str
    baud_rate: int = 115200

class ScanPlanOverridePayload(BaseModel):
    primary_ch: Optional[int] = None
    channel: Optional[int] = None
    dwell_primary_ms: Optional[int] = 1700
    dwell_patrol_ms: Optional[int] = 50

def resolve_db_mode(data_source: Optional[str] = None, mode_param: Optional[str] = None) -> str:
    if mode_param:
        return "sim" if "sim" in mode_param.lower() else "live"
    if data_source:
        return "sim" if "sim" in data_source.lower() else "live"
    return "live"

def process_telemetry_window(payload_dict: Dict[str, Any], data_source: str = "live") -> Dict[str, Any]:
    global cumulative_nfc_reads, active_attack_labelling

    now_ms = int(time.time() * 1000)
    source = payload_dict.get("data_source", data_source) or data_source
    
    # Ground truth labelling resolution
    if payload_dict.get("is_attack_labelled") is not None:
        is_attack_labelled = int(payload_dict["is_attack_labelled"])
    else:
        is_attack_labelled = 1 if active_attack_labelling else 0

    nfc_in_window = int(payload_dict.get("nfc", 0))
    if nfc_in_window > 0:
        cumulative_nfc_reads += nfc_in_window

    # 1. Statistical baseline evaluation
    evaluated = baseline_engine.evaluate_window(payload_dict)
    raw_win = payload_dict.get("win") if payload_dict.get("win") is not None else payload_dict.get("window_id")
    if raw_win is not None:
        window_id = int(raw_win)
        evaluated["window_id"] = window_id
    else:
        window_id = evaluated["window_id"]

    # 2. Correlate across multi-signal history and determine fire state
    correlated_event = correlation_engine.process(evaluated, raw_payload=payload_dict)

    # 3. Parallel detector evaluation
    if evaluated["warmed_up"]:
        flag_fixed = 1 if payload_dict.get("deauth", 0) >= FIXED_DEAUTH_THRESHOLD else 0
        flag_adaptive = 1 if any(evaluated["flags"].values()) else 0
        flag_nexus = 1 if correlation_engine.last_fire else 0
    else:
        flag_fixed = 0
        flag_adaptive = 0
        flag_nexus = 0

    metrics = evaluated["metrics"]
    conn = get_connection(db_mode=resolve_db_mode(data_source=source))

    # Normalizing telemetry values from raw payload
    deauth_cnt = int(payload_dict.get("deauth", 0))
    mgmt_cnt = int(payload_dict.get("mgmt", 0))
    ble_cnt = int(payload_dict.get("ble", 0))
    rogue_cnt = int(payload_dict.get("rogue", 0))
    rssi_mean_val = float(payload_dict.get("rssi_avg", payload_dict.get("rssi", -70.0)) or -70.0)
    rssi_min_val = float(payload_dict.get("rssi_min", -90.0) or -90.0)
    rssi_max_val = float(payload_dict.get("rssi_max", -30.0) or -30.0)
    channel_val = int(payload_dict.get("ch", payload_dict.get("channel", 1)) or 1)
    bssid_cnt_val = int(payload_dict.get("bssid_cnt", payload_dict.get("unique_bssids", 0)) or 0)

    # Forensic attribution and proximity categorization
    atk_src = str(payload_dict.get("atk_src") or payload_dict.get("attacker_mac") or "").strip().upper()
    atk_dst = str(payload_dict.get("atk_dst") or payload_dict.get("target_mac") or "").strip().upper()
    try:
        raw_atk_rssi = payload_dict.get("atk_rssi") if payload_dict.get("atk_rssi") is not None else payload_dict.get("attacker_rssi", 0)
        atk_rssi = int(raw_atk_rssi) if raw_atk_rssi is not None else 0
    except (ValueError, TypeError):
        atk_rssi = 0
    try:
        raw_atk_reason = payload_dict.get("atk_reason") if payload_dict.get("atk_reason") is not None else payload_dict.get("deauth_reason", 0)
        atk_reason = int(raw_atk_reason) if raw_atk_reason is not None else 0
    except (ValueError, TypeError):
        atk_reason = 0

    proximity_zone = str(payload_dict.get("proximity_zone") or categorize_rssi_proximity(atk_rssi))
    try:
        raw_inj_cnt = payload_dict.get("inj") if payload_dict.get("inj") is not None else payload_dict.get("raw_injection_count", 0)
        inj_cnt = int(raw_inj_cnt) if raw_inj_cnt is not None else 0
    except (ValueError, TypeError):
        inj_cnt = 0

    top_raw = payload_dict.get("top")
    if top_raw is not None and isinstance(top_raw, list):
        top_json = json.dumps(top_raw)
    elif payload_dict.get("top_sources_json"):
        top_json = str(payload_dict["top_sources_json"])
    else:
        top_json = "[]"

    insert_telemetry_window(
        conn,
        window_id=window_id,
        epoch_ms=now_ms,
        deauth_count=deauth_cnt,
        mgmt_count=mgmt_cnt,
        ble_count=ble_cnt,
        rogue_count=rogue_cnt,
        nfc_count=nfc_in_window,
        rssi_mean=rssi_mean_val,
        data_source=source,
        is_attack_labelled=is_attack_labelled,
        flag_fixed=flag_fixed,
        flag_adaptive=flag_adaptive,
        flag_nexus=flag_nexus,
        ewma_deauth_mean=baseline_engine.baselines["deauth"].mean,
        ewma_deauth_var=baseline_engine.baselines["deauth"].variance,
        ewma_mgmt_mean=baseline_engine.baselines["mgmt"].mean,
        ewma_mgmt_var=baseline_engine.baselines["mgmt"].variance,
        ewma_ble_mean=baseline_engine.baselines["ble"].mean,
        ewma_ble_var=baseline_engine.baselines["ble"].variance,
        ewma_rogue_mean=baseline_engine.baselines["rogue"].mean,
        ewma_rogue_var=baseline_engine.baselines["rogue"].variance,
        z_deauth=metrics["deauth"]["z_score"],
        z_mgmt=metrics["mgmt"]["z_score"],
        z_ble=metrics["ble"]["z_score"],
        z_rogue=metrics["rogue"]["z_score"],
        unique_bssids=bssid_cnt_val,
        top_sources_json=top_json,
        channel=channel_val,
        rssi_min=rssi_min_val,
        rssi_max=rssi_max_val,
        attacker_mac=atk_src,
        target_mac=atk_dst,
        attacker_rssi=atk_rssi,
        deauth_reason=atk_reason,
        proximity_zone=proximity_zone,
        raw_injection_count=inj_cnt
    )

    save_baseline_state(
        conn,
        alpha=EWMA_ALPHA,
        z_threshold=Z_SCORE_THRESHOLD,
        warmup_windows=WARMUP_WINDOWS,
        processed_windows=baseline_engine.processed_windows,
        updated_epoch_ms=now_ms
    )
    for feat_name, b_obj in baseline_engine.baselines.items():
        save_baseline_metric(
            conn,
            feature_name=feat_name,
            mean=b_obj.mean,
            variance=b_obj.variance,
            std_dev=b_obj.get_std_dev(),
            updated_epoch_ms=now_ms
        )

    new_alert_record = None
    if correlated_event:
        explanation = f"{correlated_event['event_type']} detected via multi-signal statistical correlation"
        new_alert_record = evidence_builder.build_record(
            window_id=window_id,
            event_type=correlated_event["event_type"],
            type_key=correlated_event["type_key"],
            severity=correlated_event["severity"],
            confidence=correlated_event["confidence"],
            evidence_dict=correlated_event["evidence"],
            explanation_text=explanation,
            data_source=source
        )

        tool_sig = map_reason_code_to_signature(atk_reason) if atk_reason else "UNKNOWN"
        new_alert_record["attacker_mac"] = atk_src
        new_alert_record["target_mac"] = atk_dst
        new_alert_record["attacker_rssi"] = atk_rssi
        new_alert_record["deauth_reason"] = atk_reason
        new_alert_record["tool_signature"] = tool_sig
        new_alert_record["proximity_zone"] = proximity_zone
        if isinstance(new_alert_record.get("evidence"), dict):
            new_alert_record["evidence"]["attacker_mac"] = atk_src
            new_alert_record["evidence"]["target_mac"] = atk_dst
            new_alert_record["evidence"]["attacker_rssi"] = atk_rssi
            new_alert_record["evidence"]["deauth_reason"] = atk_reason
            new_alert_record["evidence"]["tool_signature"] = tool_sig
            new_alert_record["evidence"]["proximity_zone"] = proximity_zone

        insert_alert_event(
            conn,
            event_id=new_alert_record["id"],
            window_id=window_id,
            epoch_ms=now_ms,
            type_key=new_alert_record["type_key"],
            event_type=new_alert_record["type"],
            severity=new_alert_record["severity"],
            confidence=new_alert_record["confidence"],
            signals_correlated=correlated_event["signals_correlated"],
            data_source=source,
            evidence_json=json.dumps(new_alert_record["evidence"]),
            explanation=explanation
        )

        incident_info = incident_manager.ingest_alert(new_alert_record, conn=conn)
        new_alert_record["incident_id"] = incident_info.get("incident_id")
    else:
        incident_info = None

    conn.close()

    result_package = {
        "window_id": window_id,
        "epoch_ms": now_ms,
        "state": (
            "ACTIVE_MONITORING" if baseline_engine.is_warmed_up
            else f"WARMUP [{baseline_engine.processed_windows}/{WARMUP_WINDOWS}]"
        ),
        "raw": payload_dict,
        "evaluated": evaluated,
        "flags": {
            "fixed": flag_fixed,
            "adaptive": flag_adaptive,
            "nexus": flag_nexus
        },
        "cumulative_nfc_reads": cumulative_nfc_reads,
        "alert": new_alert_record,
        "incident": incident_info
    }

    if connected_clients:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast_telemetry(result_package))
        except RuntimeError:
            pass

    return result_package

async def broadcast_telemetry(data: Dict[str, Any]):
    dead_sockets = []
    message_text = json.dumps(data)
    for ws in connected_clients:
        try:
            await ws.send_text(message_text)
        except Exception:
            dead_sockets.append(ws)
    for dead in dead_sockets:
        if dead in connected_clients:
            connected_clients.remove(dead)

serial_manager = SerialManager(on_window_received=lambda p: process_telemetry_window(p, data_source="live"))

@app.websocket("/ws/telemetry")
async def websocket_telemetry_stream(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

@app.get("/api/status")
def get_system_status():
    conn = get_connection()
    err_count = fetch_serial_error_count(conn)
    conn.close()

    current_state = serial_manager.state
    if current_state == "ACTIVE_MONITORING" and not baseline_engine.is_warmed_up:
        current_state = f"WARMUP [{baseline_engine.processed_windows}/{WARMUP_WINDOWS}]"

    return {
        "connection_state": current_state,
        "windows_processed": baseline_engine.processed_windows,
        "warmup_windows": WARMUP_WINDOWS,
        "is_warmed_up": baseline_engine.is_warmed_up,
        "serial_error_count": err_count + serial_manager.error_count,
        "dropped_frames": serial_manager.dropped_frames,
        "nfc_reads": cumulative_nfc_reads,
        "active_labelling": active_attack_labelling
    }

@app.post("/api/telemetry/ingest", dependencies=[Depends(verify_api_key)])
def ingest_telemetry_window(payload: WindowIngestPayload):
    return process_telemetry_window(payload.model_dump(), data_source=payload.data_source or "simulation")

@app.post("/api/telemetry/label")
def label_telemetry_window(payload: LabelWindowPayload):
    conn = get_connection()
    rows_updated = update_window_attack_label(conn, payload.window_id, payload.is_attack_labelled)
    conn.close()
    return {"window_id": payload.window_id, "is_attack_labelled": payload.is_attack_labelled, "updated": rows_updated}

@app.post("/api/telemetry/label-range")
def label_telemetry_range(payload: LabelRangePayload):
    conn = get_connection()
    rows_updated = update_window_range_attack_label(
        conn,
        payload.start_window_id,
        payload.end_window_id,
        payload.is_attack_labelled
    )
    conn.close()
    return {
        "start_window_id": payload.start_window_id,
        "end_window_id": payload.end_window_id,
        "is_attack_labelled": payload.is_attack_labelled,
        "updated": rows_updated
    }

@app.post("/api/telemetry/label-mode")
def set_label_mode(payload: LabelModePayload):
    global active_attack_labelling
    active_attack_labelling = payload.active
    return {"active_labelling": active_attack_labelling}

@app.get("/api/telemetry/label-mode")
def get_label_mode():
    return {"active_labelling": active_attack_labelling}

@app.get("/api/metrics/comparison")
def get_detector_comparison(data_source: Optional[str] = None):
    conn = get_connection()
    windows = fetch_windows_for_metrics(conn, warmup_windows=WARMUP_WINDOWS, data_source=data_source)
    conn.close()
    return compute_detector_metrics(
        windows,
        warmup_windows=WARMUP_WINDOWS,
        false_positive_windows=incident_manager.get_false_positive_windows()
    )

@app.get("/api/telemetry/rolling")
def get_telemetry_rolling(start_epoch_ms: int, end_epoch_ms: int, data_source: Optional[str] = None):
    conn = get_connection()
    rows = fetch_telemetry_rolling_window(conn, start_epoch_ms, end_epoch_ms, data_source)
    conn.close()
    return rows

@app.get("/api/telemetry/recent")
def get_telemetry_recent(
    response: Response,
    limit: Optional[int] = 100,
    offset: int = 0,
    start_epoch_ms: Optional[int] = None,
    end_epoch_ms: Optional[int] = None,
    data_source: Optional[str] = None,
    mode: Optional[str] = "live"
):
    conn = get_connection(db_mode=resolve_db_mode(data_source, mode))
    try:
        total_count = count_telemetry_windows(conn, data_source=data_source)
        response.headers["X-Total-Count"] = str(total_count)
        resolved_limit = max(total_count, 1) if (limit is None or limit <= 0) else limit
        if start_epoch_ms is not None and end_epoch_ms is not None:
            rows = fetch_telemetry_rolling_window(conn, start_epoch_ms, end_epoch_ms, data_source)
        else:
            rows = fetch_recent_telemetry(
                conn,
                limit=resolved_limit,
                data_source=data_source,
                offset=offset
            )
            rows.reverse()
        return rows
    finally:
        conn.close()

@app.post("/api/telemetry/purge-simulations")
def purge_simulations():
    conn = get_connection(db_mode="sim")
    try:
        purge_simulation_database(conn)
    finally:
        conn.close()
    return {"status": "purged", "message": "Simulation database cleared successfully."}

@app.get("/api/alerts/rolling")
def get_alerts_rolling(
    start_epoch_ms: int,
    end_epoch_ms: int,
    data_source: Optional[str] = None,
    event_type: Optional[str] = None
):
    conn = get_connection()
    rows = fetch_alerts_rolling_window(conn, start_epoch_ms, end_epoch_ms, data_source, event_type)
    conn.close()
    return rows

@app.get("/api/baseline")
def get_baseline_info():
    conn = get_connection()
    state = fetch_baseline_state(conn)
    metrics = fetch_baseline_metrics(conn)
    conn.close()
    return {"state": state, "metrics": metrics}

@app.get("/api/database/status")
def get_database_status():
    conn = get_connection()
    res = fetch_database_status(conn)
    conn.close()
    return res

@app.post("/api/settings")
def update_settings(payload: SettingsPayload):
    if payload.alpha is not None:
        if not (0.01 <= payload.alpha <= 1.0):
            raise HTTPException(status_code=400, detail="alpha must be between 0.01 and 1.0")

    if payload.z_threshold is not None:
        if not (1.0 <= payload.z_threshold <= 10.0):
            raise HTTPException(status_code=400, detail="z_threshold must be between 1.0 and 10.0")

    if payload.warmup_windows is not None:
        if payload.warmup_windows < 5:
            raise HTTPException(status_code=400, detail="warmup_windows must be >= 5")

    current = baseline_engine.update_parameters(
        alpha=payload.alpha,
        z_threshold=payload.z_threshold,
        warmup_windows=payload.warmup_windows,
        fixed_threshold=payload.fixed_threshold
    )

    conn = get_connection()
    save_baseline_state(
        conn=conn,
        alpha=current["alpha"],
        z_threshold=current["z_threshold"],
        warmup_windows=current["warmup_windows"],
        processed_windows=baseline_engine.processed_windows,
        updated_epoch_ms=int(time.time() * 1000)
    )
    conn.close()

    return {
        "status": "applied",
        "current_settings": current
    }

@app.get("/api/settings")
def get_settings():
    return {
        "status": "current",
        "current_settings": baseline_engine.get_parameters()
    }

@app.get("/api/telemetry/scan-plan")
def get_adaptive_scan_plan():
    if not baseline_engine.is_warmed_up and baseline_engine.manual_primary_ch is None:
        return {
            "cmd": "scan_plan",
            "mode": "round_robin",
            "primary_ch": 1,
            "dwell_primary_ms": 100,
            "dwell_patrol_ms": 100,
            "warmed_up": False,
            "processed_windows": baseline_engine.processed_windows,
            "warmup_windows": WARMUP_WINDOWS
        }

    plan = baseline_engine.get_optimal_scan_plan()
    plan["mode"] = "adaptive"
    plan["warmed_up"] = True
    plan["processed_windows"] = baseline_engine.processed_windows
    plan["warmup_windows"] = WARMUP_WINDOWS
    return plan

@app.post("/api/telemetry/scan-plan")
def set_adaptive_scan_plan_override(payload: ScanPlanOverridePayload):
    ch = payload.primary_ch if payload.primary_ch is not None else payload.channel
    if ch is None or not (1 <= ch <= 13):
        raise HTTPException(
            status_code=400,
            detail="Channel must be an integer between 1 and 13."
        )

    baseline_engine.set_manual_primary_channel(ch)
    plan = baseline_engine.get_optimal_scan_plan()

    if payload.dwell_primary_ms is not None:
        plan["dwell_primary_ms"] = payload.dwell_primary_ms
    if payload.dwell_patrol_ms is not None:
        plan["dwell_patrol_ms"] = payload.dwell_patrol_ms

    dispatched = False
    if serial_manager.is_connected():
        dispatched = serial_manager.write_command(plan)

    return {
        "status": "configured",
        "scan_plan": plan,
        "dispatched_to_uart": dispatched
    }

@app.get("/api/errors/counters")
def get_error_counters():
    conn = get_connection()
    counters = fetch_serial_error_counters(conn)
    conn.close()
    return counters

@app.post("/api/serial/connect", dependencies=[Depends(verify_api_key)])
def connect_serial_port(payload: SerialConnectPayload):
    success = serial_manager.connect(payload.port, payload.baud_rate)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to initialize serial port.")
    return {"status": "connected", "port": payload.port, "baud_rate": payload.baud_rate}

@app.post("/api/serial/disconnect")
def disconnect_serial_port():
    serial_manager.disconnect()
    return {"status": "disconnected"}

@app.post("/api/hardware/whitelist")
def add_hardware_whitelist(payload: HardwareWhitelistPayload):
    conn = get_connection()
    insert_hardware_whitelist(conn, payload.bssid or "", payload.ssid or "", payload.channel or 0)
    conn.close()

    cmd_dict = {
        "cmd": "wl_add",
        "ssid": payload.ssid or "",
        "bssid": payload.bssid or ""
    }
    dispatched = False
    if serial_manager.is_connected():
        dispatched = serial_manager.write_command(cmd_dict)
    return {
        "status": "whitelist_added",
        "command": cmd_dict,
        "dispatched_to_uart": dispatched
    }

@app.delete("/api/hardware/whitelist/{bssid}")
def delete_hardware_whitelist_by_path(bssid: str):
    conn = get_connection()
    deleted = delete_hardware_whitelist(conn, bssid)
    conn.close()

    cmd_dict = {"cmd": "wl_del", "bssid": bssid}
    dispatched = False
    if serial_manager.is_connected():
        dispatched = serial_manager.write_command(cmd_dict)
    return {
        "status": "whitelist_deleted",
        "bssid": bssid,
        "deleted": bool(deleted),
        "command": cmd_dict,
        "dispatched_to_uart": dispatched
    }

@app.delete("/api/hardware/whitelist")
def clear_hardware_whitelist(payload: Optional[HardwareWhitelistPayload] = None):
    bssid_to_del = payload.bssid if (payload and payload.bssid) else None
    conn = get_connection()
    deleted_count = delete_hardware_whitelist(conn, bssid_to_del)
    conn.close()

    if bssid_to_del:
        cmd_dict = {"cmd": "wl_del", "bssid": bssid_to_del}
    else:
        cmd_dict = {"cmd": "wl_clear"}
    dispatched = False
    if serial_manager.is_connected():
        dispatched = serial_manager.write_command(cmd_dict)
    return {
        "status": "whitelist_cleared",
        "deleted_count": deleted_count if not bssid_to_del else (1 if deleted_count else 0),
        "command": cmd_dict,
        "dispatched_to_uart": dispatched
    }

@app.get("/api/hardware/whitelist")
def get_hardware_whitelist():
    conn = get_connection()
    entries = fetch_all_hardware_whitelist(conn)
    conn.close()
    return entries

@app.post("/api/telemetry/reset", dependencies=[Depends(verify_api_key)])
def reset_telemetry_state():
    global cumulative_nfc_reads, active_attack_labelling
    baseline_engine.reset()
    baseline_engine.alpha = EWMA_ALPHA
    baseline_engine.z_threshold = Z_SCORE_THRESHOLD
    baseline_engine.warmup_windows = WARMUP_WINDOWS
    baseline_engine.warmup_limit = WARMUP_WINDOWS
    baseline_engine.fixed_threshold = FIXED_DEAUTH_THRESHOLD
    if hasattr(baseline_engine, "baselines"):
        for bf in baseline_engine.baselines.values():
            bf.alpha = EWMA_ALPHA
    correlation_engine.reset()
    evidence_builder.reset()
    incident_manager.reset()
    replay_engine.stop_replay()
    cumulative_nfc_reads = 0
    active_attack_labelling = False

    conn = get_connection()
    reset_telemetry_database(conn)
    conn.close()

    return {"status": "database_reset_ok"}

@app.get("/api/telemetry/history")
def get_telemetry_history(limit: int = 100):
    conn = get_connection()
    rows = fetch_recent_telemetry(conn, limit=limit)
    conn.close()
    return rows

@app.get("/api/alerts")
def get_alerts_history(limit: int = 50):
    conn = get_connection()
    rows = fetch_recent_alerts(conn, limit=limit)
    conn.close()
    return rows

@app.get("/api/logs/query")
def query_logs(
    q: Optional[str] = None,
    data_source: Optional[str] = None,
    severity: Optional[str] = None,
    window_id: Optional[int] = None,
    limit: int = 50
):
    conn = get_connection()
    results = query_alert_logs(
        conn,
        q=q,
        data_source=data_source,
        severity=severity,
        window_id=window_id,
        limit=limit
    )
    conn.close()
    return results

@app.get("/api/export/events")
def export_events(
    format: str = Query("json", pattern="^(json|csv)$"),
    data_source: Optional[str] = None,
    start_epoch_ms: Optional[int] = None,
    end_epoch_ms: Optional[int] = None
):
    conn = get_connection()
    events = fetch_all_alerts(conn, data_source=data_source)
    conn.close()
    if start_epoch_ms is not None:
        events = [e for e in events if (e.get("epoch_ms") or 0) >= start_epoch_ms]
    if end_epoch_ms is not None:
        events = [e for e in events if (e.get("epoch_ms") or 0) <= end_epoch_ms]
    now_ts = int(time.time())

    if format == "json":
        return Response(
            content=json.dumps(events, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="nexus_events_{now_ts}.json"'}
        )

    # Format as CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "event_id", "window_id", "epoch_ms", "type_key", "event_type",
        "severity", "confidence", "signals_correlated", "data_source", "evidence_json", "explanation"
    ])
    for ev in events:
        writer.writerow([
            ev.get("id", ""),
            ev.get("event_id", ""),
            ev.get("window_id", ""),
            ev.get("epoch_ms", ""),
            ev.get("type_key", ""),
            ev.get("event_type", ""),
            ev.get("severity", ""),
            ev.get("confidence", ""),
            ev.get("signals_correlated", ""),
            ev.get("data_source", ""),
            ev.get("evidence_json", ""),
            ev.get("explanation", "")
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="nexus_events_{now_ts}.csv"'}
    )

@app.get("/api/export/telemetry")
def export_telemetry(
    format: str = Query("csv", pattern="^(json|csv)$"),
    data_source: Optional[str] = None,
    start_epoch_ms: Optional[int] = None,
    end_epoch_ms: Optional[int] = None
):
    conn = get_connection()
    windows = fetch_all_telemetry(conn, data_source=data_source)
    conn.close()
    if start_epoch_ms is not None:
        windows = [w for w in windows if (w.get("epoch_ms") or 0) >= start_epoch_ms]
    if end_epoch_ms is not None:
        windows = [w for w in windows if (w.get("epoch_ms") or 0) <= end_epoch_ms]
    now_ts = int(time.time())

    if format == "json":
        return Response(
            content=json.dumps(windows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="nexus_telemetry_{now_ts}.json"'}
        )

    # Format as CSV matching Table 3.3 and FR-11
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "window_id", "epoch_ms", "data_source", "deauth", "mgmt", "ble", "rogue", "nfc", "rssi",
        "is_attack_labelled", "flag_fixed", "flag_adaptive", "flag_nexus",
        "ewma_deauth_mean", "z_deauth", "z_mgmt", "z_ble", "z_rogue"
    ])
    for w in windows:
        writer.writerow([
            w.get("window_id", ""),
            w.get("epoch_ms", ""),
            w.get("data_source", ""),
            w.get("deauth_count", 0),
            w.get("mgmt_count", 0),
            w.get("ble_count", 0),
            w.get("rogue_count", 0),
            w.get("nfc_count", 0),
            w.get("rssi_mean", -70.0),
            w.get("is_attack_labelled", 0),
            w.get("flag_fixed", 0),
            w.get("flag_adaptive", 0),
            w.get("flag_nexus", 0),
            w.get("ewma_deauth_mean", 0.0),
            w.get("z_deauth", 0.0),
            w.get("z_mgmt", 0.0),
            w.get("z_ble", 0.0),
            w.get("z_rogue", 0.0)
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="nexus_telemetry_{now_ts}.csv"'}
    )

@app.post("/api/trusted-aps/learn")
def learn_trusted_aps(payload: Optional[LearnTrustedApsPayload] = None):
    conn = get_connection()
    count = 0
    if payload and payload.aps:
        count = bulk_learn_trusted_aps(payload.aps, conn=conn)
    else:
        limit_w = payload.limit_windows if payload else 200
        count = learn_trusted_aps_from_telemetry(conn=conn, limit_windows=limit_w or 200)

    correlation_engine.set_trusted_aps(get_trusted_aps_map(conn))
    conn.close()
    return {"status": "learned", "learned_count": count}

@app.get("/api/trusted-aps")
def get_trusted_aps():
    conn = get_connection()
    aps = fetch_trusted_aps(conn)
    conn.close()
    return aps

@app.post("/api/trusted-aps")
def add_or_update_trusted_ap(payload: TrustedApPayload):
    conn = get_connection()
    now_ms = int(time.time() * 1000)
    upsert_trusted_ap(
        bssid=payload.bssid,
        ssid=payload.ssid,
        channel=payload.channel,
        epoch_ms=now_ms,
        is_active=payload.is_active,
        conn=conn
    )
    correlation_engine.set_trusted_aps(get_trusted_aps_map(conn))
    conn.close()
    return {"status": "upserted", "bssid": payload.bssid, "is_active": payload.is_active}

@app.get("/api/incidents")
def get_incidents(mode: Optional[str] = "live"):
    conn = get_connection(db_mode=resolve_db_mode(mode_param=mode))
    try:
        active = fetch_active_incidents(conn)
        stats = fetch_false_positive_stats(conn)
        return {
            "active_incidents": active,
            "false_positive_stats": stats
        }
    finally:
        conn.close()

@app.post("/api/incidents/{incident_id}/status")
def change_incident_status(incident_id: str, payload: IncidentStatusPayload):
    conn = get_connection()
    success = incident_manager.update_status(
        incident_id=incident_id,
        new_status=payload.status,
        note=payload.note or "",
        baseline_engine=baseline_engine,
        conn=conn
    )
    conn.close()
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or update failed.")
    return {"incident_id": incident_id, "status": payload.status.upper(), "updated": True}

@app.get("/api/incidents/{incident_id}")
def get_incident_by_id_endpoint(incident_id: str):
    conn = get_connection()
    inc = fetch_incident_by_id(incident_id, conn=conn)
    if not inc:
        inc = fetch_incident_with_timeline(incident_id, conn=conn)
    conn.close()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return inc

@app.post("/api/incidents/{incident_id}/remediation")
def update_incident_remediation_endpoint(incident_id: str, payload: RemediationUpdatePayload):
    conn = get_connection()
    success = update_incident_remediation(conn, incident_id, payload.completed_steps)
    conn.close()
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or update failed.")
    return {
        "status": "updated",
        "incident_id": incident_id,
        "completed_steps": payload.completed_steps
    }

@app.post("/api/incidents/batch-status")
def batch_incident_status_endpoint(payload: BatchStatusUpdate):
    conn = get_connection()
    now_ms = int(time.time() * 1000)
    try:
        if payload.incident_ids is not None:
            raw_status = (payload.status or "").strip().upper()
            if raw_status not in ["OPEN", "ACKNOWLEDGED", "RESOLVED"]:
                raise HTTPException(
                    status_code=400,
                    detail="Status must be one of ['OPEN', 'ACKNOWLEDGED', 'RESOLVED']"
                )
            if not payload.incident_ids:
                return {
                    "updated_count": 0,
                    "status": "success",
                    "incident_ids": []
                }
            placeholders = ",".join("?" for _ in payload.incident_ids)
            query = (
                f"UPDATE incidents SET status = ?, updated_at = ? "
                f"WHERE id IN ({placeholders}) OR rowid IN ({placeholders}) OR incident_id IN ({placeholders});"
            )
            params = [raw_status, now_ms] + list(payload.incident_ids) + list(payload.incident_ids) + list(payload.incident_ids)
            cursor = conn.cursor()
            cursor.execute(query, params)
            count = cursor.rowcount
            conn.commit()
            return {
                "updated_count": count,
                "status": "success",
                "incident_ids": payload.incident_ids
            }
        elif payload.from_status and payload.to_status:
            raw_to_status = payload.to_status.strip().upper()
            count = batch_update_incident_status(
                payload.from_status,
                raw_to_status,
                payload.note or "",
                conn
            )
            return {
                "updated_count": count,
                "new_status": raw_to_status,
                "status": "success"
            }
        else:
            raise HTTPException(
                status_code=400,
                detail="Either incident_ids and status, or from_status and to_status must be provided."
            )
    finally:
        conn.close()

@app.post("/api/incidents/sync", dependencies=[Depends(verify_api_key)])
def sync_incident_endpoint(payload: IncidentSyncPayload):
    alert = payload.alert or {}
    incident = payload.incident or {}

    conn = get_connection()
    try:
        if payload.alert:
            insert_alert_event(payload.alert, conn=conn)
        if payload.incident:
            insert_incident_record(payload.incident, conn=conn)
    finally:
        conn.close()

    return {
        "status": "synchronized",
        "alert_id": alert.get("id"),
        "incident_id": incident.get("id")
    }

@app.post("/api/incidents/generate-report")
def generate_incidents_report(payload: Optional[GenerateReportPayload] = None, limit: Optional[int] = Query(default=None)):
    target_limit = 20
    if payload and payload.limit:
        target_limit = payload.limit
    elif limit is not None:
        target_limit = limit

    conn = get_connection()
    incidents_data = fetch_incidents(conn, limit=target_limit)
    conn.close()

    # Collect baseline parameters from baseline_engine
    baseline_summary: Dict[str, Any] = {
        "alpha": getattr(baseline_engine, "alpha", EWMA_ALPHA),
        "z_cutoff": getattr(baseline_engine, "z_threshold", Z_SCORE_THRESHOLD),
        "features": {}
    }
    if hasattr(baseline_engine, "baselines"):
        for name, feat in baseline_engine.baselines.items():
            baseline_summary["features"][name] = {
                "alpha": getattr(feat, "alpha", EWMA_ALPHA),
                "mean": round(getattr(feat, "mean", 0.0), 2),
                "std_dev": round(feat.get_std_dev(), 2) if hasattr(feat, "get_std_dev") else 1.0
            }

    # Extract all available forensic attribution fields: attacker MAC, hardware profile, deauth reason code, proximity zone, MITRE technique ID, and SHA-256 evidence digest
    enriched_incidents: List[Dict[str, Any]] = []
    for inc in incidents_data:
        inc_copy = dict(inc)
        atk = str(inc_copy.get("attacker_mac") or "").strip().upper()
        if not inc_copy.get("hardware_profile") or inc_copy.get("hardware_profile") == "UNKNOWN":
            from .incident_manager import identify_hardware_profile
            inc_copy["hardware_profile"] = identify_hardware_profile(atk) if atk else "UNKNOWN"
        if not inc_copy.get("mitre_technique_id") or inc_copy.get("mitre_technique_id") == "T1200":
            from .incident_manager import map_incident_to_mitre
            m_info = map_incident_to_mitre(inc_copy.get("event_type") or inc_copy.get("primary_type", ""))
            inc_copy["mitre_technique_id"] = m_info["technique_id"]
            inc_copy["mitre_technique_name"] = m_info["technique_name"]
            inc_copy["mitre_tactic"] = m_info["tactic"]
        if not inc_copy.get("evidence_hash"):
            from .incident_manager import compute_evidence_hash
            inc_copy["evidence_hash"] = compute_evidence_hash(inc_copy)
        enriched_incidents.append(inc_copy)

    report_text = assistant_engine.generate_compliance_report(enriched_incidents, baseline_summary)
    now_ms = int(time.time() * 1000)

    return {
        "status": "success",
        "report_markdown": report_text,
        "incident_count": len(enriched_incidents),
        "generated_at": now_ms
    }

def mac_to_bytes(mac_str: str) -> bytes:
    try:
        clean = str(mac_str).replace("-", ":").strip()
        parts = clean.split(":")
        if len(parts) == 6:
            return bytes(int(p, 16) for p in parts)
    except Exception:
        pass
    return b"\xff\xff\xff\xff\xff\xff"

def generate_incident_pcap(incident_dict: Dict[str, Any]) -> bytes:
    """
    Constructs a valid binary libpcap capture (magic 0xA1B2C3D4, major 2, minor 4, link-type 105 DLT_IEEE802_11).
    Synthesizes 802.11 deauth/mgmt frames matching recorded attacker MAC, target MAC, sequence number, and reason code.
    """
    # Global PCAP Header (24 bytes)
    global_hdr = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # Magic number
        2,           # Version major
        4,           # Version minor
        0,           # GMT to local correction
        0,           # Accuracy of timestamps
        65535,       # Max length of captured packets
        105          # Link layer type: DLT_IEEE802_11
    )

    atk_mac_bytes = mac_to_bytes(incident_dict.get("attacker_mac", ""))
    tgt_mac_bytes = mac_to_bytes(incident_dict.get("target_mac") or incident_dict.get("target_bssid", ""))

    try:
        reason_code = int(incident_dict.get("deauth_reason", 7) or 7)
    except (ValueError, TypeError):
        reason_code = 7

    try:
        start_ms = int(incident_dict.get("start_epoch_ms") or (time.time() * 1000))
    except (ValueError, TypeError):
        start_ms = int(time.time() * 1000)

    try:
        event_count = max(int(incident_dict.get("event_count", 5) or 5), 1)
    except (ValueError, TypeError):
        event_count = 5

    frames_count = min(event_count, 10)
    packet_data_blocks = []

    for seq in range(1, frames_count + 1):
        # 802.11 Deauth Frame (26 bytes)
        frame_control = struct.pack("<H", 0x00C0)  # Type=0 (mgmt), Subtype=12 (deauth)
        duration = struct.pack("<H", 314)
        seq_control = struct.pack("<H", (seq << 4) & 0xFFF0)
        reason_bytes = struct.pack("<H", reason_code)

        frame_bytes = (
            frame_control
            + duration
            + tgt_mac_bytes
            + atk_mac_bytes
            + tgt_mac_bytes
            + seq_control
            + reason_bytes
        )

        pkt_len = len(frame_bytes)
        cur_ms = start_ms + (seq * 10)
        ts_sec = cur_ms // 1000
        ts_usec = (cur_ms % 1000) * 1000

        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        packet_data_blocks.append(pkt_hdr + frame_bytes)

    return global_hdr + b"".join(packet_data_blocks)

@app.get("/api/incidents/{incident_id}/pcap")
def download_incident_pcap(incident_id: str):
    conn = get_connection()
    inc = fetch_incident_with_timeline(incident_id, conn=conn)
    conn.close()

    if not inc or not inc.get("incident_id"):
        raise HTTPException(status_code=404, detail="Incident not found.")

    pcap_bytes = generate_incident_pcap(inc)
    return Response(
        content=pcap_bytes,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.pcap"}
    )

@app.post("/api/assistant/chat")
async def assistant_chat_endpoint(payload: AssistantChatPayload):
    async def token_generator():
        async for token in assistant_engine.stream_chat(
            message=payload.message,
            history=payload.history,
            ollama_url=payload.ollama_url,
            model=payload.model
        ):
            yield token

    return StreamingResponse(token_generator(), media_type="text/plain")

@app.post("/api/assistant/test-endpoint")
async def assistant_test_endpoint(payload: EndpointTestPayload):
    raw_url = (payload.base_url or payload.endpoint_url or "").strip()
    if not raw_url:
        return {"available": False, "status": "offline", "error": "No base_url provided."}

    target_url = f"{raw_url.rstrip('/')}/api/tags"
    headers: Dict[str, str] = {}
    if payload.api_key:
        headers["Authorization"] = f"Bearer {payload.api_key}"

    try:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=httpx.Timeout(1.0, connect=0.5)) as client:
            resp = await asyncio.wait_for(client.get(target_url, headers=headers), timeout=1.0)
        elapsed = time.perf_counter() - t0
        elapsed_ms = round(elapsed * 1000, 1)

        if resp.status_code == 200:
            data = resp.json()
            models_raw = data.get("models", [])
            available_models: List[str] = []
            for item in models_raw:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("model")
                    if name:
                        available_models.append(str(name))
                elif isinstance(item, str):
                    available_models.append(item)

            model_found = False
            if payload.model:
                target_model = payload.model.strip().lower()
                for m in available_models:
                    m_lower = m.lower()
                    if (
                        target_model == m_lower
                        or target_model == m_lower.split(":")[0]
                        or f"{target_model}:latest" == m_lower
                    ):
                        model_found = True
                        break

            return {
                "available": True,
                "latency_ms": elapsed_ms,
                "models": available_models,
                "status": "online",
                "endpoint": raw_url,
                "model_found": model_found
            }
        else:
            return {
                "available": False,
                "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                "status": "offline",
                "endpoint": raw_url
            }
    except Exception as exc:
        return {
            "available": False,
            "error": str(exc),
            "status": "offline",
            "endpoint": raw_url
        }

@app.post("/api/replay/start", dependencies=[Depends(verify_api_key)])
def start_csv_replay(payload: ReplayStartPayload):
    success = replay_engine.start_replay(
        csv_text=payload.csv_content,
        speed_ms=payload.speed_ms or 100,
        source_name=payload.source_name or "replay.csv",
        on_window=lambda p, s: process_telemetry_window(p, data_source=s)
    )
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or empty CSV content.")
    return {"status": "started", "speed_ms": replay_engine.speed_ms, "source": replay_engine.source_name}

@app.post("/api/replay/stop", dependencies=[Depends(verify_api_key)])
def stop_csv_replay():
    replay_engine.stop_replay()
    return {"status": "stopped"}

@app.get("/api/replay/status")
def get_csv_replay_status():
    return replay_engine.get_status()

@app.get("/api/evaluation/threshold-sweep")
def get_evaluation_threshold_sweep(data_source: Optional[str] = None):
    conn = get_connection()
    windows = fetch_all_telemetry(conn, data_source=data_source)
    conn.close()
    return compute_threshold_sweep(windows, warmup_windows=WARMUP_WINDOWS)

@app.get("/api/evaluation/ablation")
def get_evaluation_ablation(data_source: Optional[str] = None):
    conn = get_connection()
    windows = fetch_all_telemetry(conn, data_source=data_source)
    conn.close()
    return compute_ablation_analysis(windows, warmup_windows=WARMUP_WINDOWS)

@app.post("/api/telemetry/prune", dependencies=[Depends(verify_api_key)])
def prune_telemetry_endpoint(payload: Optional[PrunePayload] = None):
    hours = payload.retention_hours if payload else 48
    conn = get_connection()
    res = prune_historical_telemetry(retention_hours=hours, conn=conn)
    conn.close()
    return {
        "status": "pruned",
        "retention_hours": res["retention_hours"],
        "deleted_windows": res["deleted_windows"],
        "deleted_frames": res.get("deleted_frames", 0),
        "remaining_windows": res.get("remaining_windows", 0)
    }

frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
