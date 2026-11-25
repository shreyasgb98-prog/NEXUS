import sqlite3
import time
import json
import hashlib
from typing import List, Dict, Any, Optional
from pathlib import Path
from .config import DB_PATH, SIM_DB_PATH, MIGRATIONS_DIR

def get_connection(db_mode: str = "live", db_path: Optional[str] = None) -> sqlite3.Connection:
    if db_path is not None:
        target_path = db_path
        is_sim_mode = False
    elif db_mode in ("sim", "simulation"):
        target_path = SIM_DB_PATH
        is_sim_mode = True
    elif db_mode in ("live", ""):
        target_path = DB_PATH
        is_sim_mode = False
    else:
        target_path = db_mode
        is_sim_mode = False

    target_file = Path(target_path)
    target_file.parent.mkdir(parents=True, exist_ok=True)
    needs_init = (db_path is None) and (not target_file.exists() or target_file.stat().st_size == 0)

    if needs_init:
        init_db(db_path=target_path)

    conn = sqlite3.connect(target_path, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DB_PATH) -> None:
    """Initializes the SQLite database enforcing WAL pragmas and executing migrations sequentially."""
    conn = get_connection(db_path=db_path)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.commit()
    finally:
        conn.close()
    apply_migrations(db_path)
    rem_conn = get_connection(db_path=db_path)
    try:
        ensure_incident_remediation_column(rem_conn)
    finally:
        rem_conn.close()

def ensure_incident_remediation_column(conn: Optional[sqlite3.Connection] = None) -> None:
    """Ensures remediation_steps and updated_at columns exist on the incidents table."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(incidents);")
        cols = {row["name"] for row in cursor.fetchall()}
        if cols:
            if "remediation_steps" not in cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN remediation_steps TEXT DEFAULT '[]';")
            if "updated_at" not in cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN updated_at INTEGER DEFAULT 0;")
            conn.commit()
    except Exception:
        pass
    finally:
        if close_on_exit:
            conn.close()

def fetch_sqlite_pragmas(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Inspects live SQLite pragma configuration values."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0]

        cursor.execute("PRAGMA synchronous;")
        synchronous = cursor.fetchone()[0]

        cursor.execute("PRAGMA foreign_keys;")
        foreign_keys = cursor.fetchone()[0]

        cursor.execute("PRAGMA busy_timeout;")
        busy_timeout = cursor.fetchone()[0]

        return {
            "journal_mode": str(journal_mode).lower(),
            "synchronous": int(synchronous),
            "foreign_keys": int(foreign_keys),
            "busy_timeout": int(busy_timeout)
        }
    finally:
        if close_on_exit:
            conn.close()

def fetch_database_status(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Inspects live SQLite pragma configuration and operational row counts."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal_mode = str(cursor.fetchone()[0]).lower()

        cursor.execute("PRAGMA synchronous;")
        synchronous = int(cursor.fetchone()[0])

        cursor.execute("PRAGMA foreign_keys;")
        foreign_keys = int(cursor.fetchone()[0])

        cursor.execute("PRAGMA busy_timeout;")
        busy_timeout = int(cursor.fetchone()[0])

        cursor.execute("PRAGMA page_count;")
        page_count = int(cursor.fetchone()[0])

        cursor.execute("PRAGMA page_size;")
        page_size = int(cursor.fetchone()[0])

        database_bytes = page_count * page_size

        cursor.execute("SELECT count(id) FROM telemetry_windows;")
        telemetry_windows_count = int(cursor.fetchone()[0])

        cursor.execute("SELECT count(id) FROM incidents;")
        incidents_count = int(cursor.fetchone()[0])

        cursor.execute("SELECT count(bssid) FROM hardware_whitelist;")
        hardware_whitelist_count = int(cursor.fetchone()[0])

        sync_map = {0: "off", 1: "normal", 2: "full", 3: "extra"}
        sync_str = sync_map.get(synchronous, "normal")

        return {
            "journal_mode": journal_mode,
            "synchronous": synchronous,
            "synchronous_str": sync_str,
            "foreign_keys": foreign_keys,
            "busy_timeout": busy_timeout,
            "size_bytes": database_bytes,
            "telemetry_rows": telemetry_windows_count,
            "incident_rows": incidents_count,
            "whitelist_rows": hardware_whitelist_count,
            "page_count": page_count,
            "page_size": page_size,
            "database_bytes": database_bytes,
            "database_size_bytes": database_bytes,
            "telemetry_windows_count": telemetry_windows_count,
            "telemetry_windows": telemetry_windows_count,
            "incidents_count": incidents_count,
            "incidents": incidents_count,
            "hardware_whitelist_count": hardware_whitelist_count,
            "hardware_whitelist": hardware_whitelist_count,
        }
    finally:
        if close_on_exit:
            conn.close()

def apply_migrations(db_path: str = DB_PATH) -> None:
    conn = get_connection(db_path=db_path)
    old_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  version INTEGER PRIMARY KEY,"
            "  filename TEXT,"
            "  applied_epoch_ms INTEGER NOT NULL"
            ");"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS schema_versions ("
            "  version INTEGER PRIMARY KEY,"
            "  filename TEXT,"
            "  applied_epoch_ms INTEGER NOT NULL"
            ");"
        )
        cursor.execute("PRAGMA table_info(schema_migrations);")
        mig_cols = {row["name"] for row in cursor.fetchall()}
        if "filename" not in mig_cols:
            cursor.execute("ALTER TABLE schema_migrations ADD COLUMN filename TEXT;")

        cursor.execute("PRAGMA table_info(schema_versions);")
        ver_cols = {row["name"] for row in cursor.fetchall()}
        if "filename" not in ver_cols:
            cursor.execute("ALTER TABLE schema_versions ADD COLUMN filename TEXT;")

        cursor.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, filename, applied_epoch_ms) "
            "SELECT version, filename, applied_epoch_ms FROM schema_versions;"
        )
        cursor.execute(
            "INSERT OR IGNORE INTO schema_versions (version, filename, applied_epoch_ms) "
            "SELECT version, filename, applied_epoch_ms FROM schema_migrations;"
        )

        cursor.execute("SELECT version, filename FROM schema_migrations ORDER BY version ASC;")
        applied_rows = cursor.fetchall()
        applied_versions = {row["version"] for row in applied_rows}
        applied_filenames = {row["filename"] for row in applied_rows if row["filename"]}

        def migration_sort_key(p: Path) -> int:
            try:
                return int(p.name.split("_")[0])
            except (ValueError, IndexError):
                return 999999

        migration_files = sorted(Path(MIGRATIONS_DIR).glob("*.sql"), key=migration_sort_key)
        for file_path in migration_files:
            filename = file_path.name
            version_num = int(filename.split("_")[0])
            if version_num not in applied_versions or filename not in applied_filenames:
                sql_script = file_path.read_text(encoding="utf-8")
                statements = [s.strip() for s in sql_script.split(";") if s.strip()]
                for stmt in statements:
                    try:
                        cursor.execute(stmt)
                    except sqlite3.OperationalError as e:
                        err_msg = str(e).lower()
                        if "duplicate column name" in err_msg or "already exists" in err_msg:
                            continue
                        raise
                now_epoch = int(time.time() * 1000)
                cursor.execute(
                    "INSERT INTO schema_migrations (version, filename, applied_epoch_ms) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(version) DO UPDATE SET filename = excluded.filename, applied_epoch_ms = excluded.applied_epoch_ms;",
                    (version_num, filename, now_epoch)
                )
                cursor.execute(
                    "INSERT INTO schema_versions (version, filename, applied_epoch_ms) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(version) DO UPDATE SET filename = excluded.filename, applied_epoch_ms = excluded.applied_epoch_ms;",
                    (version_num, filename, now_epoch)
                )
                applied_versions.add(version_num)
                applied_filenames.add(filename)
    finally:
        conn.isolation_level = old_isolation
        conn.close()

def insert_telemetry_window(
    conn: sqlite3.Connection,
    window_id: int,
    epoch_ms: int,
    deauth_count: int,
    mgmt_count: int,
    ble_count: int,
    rogue_count: int,
    nfc_count: int,
    rssi_mean: float = -70.0,
    data_source: str = "live",
    is_attack_labelled: int = 0,
    flag_fixed: int = 0,
    flag_adaptive: int = 0,
    flag_nexus: int = 0,
    ewma_deauth_mean: float = 0.0,
    ewma_deauth_var: float = 1.0,
    ewma_mgmt_mean: float = 0.0,
    ewma_mgmt_var: float = 1.0,
    ewma_ble_mean: float = 0.0,
    ewma_ble_var: float = 1.0,
    ewma_rogue_mean: float = 0.0,
    ewma_rogue_var: float = 1.0,
    z_deauth: float = 0.0,
    z_mgmt: float = 0.0,
    z_ble: float = 0.0,
    z_rogue: float = 0.0,
    unique_bssids: int = 0,
    top_sources_json: str = "[]",
    channel: int = 1,
    rssi_min: float = -90.0,
    rssi_max: float = -30.0,
    attacker_mac: str = "",
    target_mac: str = "",
    attacker_rssi: int = 0,
    deauth_reason: int = 0,
    proximity_zone: str = "NONE",
    raw_injection_count: int = 0,
    is_laa_randomized: int = 0,
    hardware_profile: str = "UNKNOWN"
) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO telemetry_windows ("
        "  window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
        "  rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
        "  ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
        "  ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
        "  z_deauth, z_mgmt, z_ble, z_rogue, "
        "  unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
        "  attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
        "  raw_injection_count, is_laa_randomized, hardware_profile"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count,
            rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus,
            ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var,
            ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var,
            z_deauth, z_mgmt, z_ble, z_rogue,
            unique_bssids, top_sources_json, channel, rssi_min, rssi_max,
            attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone,
            raw_injection_count, is_laa_randomized, hardware_profile
        )
    )
    conn.commit()
    return cursor.lastrowid

def insert_enriched_telemetry_window(
    window_dict: Dict[str, Any],
    conn: Optional[sqlite3.Connection] = None
) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True

    try:
        top_sources = window_dict.get("top_sources_json", "[]")
        if isinstance(top_sources, (list, dict)):
            top_sources = json.dumps(top_sources)

        insert_telemetry_window(
            conn=conn,
            window_id=int(window_dict["window_id"]),
            epoch_ms=int(window_dict.get("epoch_ms", time.time() * 1000)),
            deauth_count=int(window_dict.get("deauth_count", window_dict.get("deauth", 0))),
            mgmt_count=int(window_dict.get("mgmt_count", window_dict.get("mgmt", 0))),
            ble_count=int(window_dict.get("ble_count", window_dict.get("ble", 0))),
            rogue_count=int(window_dict.get("rogue_count", window_dict.get("rogue", 0))),
            nfc_count=int(window_dict.get("nfc_count", window_dict.get("nfc", 0))),
            rssi_mean=float(window_dict.get("rssi_mean", window_dict.get("rssi", -70.0))),
            data_source=str(window_dict.get("data_source", "live")),
            is_attack_labelled=int(window_dict.get("is_attack_labelled", 0)),
            flag_fixed=int(window_dict.get("flag_fixed", 0)),
            flag_adaptive=int(window_dict.get("flag_adaptive", 0)),
            flag_nexus=int(window_dict.get("flag_nexus", 0)),
            ewma_deauth_mean=float(window_dict.get("ewma_deauth_mean", 0.0)),
            ewma_deauth_var=float(window_dict.get("ewma_deauth_var", 1.0)),
            ewma_mgmt_mean=float(window_dict.get("ewma_mgmt_mean", 0.0)),
            ewma_mgmt_var=float(window_dict.get("ewma_mgmt_var", 1.0)),
            ewma_ble_mean=float(window_dict.get("ewma_ble_mean", 0.0)),
            ewma_ble_var=float(window_dict.get("ewma_ble_var", 1.0)),
            ewma_rogue_mean=float(window_dict.get("ewma_rogue_mean", 0.0)),
            ewma_rogue_var=float(window_dict.get("ewma_rogue_var", 1.0)),
            z_deauth=float(window_dict.get("z_deauth", 0.0)),
            z_mgmt=float(window_dict.get("z_mgmt", 0.0)),
            z_ble=float(window_dict.get("z_ble", 0.0)),
            z_rogue=float(window_dict.get("z_rogue", 0.0)),
            unique_bssids=int(window_dict.get("unique_bssids", 0)),
            top_sources_json=top_sources,
            channel=int(window_dict.get("channel", 1)),
            rssi_min=float(window_dict.get("rssi_min", -90.0)),
            rssi_max=float(window_dict.get("rssi_max", -30.0)),
            attacker_mac=str(window_dict.get("attacker_mac", "")),
            target_mac=str(window_dict.get("target_mac", "")),
            attacker_rssi=int(window_dict.get("attacker_rssi", 0)),
            deauth_reason=int(window_dict.get("deauth_reason", 0)),
            proximity_zone=str(window_dict.get("proximity_zone", "NONE")),
            raw_injection_count=int(window_dict.get("raw_injection_count", 0)),
            is_laa_randomized=int(window_dict.get("is_laa_randomized", 0)),
            hardware_profile=str(window_dict.get("hardware_profile", "UNKNOWN"))
        )
    finally:
        if close_on_exit:
            conn.close()

def insert_telemetry(
    conn: Optional[sqlite3.Connection] = None,
    *args,
    **kwargs
) -> int:
    """Inserts a telemetry window record with forensic attribution."""
    close_on_exit = False
    if conn is None and not args:
        conn = get_connection()
        close_on_exit = True
    elif args and isinstance(args[0], sqlite3.Connection):
        conn = args[0]
        args = args[1:]
    elif conn is None:
        conn = get_connection()
        close_on_exit = True

    try:
        if args and isinstance(args[0], dict):
            insert_enriched_telemetry_window(args[0], conn=conn)
            return int(args[0].get("window_id", 0))
        elif kwargs and "window_dict" in kwargs:
            insert_enriched_telemetry_window(kwargs["window_dict"], conn=conn)
            return int(kwargs["window_dict"].get("window_id", 0))
        elif kwargs:
            insert_enriched_telemetry_window(kwargs, conn=conn)
            return int(kwargs.get("window_id", 0))
        return 0
    finally:
        if close_on_exit and conn:
            conn.close()

def insert_alert_event(
    alert_dict_or_conn: Any = None,
    *args,
    **kwargs
) -> int:
    close_on_exit = False
    conn = None

    if alert_dict_or_conn is None:
        if "conn" in kwargs:
            alert_dict_or_conn = kwargs["conn"]
        elif "alert_dict" in kwargs:
            alert_dict_or_conn = kwargs["alert_dict"]
        else:
            raise ValueError("alert_dict or conn must be provided")

    if isinstance(alert_dict_or_conn, sqlite3.Connection):
        conn = alert_dict_or_conn
        if args or kwargs:
            event_id = args[0] if len(args) > 0 else kwargs.get("event_id", "")
            window_id = int(args[1] if len(args) > 1 else kwargs.get("window_id", 0))
            epoch_ms = int(args[2] if len(args) > 2 else kwargs.get("epoch_ms", int(time.time() * 1000)))
            type_key = str(args[3] if len(args) > 3 else kwargs.get("type_key", "anomaly"))
            event_type = str(args[4] if len(args) > 4 else kwargs.get("event_type", "Wireless Anomaly"))
            severity = str(args[5] if len(args) > 5 else kwargs.get("severity", "MEDIUM")).lower()
            confidence = float(args[6] if len(args) > 6 else kwargs.get("confidence", 0.5))
            signals_correlated = int(args[7] if len(args) > 7 else kwargs.get("signals_correlated", 1))
            data_source = str(args[8] if len(args) > 8 else kwargs.get("data_source", "live"))
            evidence_json = str(args[9] if len(args) > 9 else kwargs.get("evidence_json", "{}"))
            explanation = str(args[10] if len(args) > 10 else kwargs.get("explanation", ""))
            mitre_technique = str(kwargs.get("mitre_technique", ""))
            owasp_category = str(kwargs.get("owasp_category", ""))
            suggested_action = str(kwargs.get("suggested_action", ""))
            mitre_technique_id = str(kwargs.get("mitre_technique_id") or kwargs.get("technique_id") or "T1200")
            mitre_technique_name = str(kwargs.get("mitre_technique_name") or kwargs.get("technique_name") or "")
            mitre_tactic = str(kwargs.get("mitre_tactic") or kwargs.get("tactic") or "")
            evidence_hash = str(kwargs.get("evidence_hash") or "")
            if not evidence_hash:
                evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
            id_val = kwargs.get("id")
        else:
            now_ms = int(time.time() * 1000)
            event_id = f"EV-{now_ms % 100000:05d}"
            window_id = 0
            epoch_ms = now_ms
            type_key = "anomaly"
            event_type = "Wireless Anomaly"
            severity = "medium"
            confidence = 0.5
            signals_correlated = 1
            data_source = "live"
            evidence_json = "{}"
            explanation = ""
            mitre_technique = ""
            owasp_category = ""
            suggested_action = ""
            mitre_technique_id = "T1200"
            mitre_technique_name = ""
            mitre_tactic = ""
            evidence_hash = hashlib.sha256(b"{}").hexdigest()
            id_val = None
    elif isinstance(alert_dict_or_conn, dict):
        alert_dict = alert_dict_or_conn
        conn = kwargs.get("conn") or (args[0] if args else None)
        if conn is None:
            conn = get_connection()
            close_on_exit = True

        now_ms = int(time.time() * 1000)
        id_raw = alert_dict.get("id")
        id_val = int(id_raw) if isinstance(id_raw, int) else None
        event_id = str(alert_dict.get("event_id") or (id_raw if isinstance(id_raw, str) else f"EV-{now_ms % 100000:05d}"))
        window_id = int(alert_dict.get("window_id") or alert_dict.get("window") or 0)
        epoch_ms = int(alert_dict.get("epoch_ms", now_ms))
        event_type = str(alert_dict.get("event_type") or alert_dict.get("type", "Wireless Anomaly"))
        severity = str(alert_dict.get("severity", "MEDIUM")).lower()
        confidence = float(alert_dict.get("confidence", 0.5))
        signals_correlated = int(alert_dict.get("signals_correlated", 1))

        evidence = alert_dict.get("evidence", alert_dict.get("evidence_json", "{}"))
        if isinstance(evidence, (dict, list)):
            evidence_json = json.dumps(evidence)
        else:
            evidence_json = str(evidence)

        mitre_technique = str(alert_dict.get("mitre_technique", ""))
        owasp_category = str(alert_dict.get("owasp_category", ""))
        suggested_action = str(alert_dict.get("suggested_action", ""))
        mitre_technique_id = str(alert_dict.get("mitre_technique_id") or alert_dict.get("technique_id") or kwargs.get("mitre_technique_id") or "T1200")
        mitre_technique_name = str(alert_dict.get("mitre_technique_name") or alert_dict.get("technique_name") or kwargs.get("mitre_technique_name") or "")
        mitre_tactic = str(alert_dict.get("mitre_tactic") or alert_dict.get("tactic") or kwargs.get("mitre_tactic") or "")
        evidence_hash = str(alert_dict.get("evidence_hash") or kwargs.get("evidence_hash") or "")
        if not evidence_hash:
            evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
        type_key = str(alert_dict.get("type_key") or event_type.lower())
        data_source = str(alert_dict.get("data_source", "live"))
        explanation = str(
            alert_dict.get("explanation")
            or alert_dict.get("explanation_text")
            or suggested_action
            or "Alert flagged by detection engine"
        )
    else:
        raise ValueError("alert_dict must be a dictionary or connection")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM telemetry_windows WHERE window_id = ? LIMIT 1;", (window_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO telemetry_windows ("
                "  window_id, epoch_ms, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
                "  rssi_mean, data_source"
                ") VALUES (?, ?, 0, 0, 0, 0, 0, -70.0, ?);",
                (window_id, epoch_ms, data_source)
            )

        cursor.execute(
            "INSERT OR REPLACE INTO alert_events ("
            "  id, event_id, window_id, epoch_ms, event_type, severity, confidence, "
            "  signals_correlated, evidence_json, mitre_technique, owasp_category, suggested_action, "
            "  type_key, data_source, explanation, explanation_text, "
            "  mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                id_val, event_id, window_id, epoch_ms, event_type, severity, confidence,
                signals_correlated, evidence_json, mitre_technique, owasp_category, suggested_action,
                type_key, data_source, explanation, explanation,
                mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash
            )
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        if close_on_exit:
            conn.close()

def insert_serial_error(
    conn: sqlite3.Connection,
    epoch_ms: int,
    error_type: str,
    raw_payload: str
) -> None:
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO serial_errors (epoch_ms, error_type, raw_payload) VALUES (?, ?, ?);",
        (epoch_ms, error_type, raw_payload)
    )
    cursor.execute(
        "INSERT INTO serial_error_counters (error_key, total_count, last_epoch_ms) "
        "VALUES (?, 1, ?) "
        "ON CONFLICT(error_key) DO UPDATE SET "
        "  total_count = total_count + 1, "
        "  last_epoch_ms = excluded.last_epoch_ms;",
        (error_type, epoch_ms)
    )
    conn.commit()

def save_baseline_state(
    conn: sqlite3.Connection,
    alpha: float,
    z_threshold: float,
    warmup_windows: int,
    processed_windows: int,
    updated_epoch_ms: int
) -> None:
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO baseline_state (id, alpha, z_threshold, warmup_windows, processed_windows, updated_epoch_ms) "
        "VALUES (1, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  alpha = excluded.alpha, "
        "  z_threshold = excluded.z_threshold, "
        "  warmup_windows = excluded.warmup_windows, "
        "  processed_windows = excluded.processed_windows, "
        "  updated_epoch_ms = excluded.updated_epoch_ms;",
        (alpha, z_threshold, warmup_windows, processed_windows, updated_epoch_ms)
    )
    conn.commit()

def fetch_baseline_state(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, alpha, z_threshold, warmup_windows, processed_windows, updated_epoch_ms "
        "FROM baseline_state WHERE id = 1;"
    )
    row = cursor.fetchone()
    return dict(row) if row else None

def save_baseline_metric(
    conn: sqlite3.Connection,
    feature_name: str,
    mean: float,
    variance: float,
    std_dev: float,
    updated_epoch_ms: int
) -> None:
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO baseline_metrics (feature_name, mean, variance, std_dev, updated_epoch_ms) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(feature_name) DO UPDATE SET "
        "  mean = excluded.mean, "
        "  variance = excluded.variance, "
        "  std_dev = excluded.std_dev, "
        "  updated_epoch_ms = excluded.updated_epoch_ms;",
        (feature_name, mean, variance, std_dev, updated_epoch_ms)
    )
    conn.commit()

def fetch_baseline_metrics(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT feature_name, mean, variance, std_dev, updated_epoch_ms "
        "FROM baseline_metrics ORDER BY feature_name ASC;"
    )
    return [dict(row) for row in cursor.fetchall()]

def fetch_channel_activity_stats(
    conn: sqlite3.Connection,
    limit_windows: int = 30
) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT channel, COUNT(window_id) AS window_count, "
        "SUM(mgmt_count) AS total_mgmt, "
        "ROUND(AVG(mgmt_count), 2) AS avg_mgmt, "
        "MAX(unique_bssids) AS max_bssids "
        "FROM ("
        "  SELECT window_id, channel, mgmt_count, unique_bssids "
        "  FROM telemetry_windows "
        "  ORDER BY window_id ASC "
        "  LIMIT ?"
        ") "
        "GROUP BY channel "
        "ORDER BY avg_mgmt DESC;",
        (limit_windows,)
    )
    return [dict(row) for row in cursor.fetchall()]

def fetch_recent_telemetry(
    conn: Optional[sqlite3.Connection] = None,
    limit: int = 50,
    data_source: Optional[str] = None,
    offset: int = 0
) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        safe_offset = max(0, int(offset))
        base_query = (
            "SELECT id, epoch_ms, window_id, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "channel, unique_bssids AS bssid_count, rssi_min, rssi_mean AS rssi_avg, rssi_max, data_source, "
            "rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "z_deauth, z_mgmt, z_ble, z_rogue, "
            "unique_bssids, top_sources_json, "
            "attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows"
        )
        if data_source:
            query = f"{base_query} WHERE data_source = ? ORDER BY window_id DESC, id DESC LIMIT ? OFFSET ?;"
            params = (data_source, limit, safe_offset)
        else:
            query = f"{base_query} ORDER BY window_id DESC, id DESC LIMIT ? OFFSET ?;"
            params = (limit, safe_offset)
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def count_telemetry_windows(
    conn: sqlite3.Connection,
    data_source: Optional[str] = None
) -> int:
    cursor = conn.cursor()
    if data_source:
        cursor.execute(
            "SELECT count(id) FROM telemetry_windows WHERE data_source = ?;",
            (data_source,)
        )
    else:
        cursor.execute("SELECT count(id) FROM telemetry_windows;")
    row = cursor.fetchone()
    return int(row[0]) if row else 0

def fetch_telemetry_rolling_window(
    conn: sqlite3.Connection,
    start_epoch_ms: int,
    end_epoch_ms: int,
    data_source: Optional[str] = None
) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    if data_source:
        cursor.execute(
            "SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "z_deauth, z_mgmt, z_ble, z_rogue, "
            "unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            "attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows "
            "WHERE data_source = ? AND epoch_ms >= ? AND epoch_ms <= ? "
            "ORDER BY epoch_ms ASC;",
            (data_source, start_epoch_ms, end_epoch_ms)
        )
    else:
        cursor.execute(
            "SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "z_deauth, z_mgmt, z_ble, z_rogue, "
            "unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            "attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows "
            "WHERE epoch_ms >= ? AND epoch_ms <= ? "
            "ORDER BY epoch_ms ASC;",
            (start_epoch_ms, end_epoch_ms)
        )
    return [dict(row) for row in cursor.fetchall()]

def update_window_attack_label(
    conn: sqlite3.Connection,
    window_id: int,
    is_attack_labelled: int
) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE telemetry_windows SET is_attack_labelled = ? WHERE window_id = ?;",
        (is_attack_labelled, window_id)
    )
    conn.commit()
    return cursor.rowcount

def update_window_range_attack_label(
    conn: sqlite3.Connection,
    start_window_id: int,
    end_window_id: int,
    is_attack_labelled: int
) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE telemetry_windows SET is_attack_labelled = ? WHERE window_id >= ? AND window_id <= ?;",
        (is_attack_labelled, start_window_id, end_window_id)
    )
    conn.commit()
    return cursor.rowcount

def fetch_all_telemetry(conn: sqlite3.Connection, data_source: Optional[str] = None) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    if data_source:
        cursor.execute(
            "SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "z_deauth, z_mgmt, z_ble, z_rogue, "
            "unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            "attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows WHERE data_source = ? ORDER BY window_id ASC;",
            (data_source,)
        )
    else:
        cursor.execute(
            "SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "z_deauth, z_mgmt, z_ble, z_rogue, "
            "unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            "attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows ORDER BY window_id ASC;"
        )
    return [dict(row) for row in cursor.fetchall()]

def fetch_all_alerts(conn: sqlite3.Connection, data_source: Optional[str] = None) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    if data_source:
        cursor.execute(
            "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
            "       confidence, signals_correlated, data_source, evidence_json, explanation, "
            "       mitre_technique, owasp_category, suggested_action, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
            "FROM alert_events WHERE data_source = ? ORDER BY id ASC;",
            (data_source,)
        )
    else:
        cursor.execute(
            "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
            "       confidence, signals_correlated, data_source, evidence_json, explanation, "
            "       mitre_technique, owasp_category, suggested_action, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
            "FROM alert_events ORDER BY id ASC;"
        )
    return [dict(row) for row in cursor.fetchall()]

def fetch_alerts(
    conn: Optional[sqlite3.Connection] = None,
    limit: int = 50,
    data_source: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches alert events with explicit column projection including MITRE taxonomy and evidence checksum."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        if data_source:
            cursor.execute(
                "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
                "       confidence, signals_correlated, data_source, evidence_json, explanation, "
                "       mitre_technique, owasp_category, suggested_action, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
                "FROM alert_events WHERE data_source = ? ORDER BY epoch_ms DESC LIMIT ?;",
                (data_source, limit)
            )
        else:
            cursor.execute(
                "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
                "       confidence, signals_correlated, data_source, evidence_json, explanation, "
                "       mitre_technique, owasp_category, suggested_action, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
                "FROM alert_events ORDER BY epoch_ms DESC LIMIT ?;",
                (limit,)
            )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def fetch_windows_for_metrics(
    conn: sqlite3.Connection,
    warmup_windows: int = 30,
    data_source: Optional[str] = None
) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    if data_source:
        cursor.execute(
            "SELECT window_id, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus "
            "FROM telemetry_windows WHERE window_id > ? AND data_source = ? ORDER BY window_id ASC;",
            (warmup_windows, data_source)
        )
    else:
        cursor.execute(
            "SELECT window_id, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus "
            "FROM telemetry_windows WHERE window_id > ? ORDER BY window_id ASC;",
            (warmup_windows,)
        )
    return [dict(row) for row in cursor.fetchall()]

def reset_telemetry_database(conn: Optional[sqlite3.Connection] = None) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incident_timeline;")
        cursor.execute("DELETE FROM incidents;")
        cursor.execute("DELETE FROM trusted_aps;")
        cursor.execute("DELETE FROM alert_events;")
        cursor.execute("DELETE FROM telemetry_windows;")
        cursor.execute("DELETE FROM serial_errors;")
        cursor.execute("DELETE FROM baseline_hourly;")
        cursor.execute("DELETE FROM evaluation_cache;")
        try:
            cursor.execute("DELETE FROM hardware_whitelist;")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("DELETE FROM telemetry;")
        except sqlite3.OperationalError:
            pass
        cursor.execute("UPDATE serial_error_counters SET total_count = 0, last_epoch_ms = 0;")
        cursor.execute("DELETE FROM baseline_metrics;")
        cursor.execute("UPDATE baseline_state SET processed_windows = 0, updated_epoch_ms = 0 WHERE id = 1;")
        conn.commit()
    finally:
        if close_on_exit:
            conn.close()

def purge_simulation_database(conn: sqlite3.Connection) -> Dict[str, str]:
    """Deletes simulation telemetry, alerts, incidents, and raw frames, then vacuums the database."""
    cursor = conn.cursor()
    for table_name in ("incident_timeline", "incidents", "alert_events", "alerts", "telemetry_windows", "raw_frames"):
        try:
            cursor.execute(f"DELETE FROM {table_name};")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.execute("VACUUM;")
    return {"status": "purged", "database": "nexus_sim.db"}

def update_alert_explanation(
    conn: sqlite3.Connection,
    event_id: str,
    explanation: str
) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE alert_events SET explanation = ?, explanation_text = ? WHERE event_id = ?;",
        (explanation, explanation, event_id)
    )
    conn.commit()
    return cursor.rowcount

def fetch_alert_by_id(conn: sqlite3.Connection, event_id: str) -> Optional[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
        "       confidence, signals_correlated, data_source, evidence_json, explanation, "
        "       mitre_technique, owasp_category, suggested_action, "
        "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
        "FROM alert_events WHERE event_id = ? OR id = ? LIMIT 1;",
        (event_id, event_id)
    )
    row = cursor.fetchone()
    return dict(row) if row else None

def fetch_recent_alerts(conn: sqlite3.Connection, limit: int = 50) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
        "       confidence, signals_correlated, data_source, evidence_json, explanation, "
        "       mitre_technique, owasp_category, suggested_action, "
        "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
        "FROM alert_events ORDER BY id DESC LIMIT ?;",
        (limit,)
    )
    return [dict(row) for row in cursor.fetchall()]

def fetch_alerts_rolling_window(
    conn: sqlite3.Connection,
    start_epoch_ms: int,
    end_epoch_ms: int,
    data_source: Optional[str] = None,
    event_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    query = (
        "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
        "       confidence, signals_correlated, data_source, evidence_json, explanation, "
        "       mitre_technique, owasp_category, suggested_action, "
        "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
        "FROM alert_events "
        "WHERE epoch_ms >= ? AND epoch_ms <= ?"
    )
    params: List[Any] = [start_epoch_ms, end_epoch_ms]
    if data_source:
        query += " AND data_source = ?"
        params.append(data_source)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    query += " ORDER BY epoch_ms ASC;"
    cursor.execute(query, tuple(params))
    return [dict(row) for row in cursor.fetchall()]

def fetch_serial_error_counters(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT error_key, total_count, last_epoch_ms FROM serial_error_counters ORDER BY error_key ASC;"
    )
    return [dict(row) for row in cursor.fetchall()]

def fetch_serial_error_count(conn: sqlite3.Connection) -> int:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(id) AS total_errors FROM serial_errors;")
    row = cursor.fetchone()
    return int(row["total_errors"]) if row else 0

def query_alert_logs(
    conn: sqlite3.Connection,
    q: Optional[str] = None,
    data_source: Optional[str] = None,
    severity: Optional[str] = None,
    window_id: Optional[int] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    conditions: List[str] = []
    params: List[Any] = []

    if data_source:
        conditions.append("data_source = ?")
        params.append(data_source)

    if severity:
        conditions.append("severity = ?")
        params.append(severity.lower())

    if window_id is not None:
        conditions.append("window_id = ?")
        params.append(window_id)

    if q:
        conditions.append(
            "(event_type LIKE ? OR explanation LIKE ? OR event_id LIKE ? OR type_key LIKE ? OR evidence_json LIKE ?)"
        )
        pattern = f"%{q}%"
        params.extend([pattern, pattern, pattern, pattern, pattern])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = (
        f"SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
        f"       confidence, signals_correlated, data_source, evidence_json, explanation, "
        f"       mitre_technique, owasp_category, suggested_action, "
        f"       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
        f"FROM alert_events {where_clause} ORDER BY id DESC LIMIT ?;"
    )
    safe_limit = max(1, min(limit, 500))
    params.append(safe_limit)

    cursor.execute(query, tuple(params))
    return [dict(row) for row in cursor.fetchall()]

# ---------------------------------------------------------------------------
# Trusted AP Allowlist Operations
# ---------------------------------------------------------------------------

def fetch_trusted_aps(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT bssid, ssid, channel, first_seen_epoch, last_seen_epoch, is_active "
            "FROM trusted_aps ORDER BY last_seen_epoch DESC;"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def upsert_trusted_ap(
    bssid: str,
    ssid: str,
    channel: int,
    epoch_ms: int,
    is_active: int = 1,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        normalized_bssid = bssid.strip().upper()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO trusted_aps (bssid, ssid, channel, first_seen_epoch, last_seen_epoch, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(bssid) DO UPDATE SET "
            "  ssid = excluded.ssid, "
            "  channel = excluded.channel, "
            "  last_seen_epoch = excluded.last_seen_epoch, "
            "  is_active = excluded.is_active;",
            (normalized_bssid, ssid, channel, epoch_ms, epoch_ms, is_active)
        )
        conn.commit()
    finally:
        if close_on_exit:
            conn.close()

def get_trusted_aps_map(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Dict[str, Any]]:
    aps = fetch_trusted_aps(conn)
    return {ap["bssid"].upper(): ap for ap in aps if int(ap.get("is_active", 1)) == 1}

def learn_trusted_aps_from_telemetry(
    conn: Optional[sqlite3.Connection] = None,
    limit_windows: int = 200
) -> int:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT top_sources_json, channel, epoch_ms FROM telemetry_windows "
            "WHERE top_sources_json != '[]' AND top_sources_json IS NOT NULL "
            "ORDER BY id DESC LIMIT ?;",
            (limit_windows,)
        )
        rows = cursor.fetchall()
        aps_to_learn = []
        for r in rows:
            raw_json = r["top_sources_json"]
            try:
                sources = json.loads(raw_json)
                if isinstance(sources, list):
                    for s in sources:
                        if isinstance(s, dict) and "bssid" in s:
                            aps_to_learn.append({
                                "bssid": s["bssid"],
                                "ssid": s.get("ssid", "Corporate-Protected-SSID"),
                                "channel": int(s.get("ch", s.get("channel", r["channel"] or 1))),
                                "epoch_ms": r["epoch_ms"]
                            })
            except Exception:
                pass
        return bulk_learn_trusted_aps(aps_to_learn, conn=conn)
    finally:
        if close_on_exit:
            conn.close()

def bulk_learn_trusted_aps(
    ap_list: List[Dict[str, Any]],
    conn: Optional[sqlite3.Connection] = None
) -> int:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        count = 0
        now_ms = int(time.time() * 1000)
        for ap in ap_list:
            bssid = ap.get("bssid", "").strip().upper()
            if not bssid:
                continue
            ssid = ap.get("ssid", "")
            channel = int(ap.get("channel", 1))
            first_seen = int(ap.get("first_seen_epoch", ap.get("epoch_ms", now_ms)))
            last_seen = int(ap.get("last_seen_epoch", ap.get("epoch_ms", now_ms)))

            cursor.execute(
                "INSERT INTO trusted_aps (bssid, ssid, channel, first_seen_epoch, last_seen_epoch, is_active) "
                "VALUES (?, ?, ?, ?, ?, 1) "
                "ON CONFLICT(bssid) DO UPDATE SET "
                "  ssid = excluded.ssid, "
                "  channel = excluded.channel, "
                "  last_seen_epoch = excluded.last_seen_epoch, "
                "  is_active = 1;",
                (bssid, ssid, channel, first_seen, last_seen)
            )
            count += 1
        conn.commit()
        return count
    finally:
        if close_on_exit:
            conn.close()

# ---------------------------------------------------------------------------
# Hardware Access Point Whitelist Operations
# ---------------------------------------------------------------------------

def insert_hardware_whitelist(
    conn_or_bssid: Any,
    bssid_or_ssid: Optional[str] = None,
    ssid_or_channel: Any = None,
    channel: int = 0,
    conn: Optional[sqlite3.Connection] = None
) -> bool:
    close_on_exit = False
    if isinstance(conn_or_bssid, sqlite3.Connection):
        actual_conn = conn_or_bssid
        actual_bssid = str(bssid_or_ssid or "")
        actual_ssid = str(ssid_or_channel or "")
        actual_channel = int(channel if channel is not None else 0)
    else:
        actual_conn = conn or get_connection()
        if conn is None:
            close_on_exit = True
        actual_bssid = str(conn_or_bssid or "")
        actual_ssid = str(bssid_or_ssid or "")
        actual_channel = int(ssid_or_channel if isinstance(ssid_or_channel, int) else channel)
    try:
        norm_bssid = actual_bssid.strip().upper()
        now_ms = int(time.time() * 1000)
        cursor = actual_conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO hardware_whitelist (bssid, ssid, channel, added_epoch_ms) VALUES (?, ?, ?, ?);",
            (norm_bssid, actual_ssid, actual_channel, now_ms)
        )
        actual_conn.commit()
        return True
    finally:
        if close_on_exit:
            actual_conn.close()

upsert_hardware_whitelist = insert_hardware_whitelist

def delete_hardware_whitelist(
    conn_or_bssid: Any = None,
    bssid: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> Any:
    """Deletes single entry or all if bssid is None."""
    close_on_exit = False
    if isinstance(conn_or_bssid, sqlite3.Connection):
        actual_conn = conn_or_bssid
        actual_bssid = bssid
    else:
        actual_conn = conn or get_connection()
        if conn is None:
            close_on_exit = True
        actual_bssid = conn_or_bssid
    try:
        cursor = actual_conn.cursor()
        if actual_bssid:
            norm_bssid = actual_bssid.strip().upper()
            cursor.execute("DELETE FROM hardware_whitelist WHERE bssid = ?;", (norm_bssid,))
            actual_conn.commit()
            return cursor.rowcount > 0
        else:
            cursor.execute("DELETE FROM hardware_whitelist;")
            actual_conn.commit()
            return cursor.rowcount
    finally:
        if close_on_exit:
            actual_conn.close()

def fetch_all_hardware_whitelist(
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT bssid, ssid, channel, added_epoch_ms "
            "FROM hardware_whitelist ORDER BY added_epoch_ms DESC;"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

fetch_hardware_whitelist = fetch_all_hardware_whitelist

def is_bssid_whitelisted(
    conn_or_bssid: Any,
    bssid: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> bool:
    close_on_exit = False
    if isinstance(conn_or_bssid, sqlite3.Connection):
        actual_conn = conn_or_bssid
        actual_bssid = bssid or ""
    else:
        actual_conn = conn or get_connection()
        if conn is None:
            close_on_exit = True
        actual_bssid = str(conn_or_bssid or "")
    try:
        norm_bssid = actual_bssid.strip().upper()
        cursor = actual_conn.cursor()
        cursor.execute(
            "SELECT 1 FROM hardware_whitelist WHERE bssid = ? LIMIT 1;",
            (norm_bssid,)
        )
        return cursor.fetchone() is not None
    finally:
        if close_on_exit:
            actual_conn.close()

# ---------------------------------------------------------------------------
# Incident Workflow, Forensic Attribution, & Analyst Feedback Operations
# ---------------------------------------------------------------------------

def insert_incident(
    incident_dict_or_conn: Any = None,
    *args,
    **kwargs
) -> str:
    """Inserts an incident record with forensic attribution, tool signature, and proximity zones."""
    close_on_exit = False
    conn = None
    incident_dict: Dict[str, Any] = {}

    if isinstance(incident_dict_or_conn, sqlite3.Connection):
        conn = incident_dict_or_conn
        if args and isinstance(args[0], dict):
            incident_dict = args[0]
        elif "incident_dict" in kwargs and isinstance(kwargs["incident_dict"], dict):
            incident_dict = kwargs["incident_dict"]
        else:
            incident_dict = kwargs
    elif isinstance(incident_dict_or_conn, dict):
        incident_dict = dict(incident_dict_or_conn)
        if kwargs:
            incident_dict.update(kwargs)
        conn = kwargs.get("conn") or (args[0] if args else None)
    elif incident_dict_or_conn is None:
        conn = kwargs.pop("conn", None)
        if "incident_dict" in kwargs and isinstance(kwargs["incident_dict"], dict):
            incident_dict = kwargs["incident_dict"]
        else:
            incident_dict = kwargs
    else:
        raise ValueError("incident_dict must be a dictionary or sqlite3.Connection")

    if conn is None:
        conn = get_connection()
        close_on_exit = True

    try:
        now_ms = int(time.time() * 1000)
        inc_id = str(
            incident_dict.get("id")
            or incident_dict.get("incident_id")
            or f"INC-{time.strftime('%Y%m%d', time.gmtime(now_ms / 1000))}-{now_ms % 100000:05d}"
        )
        start_window = int(incident_dict.get("start_window", incident_dict.get("window_id", 0)))
        last_window = int(incident_dict.get("last_window", start_window))
        start_epoch_ms = int(incident_dict.get("start_epoch_ms", now_ms))
        last_epoch_ms = int(incident_dict.get("last_epoch_ms", incident_dict.get("end_epoch_ms", start_epoch_ms)))
        title = str(incident_dict.get("title") or incident_dict.get("summary") or "Wireless Security Incident")
        primary_type = str(incident_dict.get("primary_type") or incident_dict.get("event_type") or "ANOMALY")
        severity = str(incident_dict.get("severity", "MEDIUM")).upper()
        confidence = float(incident_dict.get("confidence", 0.9))
        status = str(incident_dict.get("status", "OPEN")).upper()
        event_count = int(incident_dict.get("event_count", 1))

        signals = incident_dict.get("signals_involved_json", incident_dict.get("associated_event_ids_json", "[]"))
        if isinstance(signals, (list, dict)):
            signals_involved_json = json.dumps(signals)
        else:
            signals_involved_json = str(signals)

        target_bssid = incident_dict.get("target_bssid")
        if target_bssid is not None:
            target_bssid = str(target_bssid).strip().upper()
        analyst_notes = str(incident_dict.get("analyst_notes", ""))

        attacker_mac = str(incident_dict.get("attacker_mac", "")).strip().upper()
        target_mac = str(incident_dict.get("target_mac", "")).strip().upper()
        attacker_rssi = int(incident_dict.get("attacker_rssi", 0))
        tool_signature = str(incident_dict.get("tool_signature", "UNKNOWN"))
        deauth_reason = int(incident_dict.get("deauth_reason", 0))
        proximity_zone = str(incident_dict.get("proximity_zone", "NONE"))
        raw_injection_count = int(incident_dict.get("raw_injection_count", 0))
        is_laa_randomized = int(incident_dict.get("is_laa_randomized", 0))
        hardware_profile = str(incident_dict.get("hardware_profile") or "UNKNOWN")
        remediation_advisory = str(incident_dict.get("remediation_advisory") or "")
        remediation_steps_raw = incident_dict.get("remediation_steps", "[]")
        if isinstance(remediation_steps_raw, (list, dict)):
            remediation_steps = json.dumps(remediation_steps_raw)
        else:
            remediation_steps = str(remediation_steps_raw or "[]")
        updated_at = int(incident_dict.get("updated_at") or last_epoch_ms or now_ms)

        mitre_technique_id = str(incident_dict.get("mitre_technique_id") or incident_dict.get("technique_id") or "T1200")
        mitre_technique_name = str(incident_dict.get("mitre_technique_name") or incident_dict.get("technique_name") or "")
        mitre_tactic = str(incident_dict.get("mitre_tactic") or incident_dict.get("tactic") or "")
        evidence_hash = str(incident_dict.get("evidence_hash") or "")
        if not evidence_hash:
            payload = signals_involved_json if signals_involved_json else json.dumps({"incident_id": inc_id, "start_epoch_ms": start_epoch_ms})
            evidence_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if (not is_laa_randomized or hardware_profile == "UNKNOWN") and attacker_mac and len(attacker_mac) >= 8:
            try:
                from .incident_manager import is_mac_randomized, identify_hardware_profile
                if not is_laa_randomized and is_mac_randomized(attacker_mac):
                    is_laa_randomized = 1
                if hardware_profile == "UNKNOWN":
                    hardware_profile = identify_hardware_profile(attacker_mac)
            except Exception:
                pass

        if not remediation_advisory:
            try:
                from .incident_manager import generate_remediation_advisory
                remediation_advisory = generate_remediation_advisory(primary_type, deauth_reason, bool(deauth_reason in (2, 6, 7)))
            except Exception:
                pass

        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO incidents ("
            "  id, start_window, last_window, start_epoch_ms, last_epoch_ms, "
            "  title, primary_type, severity, confidence, status, event_count, signals_involved_json, "
            "  incident_id, end_epoch_ms, summary, event_type, associated_event_ids_json, "
            "  target_bssid, analyst_notes, "
            "  attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "  raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "  mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, "
            "  remediation_steps, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                inc_id, start_window, last_window, start_epoch_ms, last_epoch_ms,
                title, primary_type, severity, confidence, status, event_count, signals_involved_json,
                inc_id, last_epoch_ms, title, primary_type, signals_involved_json,
                target_bssid, analyst_notes,
                attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone,
                raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory,
                mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash,
                remediation_steps, updated_at
            )
        )

        cursor.execute(
            "INSERT INTO incident_timeline (incident_id, epoch_ms, entry_type, detail) "
            "VALUES (?, ?, 'ALERT_TRIGGERED', ?);",
            (inc_id, start_epoch_ms, title)
        )

        conn.commit()
        return inc_id
    finally:
        if close_on_exit:
            conn.close()

def insert_incident_record(
    incident_dict: Dict[str, Any],
    conn: Optional[sqlite3.Connection] = None
) -> str:
    return insert_incident(incident_dict=incident_dict, conn=conn)

def create_incident(
    incident_dict: Dict[str, Any],
    conn: Optional[sqlite3.Connection] = None
) -> str:
    return insert_incident(incident_dict=incident_dict, conn=conn)

def update_incident(
    incident_id_or_dict: Any,
    updates: Optional[Dict[str, Any]] = None,
    conn: Optional[sqlite3.Connection] = None,
    **kwargs
) -> bool:
    """Updates an incident record persisting forensic attribution, tool signature, and status."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        incident_id = ""
        merged_updates: Dict[str, Any] = {}
        if isinstance(incident_id_or_dict, dict):
            incident_id = str(incident_id_or_dict.get("incident_id") or incident_id_or_dict.get("id") or "")
            merged_updates.update(incident_id_or_dict)
        elif isinstance(incident_id_or_dict, str):
            incident_id = incident_id_or_dict

        if updates:
            merged_updates.update(updates)
        if kwargs:
            merged_updates.update(kwargs)

        if not incident_id and "incident_id" in merged_updates:
            incident_id = str(merged_updates["incident_id"])
        if not incident_id and "id" in merged_updates:
            incident_id = str(merged_updates["id"])

        if not incident_id:
            return False

        allowed_fields = {
            "status", "severity", "confidence", "title", "summary", "primary_type",
            "event_type", "event_count", "end_epoch_ms", "last_epoch_ms", "last_window",
            "target_bssid", "analyst_notes", "attacker_mac", "target_mac", "attacker_rssi",
            "tool_signature", "deauth_reason", "proximity_zone", "associated_event_ids_json",
            "signals_involved_json", "raw_injection_count", "is_laa_randomized",
            "hardware_profile", "remediation_advisory",
            "mitre_technique_id", "mitre_technique_name", "mitre_tactic", "evidence_hash",
            "remediation_steps", "updated_at"
        }

        set_clauses: List[str] = []
        params: List[Any] = []
        for k, v in merged_updates.items():
            if k in allowed_fields:
                if k in ("associated_event_ids_json", "signals_involved_json", "remediation_steps") and isinstance(v, (list, dict)):
                    v = json.dumps(v)
                if k in ("attacker_mac", "target_mac", "target_bssid") and v is not None:
                    v = str(v).strip().upper()
                set_clauses.append(f"{k} = ?")
                params.append(v)

        if not set_clauses:
            return False

        params.extend([incident_id, incident_id])
        query = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE incident_id = ? OR id = ?;"
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        rowcount = cursor.rowcount
        conn.commit()
        return rowcount > 0
    finally:
        if close_on_exit:
            conn.close()

def update_incident_status(
    incident_id: str,
    new_status: str,
    note: str,
    epoch_ms: int,
    conn: Optional[sqlite3.Connection] = None
) -> bool:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT incident_id, analyst_notes FROM incidents WHERE incident_id = ? OR id = ?;",
            (incident_id, incident_id)
        )
        row = cursor.fetchone()
        if not row:
            return False

        clean_status = new_status.strip().upper()
        clean_note = note.strip()

        cursor.execute(
            "UPDATE incidents "
            "SET status = ?, "
            "    end_epoch_ms = MAX(end_epoch_ms, ?), "
            "    last_epoch_ms = MAX(last_epoch_ms, ?), "
            "    analyst_notes = CASE "
            "      WHEN ? = '' THEN analyst_notes "
            "      WHEN analyst_notes = '' OR analyst_notes IS NULL THEN ? "
            "      ELSE analyst_notes || CHAR(10) || ? "
            "    END "
            "WHERE incident_id = ? OR id = ?;",
            (clean_status, epoch_ms, epoch_ms, clean_note, clean_note, clean_note, incident_id, incident_id)
        )

        cursor.execute(
            "INSERT INTO incident_timeline (incident_id, epoch_ms, entry_type, detail) "
            "VALUES (?, ?, 'STATUS_CHANGE', ?);",
            (incident_id, epoch_ms, f"Status changed to {clean_status}")
        )

        if clean_note:
            cursor.execute(
                "INSERT INTO incident_timeline (incident_id, epoch_ms, entry_type, detail) "
                "VALUES (?, ?, 'ANALYST_NOTE', ?);",
                (incident_id, epoch_ms, clean_note)
            )

        conn.commit()
        return True
    finally:
        if close_on_exit:
            conn.close()

def batch_update_incident_status(
    from_status: str,
    to_status: str,
    note: str = "",
    conn: Optional[sqlite3.Connection] = None
) -> int:
    """Batch updates incident status and appends analyst notes."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE incidents SET status = ?, analyst_notes = analyst_notes || ? WHERE status = ?;",
            (to_status.strip().upper(), note, from_status.strip().upper())
        )
        conn.commit()
        return cursor.rowcount
    finally:
        if close_on_exit:
            conn.close()

def update_incident_remediation(
    conn: Optional[sqlite3.Connection] = None,
    incident_id: Any = None,
    completed_steps: Optional[List[int]] = None
) -> bool:
    """Updates the completed remediation checklist steps for a target incident."""
    if isinstance(incident_id, sqlite3.Connection) and not isinstance(conn, sqlite3.Connection):
        conn, incident_id = incident_id, conn
    if completed_steps is None:
        completed_steps = []

    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        ensure_incident_remediation_column(conn)
        now_ms = int(time.time() * 1000)
        steps_json = json.dumps(completed_steps)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE incidents SET remediation_steps = ?, updated_at = ? "
            "WHERE id = ? OR incident_id = ? OR rowid = ?;",
            (steps_json, now_ms, str(incident_id), str(incident_id), str(incident_id))
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        if close_on_exit:
            conn.close()

def aggregate_alert_to_incident(
    incident_id: str,
    event_id: str,
    epoch_ms: int,
    severity: str,
    summary_detail: str,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT incident_id, severity, associated_event_ids_json, signals_involved_json FROM incidents WHERE incident_id = ? OR id = ?;",
            (incident_id, incident_id)
        )
        row = cursor.fetchone()
        if not row:
            return

        current_events = []
        try:
            current_events = json.loads(row["associated_event_ids_json"])
        except Exception:
            current_events = []

        if event_id not in current_events:
            current_events.append(event_id)

        sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        current_sev = str(row["severity"]).upper()
        new_sev = severity.upper()
        final_sev = current_sev if sev_order.get(current_sev, 1) >= sev_order.get(new_sev, 1) else new_sev

        cursor.execute(
            "UPDATE incidents "
            "SET end_epoch_ms = MAX(end_epoch_ms, ?), "
            "    last_epoch_ms = MAX(last_epoch_ms, ?), "
            "    event_count = event_count + 1, "
            "    severity = ?, "
            "    associated_event_ids_json = ?, "
            "    signals_involved_json = ? "
            "WHERE incident_id = ? OR id = ?;",
            (epoch_ms, epoch_ms, final_sev, json.dumps(current_events), json.dumps(current_events), incident_id, incident_id)
        )

        cursor.execute(
            "INSERT INTO incident_timeline (incident_id, epoch_ms, entry_type, detail) "
            "VALUES (?, ?, 'ALERT_AGGREGATED', ?);",
            (incident_id, epoch_ms, summary_detail)
        )

        conn.commit()
    finally:
        if close_on_exit:
            conn.close()

def fetch_incidents(
    conn: Optional[sqlite3.Connection] = None,
    limit: int = 50,
    status: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches incident records with explicit column projection including forensic attribution."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        if status:
            cursor.execute(
                "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
                "       start_window, last_window, event_type, primary_type, severity, "
                "       confidence, status, event_count, associated_event_ids_json, "
                "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
                "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
                "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, remediation_steps, updated_at "
                "FROM incidents WHERE status = ? ORDER BY start_epoch_ms DESC LIMIT ?;",
                (status.upper(), limit)
            )
        else:
            cursor.execute(
                "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
                "       start_window, last_window, event_type, primary_type, severity, "
                "       confidence, status, event_count, associated_event_ids_json, "
                "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
                "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
                "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, remediation_steps, updated_at "
                "FROM incidents ORDER BY start_epoch_ms DESC LIMIT ?;",
                (limit,)
            )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def fetch_incident_by_id(
    incident_id: str,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[Dict[str, Any]]:
    """Fetches a specific incident by ID with explicit column projection including forensic attribution."""
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
            "       start_window, last_window, event_type, primary_type, severity, "
            "       confidence, status, event_count, associated_event_ids_json, "
            "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
            "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, remediation_steps, updated_at "
            "FROM incidents WHERE incident_id = ? OR id = ? LIMIT 1;",
            (incident_id, incident_id)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        if close_on_exit:
            conn.close()

def fetch_active_incidents(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
            "       start_window, last_window, event_type, primary_type, severity, "
            "       confidence, status, event_count, associated_event_ids_json, "
            "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
            "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, remediation_steps, updated_at "
            "FROM incidents "
            "WHERE status IN ('OPEN', 'ACKNOWLEDGED') "
            "ORDER BY start_epoch_ms DESC;"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def fetch_incident_with_timeline(
    incident_id: str,
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
            "       start_window, last_window, event_type, primary_type, severity, "
            "       confidence, status, event_count, associated_event_ids_json, "
            "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
            "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash, remediation_steps, updated_at "
            "FROM incidents WHERE incident_id = ? OR id = ? LIMIT 1;",
            (incident_id, incident_id)
        )
        row = cursor.fetchone()
        if not row:
            return {}

        incident_dict = dict(row)
        cursor.execute(
            "SELECT id, incident_id, epoch_ms, entry_type, detail "
            "FROM incident_timeline WHERE incident_id = ? ORDER BY epoch_ms ASC;",
            (incident_dict["incident_id"],)
        )
        incident_dict["timeline"] = [dict(t) for t in cursor.fetchall()]
        return incident_dict
    finally:
        if close_on_exit:
            conn.close()

def fetch_false_positive_stats(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(incident_id) AS total_incidents, "
            "       SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS false_positive_count, "
            "       SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_count, "
            "       SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) AS open_count, "
            "       SUM(CASE WHEN status = 'ACKNOWLEDGED' THEN 1 ELSE 0 END) AS acknowledged_count "
            "FROM incidents;"
        )
        summary_row = cursor.fetchone()

        total = int(summary_row["total_incidents"] or 0)
        fp_count = int(summary_row["false_positive_count"] or 0)
        fp_rate = round(fp_count / total, 4) if total > 0 else 0.0

        cursor.execute(
            "SELECT event_type, "
            "       COUNT(incident_id) AS total, "
            "       SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS fp_count "
            "FROM incidents "
            "GROUP BY event_type ORDER BY total DESC;"
        )
        by_event = [
            {
                "event_type": row["event_type"],
                "total": int(row["total"] or 0),
                "false_positives": int(row["fp_count"] or 0),
                "false_positive_rate": round(int(row["fp_count"] or 0) / int(row["total"] or 1), 4)
            }
            for row in cursor.fetchall()
        ]

        return {
            "total_incidents": total,
            "false_positive_count": fp_count,
            "false_positive_rate": fp_rate,
            "open_count": int(summary_row["open_count"] or 0),
            "acknowledged_count": int(summary_row["acknowledged_count"] or 0),
            "resolved_count": int(summary_row["resolved_count"] or 0),
            "by_event_type": by_event
        }
    finally:
        if close_on_exit:
            conn.close()

# ---------------------------------------------------------------------------
# Query Functions for Streaming LLM Assistant
# ---------------------------------------------------------------------------

def db_get_alerts(
    time_range_seconds: int = 3600,
    alert_type: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cutoff_epoch_ms = int(time.time() * 1000) - (time_range_seconds * 1000)
        cursor = conn.cursor()
        if alert_type:
            cursor.execute(
                "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
                "       confidence, signals_correlated, data_source, evidence_json, explanation, "
                "       mitre_technique, owasp_category, suggested_action, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
                "FROM alert_events "
                "WHERE epoch_ms >= ? AND (type_key = ? OR event_type LIKE ?) "
                "ORDER BY epoch_ms DESC;",
                (cutoff_epoch_ms, alert_type, f"%{alert_type}%")
            )
        else:
            cursor.execute(
                "SELECT id, event_id, window_id, epoch_ms, type_key, event_type, severity, "
                "       confidence, signals_correlated, data_source, evidence_json, explanation, "
                "       mitre_technique, owasp_category, suggested_action, "
                "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
                "FROM alert_events "
                "WHERE epoch_ms >= ? "
                "ORDER BY epoch_ms DESC;",
                (cutoff_epoch_ms,)
            )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def db_get_window(
    window_id: int,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            "       rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            "       ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            "       ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            "       z_deauth, z_mgmt, z_ble, z_rogue, "
            "       unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            "       attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            "FROM telemetry_windows "
            "WHERE window_id = ?;",
            (window_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        if close_on_exit:
            conn.close()

def db_compare_detectors(
    limit: int = 50,
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT window_id, flag_fixed, flag_adaptive, flag_nexus, is_attack_labelled "
            "FROM telemetry_windows ORDER BY window_id DESC LIMIT ?;",
            (limit,)
        )
        rows = cursor.fetchall()
        total_eval = len(rows)

        fixed_count = 0
        adaptive_count = 0
        nexus_count = 0
        overlap_fixed_nexus = 0
        overlap_adaptive_nexus = 0
        overlap_all_three = 0

        for r in rows:
            ff = int(r["flag_fixed"])
            fa = int(r["flag_adaptive"])
            fn = int(r["flag_nexus"])

            fixed_count += ff
            adaptive_count += fa
            nexus_count += fn

            if ff and fn:
                overlap_fixed_nexus += 1
            if fa and fn:
                overlap_adaptive_nexus += 1
            if ff and fa and fn:
                overlap_all_three += 1

        suppression_rate = (
            round((adaptive_count - nexus_count) / adaptive_count, 4)
            if adaptive_count > 0 else 0.0
        )
        agreement_fixed_nexus = (
            round(overlap_fixed_nexus / fixed_count, 4)
            if fixed_count > 0 else 1.0
        )

        return {
            "windows_evaluated": total_eval,
            "counts": {
                "fixed_detector": fixed_count,
                "adaptive_detector": adaptive_count,
                "nexus_detector": nexus_count
            },
            "overlaps": {
                "fixed_and_nexus": overlap_fixed_nexus,
                "adaptive_and_nexus": overlap_adaptive_nexus,
                "all_three": overlap_all_three
            },
            "noise_suppression_rate_vs_adaptive": suppression_rate,
            "agreement_fixed_nexus_rate": agreement_fixed_nexus
        }
    finally:
        if close_on_exit:
            conn.close()

def db_get_baseline(
    feature: str,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT feature_name, mean, variance, std_dev, updated_epoch_ms "
            "FROM baseline_metrics WHERE feature_name = ?;",
            (feature,)
        )
        metric_row = cursor.fetchone()
        if not metric_row:
            return None

        cursor.execute(
            "SELECT id, alpha, z_threshold, warmup_windows, processed_windows, updated_epoch_ms "
            "FROM baseline_state WHERE id = 1;"
        )
        state_row = cursor.fetchone()

        result = dict(metric_row)
        if state_row:
            result["alpha"] = state_row["alpha"]
            result["z_threshold"] = state_row["z_threshold"]
            result["warmup_windows"] = state_row["warmup_windows"]
            result["processed_windows"] = state_row["processed_windows"]

        return result
    finally:
        if close_on_exit:
            conn.close()

def db_link_health(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT error_key, total_count, last_epoch_ms FROM serial_error_counters ORDER BY error_key ASC;"
        )
        counters = [dict(r) for r in cursor.fetchall()]
        counter_map = {c["error_key"]: c["total_count"] for c in counters}

        cursor.execute(
            "SELECT window_id, epoch_ms FROM telemetry_windows ORDER BY window_id DESC LIMIT 20;"
        )
        recent_windows = [dict(r) for r in cursor.fetchall()]

        continuity_gaps = 0
        missing_windows = 0
        if len(recent_windows) > 1:
            sorted_wins = sorted(recent_windows, key=lambda w: w["window_id"])
            for i in range(len(sorted_wins) - 1):
                diff = sorted_wins[i + 1]["window_id"] - sorted_wins[i]["window_id"]
                if diff > 1:
                    continuity_gaps += 1
                    missing_windows += (diff - 1)

        dropped_frames = counter_map.get("MALFORMED_FRAME_DROP", 0)
        json_parse_errors = counter_map.get("JSON_PARSE_ERROR", 0)
        buffer_overflows = counter_map.get("RX_BUFFER_OVERFLOW", 0)

        is_healthy = (continuity_gaps == 0) and (buffer_overflows == 0)

        return {
            "status": "HEALTHY" if is_healthy else "DEGRADED",
            "counters": counter_map,
            "dropped_frames": dropped_frames,
            "json_parse_errors": json_parse_errors,
            "rx_buffer_overflows": buffer_overflows,
            "recent_windows_inspected": len(recent_windows),
            "continuity_gaps_detected": continuity_gaps,
            "missing_windows_estimate": missing_windows,
            "last_window_id": recent_windows[0]["window_id"] if recent_windows else 0,
            "last_seen_epoch_ms": recent_windows[0]["epoch_ms"] if recent_windows else 0
        }
    finally:
        if close_on_exit:
            conn.close()

def db_get_incident_summary(
    incident_id: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        if incident_id:
            return fetch_incident_with_timeline(incident_id, conn)

        cursor.execute(
            "SELECT id, incident_id, start_epoch_ms, end_epoch_ms, last_epoch_ms, "
            "       start_window, last_window, event_type, primary_type, severity, "
            "       confidence, status, event_count, associated_event_ids_json, "
            "       signals_involved_json, target_bssid, summary, title, analyst_notes, "
            "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
            "FROM incidents ORDER BY start_epoch_ms DESC LIMIT 5;"
        )
        recent_incidents = [dict(r) for r in cursor.fetchall()]
        if recent_incidents:
            latest = recent_incidents[0]
            latest_id = latest["incident_id"]
            cursor.execute(
                "SELECT id, incident_id, epoch_ms, entry_type, detail "
                "FROM incident_timeline WHERE incident_id = ? ORDER BY epoch_ms ASC;",
                (latest_id,)
            )
            latest["timeline"] = [dict(t) for t in cursor.fetchall()]
            return {
                "latest_incident": latest,
                "recent_incidents": recent_incidents
            }
        return {"latest_incident": None, "recent_incidents": []}
    finally:
        if close_on_exit:
            conn.close()

def query_recent_incidents(
    limit: int = 5,
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, incident_id, title, primary_type, severity, confidence, status, "
            "       start_epoch_ms, end_epoch_ms, event_count, "
            "       attacker_mac, target_mac, attacker_rssi, tool_signature, deauth_reason, proximity_zone, "
            "       raw_injection_count, is_laa_randomized, hardware_profile, remediation_advisory, "
            "       mitre_technique_id, mitre_technique_name, mitre_tactic, evidence_hash "
            "FROM incidents ORDER BY start_epoch_ms DESC LIMIT ?;",
            (limit,)
        )
        return [dict(r) for r in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

# ---------------------------------------------------------------------------
# Data Retention Pruning, Diurnal Baseline, and Evaluation Cache Operations
# ---------------------------------------------------------------------------

def prune_historical_telemetry(
    retention_hours: int = 48,
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        now_ms = int(time.time() * 1000)
        cutoff_epoch_ms = now_ms - (int(retention_hours) * 3600 * 1000)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM telemetry_windows "
            "WHERE epoch_ms < ? "
            "  AND is_attack_labelled = 0 "
            "  AND flag_fixed = 0 "
            "  AND flag_adaptive = 0 "
            "  AND flag_nexus = 0 "
            "  AND window_id NOT IN (SELECT window_id FROM alert_events WHERE window_id IS NOT NULL);",
            (cutoff_epoch_ms,)
        )
        deleted_count = cursor.rowcount

        deleted_frames = 0
        try:
            cursor.execute("DELETE FROM raw_frames WHERE epoch_ms < ?;", (cutoff_epoch_ms,))
            deleted_frames = cursor.rowcount
        except sqlite3.OperationalError:
            pass

        conn.commit()

        cursor.execute("SELECT COUNT(id) AS remaining_count FROM telemetry_windows;")
        rem_row = cursor.fetchone()
        remaining = int(rem_row["remaining_count"]) if rem_row else 0

        return {
            "retention_hours": retention_hours,
            "cutoff_epoch_ms": cutoff_epoch_ms,
            "deleted_windows": deleted_count,
            "deleted_frames": deleted_frames,
            "remaining_windows": remaining
        }
    finally:
        if close_on_exit:
            conn.close()

def prune_old_windows(
    cutoff_epoch_ms: int,
    conn: Optional[sqlite3.Connection] = None
) -> int:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM telemetry_windows "
            "WHERE epoch_ms < ? "
            "  AND is_attack_labelled = 0 "
            "  AND window_id NOT IN (SELECT window_id FROM alert_events WHERE window_id IS NOT NULL);",
            (cutoff_epoch_ms,)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        if close_on_exit:
            conn.close()

def fetch_hourly_baseline(
    feature_name: str,
    hour_of_day: int,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT feature_name, hour_of_day, mean, variance, sample_count "
            "FROM baseline_hourly WHERE feature_name = ? AND hour_of_day = ?;",
            (feature_name, hour_of_day)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        if close_on_exit:
            conn.close()

def save_hourly_baseline(
    feature_name: str,
    hour_of_day: int,
    mean: float,
    variance: float,
    count: int,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO baseline_hourly (feature_name, hour_of_day, mean, variance, sample_count) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(feature_name, hour_of_day) DO UPDATE SET "
            "  mean = excluded.mean, "
            "  variance = excluded.variance, "
            "  sample_count = excluded.sample_count;",
            (feature_name, hour_of_day, mean, variance, count)
        )
        conn.commit()
    finally:
        if close_on_exit:
            conn.close()

def fetch_evaluation_windows(
    data_source: Optional[str] = None,
    only_labelled: bool = False,
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        conditions: List[str] = []
        params: List[Any] = []

        if data_source:
            conditions.append("data_source = ?")
            params.append(data_source)
        if only_labelled:
            conditions.append("is_attack_labelled = 1")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = (
            f"SELECT id, window_id, epoch_ms, data_source, deauth_count, mgmt_count, ble_count, rogue_count, nfc_count, "
            f"       rssi_mean, is_attack_labelled, flag_fixed, flag_adaptive, flag_nexus, "
            f"       ewma_deauth_mean, ewma_deauth_var, ewma_mgmt_mean, ewma_mgmt_var, "
            f"       ewma_ble_mean, ewma_ble_var, ewma_rogue_mean, ewma_rogue_var, "
            f"       z_deauth, z_mgmt, z_ble, z_rogue, "
            f"       unique_bssids, top_sources_json, channel, rssi_min, rssi_max, "
            f"       attacker_mac, target_mac, attacker_rssi, deauth_reason, proximity_zone, "
            f"       raw_injection_count, is_laa_randomized, hardware_profile, created_at "
            f"FROM telemetry_windows {where_clause} ORDER BY window_id ASC;"
        )
        cursor.execute(query, tuple(params))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        if close_on_exit:
            conn.close()

def get_evaluation_cache(
    cache_key: str,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[Dict[str, Any]]:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cache_key, data_json, generated_epoch_ms "
            "FROM evaluation_cache WHERE cache_key = ?;",
            (cache_key,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "cache_key": row["cache_key"],
            "data": json.loads(row["data_json"]),
            "generated_epoch_ms": row["generated_epoch_ms"]
        }
    finally:
        if close_on_exit:
            conn.close()

def set_evaluation_cache(
    cache_key: str,
    data_json: str,
    generated_epoch_ms: int,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    close_on_exit = False
    if conn is None:
        conn = get_connection()
        close_on_exit = True
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO evaluation_cache (cache_key, data_json, generated_epoch_ms) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(cache_key) DO UPDATE SET "
            "  data_json = excluded.data_json, "
            "  generated_epoch_ms = excluded.generated_epoch_ms;",
            (cache_key, data_json, generated_epoch_ms)
        )
        conn.commit()
    finally:
        if close_on_exit:
            conn.close()
