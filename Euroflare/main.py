
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
from typing import Optional
from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
import numpy as np
import joblib
import sqlite3
import logging
import io
import os
import json
from datetime import datetime
from collections import defaultdict

class IQRCapper(BaseEstimator, TransformerMixin):
    def __init__(self, factor=1.5):
        self.factor = factor

    def fit(self, X, y=None):
        X_df        = pd.DataFrame(X)
        Q1          = X_df.quantile(0.25)
        Q3          = X_df.quantile(0.75)
        IQR         = Q3 - Q1
        self.lower_ = Q1 - self.factor * IQR
        self.upper_ = Q3 + self.factor * IQR
        return self

    def transform(self, X, y=None):
        return pd.DataFrame(X).clip(
            lower=self.lower_.values,
            upper=self.upper_.values,
            axis=1
        ).values

MODEL_DIR         = os.getenv("MODEL_DIR", "./models")
DEFAULT_THRESHOLD = 0.35
DB_PATH           = os.getenv("DB_PATH", "./ids_history.db")
LOG_PATH          = os.getenv("LOG_PATH", "./ids.log")

SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
    "Packet Length Mean",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Flow IAT Mean",
    "Flow IAT Std",
]

SEVERITY = {
    "BENIGN":                    "INFO",
    "Bot":                       "HIGH",
    "DDoS":                      "CRITICAL",
    "DoS GoldenEye":             "HIGH",
    "DoS Hulk":                  "HIGH",
    "DoS Slowhttptest":          "MEDIUM",
    "DoS slowloris":             "MEDIUM",
    "FTP-Patator":               "HIGH",
    "Heartbleed":                "CRITICAL",
    "Infiltration":              "CRITICAL",
    "PortScan":                  "MEDIUM",
    "SSH-Patator":               "HIGH",
    "Web Attack - Brute Force":  "HIGH",
    "Web Attack - Sql Injection":"CRITICAL",
    "Web Attack - XSS":          "HIGH",
}

ACTIONS = {
    "BENIGN":                    "Aucune action requise.",
    "Bot":                       "Isoler la machine source. Analyser les connexions sortantes.",
    "DDoS":                      "Activer la limitation de debit. Contacter le FAI. Mitigation DDoS.",
    "DoS GoldenEye":             "Bloquer l'IP source. Verifier la disponibilite des services web.",
    "DoS Hulk":                  "Bloquer l'IP source. Augmenter la capacite si possible.",
    "DoS Slowhttptest":          "Configurer les timeouts HTTP. Bloquer l'IP source.",
    "DoS slowloris":             "Limiter les connexions simultanees par IP. Bloquer la source.",
    "FTP-Patator":               "Bloquer l'IP source. Verifier les comptes FTP. Activer le 2FA.",
    "Heartbleed":                "URGENCE : Patcher OpenSSL immediatement. Revoquer les certificats.",
    "Infiltration":              "URGENCE : Isoler le reseau. Audit de securite complet.",
    "PortScan":                  "Surveiller l'IP source. Verifier les ports ouverts exposes.",
    "SSH-Patator":               "Bloquer l'IP source. Verifier les comptes SSH. Activer le 2FA.",
    "Web Attack - Brute Force":  "Bloquer l'IP source. Activer le CAPTCHA. Limiter les tentatives.",
    "Web Attack - Sql Injection":"Bloquer l'IP source. Verifier les requetes SQL. Audit du code.",
    "Web Attack - XSS":          "Bloquer l'IP source. Verifier les entrees utilisateur.",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("IDS")

import threading
_db_local = threading.local()

def get_db():
    if not hasattr(_db_local, "conn") or _db_local.conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA cache_size=-64000")
        conn.row_factory = sqlite3.Row
        _db_local.conn = conn
    return _db_local.conn

def close_db():
    if hasattr(_db_local, "conn") and _db_local.conn:
        try: _db_local.conn.close()
        except: pass
        _db_local.conn = None

def db_execute(query, params=(), fetch=None, commit=False):
    import time as _time
    for attempt in range(5):
        try:
            conn = get_db()
            cur  = conn.cursor()
            cur.execute(query, params)
            if commit:
                conn.commit()
            if fetch == "one":  return cur.fetchone()
            if fetch == "all":  return cur.fetchall()
            return cur
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < 4:
                _time.sleep(0.05 * (attempt + 1))
                close_db()
                continue
            logger.error(f"SQLite error ({attempt+1}/5): {e}")
            raise
    return None

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            is_attack   INTEGER NOT NULL,
            attack_type TEXT NOT NULL,
            severity    TEXT NOT NULL,
            confidence  REAL NOT NULL,
            threshold   REAL NOT NULL,
            blocked     INTEGER NOT NULL,
            source_ip   TEXT,
            dest_ip     TEXT,
            protocol    TEXT,
            action      TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            key   TEXT PRIMARY KEY,
            value INTEGER DEFAULT 0
        )
    """)
    for key in ["total_analyzed", "total_attacks", "total_blocked"]:
        c.execute("INSERT OR IGNORE INTO stats (key, value) VALUES (?, 0)", (key,))

    c.execute("""
        CREATE TABLE IF NOT EXISTS attacker_ips (
            ip           TEXT PRIMARY KEY,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            attack_count INTEGER DEFAULT 1,
            attack_types TEXT,
            max_severity TEXT DEFAULT 'INFO',
            blacklisted  INTEGER DEFAULT 0,
            blacklisted_at TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Base de donnees SQLite initialisee : {DB_PATH}")

def db_upsert_attacker_ip(result: dict):
    ip = result.get("source_ip")
    if not ip or not result.get("is_attack"):
        return
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        c    = conn.cursor()
        now  = result.get("timestamp", datetime.now().isoformat())
        atype= result.get("attack_type","UNKNOWN")
        sev  = result.get("severity","INFO")
        sev_order = {"INFO":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}

        existing = c.execute(
            "SELECT attack_count, attack_types, max_severity FROM attacker_ips WHERE ip=?", (ip,)
        ).fetchone()

        if existing:
            count     = existing[0] + 1
            types_set = set(existing[1].split(",")) if existing[1] else set()
            types_set.add(atype)
            cur_sev   = existing[2]
            new_sev   = sev if sev_order.get(sev,0) > sev_order.get(cur_sev,0) else cur_sev
            c.execute("""
                UPDATE attacker_ips
                SET last_seen=?, attack_count=?, attack_types=?, max_severity=?
                WHERE ip=?
            """, (now, count, ",".join(types_set), new_sev, ip))
        else:
            c.execute("""
                INSERT INTO attacker_ips
                (ip, first_seen, last_seen, attack_count, attack_types, max_severity)
                VALUES (?,?,?,1,?,?)
            """, (ip, now, now, atype, sev))

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Erreur upsert attacker_ip : {e}")

import queue as _queue
_insert_queue = _queue.Queue()
_batch_lock   = threading.Lock()

def db_insert_alert(result: dict):
    _insert_queue.put(result)

def _flush_insert_queue():
    if _insert_queue.empty():
        return
    items = []
    try:
        while True:
            items.append(_insert_queue.get_nowait())
    except _queue.Empty:
        pass
    if not items:
        return
    import time as _time
    for attempt in range(5):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            cur  = conn.cursor()
            n_attacks = 0
            for result in items:
                cur.execute("""
                    INSERT INTO alerts
                    (timestamp, is_attack, attack_type, severity, confidence,
                     threshold, blocked, source_ip, dest_ip, protocol, action)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    result["timestamp"], int(result["is_attack"]),
                    result["attack_type"], result["severity"],
                    result["confidence"], result["threshold_used"],
                    int(result["blocked"]),
                    result.get("source_ip"), result.get("dest_ip"),
                    result.get("protocol"), result["action"],
                ))
                if result["is_attack"]:
                    n_attacks += 1
            cur.execute("UPDATE stats SET value = value + ? WHERE key = 'total_analyzed'", (len(items),))
            if n_attacks:
                cur.execute("UPDATE stats SET value = value + ? WHERE key = 'total_attacks'", (n_attacks,))
                cur.execute("UPDATE stats SET value = value + ? WHERE key = 'total_blocked'", (n_attacks,))
            conn.commit()
            conn.close()
            return
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < 4:
                _time.sleep(0.1 * (attempt + 1))
                continue
            logger.error(f"Erreur SQLite insert batch ({attempt+1}/5): {e}")
            return

def db_get_stats() -> dict:
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        c = conn.cursor()

        c.execute("SELECT key, value FROM stats")
        stats = {row[0]: row[1] for row in c.fetchall()}

        c.execute("""
            SELECT attack_type, COUNT(*) FROM alerts
            WHERE is_attack = 1
            GROUP BY attack_type
        """)
        by_type = {row[0]: row[1] for row in c.fetchall()}

        c.execute("""
            SELECT severity, COUNT(*) FROM alerts
            WHERE is_attack = 1
            GROUP BY severity
        """)
        by_severity = {row[0]: row[1] for row in c.fetchall()}

        conn.close()

        total   = stats.get("total_analyzed", 0)
        attacks = stats.get("total_attacks", 0)

        return {
            "total_analyzed": total,
            "total_attacks":  attacks,
            "total_blocked":  stats.get("total_blocked", 0),
            "attack_rate":    round(attacks / total * 100, 2) if total > 0 else 0,
            "by_type":        by_type,
            "by_severity":    by_severity,
            "timestamp":      datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Erreur SQLite stats : {e}")
        return {}

def db_get_history(limit: int = 100, attacks_only: bool = False, offset: int = 0) -> list:
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        where = "WHERE is_attack = 1" if attacks_only else ""
        c.execute(f"""
            SELECT * FROM alerts
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        for r in rows:
            r["is_attack"] = bool(r["is_attack"])
            r["blocked"]   = bool(r["blocked"])
        return rows
    except Exception as e:
        logger.error(f"Erreur SQLite history : {e}")
        return []

def db_reset():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM alerts")
        c.execute("UPDATE stats SET value = 0")
        conn.commit()
        conn.close()
        logger.info("Base de donnees reinitalisee.")
    except Exception as e:
        logger.error(f"Erreur SQLite reset : {e}")

def load_models():
    models = {}
    try:
        iqr_bounds           = joblib.load(f"{MODEL_DIR}/ids_iqr_bounds.pkl")
        models["iqr_lower"]  = np.array(iqr_bounds["lower"])
        models["iqr_upper"]  = np.array(iqr_bounds["upper"])
        models["scaler"]     = joblib.load(f"{MODEL_DIR}/ids_scaler.pkl")
        models["xgb_bin"]    = joblib.load(f"{MODEL_DIR}/ids_xgb_binaire.pkl")
        models["xgb_multi"]  = joblib.load(f"{MODEL_DIR}/ids_xgb_multiclasse.pkl")
        models["le"]         = joblib.load(f"{MODEL_DIR}/ids_label_encoder.pkl")
        models["threshold"]  = joblib.load(f"{MODEL_DIR}/ids_best_threshold.pkl")
        logger.info(f"Modeles charges depuis {MODEL_DIR}")
        logger.info(f"Seuil de detection : {models['threshold']:.2f}")
    except FileNotFoundError as e:
        logger.warning(f"Modeles non trouves ({e}) — Mode demo active")
        models = None
    except Exception as e:
        logger.error(f"Erreur chargement modeles : {e}")
        models = None
    return models

init_db()
MODELS = load_models()

_LOCAL = {"127.0.0.1", "::1"}

def _rate_key(request: Request) -> str:
    ip = get_remote_address(request)
    return "local" if ip in _LOCAL else ip

limiter = Limiter(key_func=_rate_key)

class NetworkFlow(BaseModel):
    destination_port:          float = Field(..., description="Port de destination")
    flow_duration:             float = Field(..., description="Duree du flux (us)")
    total_fwd_packets:         float = Field(..., description="Paquets forward")
    total_backward_packets:    float = Field(..., description="Paquets backward")
    flow_bytes_per_s:          float = Field(..., description="Debit octets/s")
    flow_packets_per_s:        float = Field(..., description="Debit paquets/s")
    average_packet_size:       float = Field(..., description="Taille moyenne paquet")
    packet_length_mean:        float = Field(..., description="Longueur moyenne paquet")
    init_win_bytes_forward:    float = Field(..., description="Fenetre TCP forward")
    init_win_bytes_backward:   float = Field(..., description="Fenetre TCP backward")
    flow_iat_mean:             float = Field(..., description="IAT moyen")
    flow_iat_std:              float = Field(..., description="IAT ecart-type")
    source_ip:    Optional[str] = None
    dest_ip:      Optional[str] = None
    protocol:     Optional[str] = None
    timestamp:    Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "destination_port": 80,
                "flow_duration": 1293792,
                "total_fwd_packets": 3,
                "total_backward_packets": 7,
                "flow_bytes_per_s": 8991.4,
                "flow_packets_per_s": 7.73,
                "average_packet_size": 1163.3,
                "packet_length_mean": 1057.5,
                "init_win_bytes_forward": 8192,
                "init_win_bytes_backward": 229,
                "flow_iat_mean": 143754.7,
                "flow_iat_std": 430865.8,
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP"
            }
        }

class PredictionResult(BaseModel):
    is_attack:      bool
    attack_type:    str
    severity:       str
    confidence:     float
    threshold_used: float
    action:         str
    blocked:        bool
    timestamp:      str
    source_ip:      Optional[str]
    dest_ip:        Optional[str]
    protocol:       Optional[str]

def predict_flow(flow_values: list, meta: dict = None) -> dict:
    ts = datetime.now().isoformat()

    try:
        if MODELS is None:
            import random
            classes     = list(SEVERITY.keys())
            attack_type = random.choice(classes)
            is_attack   = attack_type != "BENIGN"
            confidence  = round(random.uniform(0.6, 0.99), 4)
            threshold   = DEFAULT_THRESHOLD
        else:
            X = np.array(flow_values, dtype=float).reshape(1, -1)

            X_capped = np.clip(X, MODELS["iqr_lower"], MODELS["iqr_upper"])

            X_scaled = MODELS["scaler"].transform(X_capped)

            threshold = float(MODELS["threshold"])
            proba_bin = float(MODELS["xgb_bin"].predict_proba(X_scaled)[0, 1])
            is_attack = proba_bin >= threshold

            if is_attack:
                pred_idx    = int(MODELS["xgb_multi"].predict(X_scaled)[0])
                attack_type = MODELS["le"].inverse_transform([pred_idx])[0]
                attack_type = attack_type.encode("ascii", "ignore").decode("ascii").strip()

                if attack_type == "BENIGN":
                    proba_multi = MODELS["xgb_multi"].predict_proba(X_scaled)[0]
                    classes     = MODELS["le"].classes_
                    best_idx, best_p = None, 0.0
                    for idx, (cls, p) in enumerate(zip(classes, proba_multi)):
                        if cls != "BENIGN" and p > best_p:
                            best_p, best_idx = p, idx
                    attack_type = classes[best_idx] if best_idx is not None else "DoS Hulk"

                confidence = round(float(proba_bin), 4)
            else:
                attack_type = "BENIGN"
                confidence  = round(1 - proba_bin, 4)

    except Exception as e:
        logger.error(f"Erreur prediction : {e}")
        attack_type = "BENIGN"
        is_attack   = False
        confidence  = 0.0
        threshold   = DEFAULT_THRESHOLD

    severity = SEVERITY.get(attack_type, "MEDIUM")
    action   = ACTIONS.get(attack_type, "Surveiller.")
    blocked  = is_attack

    result = {
        "is_attack":      bool(is_attack),
        "attack_type":    attack_type,
        "severity":       severity,
        "confidence":     confidence,
        "threshold_used": threshold,
        "action":         action,
        "blocked":        blocked,
        "timestamp":      ts,
        "source_ip":      meta.get("source_ip") if meta else None,
        "dest_ip":        meta.get("dest_ip")   if meta else None,
        "protocol":       meta.get("protocol")  if meta else None,
    }

    if is_attack:
        logger.warning(
            f"ATTAQUE DETECTEE | {attack_type} | {severity} | "
            f"Conf: {confidence*100:.1f}% | "
            f"{meta.get('source_ip','?')} -> {meta.get('dest_ip','?')}"
        )
    else:
        logger.info(
            f"BENIGN | Conf: {confidence*100:.1f}% | "
            f"{meta.get('source_ip','?')} -> {meta.get('dest_ip','?')}"
        )

    db_insert_alert(result)
    db_upsert_attacker_ip(result)
    try: _flush_insert_queue()
    except: pass

    return result

app = FastAPI(
    title="IDS — Système de Détection d'Intrusions",
    description="EUROFLARE IDS — API de detection d'intrusions reseau",
    version="2.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", tags=["Système"])
def health_check():
    return {
        "status":        "online",
        "models_loaded": MODELS is not None,
        "mode":          "production" if MODELS else "demo",
        "threshold":     float(MODELS["threshold"]) if MODELS else DEFAULT_THRESHOLD,
        "db":            DB_PATH,
        "log":           LOG_PATH,
        "timestamp":     datetime.now().isoformat(),
    }

@app.post("/predict", response_model=PredictionResult, tags=["Détection"])
@limiter.limit("50000/minute")
def predict_single(
    request: Request,
    flow: NetworkFlow
):
    flow_values = [
        flow.destination_port,
        flow.flow_duration,
        flow.total_fwd_packets,
        flow.total_backward_packets,
        flow.flow_bytes_per_s,
        flow.flow_packets_per_s,
        flow.average_packet_size,
        flow.packet_length_mean,
        flow.init_win_bytes_forward,
        flow.init_win_bytes_backward,
        flow.flow_iat_mean,
        flow.flow_iat_std,
    ]
    meta = {
        "source_ip": flow.source_ip,
        "dest_ip":   flow.dest_ip,
        "protocol":  flow.protocol,
    }
    return predict_flow(flow_values, meta)

@app.post("/predict/batch", tags=["Détection"])
@limiter.limit("50000/minute")
async def predict_batch(
    request: Request,
    file: UploadFile = File(...)
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .csv sont acceptes.")

    try:
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lecture CSV : {str(e)}")

    df.columns = df.columns.str.strip()

    col_mapping = {
        "Destination Port":        "Destination Port",
        "Flow Duration":           "Flow Duration",
        "Total Fwd Packets":       "Total Fwd Packets",
        "Total Backward Packets":  "Total Backward Packets",
        "Flow Bytes/s":            "Flow Bytes/s",
        "Flow Packets/s":          "Flow Packets/s",
        "Average Packet Size":     "Average Packet Size",
        "Packet Length Mean":      "Packet Length Mean",
        "Init_Win_bytes_forward":  "Init_Win_bytes_forward",
        "Init_Win_bytes_backward": "Init_Win_bytes_backward",
        "Flow IAT Mean":           "Flow IAT Mean",
        "Flow IAT Std":            "Flow IAT Std",
    }

    missing = [c for c in col_mapping if c not in df.columns]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Colonnes manquantes : {missing}"
        )

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    n_total  = len(df)
    ts_batch = datetime.now().isoformat()

    if MODELS is not None:
        X        = df[list(col_mapping.keys())].values.astype(float)
        X_capped = np.clip(X, MODELS["iqr_lower"], MODELS["iqr_upper"])
        X_scaled = MODELS["scaler"].transform(X_capped)
        threshold     = float(MODELS["threshold"])
        proba_bin     = MODELS["xgb_bin"].predict_proba(X_scaled)[:, 1]
        is_attack_arr = proba_bin >= threshold
        attack_types  = np.full(n_total, "BENIGN", dtype=object)
        confidences   = np.round(1 - proba_bin, 4)
        idx_atk = np.where(is_attack_arr)[0]
        if len(idx_atk) > 0:
            preds   = MODELS["xgb_multi"].predict(X_scaled[idx_atk])
            probas  = MODELS["xgb_multi"].predict_proba(X_scaled[idx_atk]).max(axis=1)
            labels  = MODELS["le"].inverse_transform(preds.astype(int))
            attack_types[idx_atk] = [l.encode("ascii","ignore").decode().strip() for l in labels]
            confidences[idx_atk]  = np.round(probas, 4)
    else:
        import random as _r
        attack_types  = np.array([_r.choice(list(SEVERITY.keys())) for _ in range(n_total)])
        is_attack_arr = attack_types != "BENIGN"
        confidences   = np.round(np.random.uniform(0.6, 0.99, n_total), 4)
        threshold     = DEFAULT_THRESHOLD

    src_ips   = df.get("Source IP",      [""] * n_total).astype(str).values if "Source IP" in df.columns else [""] * n_total
    dst_ips   = df.get("Destination IP", [""] * n_total).astype(str).values if "Destination IP" in df.columns else [""] * n_total
    protocols = df.get("Protocol",       [""] * n_total).astype(str).values if "Protocol" in df.columns else [""] * n_total

    results = []
    by_type = {}
    for i in range(n_total):
        atype = str(attack_types[i]); is_atk = bool(is_attack_arr[i])
        row = {
            "timestamp": ts_batch, "is_attack": is_atk,
            "attack_type": atype, "severity": SEVERITY.get(atype, "MEDIUM"),
            "confidence": float(confidences[i]), "threshold_used": threshold,
            "action": ACTIONS.get(atype, "Surveiller."), "blocked": is_atk,
            "source_ip": src_ips[i] or None,
            "dest_ip":   dst_ips[i] or None,
            "protocol":  protocols[i] or None,
        }
        results.append(row)
        db_insert_alert(row)
        db_upsert_attacker_ip(row)
        if is_atk: by_type[atype] = by_type.get(atype, 0) + 1

    n_attacks = int(is_attack_arr.sum())
    logger.info(f"Batch vectorise : {n_total} flux, {n_attacks} attaques detectees")

    return {
        "summary": {
            "total_analyzed": n_total,
            "total_attacks":  n_attacks,
            "total_blocked":  n_attacks,
            "attack_rate":    round(n_attacks / n_total * 100, 2) if n_total > 0 else 0,
            "attack_types":   by_type,
        },
        "results": results,
    }

@app.get("/stats", tags=["Statistiques"])
@limiter.limit("50000/minute")
def get_stats(
    request: Request
):
    return db_get_stats()

@app.get("/history", tags=["Historique"])
@limiter.limit("50000/minute")
def get_history(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    attacks_only: bool = False
):
    history = db_get_history(limit=limit, attacks_only=attacks_only)
    return {
        "count":   len(history),
        "history": history,
    }

@app.get("/history/recent", tags=["Historique"])
@limiter.limit("50000/minute")
def get_recent_alerts(
    request: Request
):
    alerts = db_get_history(limit=50, attacks_only=True)
    return {
        "count":  len(alerts),
        "alerts": alerts,
    }

@app.delete("/history", tags=["Historique"])
def reset_history():
    db_reset()
    return {"message": "Historique et statistiques reinitialises."}

@app.get("/attacker-ips", tags=["Blacklist"])
@limiter.limit("50000/minute")
def get_attacker_ips(
    request: Request,
    blacklisted_only: bool = False,
    limit: int = 200,
):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        where = "WHERE blacklisted = 1" if blacklisted_only else ""
        rows  = conn.execute(f"""
            SELECT * FROM attacker_ips
            {where}
            ORDER BY attack_count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["blacklisted"] = bool(d["blacklisted"])
            d["attack_types_list"] = d["attack_types"].split(",") if d["attack_types"] else []
            result.append(d)
        return {"count": len(result), "ips": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attacker-ips/{ip}/blacklist", tags=["Blacklist"])
def blacklist_ip(ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        now  = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO attacker_ips (ip, first_seen, last_seen, blacklisted, blacklisted_at)
            VALUES (?,?,?,1,?)
            ON CONFLICT(ip) DO UPDATE SET blacklisted=1, blacklisted_at=?
        """, (ip, now, now, now, now))
        conn.commit()
        conn.close()
        logger.info(f"IP blacklistée : {ip}")
        return {"message": f"{ip} blacklistée.", "ip": ip, "blacklisted": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/attacker-ips/{ip}/blacklist", tags=["Blacklist"])
def unblacklist_ip(ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE attacker_ips SET blacklisted=0, blacklisted_at=NULL WHERE ip=?", (ip,)
        )
        conn.commit()
        conn.close()
        logger.info(f"IP retirée de la blacklist : {ip}")
        return {"message": f"{ip} retirée de la blacklist.", "ip": ip, "blacklisted": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/attacker-ips/blacklist/all", tags=["Blacklist"])
def clear_blacklist():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE attacker_ips SET blacklisted=0, blacklisted_at=NULL")
        conn.commit()
        conn.close()
        return {"message": "Blacklist vidée."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
