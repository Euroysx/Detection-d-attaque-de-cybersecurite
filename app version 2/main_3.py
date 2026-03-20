# ================================================================
# IDS — FASTAPI BACKEND (VERSION FINALE)
# Système de Détection d'Intrusions pour PME
# ================================================================
#
# LANCEMENT :
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# ENDPOINTS :
#   POST /predict         — Analyse un flux réseau unique (JSON)
#   POST /predict/batch   — Analyse un fichier CSV de logs
#   GET  /stats           — Statistiques globales
#   GET  /history         — Historique complet (SQLite)
#   GET  /history/recent  — 50 dernières alertes
#   DELETE /history       — Réinitialiser l'historique
#   GET  /health          — Santé de l'API
#
# AUTHENTIFICATION :
#   (sauf /health qui est public)
#
# ================================================================

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

# ================================================================
# CLASSE IQRCapper — REQUISE POUR CHARGER ids_pipeline.pkl
# ================================================================

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

# ================================================================
# CONFIGURATION
# ================================================================

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

# ================================================================
# LOGGING — Fichier de logs sur disque
# ================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("IDS")

# ================================================================
# SQLITE — Base de données persistante
# ================================================================

def init_db():
    """Initialise la base de données SQLite."""
    conn = sqlite3.connect(DB_PATH)
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
    # Initialiser les compteurs si absents
    for key in ["total_analyzed", "total_attacks", "total_blocked"]:
        c.execute("INSERT OR IGNORE INTO stats (key, value) VALUES (?, 0)", (key,))
    conn.commit()
    conn.close()
    logger.info(f"Base de donnees SQLite initialisee : {DB_PATH}")


def db_insert_alert(result: dict):
    """Insère une alerte dans la base de données."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO alerts
            (timestamp, is_attack, attack_type, severity, confidence,
             threshold, blocked, source_ip, dest_ip, protocol, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["timestamp"],
            int(result["is_attack"]),
            result["attack_type"],
            result["severity"],
            result["confidence"],
            result["threshold_used"],
            int(result["blocked"]),
            result.get("source_ip"),
            result.get("dest_ip"),
            result.get("protocol"),
            result["action"],
        ))
        # Mise à jour des stats
        c.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_analyzed'")
        if result["is_attack"]:
            c.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_attacks'")
            c.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_blocked'")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Erreur SQLite insert : {e}")


def db_get_stats() -> dict:
    """Récupère les statistiques depuis SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Stats globales
        c.execute("SELECT key, value FROM stats")
        stats = {row[0]: row[1] for row in c.fetchall()}

        # Stats par type d'attaque
        c.execute("""
            SELECT attack_type, COUNT(*) FROM alerts
            WHERE is_attack = 1
            GROUP BY attack_type
        """)
        by_type = {row[0]: row[1] for row in c.fetchall()}

        # Stats par sévérité
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


def db_get_history(limit: int = 100, attacks_only: bool = False) -> list:
    """Récupère l'historique depuis SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        where = "WHERE is_attack = 1" if attacks_only else ""
        c.execute(f"""
            SELECT * FROM alerts
            {where}
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        # Convertir les entiers en booléens
        for r in rows:
            r["is_attack"] = bool(r["is_attack"])
            r["blocked"]   = bool(r["blocked"])
        return rows
    except Exception as e:
        logger.error(f"Erreur SQLite history : {e}")
        return []


def db_reset():
    """Réinitialise la base de données."""
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

# ================================================================
# CHARGEMENT DES MODÈLES
# ================================================================

def load_models():
    """Charge tous les modèles depuis le dossier models/."""
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

# Initialisation
init_db()
MODELS = load_models()

# ================================================================
# RATE LIMITING
# ================================================================

limiter = Limiter(key_func=get_remote_address)



# ================================================================
# SCHÉMAS PYDANTIC
# ================================================================

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

# ================================================================
# LOGIQUE DE PRÉDICTION
# ================================================================

def predict_flow(flow_values: list, meta: dict = None) -> dict:
    """Prédit si un flux est une attaque et son type."""
    ts = datetime.now().isoformat()

    try:
        if MODELS is None:
            # Mode démo
            import random
            classes     = list(SEVERITY.keys())
            attack_type = random.choice(classes)
            is_attack   = attack_type != "BENIGN"
            confidence  = round(random.uniform(0.6, 0.99), 4)
            threshold   = DEFAULT_THRESHOLD
        else:
            X = np.array(flow_values, dtype=float).reshape(1, -1)

            # IQR Capping
            X_capped = np.clip(X, MODELS["iqr_lower"], MODELS["iqr_upper"])

            # RobustScaler
            X_scaled = MODELS["scaler"].transform(X_capped)

            # Prédiction binaire
            threshold = float(MODELS["threshold"])
            proba_bin = float(MODELS["xgb_bin"].predict_proba(X_scaled)[0, 1])
            is_attack = proba_bin >= threshold

            if is_attack:
                pred_idx    = int(MODELS["xgb_multi"].predict(X_scaled)[0])
                attack_type = MODELS["le"].inverse_transform([pred_idx])[0]
                attack_type = attack_type.encode("ascii", "ignore").decode("ascii").strip()
                confidence  = round(float(MODELS["xgb_multi"].predict_proba(X_scaled).max()), 4)
            else:
                attack_type = "BENIGN"
                confidence  = round(1 - proba_bin, 4)

    except Exception as e:
        logger.error(f"Erreur prediction : {e}")
        # Fail-safe : en cas d'erreur on logue et retourne BENIGN
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

    # Log dans le fichier
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

    # Sauvegarde SQLite
    db_insert_alert(result)

    return result

# ================================================================
# APPLICATION FASTAPI
# ================================================================

app = FastAPI(
    title="IDS — Système de Détection d'Intrusions",
    description="""
## API de détection d'intrusions réseau pour PME

**Pipeline** : `Flux -> IQR Capping -> RobustScaler -> XGBoost Binaire -> XGBoost Multi-classe`

**Attaques détectables** : DDoS, DoS (GoldenEye, Hulk, Slowhttptest, Slowloris),
FTP-Patator, SSH-Patator, Web Attack (Brute Force, SQL Injection, XSS),
Bot, Infiltration, PortScan, Heartbleed
    """,
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

# ================================================================
# ENDPOINTS
# ================================================================

@app.get("/health", tags=["Système"])
def health_check():
    """Endpoint public — vérifie que l'API est opérationnelle."""
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
@limiter.limit("60/minute")
def predict_single(
    request: Request,
    flow: NetworkFlow
):
    """
    Analyse un flux réseau unique.

    **Rate limit** : 60 requêtes/minute par IP.
    """
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
@limiter.limit("10/minute")
async def predict_batch(
    request: Request,
    file: UploadFile = File(...)
):
    """
    Analyse un fichier CSV de logs réseau.

    **Rate limit** : 10 uploads/minute par IP.
    """
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

    results = []
    for _, row in df.iterrows():
        flow_values = [row[c] for c in col_mapping.keys()]
        meta = {
            "source_ip": str(row.get("Source IP", "")),
            "dest_ip":   str(row.get("Destination IP", "")),
            "protocol":  str(row.get("Protocol", "")),
        }
        result = predict_flow(flow_values, meta)
        results.append(result)

    n_total   = len(results)
    n_attacks = sum(1 for r in results if r["is_attack"])
    by_type   = {}
    for r in results:
        if r["is_attack"]:
            t = r["attack_type"]
            by_type[t] = by_type.get(t, 0) + 1

    logger.info(f"Batch analyse : {n_total} flux, {n_attacks} attaques detectees")

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
@limiter.limit("30/minute")
def get_stats(
    request: Request
):
    """Statistiques globales depuis SQLite (persistantes)."""
    return db_get_stats()


@app.get("/history", tags=["Historique"])
@limiter.limit("30/minute")
def get_history(
    request: Request,
    limit: int = 100,
    attacks_only: bool = False
):
    """
    Historique des flux analysés (SQLite — persistant entre redémarrages).

    - limit       : nombre max d'entrées
    - attacks_only: si True, retourne uniquement les attaques
    """
    history = db_get_history(limit=limit, attacks_only=attacks_only)
    return {
        "count":   len(history),
        "history": history,
    }


@app.get("/history/recent", tags=["Historique"])
@limiter.limit("30/minute")
def get_recent_alerts(
    request: Request
):
    """50 dernières attaques détectées."""
    alerts = db_get_history(limit=50, attacks_only=True)
    return {
        "count":  len(alerts),
        "alerts": alerts,
    }


@app.delete("/history", tags=["Historique"])
def reset_history():
    """Réinitialise l'historique et les statistiques (SQLite)."""
    db_reset()
    return {"message": "Historique et statistiques reinitialises."}
