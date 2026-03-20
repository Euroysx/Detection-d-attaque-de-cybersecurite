# ================================================================
# IDS — FASTAPI BACKEND
# Système de Détection d'Intrusions pour PME
# ================================================================
#
# LANCEMENT :
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# ENDPOINTS :
#   POST /predict         — Analyse un flux réseau unique (JSON)
#   POST /predict/batch   — Analyse un fichier CSV de logs
#   GET  /stats           — Statistiques globales des attaques
#   GET  /history         — Historique complet des alertes
#   GET  /history/recent  — 50 dernières alertes
#   DELETE /history       — Réinitialiser l'historique
#   GET  /health          — Santé de l'API
# ================================================================

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import pandas as pd
import numpy as np
import joblib
import io
import os
from datetime import datetime
from collections import defaultdict
from sklearn.base import BaseEstimator, TransformerMixin

# ================================================================
# CLASSE IQRCapper — REQUISE POUR CHARGER ids_pipeline.pkl
#
# Cette classe doit etre definie dans main.py car joblib cherche
# la classe dans le module courant au moment du chargement.
# Elle doit etre IDENTIQUE a celle utilisee dans le notebook.
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

# Chemin vers les modèles sauvegardés
# Adaptez ce chemin selon votre environnement
MODEL_DIR = os.getenv("MODEL_DIR", "./models")

# Seuil de détection (chargé depuis le fichier ou valeur par défaut)
DEFAULT_THRESHOLD = 0.35

# Features attendues (dans l'ordre exact du modèle)
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

# Niveaux de sévérité par type d'attaque
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

# Actions recommandées par type d'attaque
ACTIONS = {
    "BENIGN":                    "Aucune action requise.",
    "Bot":                       "Isoler la machine source. Analyser les connexions sortantes.",
    "DDoS":                      "Activer la limitation de débit. Contacter le FAI. Mitigation DDoS.",
    "DoS GoldenEye":             "Bloquer l'IP source. Vérifier la disponibilité des services web.",
    "DoS Hulk":                  "Bloquer l'IP source. Augmenter la capacité si possible.",
    "DoS Slowhttptest":          "Configurer les timeouts HTTP. Bloquer l'IP source.",
    "DoS slowloris":             "Limiter les connexions simultanées par IP. Bloquer la source.",
    "FTP-Patator":               "Bloquer l'IP source. Vérifier les comptes FTP. Activer le 2FA.",
    "Heartbleed":                "URGENCE : Patcher OpenSSL immédiatement. Révoquer les certificats.",
    "Infiltration":              "URGENCE : Isoler le réseau. Audit de sécurité complet.",
    "PortScan":                  "Surveiller l'IP source. Vérifier les ports ouverts exposés.",
    "SSH-Patator":               "Bloquer l'IP source. Vérifier les comptes SSH. Activer le 2FA.",
    "Web Attack \xef\xbf\xbd Brute Force":  "Bloquer l'IP source. Activer le CAPTCHA. Limiter les tentatives.",
    "Web Attack \xef\xbf\xbd Sql Injection":"Bloquer l'IP source. Verifier les requetes SQL. Audit du code.",
    "Web Attack \xef\xbf\xbd XSS":          "Bloquer l'IP source. Verifier les entrees utilisateur.",
    "Web Attack - Brute Force":  "Bloquer l'IP source. Activer le CAPTCHA. Limiter les tentatives.",
    "Web Attack - Sql Injection":"Bloquer l'IP source. Verifier les requetes SQL. Audit du code.",
    "Web Attack - XSS":          "Bloquer l'IP source. Verifier les entrees utilisateur.",
}

# ================================================================
# CHARGEMENT DES MODÈLES
# ================================================================

def load_models():
    """Charge tous les modeles et outils depuis le dossier models/."""
    models = {}
    try:
        # Chargement IQR bounds + scaler separement (pas de classe custom)
        iqr_bounds           = joblib.load(f"{MODEL_DIR}/ids_iqr_bounds.pkl")
        models["iqr_lower"]  = np.array(iqr_bounds["lower"])
        models["iqr_upper"]  = np.array(iqr_bounds["upper"])
        models["scaler"]     = joblib.load(f"{MODEL_DIR}/ids_scaler.pkl")
        models["xgb_bin"]    = joblib.load(f"{MODEL_DIR}/ids_xgb_binaire.pkl")
        models["xgb_multi"]  = joblib.load(f"{MODEL_DIR}/ids_xgb_multiclasse.pkl")
        models["le"]         = joblib.load(f"{MODEL_DIR}/ids_label_encoder.pkl")
        models["threshold"]  = joblib.load(f"{MODEL_DIR}/ids_best_threshold.pkl")
        print(f"[IDS] Modeles charges depuis {MODEL_DIR}")
        print(f"[IDS] Seuil de detection : {models['threshold']:.2f}")
    except FileNotFoundError as e:
        print(f"[IDS] ATTENTION : Modeles non trouves ({e})")
        print(f"[IDS] Mode demo active")
        models = None
    return models

MODELS = load_models()

# ================================================================
# HISTORIQUE EN MÉMOIRE (remplaçable par une base de données)
# ================================================================

alert_history = []
stats_counter = defaultdict(int)
stats_counter["total_analyzed"] = 0

# ================================================================
# SCHÉMAS PYDANTIC
# ================================================================

class NetworkFlow(BaseModel):
    """Représente un flux réseau à analyser."""
    destination_port:          float = Field(..., description="Port de destination")
    flow_duration:             float = Field(..., description="Durée du flux (µs)")
    total_fwd_packets:         float = Field(..., description="Paquets forward")
    total_backward_packets:    float = Field(..., description="Paquets backward")
    flow_bytes_per_s:          float = Field(..., description="Débit octets/s")
    flow_packets_per_s:        float = Field(..., description="Débit paquets/s")
    average_packet_size:       float = Field(..., description="Taille moyenne paquet")
    packet_length_mean:        float = Field(..., description="Longueur moyenne paquet")
    init_win_bytes_forward:    float = Field(..., description="Fenêtre TCP forward")
    init_win_bytes_backward:   float = Field(..., description="Fenêtre TCP backward")
    flow_iat_mean:             float = Field(..., description="IAT moyen")
    flow_iat_std:              float = Field(..., description="IAT écart-type")

    # Métadonnées optionnelles (pour le contexte)
    source_ip:    Optional[str] = Field(None, description="IP source (info)")
    dest_ip:      Optional[str] = Field(None, description="IP destination (info)")
    protocol:     Optional[str] = Field(None, description="Protocole (info)")
    timestamp:    Optional[str] = Field(None, description="Horodatage")

    class Config:
        json_schema_extra = {
            "example": {
                "destination_port": 80,
                "flow_duration": 38308,
                "total_fwd_packets": 1,
                "total_backward_packets": 1,
                "flow_bytes_per_s": 156.9,
                "flow_packets_per_s": 52.2,
                "average_packet_size": 6.0,
                "packet_length_mean": 6.0,
                "init_win_bytes_forward": 65535,
                "init_win_bytes_backward": 65535,
                "flow_iat_mean": 38308.0,
                "flow_iat_std": 0.0,
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP"
            }
        }

class PredictionResult(BaseModel):
    """Résultat d'une analyse de flux."""
    is_attack:        bool
    attack_type:      str
    severity:         str
    confidence:       float
    threshold_used:   float
    action:           str
    blocked:          bool
    timestamp:        str
    source_ip:        Optional[str]
    dest_ip:          Optional[str]
    protocol:         Optional[str]

# ================================================================
# LOGIQUE DE PRÉDICTION
# ================================================================

def predict_flow(flow_values: list, meta: dict = None) -> dict:
    """
    Prédit si un flux est une attaque et son type.
    
    Paramètres
    ----------
    flow_values : list de 12 valeurs dans l'ordre des features
    meta        : dict optionnel avec source_ip, dest_ip, protocol
    
    Retourne
    --------
    dict avec tous les champs de PredictionResult
    """
    ts = datetime.now().isoformat()

    if MODELS is None:
        # Mode démo : simulation aléatoire
        import random
        classes = list(SEVERITY.keys())
        attack_type = random.choice(classes)
        is_attack   = attack_type != "BENIGN"
        confidence  = round(random.uniform(0.6, 0.99), 4)
    else:
        X = np.array(flow_values).reshape(1, -1)

        # IQR Capping manuel (bornes chargees depuis ids_iqr_bounds.pkl)
        X_capped = np.clip(X, MODELS["iqr_lower"], MODELS["iqr_upper"])

        # RobustScaler
        X_scaled = MODELS["scaler"].transform(X_capped)

        # Prédiction binaire avec seuil optimal
        threshold  = MODELS["threshold"]
        proba_bin  = MODELS["xgb_bin"].predict_proba(X_scaled)[0, 1]
        is_attack  = bool(proba_bin >= threshold)

        if is_attack:
            pred_idx    = MODELS["xgb_multi"].predict(X_scaled)[0]
            attack_type = MODELS["le"].inverse_transform([pred_idx])[0]
            # Nettoyage des caractères spéciaux
            attack_type = attack_type.encode("ascii", "ignore").decode("ascii").strip()
            proba_multi = float(MODELS["xgb_multi"].predict_proba(X_scaled).max())
            confidence  = round(proba_multi, 4)
        else:
            attack_type = "BENIGN"
            confidence  = round(1 - proba_bin, 4)
            threshold   = MODELS["threshold"]

    severity = SEVERITY.get(attack_type, "MEDIUM")
    action   = ACTIONS.get(attack_type, "Surveiller.")
    blocked  = is_attack  # On bloque automatiquement toute attaque détectée

    result = {
        "is_attack":      is_attack,
        "attack_type":    attack_type,
        "severity":       severity,
        "confidence":     confidence,
        "threshold_used": float(MODELS["threshold"]) if MODELS else DEFAULT_THRESHOLD,
        "action":         action,
        "blocked":        blocked,
        "timestamp":      ts,
        "source_ip":      meta.get("source_ip") if meta else None,
        "dest_ip":        meta.get("dest_ip") if meta else None,
        "protocol":       meta.get("protocol") if meta else None,
    }

    # Mise à jour des statistiques
    stats_counter["total_analyzed"] += 1
    if is_attack:
        stats_counter["total_attacks"] += 1
        stats_counter["total_blocked"] += 1
        stats_counter[f"type_{attack_type}"] += 1
        stats_counter[f"severity_{severity}"] += 1

    # Ajout à l'historique
    alert_history.append(result)

    return result

# ================================================================
# APPLICATION FASTAPI
# ================================================================

app = FastAPI(
    title="IDS — Système de Détection d'Intrusions",
    description="""
## API de détection d'intrusions réseau pour PME

Utilise un modèle **XGBoost** entraîné sur le dataset **CIC-IDS2017**.

### Attaques détectables
- DDoS, DoS (GoldenEye, Hulk, Slowhttptest, Slowloris)
- FTP-Patator, SSH-Patator
- Web Attack (Brute Force, SQL Injection, XSS)
- Bot, Infiltration, PortScan, Heartbleed

### Pipeline
`Flux réseau → IQR Capping → RobustScaler → XGBoost Binaire → XGBoost Multi-classe → Blocage`
    """,
    version="1.0.0",
)

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
    """Vérifie que l'API et les modèles sont opérationnels."""
    return {
        "status":        "online",
        "models_loaded": MODELS is not None,
        "mode":          "production" if MODELS else "demo",
        "threshold":     float(MODELS["threshold"]) if MODELS else DEFAULT_THRESHOLD,
        "timestamp":     datetime.now().isoformat(),
    }


@app.post("/predict", response_model=PredictionResult, tags=["Détection"])
def predict_single(flow: NetworkFlow):
    """
    Analyse un flux réseau unique et détermine s'il est malveillant.
    
    Retourne le type d'attaque, la sévérité, la confiance du modèle
    et l'action recommandée.
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

    result = predict_flow(flow_values, meta)
    return result


@app.post("/predict/batch", tags=["Détection"])
async def predict_batch(file: UploadFile = File(...)):
    """
    Analyse un fichier CSV de logs réseau.
    
    Le CSV doit contenir les colonnes correspondant aux 12 features
    (noms originaux CIC-IDS2017 ou noms normalisés acceptés).
    
    Retourne un résumé + la liste de tous les flux analysés.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .csv sont acceptés.")

    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lecture CSV : {str(e)}")

    # Normalisation des noms de colonnes
    df.columns = df.columns.str.strip()

    # Mapping colonnes CIC-IDS2017 -> features du modèle
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

    # Vérification des colonnes disponibles
    missing = [c for c in col_mapping if c not in df.columns]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Colonnes manquantes : {missing}. Colonnes trouvées : {list(df.columns)}"
        )

    # Nettoyage
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

    # Résumé
    n_total   = len(results)
    n_attacks = sum(1 for r in results if r["is_attack"])
    n_blocked = n_attacks

    attack_types = {}
    for r in results:
        if r["is_attack"]:
            t = r["attack_type"]
            attack_types[t] = attack_types.get(t, 0) + 1

    return {
        "summary": {
            "total_analyzed": n_total,
            "total_attacks":  n_attacks,
            "total_blocked":  n_blocked,
            "attack_rate":    round(n_attacks / n_total * 100, 2) if n_total > 0 else 0,
            "attack_types":   attack_types,
        },
        "results": results,
    }


@app.get("/stats", tags=["Statistiques"])
def get_stats():
    """
    Retourne les statistiques globales depuis le démarrage de l'API :
    total analysé, total attaques, répartition par type et sévérité.
    """
    total   = stats_counter["total_analyzed"]
    attacks = stats_counter["total_attacks"]

    # Répartition par type
    types = {
        k.replace("type_", ""): v
        for k, v in stats_counter.items()
        if k.startswith("type_")
    }

    # Répartition par sévérité
    severities = {
        k.replace("severity_", ""): v
        for k, v in stats_counter.items()
        if k.startswith("severity_")
    }

    return {
        "total_analyzed": total,
        "total_attacks":  attacks,
        "total_blocked":  stats_counter["total_blocked"],
        "attack_rate":    round(attacks / total * 100, 2) if total > 0 else 0,
        "by_type":        types,
        "by_severity":    severities,
        "timestamp":      datetime.now().isoformat(),
    }


@app.get("/history", tags=["Historique"])
def get_history(limit: int = 100, attacks_only: bool = False):
    """
    Retourne l'historique des flux analysés.
    
    Paramètres :
    - limit       : nombre maximum d'entrées (défaut 100)
    - attacks_only: si True, retourne uniquement les attaques
    """
    history = alert_history[-limit:]
    if attacks_only:
        history = [h for h in history if h["is_attack"]]

    return {
        "count":   len(history),
        "history": history,
    }


@app.get("/history/recent", tags=["Historique"])
def get_recent_alerts():
    """Retourne les 50 dernières attaques détectées."""
    attacks = [h for h in alert_history if h["is_attack"]]
    return {
        "count":   len(attacks[-50:]),
        "alerts":  attacks[-50:],
    }


@app.delete("/history", tags=["Historique"])
def reset_history():
    """Réinitialise l'historique et les statistiques."""
    alert_history.clear()
    stats_counter.clear()
    stats_counter["total_analyzed"] = 0
    return {"message": "Historique et statistiques réinitialisés."}
